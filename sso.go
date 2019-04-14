package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"
)

const (
	loginTemplate     = "static/login.html"
	logoutTemplate    = "static/logout.html"
	forbiddenTemplate = "static/forbidden.html"

	loginRoute  = "/sso/login"
	logoutRoute = "/sso/logout"
)

var (
	templateFuncs = template.FuncMap{
		"html": func(value interface{}) template.HTML {
			return template.HTML(fmt.Sprint(value))
		},
	}
)

type SSO struct {
	c     *Config
	proxy *httputil.ReverseProxy
}

type State struct {
	TTL      time.Time `json:"ttl"`
	Token    string    `json:"token"`
	Policies []string  `json:"policies"`
}

func New(c *Config) (*SSO, error) {
	proxy := httputil.NewSingleHostReverseProxy(c.upstreamURL)
	proxy.Transport = http.DefaultTransport
	s := &SSO{
		c:     c,
		proxy: proxy,
	}
	return s, nil
}

func (s *SSO) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mux := http.NewServeMux()
	mux.HandleFunc(loginRoute, s.handleLogin)
	mux.HandleFunc(logoutRoute, s.handleLogout)
	mux.HandleFunc("/", s.handleRequest)
	mux.ServeHTTP(w, r)
}

func (s *SSO) handleLogin(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodPost:
		s.handlePostLogin(w, req)
		return
	case http.MethodGet:
		s.handleGetLogin(w, req)
		return
	}
	http.Error(w, "Unsupported HTTP method.", http.StatusBadRequest)
}

func (s *SSO) handleGetLogin(w http.ResponseWriter, req *http.Request) {
	t, err := template.ParseFiles(loginTemplate)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse html template. %v", err), http.StatusInternalServerError)
		return
	}
	t.Funcs(templateFuncs).Execute(w, s.c.Meta)
}

func (s *SSO) isAccessAllowed(method, path string, policies []string) ([]string, bool) {
	if len(s.c.AccessList) == 0 {
		return nil, true
	}
	for _, item := range s.c.AccessList {
		if !item.re.MatchString(path) {
			continue
		}
		if len(item.methodMap) > 0 {
			_, ok := item.methodMap[method]
			if !ok {
				continue
			}
		}
		for _, p := range policies {
			_, ok := item.policyMap[p]
			if ok {
				return nil, true
			}
		}
		return item.Policies, false
	}

	return nil, true
}

func (s *SSO) newCookieFromSecret(secret *Secret) (*http.Cookie, error) {
	userState := &State{
		Policies: secret.Auth.Policies,
		Token:    secret.Auth.ClientToken,
		TTL:      time.Now().Add(secret.TTL),
	}
	b, err := json.Marshal(userState)
	if err != nil {
		return nil, fmt.Errorf("Failed to marshal user state. %v", err)
	}
	encryptedCookie, nonce, err := encrypt(b, []byte(s.c.CookieEncryptionKey))
	if err != nil {
		return nil, errors.New("Failed to encrypt user state")
	}
	encryptedCookie = append(nonce, encryptedCookie...)
	encodedCookie := base64.StdEncoding.EncodeToString(encryptedCookie)
	cookie := &http.Cookie{
		Name:    s.c.CookieName,
		Value:   encodedCookie,
		Path:    "/",
		Domain:  s.c.publicURL.Hostname(),
		Expires: userState.TTL,
	}
	return cookie, nil
}

func (s *SSO) handlePostLogin(w http.ResponseWriter, req *http.Request) {
	secret, err := Auth(s.c.VaultConfig, req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to login. %v", err), http.StatusBadRequest)
		return
	}
	cookie, err := s.newCookieFromSecret(secret)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, req, "/", http.StatusFound)
}

func (s *SSO) handleLogout(w http.ResponseWriter, req *http.Request) {
	s.setLogoutCookie(w)
	t, err := template.ParseFiles(logoutTemplate)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse html template. %v", err), http.StatusInternalServerError)
		return
	}
	t.Funcs(templateFuncs).Execute(w, s.c.Meta)
}

func (s *SSO) setLogoutCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:    s.c.CookieName,
		Value:   "",
		Path:    "/",
		Domain:  s.c.publicURL.Hostname(),
		Expires: time.Date(1970, time.January, 1, 1, 0, 0, 0, time.UTC),
	})
}

func (s *SSO) handleRequest(w http.ResponseWriter, r *http.Request) {
	state, b, err := s.stateFromRequest(r)
	if err != nil && err != http.ErrNoCookie {
		s.setLogoutCookie(w)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if state == nil {
		http.Redirect(w, r, loginRoute, http.StatusFound)
		return
	}
	requiredPolicies, ok := s.isAccessAllowed(r.Method, r.URL.Path, state.Policies)
	if !ok {
		t, err := template.ParseFiles(forbiddenTemplate)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to parse html template. %v", err), http.StatusInternalServerError)
			return
		}
		data := s.c.Meta
		data["method"] = r.Method
		data["page"] = r.URL.Path
		data["policies"] = strings.Join(requiredPolicies, ", ")
		t.Funcs(templateFuncs).Execute(w, s.c.Meta)
		return
	}
	r.Header.Add(s.c.HeaderName, string(b))
	r.URL.Scheme = s.c.upstreamURL.Scheme
	r.URL.Host = s.c.upstreamURL.Host
	r.Host = s.c.upstreamURL.Host
	r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
	s.proxy.ServeHTTP(w, r)
}

func (s *SSO) stateFromRequest(req *http.Request) (*State, []byte, error) {
	cookie, err := req.Cookie(s.c.CookieName)
	if err == http.ErrNoCookie {
		return nil, nil, http.ErrNoCookie
	}
	if err != nil {
		return nil, nil, err
	}
	decodedCookie, err := base64.StdEncoding.DecodeString(cookie.Value)
	if err != nil {
		return nil, nil, err
	}
	encryptedCookie := []byte(decodedCookie)
	nonce := encryptedCookie[:12]
	encryptedCookie = encryptedCookie[12:]
	if len(nonce) != 12 {
		return nil, nil, errors.New("Nonce must be 12 characters in length")
	}
	if len(encryptedCookie) == 0 {
		return nil, nil, errors.New("Encrypted Cookie missing")
	}
	b, err := decrypt(encryptedCookie, nonce, []byte(s.c.CookieEncryptionKey))
	if err != nil {
		return nil, nil, err
	}
	var state *State
	err = json.NewDecoder(bytes.NewReader(b)).Decode(&state)
	if err != nil {
		return nil, nil, err
	}
	return state, b, nil
}
