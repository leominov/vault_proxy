package sso

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	loginTemplate     = "static/login.html"
	logoutTemplate    = "static/logout.html"
	forbiddenTemplate = "static/forbidden.html"

	loginRoute  = "/_/login"
	logoutRoute = "/_/logout"
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
	log   *logrus.Logger
	proxy *httputil.ReverseProxy
}

type State struct {
	TTL      time.Time `json:"ttl"`
	Token    string    `json:"token"`
	Policies []string  `json:"policies"`
}

func New(c *Config, l *logrus.Logger) (*SSO, error) {
	proxy := httputil.NewSingleHostReverseProxy(c.upstreamURL)
	entry := logrus.NewEntry(l)
	proxy.ErrorLog = log.New(entry.WriterLevel(logrus.ErrorLevel), "", 0)
	proxy.Transport = http.DefaultTransport
	s := &SSO{
		c:     c,
		log:   l,
		proxy: proxy,
	}
	return s, nil
}

func (s *SSO) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mux := http.NewServeMux()
	fs := http.FileServer(http.Dir("static"))

	mux.HandleFunc(loginRoute, s.LoginRequest)
	mux.HandleFunc(logoutRoute, s.LogoutRequest)
	mux.Handle("/_/", http.StripPrefix("/_/", fs))
	mux.HandleFunc("/", s.ProxyRequest)

	mux.ServeHTTP(w, r)
}

func (s *SSO) isAccessAllowed(method, path string, policies []string) (*AccesItem, bool) {
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
		return item, false
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

func (s *SSO) showForbiddenError(w http.ResponseWriter, r *http.Request, meta map[string]interface{}) {
	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	switch contentType {
	case "application/json":
		encoder := json.NewEncoder(w)
		message := map[string]interface{}{
			"request":    meta["request"],
			"error":      "Access forbidden",
			"error_code": http.StatusForbidden,
		}
		w.WriteHeader(http.StatusForbidden)
		encoder.Encode(message)
	default:
		t, err := template.ParseFiles(forbiddenTemplate)
		if err != nil {
			s.log.Errorf("Failed to parse html template. %v", err)
			http.Error(w, fmt.Sprintf("Failed to parse html template. %v", err), http.StatusInternalServerError)
			return
		}
		t.Funcs(templateFuncs).Execute(w, meta)
	}
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
