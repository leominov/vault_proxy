package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

type SSO struct {
	c           *Config
	publicURL   *url.URL
	upstreamURL *url.URL
	proxy       *httputil.ReverseProxy
}

type State struct {
	Token string `json:"token"`
}

func New(c *Config) (*SSO, error) {
	publicURL, err := url.Parse(c.PublicURL)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse PublicURL. %v", err)
	}
	upstreamURL, err := url.Parse(c.UpstreamURL)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse UpstreamURL. %v", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(upstreamURL)
	proxy.Transport = http.DefaultTransport
	s := &SSO{
		c:           c,
		publicURL:   publicURL,
		upstreamURL: upstreamURL,
		proxy:       proxy,
	}
	return s, nil
}

func (s *SSO) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mux := http.NewServeMux()
	fs := http.FileServer(http.Dir("static"))
	mux.Handle("/sso/", http.StripPrefix("/sso/", fs))

	mux.HandleFunc("/sso/login", s.handleLogin)
	mux.HandleFunc("/sso/logout", s.handleLogout)
	mux.HandleFunc("/", s.handleRequest)

	mux.ServeHTTP(w, r)
}

func (s *SSO) handleLogin(w http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		http.Error(w, "Failed to parse form.", http.StatusBadRequest)
		return
	}
	login := req.Form.Get("login")
	pass := req.Form.Get("password")
	if len(login) == 0 || len(pass) == 0 {
		http.Error(w, "Login and password must be specified.", http.StatusBadRequest)
		return
	}
	secret, err := Auth(s.c.VaultAddr, s.c.VaultAuthMethod, login, pass)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to login. %v", err), http.StatusBadRequest)
		return
	}
	var allowed bool
	for _, policy := range secret.Auth.Policies {
		if policy == s.c.VaultPolicyName {
			allowed = true
		}
	}
	if !allowed {
		http.Error(w, "Access forbidden.", http.StatusForbidden)
		return
	}
	userState := &State{
		Token: secret.Auth.ClientToken,
	}
	b, err := json.Marshal(userState)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	encryptedCookie, nonce, err := encrypt(b, []byte(s.c.CookieEncryptionKey))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	encryptedCookie = append(nonce, encryptedCookie...)
	encodedCookie := base64.StdEncoding.EncodeToString(encryptedCookie)
	http.SetCookie(w, &http.Cookie{
		Name:    s.c.CookieName,
		Value:   encodedCookie,
		Path:    "/",
		Domain:  s.publicURL.Hostname(),
		Expires: time.Now().Add(time.Duration(secret.Auth.LeaseDuration) * time.Second),
	})
	http.Redirect(w, req, "/", http.StatusFound)
}

func (s *SSO) handleLogout(w http.ResponseWriter, req *http.Request) {
	s.setLogoutCookie(w)
	w.Write([]byte("Logged out"))
}

func (s *SSO) setLogoutCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:    s.c.CookieName,
		Value:   "",
		Path:    "/",
		Domain:  s.publicURL.Hostname(),
		Expires: time.Date(1970, time.January, 1, 1, 0, 0, 0, time.UTC),
	})
}

func (s *SSO) handleRequest(w http.ResponseWriter, r *http.Request) {
	state, err := s.stateFromRequest(r)
	if err != nil && err != http.ErrNoCookie {
		s.setLogoutCookie(w)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if state != nil {
		b, err := json.Marshal(state)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		r.Header.Add(s.c.HeaderName, string(b))
		r.URL.Scheme = s.upstreamURL.Scheme
		r.URL.Host = s.upstreamURL.Host
		r.Host = s.upstreamURL.Host
		r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
		s.proxy.ServeHTTP(w, r)
		return
	}
	http.Redirect(w, r, "/sso/login.html", http.StatusFound)
}

func (s *SSO) stateFromRequest(req *http.Request) (*State, error) {
	cookie, err := req.Cookie(s.c.CookieName)
	if err == http.ErrNoCookie {
		return nil, http.ErrNoCookie
	}
	if err != nil {
		return nil, err
	}
	decodedCookie, err := base64.StdEncoding.DecodeString(cookie.Value)
	if err != nil {
		return nil, err
	}
	encryptedCookie := []byte(decodedCookie)
	nonce := encryptedCookie[:12]
	encryptedCookie = encryptedCookie[12:]
	if len(nonce) != 12 {
		return nil, errors.New("Nonce must be 12 characters in length")
	}
	if len(encryptedCookie) == 0 {
		return nil, errors.New("Encrypted Cookie missing")
	}
	b, err := decrypt(encryptedCookie, nonce, []byte(s.c.CookieEncryptionKey))
	if err != nil {
		return nil, err
	}
	var state *State
	err = json.NewDecoder(bytes.NewReader(b)).Decode(&state)
	if err != nil {
		return nil, err
	}
	return state, nil
}
