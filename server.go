package main

import (
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

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

const (
	loginTemplate     = "static/login.html"
	logoutTemplate    = "static/logout.html"
	forbiddenTemplate = "static/forbidden.html"

	loginRoute   = "/-/login"
	logoutRoute  = "/-/logout"
	metricsRoute = "/-/metrics"
)

var (
	templateFuncs = template.FuncMap{
		"html": func(value interface{}) template.HTML {
			return template.HTML(fmt.Sprint(value))
		},
	}
)

type Server struct {
	c     *Config
	log   *logrus.Logger
	proxy *httputil.ReverseProxy
}

func New(c *Config, l *logrus.Logger) (*Server, error) {
	proxy := httputil.NewSingleHostReverseProxy(c.upstreamURL)
	entry := logrus.NewEntry(l)
	proxy.ErrorLog = log.New(entry.WriterLevel(logrus.ErrorLevel), "", 0)
	proxy.Transport = http.DefaultTransport
	s := &Server{
		c:     c,
		log:   l,
		proxy: proxy,
	}
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mux := http.NewServeMux()
	fs := http.FileServer(http.Dir("static"))

	mux.HandleFunc(loginRoute, s.LoginRequest)
	mux.HandleFunc(logoutRoute, s.LogoutRequest)
	mux.Handle(metricsRoute, promhttp.Handler())
	mux.Handle("/_/", http.StripPrefix("/_/", fs))
	mux.HandleFunc("/", s.ProxyRequest)

	mux.ServeHTTP(w, r)
}

func (s *Server) isAccessAllowed(method, path string, policies []string) (*Rule, bool) {
	if len(s.c.Rules) == 0 {
		return nil, true
	}
	for _, rule := range s.c.Rules {
		if !rule.re.MatchString(path) {
			continue
		}
		if len(rule.methodMap) > 0 {
			_, ok := rule.methodMap[method]
			if !ok {
				continue
			}
		}
		for _, p := range policies {
			_, ok := rule.policyMap[p]
			if ok {
				return nil, true
			}
		}
		return rule, false
	}

	return nil, true
}

func (s *Server) newCookieFromSecret(secret *Secret) (*http.Cookie, error) {
	userState := &State{
		Policies: secret.Auth.Policies,
		TTL:      time.Now().Add(secret.TTL),
	}
	b, err := json.Marshal(userState)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal user state. %v", err)
	}
	encryptedCookie, nonce, err := encrypt(b, []byte(s.c.CookieEncryptionKey))
	if err != nil {
		return nil, errors.New("failed to encrypt user state")
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

func (s *Server) showForbiddenError(w http.ResponseWriter, r *http.Request, meta map[string]interface{}) {
	var terr error
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
		terr = encoder.Encode(message)
	default:
		t, err := template.ParseFiles(forbiddenTemplate)
		if err != nil {
			s.log.Errorf("Failed to parse html template. %v", err)
			http.Error(w, fmt.Sprintf("Failed to parse html template. %v", err), http.StatusInternalServerError)
			return
		}
		terr = t.Funcs(templateFuncs).Execute(w, meta)
	}
	if terr != nil {
		s.log.Errorf("Failed to render template: %v", terr)
		http.Error(w, fmt.Sprintf("Failed to render tamplate: %v", terr), http.StatusInternalServerError)
	}
}
