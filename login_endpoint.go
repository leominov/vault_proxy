package main

import (
	"fmt"
	"html/template"
	"net/http"
)

func (s *Server) LoginRequest(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.processFormLogin(w, r)
		return
	case http.MethodGet:
		s.showFormLogin(w, r)
		return
	}
	http.Error(w, "Unsupported HTTP method.", http.StatusBadRequest)
}

func (s *Server) showFormLogin(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles(loginTemplate)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse html template. %v", err), http.StatusInternalServerError)
		return
	}
	data := map[string]interface{}{
		"meta": s.c.Meta,
		"vars": map[string]string{
			"login": loginRoute,
		},
	}
	t.Funcs(templateFuncs).Execute(w, data)
}

func (s *Server) processFormLogin(w http.ResponseWriter, r *http.Request) {
	secret, err := Auth(r, s.c.VaultConfig)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to login. %v", err), http.StatusBadRequest)
		return
	}
	s.log.WithField("vault_request_id", secret.RequestID).Debugf("Authorized: %v", secret.Auth.Metadata)
	cookie, err := s.newCookieFromSecret(secret)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/", http.StatusFound)
}
