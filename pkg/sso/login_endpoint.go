package sso

import (
	"fmt"
	"html/template"
	"net/http"
)

func (s *SSO) LoginRequest(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodPost:
		s.processFormLogin(w, req)
		return
	case http.MethodGet:
		s.showFormLogin(w, req)
		return
	}
	http.Error(w, "Unsupported HTTP method.", http.StatusBadRequest)
}

func (s *SSO) showFormLogin(w http.ResponseWriter, req *http.Request) {
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

func (s *SSO) processFormLogin(w http.ResponseWriter, req *http.Request) {
	secret, err := Auth(s.c.VaultConfig, req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to login. %v", err), http.StatusBadRequest)
		return
	}
	s.log.Debugf("Authorized: %v", secret.Auth.Metadata)
	cookie, err := s.newCookieFromSecret(secret)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, req, "/", http.StatusFound)
}
