package main

import (
	"fmt"
	"html/template"
	"net/http"
	"time"
)

func (s *SSO) LogoutRequest(w http.ResponseWriter, req *http.Request) {
	s.setLogoutCookie(w)
	t, err := template.ParseFiles(logoutTemplate)
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

func (s *SSO) setLogoutCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:    s.c.CookieName,
		Value:   "",
		Path:    "/",
		Domain:  s.c.publicURL.Hostname(),
		Expires: time.Date(1970, time.January, 1, 1, 0, 0, 0, time.UTC),
	})
}
