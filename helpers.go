package main

import (
	"errors"
	"net/http"
)

func parseFormRequest(r *http.Request) (login string, password string, err error) {
	err = r.ParseForm()
	if err != nil {
		err = errors.New("Failed to parse form")
		return
	}
	login = r.Form.Get("login")
	password = r.Form.Get("password")
	return
}
