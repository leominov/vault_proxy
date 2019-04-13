package main

import (
	"log"
	"net/http"

	"github.com/Sirupsen/logrus"
)

func main() {
	c, err := LoadConfig("config.yaml")
	if err != nil {
		log.Fatal(err)
	}
	sso, err := New(c)
	if err != nil {
		log.Fatal(err)
	}
	s := &http.Server{
		Addr:    ":8080",
		Handler: sso,
	}
	logrus.Infof("HTTP service listening on %s", s.Addr)
	logrus.Panic(s.ListenAndServe())
}
