package main

import (
	"log"
	"net/http"
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
	log.Printf("HTTP service listening on %s", s.Addr)
	log.Fatal(s.ListenAndServe())
}
