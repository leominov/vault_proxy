package main

import (
	"flag"
	"log"
	"net/http"
)

var (
	configFile    = flag.String("config", "config.yaml", "Path to configuration file")
	listenAddress = flag.String("listen-address", ":8080", "Address to server requests")
)

func main() {
	flag.Parse()
	log.Println("Starting vault-auth-proxy...")
	c, err := LoadConfig(*configFile)
	if err != nil {
		log.Fatal(err)
	}
	sso, err := New(c)
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{
		Addr:    *listenAddress,
		Handler: sso,
	}
	log.Printf("Serving incoming requests on %s address", server.Addr)
	log.Fatal(server.ListenAndServe())
}
