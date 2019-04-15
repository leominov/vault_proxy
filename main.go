package main

import (
	"flag"
	"net/http"

	"github.com/sirupsen/logrus"
)

var (
	configFile    = flag.String("config", "config.yaml", "Path to configuration file")
	listenAddress = flag.String("listen-address", "127.0.0.1:8080", "Address to server requests")
	logLevel      = flag.String("log-level", "debug", "Logging level")
)

func main() {
	flag.Parse()

	logger := logrus.New()
	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		logger.Fatal(err)
	}

	logger.SetLevel(level)
	logger.Info("Starting vault_proxy...")

	c, err := LoadConfig(*configFile)
	if err != nil {
		logger.Fatal(err)
	}

	server, err := New(c, logger)
	if err != nil {
		logger.Fatal(err)
	}

	httpServer := &http.Server{
		Addr:    *listenAddress,
		Handler: server,
	}

	logger.Infof("Listening address: %s", httpServer.Addr)
	logger.Fatal(httpServer.ListenAndServe())
}
