package main

import (
	"fmt"
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

type Config struct {
	VaultConfig         *VaultConfig      `yaml:"vaultConfig"`
	CookieEncryptionKey string            `yaml:"cookieEncryptionKey"`
	CookieName          string            `yaml:"cookieName"`
	HeaderName          string            `yaml:"headerName"`
	PublicURL           string            `yaml:"publicURL"`
	UpstreamURL         string            `yaml:"upstreamURL"`
	Meta                map[string]string `yaml:"meta"`
}

func LoadConfig(filename string) (*Config, error) {
	out, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("Unable to load configuration file. %v", err)
	}
	c := &Config{}
	err = yaml.Unmarshal(out, &c)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse configuration file. %v", err)
	}
	return c, nil
}
