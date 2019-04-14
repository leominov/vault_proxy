package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"time"

	"gopkg.in/yaml.v2"
)

type Config struct {
	VaultConfig         *VaultConfig      `yaml:"vaultConfig"`
	CookieEncryptionKey string            `yaml:"cookieEncryptionKey"`
	CookieName          string            `yaml:"cookieName"`
	HeaderName          string            `yaml:"headerName"`
	PublicURLRaw        string            `yaml:"publicURL"`
	UpstreamURLRaw      string            `yaml:"upstreamURL"`
	Meta                map[string]string `yaml:"meta"`
	publicURL           *url.URL
	upstreamURL         *url.URL
}

type VaultConfig struct {
	Addr       string `yaml:"addr"`
	AuthMethod string `yaml:"authMethod"`
	PolicyName string `yaml:"policyName"`
	TTLRaw     string `yaml:"ttl"`
	ttl        time.Duration
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
	if c.VaultConfig == nil {
		return nil, errors.New("Vault configuration must be specified")
	}
	if err := c.parse(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) parse() error {
	publicURL, err := url.Parse(c.PublicURLRaw)
	if err != nil {
		return fmt.Errorf("Unable to parse PublicURL. %v", err)
	}
	c.publicURL = publicURL
	upstreamURL, err := url.Parse(c.UpstreamURLRaw)
	if err != nil {
		return fmt.Errorf("Unable to parse UpstreamURL. %v", err)
	}
	c.upstreamURL = upstreamURL
	if err := c.VaultConfig.parse(); err != nil {
		return err
	}
	return nil
}

func (v *VaultConfig) parse() error {
	if v.TTLRaw != "token" {
		d, err := time.ParseDuration(v.TTLRaw)
		if err != nil {
			return fmt.Errorf("Unable to parse TTL. %v", err)
		}
		v.ttl = d
	}
	_, err := url.Parse(v.Addr)
	if err != nil {
		return fmt.Errorf("Unable to parse Vault address. %v", err)
	}
	return nil
}
