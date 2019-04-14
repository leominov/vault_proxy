package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"regexp"
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
	AccessList          []*AccesItem      `yaml:"accessList"`
	routeRegExpMap      map[string]*regexp.Regexp
	publicURL           *url.URL
	upstreamURL         *url.URL
}

type AccesItem struct {
	Path   string `yaml:"path"`
	Policy string `yaml:"policy"`
	re     *regexp.Regexp
}

type VaultConfig struct {
	Addr       string `yaml:"addr"`
	AuthMethod string `yaml:"authMethod"`
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
	c.routeRegExpMap = make(map[string]*regexp.Regexp, len(c.AccessList))
	for _, item := range c.AccessList {
		re, err := regexp.Compile(item.Path)
		if err != nil {
			return fmt.Errorf("Unable to parse '%s' as regular expression. %v", item.Path, err)
		}
		item.re = re
	}
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
