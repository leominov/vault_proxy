package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"regexp"
	"strings"

	"gopkg.in/yaml.v2"
)

type Config struct {
	VaultConfig         *VaultConfig           `yaml:"vaultConfig"`
	CookieEncryptionKey string                 `yaml:"cookieEncryptionKey"`
	CookieName          string                 `yaml:"cookieName"`
	HeaderName          string                 `yaml:"headerName"`
	PublicURLRaw        string                 `yaml:"publicURL"`
	UpstreamURLRaw      string                 `yaml:"upstreamURL"`
	Meta                map[string]interface{} `yaml:"meta"`
	Rules               []*Rule                `yaml:"rules"`
	routeRegExpMap      map[string]*regexp.Regexp
	publicURL           *url.URL
	upstreamURL         *url.URL
}

type Rule struct {
	Name      string   `yaml:"name"`
	Path      string   `yaml:"path"`
	Policies  []string `yaml:"policies"`
	Methods   []string `yaml:"methods"`
	methodMap map[string]bool
	policyMap map[string]bool
	re        *regexp.Regexp
}

func LoadConfig(filename string) (*Config, error) {
	out, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("unable to load configuration file. %v", err)
	}
	c := &Config{}
	err = yaml.Unmarshal(out, &c)
	if err != nil {
		return nil, fmt.Errorf("unable to parse configuration file. %v", err)
	}
	if err := c.Parse(); err != nil {
		return nil, err
	}
	return c, nil
}

func (r *Rule) Parse() error {
	r.policyMap = make(map[string]bool, len(r.Policies))
	for _, policy := range r.Policies {
		r.policyMap[policy] = true
	}
	r.methodMap = make(map[string]bool, len(r.Methods))
	for _, method := range r.Methods {
		r.methodMap[strings.ToUpper(method)] = true
	}
	re, err := regexp.Compile(r.Path)
	if err != nil {
		return fmt.Errorf("unable to parse '%s' as regular expression. %v", r.Path, err)
	}
	r.re = re
	return nil
}

func (c *Config) Parse() error {
	publicURL, err := url.Parse(c.PublicURLRaw)
	if err != nil {
		return fmt.Errorf("unable to parse PublicURL. %v", err)
	}
	c.publicURL = publicURL
	upstreamURL, err := url.Parse(c.UpstreamURLRaw)
	if err != nil {
		return fmt.Errorf("unable to parse UpstreamURL. %v", err)
	}
	c.upstreamURL = upstreamURL
	c.routeRegExpMap = make(map[string]*regexp.Regexp, len(c.Rules))
	for _, rule := range c.Rules {
		err := rule.Parse()
		if err != nil {
			return err
		}
	}
	if c.VaultConfig == nil {
		return errors.New("configuration for Vault must be specified")
	}
	return c.VaultConfig.Parse()
}
