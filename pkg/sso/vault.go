package sso

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/hashicorp/vault/api"
)

type VaultConfig struct {
	Addr       string `yaml:"addr"`
	AuthMethod string `yaml:"authMethod"`
	TTLRaw     string `yaml:"ttl"`
	ttl        time.Duration
}

type Secret struct {
	*api.Secret
	TTL time.Duration
}

func Auth(c *VaultConfig, r *http.Request) (*Secret, error) {
	login, password, err := parseFormRequest(r)
	if err != nil {
		return nil, err
	}
	config := api.Config{
		Address: c.Addr,
	}
	client, err := api.NewClient(&config)
	if err != nil {
		return nil, err
	}
	options := map[string]interface{}{
		"password": password,
	}
	path := fmt.Sprintf("auth/%s/login/%s", c.AuthMethod, login)
	secret, err := client.Logical().Write(path, options)
	if err != nil {
		return nil, err
	}
	ttl := time.Duration(secret.Auth.LeaseDuration) * time.Second
	if c.TTLRaw != "token" {
		ttl = c.ttl
	}
	return &Secret{secret, ttl}, nil
}

func (v *VaultConfig) Parse() error {
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
