package sso

import (
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/vault/api"
)

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
