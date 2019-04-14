package main

import (
	"fmt"
	"net/http"

	"github.com/hashicorp/vault/api"
)

type VaultConfig struct {
	Addr       string `yaml:"addr"`
	AuthMethod string `yaml:"authMethod"`
	PolicyName string `yaml:"policyName"`
}

func Auth(c *VaultConfig, r *http.Request) (*api.Secret, error) {
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
	return secret, nil
}
