package main

import (
	"fmt"

	"github.com/hashicorp/vault/api"
)

type VaultConfig struct {
	Addr       string `yaml:"addr"`
	AuthMethod string `yaml:"authMethod"`
	PolicyName string `yaml:"policyName"`
}

func Auth(c *VaultConfig, login, password string) (*api.Secret, error) {
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
