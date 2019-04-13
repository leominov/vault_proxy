package main

import (
	"fmt"

	"github.com/hashicorp/vault/api"
)

func Auth(addr, method, login, password string) (*api.Secret, error) {
	config := api.Config{
		Address: addr,
	}
	client, err := api.NewClient(&config)
	if err != nil {
		return nil, err
	}
	options := map[string]interface{}{
		"password": password,
	}
	path := fmt.Sprintf("auth/%s/login/%s", method, login)
	secret, err := client.Logical().Write(path, options)
	if err != nil {
		return nil, err
	}
	return secret, nil
}
