package main

import (
	"fmt"
	"net/url"
	"time"
)

type VaultConfig struct {
	Addr       string `yaml:"addr"`
	AuthMethod string `yaml:"authMethod"`
	MaxRetries int    `yaml:"maxRetries"`
	TTLRaw     string `yaml:"ttl"`
	ttl        time.Duration
}

func (v *VaultConfig) Parse() error {
	if v.TTLRaw != "token" {
		d, err := time.ParseDuration(v.TTLRaw)
		if err != nil {
			return fmt.Errorf("unable to parse TTL. %v", err)
		}
		v.ttl = d
	}
	if v.AuthMethod != "userpass" && v.AuthMethod != "ldap" {
		return fmt.Errorf("unknown Vault auth method: %s", v.AuthMethod)
	}
	_, err := url.Parse(v.Addr)
	if err != nil {
		return fmt.Errorf("unable to parse Vault address. %v", err)
	}
	return nil
}
