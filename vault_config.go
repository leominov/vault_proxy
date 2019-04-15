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
