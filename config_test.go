package main

import (
	"testing"
)

func TestParse_Rule(t *testing.T) {
	a := &Rule{
		Policies: []string{"admin"},
		Methods:  []string{"post", "get"},
		Path:     "/route",
	}
	err := a.Parse()
	if err != nil {
		t.Errorf("Must be nil, but got %v", err)
	}
	b := &Rule{
		Policies: []string{"admin"},
		Methods:  []string{"post", "get"},
		Path:     "`[[/route",
	}
	err = b.Parse()
	if err == nil {
		t.Error("Must be error, but got nil")
	}
}

func TestParse_Config(t *testing.T) {
	var (
		c   *Config
		err error
	)
	c = &Config{
		VaultConfig: &VaultConfig{
			Addr:       "https://google.com",
			TTLRaw:     "token",
			AuthMethod: "ldap",
		},
		PublicURLRaw:   "https://google.com",
		UpstreamURLRaw: "https://google.com",
		Rules: []*Rule{
			{
				Policies: []string{"admin"},
				Methods:  []string{"post", "get"},
				Path:     "/route",
			},
		},
	}
	err = c.Parse()
	if err != nil {
		t.Errorf("Must be nil, but got %v", err)
	}
	c = &Config{
		VaultConfig: &VaultConfig{
			Addr:   "https://google.com",
			TTLRaw: "token",
		},
		PublicURLRaw:   "https`://google.com",
		UpstreamURLRaw: "https://google.com",
		Rules: []*Rule{
			{
				Policies: []string{"admin"},
				Methods:  []string{"post", "get"},
				Path:     "/route",
			},
		},
	}
	err = c.Parse()
	if err == nil {
		t.Error("Must be error, but got nil")
	}
	c = &Config{
		VaultConfig: &VaultConfig{
			Addr:   "https://google.com",
			TTLRaw: "token",
		},
		PublicURLRaw:   "https://google.com",
		UpstreamURLRaw: "https`://google.com",
		Rules: []*Rule{
			{
				Policies: []string{"admin"},
				Methods:  []string{"post", "get"},
				Path:     "/route",
			},
		},
	}
	err = c.Parse()
	if err == nil {
		t.Error("Must be error, but got nil")
	}
	c = &Config{
		VaultConfig: &VaultConfig{
			Addr:   "https://google.com",
			TTLRaw: "token",
		},
		PublicURLRaw:   "https://google.com",
		UpstreamURLRaw: "https://google.com",
		Rules: []*Rule{
			{
				Policies: []string{"admin"},
				Methods:  []string{"post", "get"},
				Path:     "`[[/route",
			},
		},
	}
	err = c.Parse()
	if err == nil {
		t.Error("Must be error, but got nil")
	}
	c = &Config{
		VaultConfig:    nil,
		PublicURLRaw:   "https://google.com",
		UpstreamURLRaw: "https://google.com",
		Rules: []*Rule{
			&Rule{
				Policies: []string{"admin"},
				Methods:  []string{"post", "get"},
				Path:     "/route",
			},
		},
	}
	err = c.Parse()
	if err == nil {
		t.Error("Must be error, but got nil")
	}
	c = &Config{
		VaultConfig: &VaultConfig{
			Addr:   "https://google.com",
			TTLRaw: "token2",
		},
		PublicURLRaw:   "https://google.com",
		UpstreamURLRaw: "https://google.com",
		Rules: []*Rule{
			{
				Policies: []string{"admin"},
				Methods:  []string{"post", "get"},
				Path:     "/route",
			},
		},
	}
	err = c.Parse()
	if err == nil {
		t.Error("Must be error, but got nil")
	}
}

func TestLoadConfig(t *testing.T) {
	_, err := LoadConfig("test_data/config_not_found.yaml")
	if err == nil {
		t.Error("Must be error, but got nil")
	}
	_, err = LoadConfig("test_data/config_invalid_unmarshal.yaml")
	if err == nil {
		t.Error("Must be error, but got nil")
	}
	_, err = LoadConfig("test_data/config_invalid_public_url.yaml")
	if err == nil {
		t.Error("Must be error, but got nil")
	}
	_, err = LoadConfig("test_data/config_valid.yaml")
	if err != nil {
		t.Error(err)
	}
}
