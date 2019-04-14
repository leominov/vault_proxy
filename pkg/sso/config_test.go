package sso

import (
	"testing"
)

func TestParse_AccesItem(t *testing.T) {
	a := &AccesItem{
		Policies: []string{"admin"},
		Methods:  []string{"post", "get"},
		Path:     "/route",
	}
	err := a.Parse()
	if err != nil {
		t.Errorf("Must be nil, but got %v", err)
	}
	b := &AccesItem{
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
			Addr:   "https://google.com",
			TTLRaw: "token",
		},
		PublicURLRaw:   "https://google.com",
		UpstreamURLRaw: "https://google.com",
		AccessList: []*AccesItem{
			&AccesItem{
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
		AccessList: []*AccesItem{
			&AccesItem{
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
		AccessList: []*AccesItem{
			&AccesItem{
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
		AccessList: []*AccesItem{
			&AccesItem{
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
		AccessList: []*AccesItem{
			&AccesItem{
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
		AccessList: []*AccesItem{
			&AccesItem{
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
