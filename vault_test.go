package main

import "testing"

func TestParse(t *testing.T) {
	var (
		c   *VaultConfig
		err error
	)
	c = &VaultConfig{
		Addr:   "https://google.com",
		TTLRaw: "7d",
	}
	err = c.Parse()
	if err == nil {
		t.Error("Must be error, but got nil")
	}
	c = &VaultConfig{
		Addr:   "https://google.com",
		TTLRaw: "120h",
	}
	err = c.Parse()
	if err != nil {
		t.Errorf("Must be nil, but got %v", err)
	}
	c = &VaultConfig{
		Addr:   "https`://google.com",
		TTLRaw: "120h",
	}
	err = c.Parse()
	if err == nil {
		t.Error("Must be error, but got nil")
	}
}
