package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
)

func parseFormRequest(r *http.Request) (login string, password string, err error) {
	err = r.ParseForm()
	if err != nil {
		err = errors.New("failed to parse form")
		return
	}
	login = r.Form.Get("login")
	password = r.Form.Get("password")
	return
}

// https://gist.github.com/kkirsche/e28da6754c39d5e7ea10
func encrypt(plaintext, key []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	return aesgcm.Seal(nil, nonce, plaintext, nil), nonce, nil
}

func decrypt(ciphertext, nonce, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesgcm.Open(nil, nonce, ciphertext, nil)
}
