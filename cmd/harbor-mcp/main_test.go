package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestLoadOrGenerateKey_GeneratesWhenEmpty(t *testing.T) {
	key, err := loadOrGenerateKey("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
	if key.N.BitLen() != 2048 {
		t.Errorf("key size = %d, want 2048", key.N.BitLen())
	}
}

func TestLoadOrGenerateKey_ParsesValidPEM(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	parsed, err := loadOrGenerateKey(string(pemBytes))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.N.Cmp(key.N) != 0 {
		t.Error("parsed key does not match original")
	}
}

func TestLoadOrGenerateKey_InvalidPEM(t *testing.T) {
	_, err := loadOrGenerateKey("not a pem")
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestLoadOrGenerateKey_InvalidKeyBytes(t *testing.T) {
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("not a valid key"),
	})

	_, err := loadOrGenerateKey(string(pemBytes))
	if err == nil {
		t.Fatal("expected error for invalid key bytes")
	}
}
