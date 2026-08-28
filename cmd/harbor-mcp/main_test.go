package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadOrGenerateKey_GeneratesWhenEmpty(t *testing.T) {
	key, err := loadOrGenerateKey("")
	require.NoError(t, err)
	require.NotNil(t, key)
	assert.Equal(t, 2048, key.N.BitLen())
}

func TestLoadOrGenerateKey_ParsesValidPEM(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	parsed, err := loadOrGenerateKey(string(pemBytes))
	require.NoError(t, err)
	assert.Equal(t, 0, parsed.N.Cmp(key.N), "parsed key does not match original")
}

func TestLoadOrGenerateKey_InvalidPEM(t *testing.T) {
	_, err := loadOrGenerateKey("not a pem")
	require.Error(t, err)
}

func TestLoadOrGenerateKey_InvalidKeyBytes(t *testing.T) {
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("not a valid key"),
	})

	_, err := loadOrGenerateKey(string(pemBytes))
	require.Error(t, err)
}
