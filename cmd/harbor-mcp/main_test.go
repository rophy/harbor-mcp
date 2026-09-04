package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadOrGenerateKey_GeneratesAndPersists(t *testing.T) {
	dir := t.TempDir()
	key, err := loadOrGenerateKey("", dir)
	require.NoError(t, err)
	require.NotNil(t, key)
	assert.Equal(t, 2048, key.N.BitLen())

	_, err = os.Stat(filepath.Join(dir, "signing-key.pem"))
	assert.NoError(t, err, "signing key file should be created")

	key2, err := loadOrGenerateKey("", dir)
	require.NoError(t, err)
	assert.Equal(t, 0, key2.N.Cmp(key.N), "reloaded key should match")
}

func TestLoadOrGenerateKey_ParsesPKCS1(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	parsed, err := loadOrGenerateKey(string(pemBytes), t.TempDir())
	require.NoError(t, err)
	assert.Equal(t, 0, parsed.N.Cmp(key.N))
}

func TestLoadOrGenerateKey_ParsesPKCS8(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	})

	parsed, err := loadOrGenerateKey(string(pemBytes), t.TempDir())
	require.NoError(t, err)
	assert.Equal(t, 0, parsed.N.Cmp(key.N))
}

func TestLoadOrGenerateKey_InvalidPEM(t *testing.T) {
	_, err := loadOrGenerateKey("not a pem", t.TempDir())
	require.Error(t, err)
}

func TestLoadOrGenerateKey_InvalidKeyBytes(t *testing.T) {
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("not a valid key"),
	})

	_, err := loadOrGenerateKey(string(pemBytes), t.TempDir())
	require.Error(t, err)
}

func TestLoadOrGenerateGlobalSecret_GeneratesAndPersists(t *testing.T) {
	dir := t.TempDir()
	secret, err := loadOrGenerateGlobalSecret(dir)
	require.NoError(t, err)
	assert.Len(t, secret, 32)

	secret2, err := loadOrGenerateGlobalSecret(dir)
	require.NoError(t, err)
	assert.Equal(t, secret, secret2, "reloaded secret should match")
}
