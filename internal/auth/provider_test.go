package auth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rophy/harbor-mcp/internal/auth"
)

func TestNewOAuthProvider(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	store := auth.NewMemoryStore()
	provider := auth.NewOAuthProvider(store, key)
	require.NotNil(t, provider)
}

func TestMemoryStore_RegisterAndGetClient(t *testing.T) {
	store := auth.NewMemoryStore()
	store.RegisterClient("test-client", []string{"http://localhost:3000/callback"})

	client, err := store.GetClient(nil, "test-client")
	require.NoError(t, err)
	assert.Equal(t, "test-client", client.GetID())
}

func TestMemoryStore_GetClient_NotFound(t *testing.T) {
	store := auth.NewMemoryStore()
	_, err := store.GetClient(nil, "nonexistent")
	require.Error(t, err)
}
