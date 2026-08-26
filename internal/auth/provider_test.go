package auth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/rophy/harbor-mcp/internal/auth"
)

func TestNewOAuthProvider(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	store := auth.NewMemoryStore()
	provider := auth.NewOAuthProvider(store, key)
	if provider == nil {
		t.Fatal("provider is nil")
	}
}

func TestMemoryStore_RegisterAndGetClient(t *testing.T) {
	store := auth.NewMemoryStore()
	store.RegisterClient("test-client", []string{"http://localhost:3000/callback"})

	client, err := store.GetClient(nil, "test-client")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.GetID() != "test-client" {
		t.Errorf("ID = %q, want %q", client.GetID(), "test-client")
	}
}

func TestMemoryStore_GetClient_NotFound(t *testing.T) {
	store := auth.NewMemoryStore()
	_, err := store.GetClient(nil, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent client")
	}
}
