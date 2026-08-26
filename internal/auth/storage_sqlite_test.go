package auth_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ory/fosite"
	"github.com/rophy/harbor-mcp/internal/auth"
)

func TestSQLiteStore_PersistsClients(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")

	store1, err := auth.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	store1.RegisterClient("test-client-1", []string{"http://localhost/callback"})
	store1.RegisterClient("test-client-2", []string{"http://example.com/cb1", "http://example.com/cb2"})

	client, err := store1.GetClient(context.Background(), "test-client-1")
	if err != nil {
		t.Fatalf("get client from store1: %v", err)
	}
	if client.GetID() != "test-client-1" {
		t.Errorf("client ID = %q, want test-client-1", client.GetID())
	}

	store1.Close()

	store2, err := auth.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer store2.Close()

	client, err = store2.GetClient(context.Background(), "test-client-1")
	if err != nil {
		t.Fatalf("get client from store2: %v", err)
	}
	if client.GetID() != "test-client-1" {
		t.Errorf("client ID = %q, want test-client-1", client.GetID())
	}

	client2, err := store2.GetClient(context.Background(), "test-client-2")
	if err != nil {
		t.Fatalf("get client2 from store2: %v", err)
	}
	uris := client2.GetRedirectURIs()
	if len(uris) != 2 {
		t.Errorf("redirect URIs count = %d, want 2", len(uris))
	}

	_, err = store2.GetClient(context.Background(), "nonexistent")
	if err != fosite.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}
