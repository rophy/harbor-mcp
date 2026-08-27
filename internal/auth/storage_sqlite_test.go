package auth_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ory/fosite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rophy/harbor-mcp/internal/auth"
)

func TestSQLiteStore_InvalidPath(t *testing.T) {
	_, err := auth.NewSQLiteStore("/dev/null/impossible/path.db")
	require.Error(t, err)
}

func TestSQLiteStore_PersistsClients(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")

	store1, err := auth.NewSQLiteStore(dbPath)
	require.NoError(t, err)

	store1.RegisterClient("test-client-1", []string{"http://localhost/callback"})
	store1.RegisterClient("test-client-2", []string{"http://example.com/cb1", "http://example.com/cb2"})

	client, err := store1.GetClient(context.Background(), "test-client-1")
	require.NoError(t, err)
	assert.Equal(t, "test-client-1", client.GetID())

	store1.Close()

	store2, err := auth.NewSQLiteStore(dbPath)
	require.NoError(t, err)
	defer store2.Close()

	client, err = store2.GetClient(context.Background(), "test-client-1")
	require.NoError(t, err)
	assert.Equal(t, "test-client-1", client.GetID())

	client2, err := store2.GetClient(context.Background(), "test-client-2")
	require.NoError(t, err)
	assert.Len(t, client2.GetRedirectURIs(), 2)

	_, err = store2.GetClient(context.Background(), "nonexistent")
	assert.ErrorIs(t, err, fosite.ErrNotFound)
}
