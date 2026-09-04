package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rophy/harbor-mcp/internal/auth"
)

func TestNewOAuthProvider(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	store := auth.NewMemoryStore()
	provider := auth.NewOAuthProvider(store, key, make([]byte, 32))
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

func newReq(id string) *fosite.Request {
	r := fosite.NewRequest()
	r.SetID(id)
	return r
}

func TestMemoryStore_ClientAssertionJWT(t *testing.T) {
	store := auth.NewMemoryStore()
	ctx := context.Background()
	assert.NoError(t, store.ClientAssertionJWTValid(ctx, "jti"))
	assert.NoError(t, store.SetClientAssertionJWT(ctx, "jti", time.Now().Add(time.Hour)))
}

func TestMemoryStore_AccessTokenSessions(t *testing.T) {
	store := auth.NewMemoryStore()
	ctx := context.Background()
	req := newReq("req-1")

	require.NoError(t, store.CreateAccessTokenSession(ctx, "sig-1", req))

	got, err := store.GetAccessTokenSession(ctx, "sig-1", nil)
	require.NoError(t, err)
	assert.Equal(t, "req-1", got.GetID())

	require.NoError(t, store.DeleteAccessTokenSession(ctx, "sig-1"))

	_, err = store.GetAccessTokenSession(ctx, "sig-1", nil)
	assert.ErrorIs(t, err, fosite.ErrNotFound)
}

func TestMemoryStore_RefreshTokenSessions(t *testing.T) {
	store := auth.NewMemoryStore()
	ctx := context.Background()
	req := newReq("req-2")

	require.NoError(t, store.CreateRefreshTokenSession(ctx, "sig-r1", "req-2", req))

	got, err := store.GetRefreshTokenSession(ctx, "sig-r1", nil)
	require.NoError(t, err)
	assert.Equal(t, "req-2", got.GetID())

	require.NoError(t, store.DeleteRefreshTokenSession(ctx, "sig-r1"))

	_, err = store.GetRefreshTokenSession(ctx, "sig-r1", nil)
	assert.ErrorIs(t, err, fosite.ErrNotFound)
}

func TestMemoryStore_RevokeRefreshToken(t *testing.T) {
	store := auth.NewMemoryStore()
	ctx := context.Background()
	req := newReq("req-3")

	require.NoError(t, store.CreateRefreshTokenSession(ctx, "sig-r2", "req-3", req))
	require.NoError(t, store.RevokeRefreshToken(ctx, "req-3"))

	_, err := store.GetRefreshTokenSession(ctx, "sig-r2", nil)
	assert.ErrorIs(t, err, fosite.ErrNotFound)
}

func TestMemoryStore_RevokeRefreshToken_NoMatch(t *testing.T) {
	store := auth.NewMemoryStore()
	assert.NoError(t, store.RevokeRefreshToken(context.Background(), "nonexistent"))
}

func TestMemoryStore_RotateRefreshToken(t *testing.T) {
	store := auth.NewMemoryStore()
	ctx := context.Background()
	req := newReq("req-4")

	require.NoError(t, store.CreateRefreshTokenSession(ctx, "old-sig", "req-4", req))
	require.NoError(t, store.RotateRefreshToken(ctx, "req-4", "old-sig"))

	_, err := store.GetRefreshTokenSession(ctx, "old-sig", nil)
	assert.ErrorIs(t, err, fosite.ErrNotFound)
}

func TestMemoryStore_RevokeAccessToken(t *testing.T) {
	store := auth.NewMemoryStore()
	ctx := context.Background()
	req := newReq("req-5")

	require.NoError(t, store.CreateAccessTokenSession(ctx, "sig-a1", req))
	require.NoError(t, store.RevokeAccessToken(ctx, "req-5"))

	_, err := store.GetAccessTokenSession(ctx, "sig-a1", nil)
	assert.ErrorIs(t, err, fosite.ErrNotFound)
}
