package config_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rophy/harbor-mcp/internal/config"
)

func TestLoad_AllSet(t *testing.T) {
	t.Setenv("HARBOR_URL", "https://harbor.example.com")
	t.Setenv("HARBOR_ROBOT_NAME", "robot$reader")
	t.Setenv("HARBOR_ROBOT_SECRET", "secret123")
	t.Setenv("OAUTH_UPSTREAM_ISSUER", "https://keycloak.example.com/realms/harbor")
	t.Setenv("OAUTH_UPSTREAM_CLIENT_ID", "harbor-mcp")
	t.Setenv("OAUTH_UPSTREAM_CLIENT_SECRET", "client-secret")
	t.Setenv("SERVER_BASE_URL", "http://localhost:8080")

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, "https://harbor.example.com", cfg.HarborURL)
	assert.Equal(t, 8080, cfg.ServerPort)
	assert.False(t, cfg.RateLimitEnabled)
	assert.Equal(t, 60, cfg.RateLimitRPM)
	assert.Equal(t, 20, cfg.RateLimitBurst)
}

func TestLoad_RateLimitConfig(t *testing.T) {
	t.Setenv("HARBOR_URL", "https://harbor.example.com")
	t.Setenv("HARBOR_ROBOT_NAME", "robot$reader")
	t.Setenv("HARBOR_ROBOT_SECRET", "secret123")
	t.Setenv("OAUTH_UPSTREAM_ISSUER", "https://keycloak.example.com/realms/harbor")
	t.Setenv("OAUTH_UPSTREAM_CLIENT_ID", "harbor-mcp")
	t.Setenv("OAUTH_UPSTREAM_CLIENT_SECRET", "client-secret")
	t.Setenv("SERVER_BASE_URL", "http://localhost:8080")
	t.Setenv("RATE_LIMIT_ENABLED", "true")
	t.Setenv("RATE_LIMIT_RPM", "30")
	t.Setenv("RATE_LIMIT_BURST", "10")

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.True(t, cfg.RateLimitEnabled)
	assert.Equal(t, 30, cfg.RateLimitRPM)
	assert.Equal(t, 10, cfg.RateLimitBurst)
}

func TestLoad_MissingRequired(t *testing.T) {
	os.Clearenv()
	_, err := config.Load()
	require.Error(t, err)
}

func TestLoad_CustomPort(t *testing.T) {
	t.Setenv("HARBOR_URL", "https://harbor.example.com")
	t.Setenv("HARBOR_ROBOT_NAME", "robot$reader")
	t.Setenv("HARBOR_ROBOT_SECRET", "secret123")
	t.Setenv("OAUTH_UPSTREAM_ISSUER", "https://keycloak.example.com/realms/harbor")
	t.Setenv("OAUTH_UPSTREAM_CLIENT_ID", "harbor-mcp")
	t.Setenv("OAUTH_UPSTREAM_CLIENT_SECRET", "client-secret")
	t.Setenv("SERVER_BASE_URL", "http://localhost:9090")
	t.Setenv("SERVER_PORT", "9090")

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, 9090, cfg.ServerPort)
}
