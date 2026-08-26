package config_test

import (
	"os"
	"testing"

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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.HarborURL != "https://harbor.example.com" {
		t.Errorf("HarborURL = %q, want %q", cfg.HarborURL, "https://harbor.example.com")
	}
	if cfg.ServerPort != 8080 {
		t.Errorf("ServerPort = %d, want 8080", cfg.ServerPort)
	}
}

func TestLoad_MissingRequired(t *testing.T) {
	os.Clearenv()
	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error for missing required vars")
	}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ServerPort != 9090 {
		t.Errorf("ServerPort = %d, want 9090", cfg.ServerPort)
	}
}
