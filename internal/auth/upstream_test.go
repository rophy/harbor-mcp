package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rophy/harbor-mcp/internal/auth"
)

func TestNewUpstreamOIDC(t *testing.T) {
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			json.NewEncoder(w).Encode(map[string]string{
				"authorization_endpoint": "https://idp.example.com/authorize",
				"token_endpoint":         "https://idp.example.com/token",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer idp.Close()

	upstream, err := auth.NewUpstreamOIDC(idp.URL, "client-id", "client-secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if upstream.AuthorizationEndpoint != "https://idp.example.com/authorize" {
		t.Errorf("AuthorizationEndpoint = %q", upstream.AuthorizationEndpoint)
	}
}

func TestNewUpstreamOIDC_DiscoveryFails(t *testing.T) {
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer idp.Close()

	_, err := auth.NewUpstreamOIDC(idp.URL, "client-id", "client-secret")
	if err == nil {
		t.Fatal("expected error for failed discovery")
	}
}

func TestUpstreamOIDC_AuthorizationURL(t *testing.T) {
	upstream := &auth.UpstreamOIDC{
		AuthorizationEndpoint: "https://idp.example.com/authorize",
		ClientID:              "harbor-mcp",
	}
	u := upstream.AuthorizationURL("state123", "http://localhost:8080/auth/callback")
	if u == "" {
		t.Fatal("empty authorization URL")
	}
}

func TestUpstreamOIDC_ExchangeCode(t *testing.T) {
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		json.NewEncoder(w).Encode(map[string]string{
			"access_token": "upstream-access-token",
			"id_token":     "upstream-id-token",
		})
	}))
	defer idp.Close()

	upstream := &auth.UpstreamOIDC{
		TokenEndpoint: idp.URL + "/token",
		ClientID:      "harbor-mcp",
		ClientSecret:  "secret",
	}

	tokens, err := upstream.ExchangeCode(context.Background(), "auth-code", "http://localhost:8080/auth/callback")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokens.AccessToken != "upstream-access-token" {
		t.Errorf("AccessToken = %q", tokens.AccessToken)
	}
}
