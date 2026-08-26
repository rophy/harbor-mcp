package auth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rophy/harbor-mcp/internal/auth"
)

func setupOAuthServer(t *testing.T) *httptest.Server {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	store := auth.NewMemoryStore()
	provider := auth.NewOAuthProvider(store, key)

	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			json.NewEncoder(w).Encode(map[string]string{
				"authorization_endpoint": "https://idp.example.com/authorize",
				"token_endpoint":         "https://idp.example.com/token",
			})
		}
	}))
	t.Cleanup(idp.Close)

	upstream, err := auth.NewUpstreamOIDC(idp.URL, "client-id", "client-secret")
	if err != nil {
		t.Fatalf("upstream setup: %v", err)
	}

	mux := http.NewServeMux()
	handlers := auth.NewOAuthHandlers(provider, store, upstream, "http://localhost:8080")
	handlers.RegisterRoutes(mux)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestMetadataEndpoint(t *testing.T) {
	srv := setupOAuthServer(t)

	resp, err := http.Get(srv.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var metadata map[string]any
	json.NewDecoder(resp.Body).Decode(&metadata)

	if metadata["authorization_endpoint"] != "http://localhost:8080/authorize" {
		t.Errorf("authorization_endpoint = %v", metadata["authorization_endpoint"])
	}
	if metadata["token_endpoint"] != "http://localhost:8080/token" {
		t.Errorf("token_endpoint = %v", metadata["token_endpoint"])
	}
}

func TestRegisterEndpoint(t *testing.T) {
	srv := setupOAuthServer(t)

	body := `{"redirect_uris": ["http://localhost:3000/callback"], "client_name": "test"}`
	resp, err := http.Post(srv.URL+"/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)

	if result["client_id"] == nil || result["client_id"] == "" {
		t.Error("client_id should be set")
	}
}

func TestRegisterEndpoint_MissingRedirectURIs(t *testing.T) {
	srv := setupOAuthServer(t)

	body := `{"client_name": "test"}`
	resp, err := http.Post(srv.URL+"/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}
