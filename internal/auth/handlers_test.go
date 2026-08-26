package auth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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

	upstream, err := auth.NewUpstreamOIDC(idp.URL, "client-id", "client-secret", "")
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

func TestRegisterEndpoint_InvalidJSON(t *testing.T) {
	srv := setupOAuthServer(t)

	resp, err := http.Post(srv.URL+"/register", "application/json", strings.NewReader("not json"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAuthorizeEndpoint_UnknownClient(t *testing.T) {
	srv := setupOAuthServer(t)

	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := client.Get(srv.URL + "/authorize?client_id=unknown&response_type=code&redirect_uri=http://localhost/cb&code_challenge=test&code_challenge_method=S256")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther {
		t.Fatalf("should not redirect for unknown client, got %d", resp.StatusCode)
	}
}

func registerAndGetClientID(t *testing.T, srvURL string) string {
	t.Helper()
	body := `{"redirect_uris": ["http://localhost:9999/callback"], "client_name": "test"}`
	resp, err := http.Post(srvURL+"/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer resp.Body.Close()
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	return result["client_id"].(string)
}

func TestAuthorizeEndpoint_RedirectsToUpstream(t *testing.T) {
	srv := setupOAuthServer(t)
	clientID := registerAndGetClientID(t, srv.URL)

	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	authorizeURL := fmt.Sprintf("%s/authorize?client_id=%s&response_type=code&redirect_uri=%s&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&state=test-state",
		srv.URL, clientID, url.QueryEscape("http://localhost:9999/callback"))

	resp, err := client.Get(authorizeURL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 302; body: %s", resp.StatusCode, body)
	}

	location := resp.Header.Get("Location")
	if !strings.Contains(location, "idp.example.com/authorize") {
		t.Errorf("expected redirect to upstream IDP, got: %s", location)
	}
	if !strings.Contains(location, "client_id=client-id") {
		t.Errorf("expected upstream client_id in redirect, got: %s", location)
	}
}

func TestTokenEndpoint_InvalidGrant(t *testing.T) {
	srv := setupOAuthServer(t)

	resp, err := http.PostForm(srv.URL+"/token", url.Values{
		"grant_type": {"authorization_code"},
		"code":       {"invalid-code"},
		"client_id":  {"nonexistent"},
	})
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		t.Fatal("expected error for invalid token request")
	}
}

func TestCallbackEndpoint_MissingParams(t *testing.T) {
	srv := setupOAuthServer(t)

	resp, err := http.Get(srv.URL + "/auth/callback")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestCallbackEndpoint_UnknownState(t *testing.T) {
	srv := setupOAuthServer(t)

	resp, err := http.Get(srv.URL + "/auth/callback?state=unknown&code=somecode")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestRequireBearerToken_MissingToken(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	store := auth.NewMemoryStore()
	provider := auth.NewOAuthProvider(store, key)

	handler := auth.RequireBearerToken(provider, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestRequireBearerToken_InvalidToken(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	store := auth.NewMemoryStore()
	provider := auth.NewOAuthProvider(store, key)

	handler := auth.RequireBearerToken(provider, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}
