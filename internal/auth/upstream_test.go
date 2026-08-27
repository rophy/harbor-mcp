package auth_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

	upstream, err := auth.NewUpstreamOIDC(idp.URL, "client-id", "client-secret", "")
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

	_, err := auth.NewUpstreamOIDC(idp.URL, "client-id", "client-secret", "")
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

func TestNewUpstreamOIDC_DiscoveryInvalidJSON(t *testing.T) {
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer idp.Close()

	_, err := auth.NewUpstreamOIDC(idp.URL, "client-id", "client-secret", "")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestNewUpstreamOIDC_MissingEndpoints(t *testing.T) {
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"authorization_endpoint": "https://idp.example.com/authorize",
		})
	}))
	defer idp.Close()

	_, err := auth.NewUpstreamOIDC(idp.URL, "client-id", "client-secret", "")
	if err == nil {
		t.Fatal("expected error for missing token_endpoint")
	}
}

func TestNewUpstreamOIDC_Unreachable(t *testing.T) {
	_, err := auth.NewUpstreamOIDC("http://127.0.0.1:1", "client-id", "client-secret", "")
	if err == nil {
		t.Fatal("expected error for unreachable issuer")
	}
}

func TestNewUpstreamOIDC_ExternalURL(t *testing.T) {
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"authorization_endpoint": "https://idp.example.com/authorize",
			"token_endpoint":         "https://idp.example.com/token",
		})
	}))
	defer idp.Close()

	upstream, err := auth.NewUpstreamOIDC(idp.URL, "client-id", "client-secret", "https://external.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if upstream.AuthorizationEndpoint != "https://external.example.com/authorize" {
		t.Errorf("AuthorizationEndpoint = %q, want external URL override", upstream.AuthorizationEndpoint)
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

func TestUpstreamOIDC_ExchangeCode_ServerError(t *testing.T) {
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer idp.Close()

	upstream := &auth.UpstreamOIDC{
		TokenEndpoint: idp.URL + "/token",
		ClientID:      "harbor-mcp",
		ClientSecret:  "secret",
	}

	_, err := upstream.ExchangeCode(context.Background(), "auth-code", "http://localhost:8080/auth/callback")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestUpstreamOIDC_ExchangeCode_InvalidJSON(t *testing.T) {
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer idp.Close()

	upstream := &auth.UpstreamOIDC{
		TokenEndpoint: idp.URL + "/token",
		ClientID:      "harbor-mcp",
		ClientSecret:  "secret",
	}

	_, err := upstream.ExchangeCode(context.Background(), "auth-code", "http://localhost:8080/auth/callback")
	if err == nil {
		t.Fatal("expected error for invalid JSON response")
	}
}

func TestUpstreamOIDC_ExchangeCode_Unreachable(t *testing.T) {
	upstream := &auth.UpstreamOIDC{
		TokenEndpoint: "http://127.0.0.1:1/token",
		ClientID:      "harbor-mcp",
		ClientSecret:  "secret",
	}

	_, err := upstream.ExchangeCode(context.Background(), "auth-code", "http://localhost:8080/auth/callback")
	if err == nil {
		t.Fatal("expected error for unreachable token endpoint")
	}
}

func fakeJWT(sub string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"sub":%q}`, sub)))
	return header + "." + payload + "."
}

func TestUpstreamTokens_Subject(t *testing.T) {
	tests := []struct {
		name    string
		idToken string
		want    string
	}{
		{"valid JWT", fakeJWT("alice"), "alice"},
		{"empty id_token", "", ""},
		{"not a JWT", "not-a-jwt", ""},
		{"invalid base64 payload", "header.!!!invalid!!!.sig", ""},
		{"invalid JSON payload", "header." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".sig", ""},
		{"missing sub claim", "header." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"test"}`)) + ".sig", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := &auth.UpstreamTokens{IDToken: tt.idToken}
			if got := tokens.Subject(); got != tt.want {
				t.Errorf("Subject() = %q, want %q", got, tt.want)
			}
		})
	}
}
