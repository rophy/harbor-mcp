package auth_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	require.NoError(t, err)
	assert.Equal(t, "https://idp.example.com/authorize", upstream.AuthorizationEndpoint)
}

func TestNewUpstreamOIDC_DiscoveryFails(t *testing.T) {
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer idp.Close()

	_, err := auth.NewUpstreamOIDC(idp.URL, "client-id", "client-secret", "")
	require.Error(t, err)
}

func TestUpstreamOIDC_AuthorizationURL(t *testing.T) {
	upstream := &auth.UpstreamOIDC{
		AuthorizationEndpoint: "https://idp.example.com/authorize",
		ClientID:              "harbor-mcp",
	}
	u := upstream.AuthorizationURL("state123", "http://localhost:8080/auth/callback")
	assert.NotEmpty(t, u)
}

func TestNewUpstreamOIDC_DiscoveryInvalidJSON(t *testing.T) {
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer idp.Close()

	_, err := auth.NewUpstreamOIDC(idp.URL, "client-id", "client-secret", "")
	require.Error(t, err)
}

func TestNewUpstreamOIDC_MissingEndpoints(t *testing.T) {
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"authorization_endpoint": "https://idp.example.com/authorize",
		})
	}))
	defer idp.Close()

	_, err := auth.NewUpstreamOIDC(idp.URL, "client-id", "client-secret", "")
	require.Error(t, err)
}

func TestNewUpstreamOIDC_Unreachable(t *testing.T) {
	_, err := auth.NewUpstreamOIDC("http://127.0.0.1:1", "client-id", "client-secret", "")
	require.Error(t, err)
}

func TestNewUpstreamOIDC_CustomHTTPClient(t *testing.T) {
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"authorization_endpoint": "https://idp.example.com/authorize",
			"token_endpoint":         "http://" + r.Host + "/token",
		})
	}))
	defer idp.Close()

	customClient := idp.Client()
	upstream, err := auth.NewUpstreamOIDC(idp.URL, "client-id", "client-secret", "", customClient)
	require.NoError(t, err)
	assert.Contains(t, upstream.TokenEndpoint, "/token")
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
	require.NoError(t, err)
	assert.Equal(t, "https://external.example.com/authorize", upstream.AuthorizationEndpoint)
}

func TestUpstreamOIDC_ExchangeCode(t *testing.T) {
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
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
	require.NoError(t, err)
	assert.Equal(t, "upstream-access-token", tokens.AccessToken)
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
	require.Error(t, err)
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
	require.Error(t, err)
}

func TestUpstreamOIDC_ExchangeCode_Unreachable(t *testing.T) {
	upstream := &auth.UpstreamOIDC{
		TokenEndpoint: "http://127.0.0.1:1/token",
		ClientID:      "harbor-mcp",
		ClientSecret:  "secret",
	}

	_, err := upstream.ExchangeCode(context.Background(), "auth-code", "http://localhost:8080/auth/callback")
	require.Error(t, err)
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
			assert.Equal(t, tt.want, tokens.Subject())
		})
	}
}
