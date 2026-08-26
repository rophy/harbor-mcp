//go:build e2e

package e2e

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

var (
	mcpServerURL = envOr("MCP_SERVER_URL", "http://localhost:28080")
	oidcMockURL  = envOr("OIDC_MOCK_URL", "http://localhost:28090")
	harborURL    = envOr("HARBOR_URL", "http://localhost:8880")
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// noRedirectClient returns an HTTP client that captures redirects instead of following them.
func noRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// registerClient performs Dynamic Client Registration and returns the client_id.
func registerClient(t *testing.T, redirectURI string) string {
	t.Helper()
	body := fmt.Sprintf(`{"redirect_uris": [%q], "client_name": "e2e-test"}`, redirectURI)
	resp, err := http.Post(mcpServerURL+"/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("register request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("register: status %d, body: %s", resp.StatusCode, b)
	}

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	return result["client_id"].(string)
}

// fullOAuthFlow performs the complete OAuth 2.1 + PKCE + OIDC flow and returns an access token.
func fullOAuthFlow(t *testing.T) string {
	t.Helper()
	client := noRedirectClient()

	// The redirect URI for the "client" (our test). We don't actually run a server
	// here — we just capture the redirect from harbor-mcp.
	redirectURI := "http://localhost:19999/callback"

	// Step 1: Register a client
	clientID := registerClient(t, redirectURI)
	t.Logf("registered client: %s", clientID)

	// Step 2: Generate PKCE code verifier and challenge
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])
	state := "e2e-test-state-123"

	// Step 3: Start authorize flow — should redirect to oidc-mock
	authorizeURL := fmt.Sprintf(
		"%s/authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=harbor:read&state=%s&code_challenge=%s&code_challenge_method=S256",
		mcpServerURL, clientID, url.QueryEscape(redirectURI), state, codeChallenge,
	)
	resp, err := client.Get(authorizeURL)
	if err != nil {
		t.Fatalf("authorize request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: expected 302, got %d", resp.StatusCode)
	}

	oidcRedirectURL := resp.Header.Get("Location")
	if !strings.Contains(oidcRedirectURL, "oidc-mock") && !strings.Contains(oidcRedirectURL, "28090") && !strings.Contains(oidcRedirectURL, "/authorize") {
		t.Fatalf("authorize did not redirect to oidc-mock: %s", oidcRedirectURL)
	}
	t.Logf("redirected to oidc-mock: %s", oidcRedirectURL)

	// Step 4: Extract the upstream state from the oidc-mock redirect URL
	parsedOIDC, err := url.Parse(oidcRedirectURL)
	if err != nil {
		t.Fatalf("parse oidc redirect URL: %v", err)
	}
	upstreamState := parsedOIDC.Query().Get("state")
	upstreamRedirectURI := parsedOIDC.Query().Get("redirect_uri")

	// Step 5: "Pick" user alice on oidc-mock by POSTing to /authorize/callback
	// The oidc-mock URL uses internal docker hostname (oidc-mock:8080),
	// but we need to hit it from the host (localhost:28090).
	oidcCallbackData := url.Values{
		"sub":          {"alice"},
		"client_id":    {"harbor-mcp"},
		"redirect_uri": {upstreamRedirectURI},
		"state":        {upstreamState},
		"nonce":        {""},
	}
	oidcCallbackResp, err := client.PostForm(oidcMockURL+"/authorize/callback", oidcCallbackData)
	if err != nil {
		t.Fatalf("oidc-mock callback failed: %v", err)
	}
	oidcCallbackResp.Body.Close()

	if oidcCallbackResp.StatusCode != http.StatusFound {
		t.Fatalf("oidc-mock callback: expected 302, got %d", oidcCallbackResp.StatusCode)
	}

	// Step 6: oidc-mock redirects back to our /auth/callback with upstream code
	ourCallbackURL := oidcCallbackResp.Header.Get("Location")
	t.Logf("oidc-mock redirects to our callback: %s", ourCallbackURL)

	// The redirect goes to the internal URL (oidc-mock:8080 based redirect_uri).
	// Replace the internal hostname with localhost:28080 to hit from host.
	ourCallbackURL = strings.Replace(ourCallbackURL, "http://oidc-mock:8080", mcpServerURL, 1)
	ourCallbackURL = strings.Replace(ourCallbackURL, "http://localhost:28080", mcpServerURL, 1)

	// Step 7: Hit our /auth/callback — it exchanges code with oidc-mock and issues our auth code
	callbackResp, err := client.Get(ourCallbackURL)
	if err != nil {
		t.Fatalf("our callback failed: %v", err)
	}
	callbackResp.Body.Close()

	if callbackResp.StatusCode != http.StatusFound && callbackResp.StatusCode != http.StatusSeeOther {
		b, _ := io.ReadAll(callbackResp.Body)
		t.Fatalf("our callback: expected 302 or 303, got %d; body: %s", callbackResp.StatusCode, b)
	}

	// Step 8: Extract our auth code from the redirect to the client's redirect_uri
	clientRedirectURL := callbackResp.Header.Get("Location")
	t.Logf("our server redirects to client: %s", clientRedirectURL)

	parsedClient, err := url.Parse(clientRedirectURL)
	if err != nil {
		t.Fatalf("parse client redirect: %v", err)
	}
	authCode := parsedClient.Query().Get("code")
	if authCode == "" {
		t.Fatalf("no auth code in client redirect: %s", clientRedirectURL)
	}
	t.Logf("got auth code: %s", authCode[:min(len(authCode), 20)]+"...")

	// Step 9: Exchange auth code for access token
	tokenData := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {codeVerifier},
	}
	tokenResp, err := http.PostForm(mcpServerURL+"/token", tokenData)
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("token exchange: status %d, body: %s", tokenResp.StatusCode, b)
	}

	var tokenResult map[string]any
	json.NewDecoder(tokenResp.Body).Decode(&tokenResult)
	accessToken, ok := tokenResult["access_token"].(string)
	if !ok || accessToken == "" {
		t.Fatalf("no access_token in response: %v", tokenResult)
	}
	t.Logf("got access token (%d chars)", len(accessToken))

	return accessToken
}

func TestOAuthMetadataDiscovery(t *testing.T) {
	resp, err := http.Get(mcpServerURL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var metadata map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		t.Fatalf("decode: %v", err)
	}

	required := []string{
		"authorization_endpoint",
		"token_endpoint",
		"registration_endpoint",
		"code_challenge_methods_supported",
	}
	for _, key := range required {
		if metadata[key] == nil {
			t.Errorf("missing %s in metadata", key)
		}
	}
}

func TestDynamicClientRegistration(t *testing.T) {
	clientID := registerClient(t, "http://localhost:3000/callback")
	if clientID == "" {
		t.Error("client_id should be non-empty")
	}
}

func TestMCPEndpointRequiresAuth(t *testing.T) {
	resp, err := http.Post(mcpServerURL+"/mcp", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (no bearer token)", resp.StatusCode)
	}
}

func TestMCPEndpointRejectsInvalidToken(t *testing.T) {
	req, _ := http.NewRequest("POST", mcpServerURL+"/mcp", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer invalid-token-here")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (invalid token)", resp.StatusCode)
	}
}

func TestFullOAuthFlowAndMCPAccess(t *testing.T) {
	accessToken := fullOAuthFlow(t)

	// Use the token to access the MCP endpoint
	// Send a JSON-RPC initialize request
	jsonRPC := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"e2e-test","version":"1.0"}}}`
	req, _ := http.NewRequest("POST", mcpServerURL+"/mcp", strings.NewReader(jsonRPC))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("MCP request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	t.Logf("MCP response status: %d", resp.StatusCode)
	t.Logf("MCP response body: %s", string(body))

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("MCP with valid token: status %d, want 200; body: %s", resp.StatusCode, body)
	}
}

func TestHarborIsAccessible(t *testing.T) {
	resp, err := http.Get(harborURL + "/api/v2.0/ping")
	if err != nil {
		t.Fatalf("Harbor ping failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Harbor ping status = %d, want 200", resp.StatusCode)
	}
}

func TestHarborProjectExists(t *testing.T) {
	req, _ := http.NewRequest("GET", harborURL+"/api/v2.0/projects?name=library", nil)
	req.SetBasicAuth("admin", "Harbor12345")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var projects []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&projects); err != nil {
		t.Fatalf("decode: %v", err)
	}

	found := false
	for _, p := range projects {
		if name, ok := p["name"].(string); ok && name == "library" {
			found = true
			break
		}
	}
	if !found {
		t.Error("test project 'library' not found — did setup.sh run?")
	}
}

func TestHarborRobotAccountWorks(t *testing.T) {
	robotName := os.Getenv("HARBOR_ROBOT_NAME")
	robotSecret := os.Getenv("HARBOR_ROBOT_SECRET")
	if robotName == "" || robotSecret == "" {
		t.Skip("HARBOR_ROBOT_NAME/HARBOR_ROBOT_SECRET not set — skipping robot account test")
	}

	req, _ := http.NewRequest("GET", harborURL+"/api/v2.0/projects", nil)
	req.SetBasicAuth(robotName, robotSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("robot account API call failed: status %d, body: %s", resp.StatusCode, body)
	}

	fmt.Fprintf(os.Stderr, "  robot account %s can list projects\n", robotName)
}
