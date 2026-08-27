//go:build e2e

package e2e

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var (
	mcpServerURL = envOr("MCP_SERVER_URL", "http://localhost:28080")
	oidcMockURL  = envOr("OIDC_MOCK_URL", "http://localhost:28090")
	harborURL    = envOr("HARBOR_URL", "http://localhost:8880")
)

func loadEnvFile() {
	_, thisFile, _, _ := runtime.Caller(0)
	envPath := filepath.Join(filepath.Dir(thisFile), ".env")
	f, err := os.Open(envPath)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, "'\"")
		if os.Getenv(k) == "" {
			os.Setenv(k, v)
		}
	}
}

func init() {
	loadEnvFile()
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func noRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

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

func fullOAuthFlow(t *testing.T) string {
	t.Helper()
	client := noRedirectClient()

	redirectURI := "http://localhost:19999/callback"
	clientID := registerClient(t, redirectURI)
	t.Logf("registered client: %s", clientID)

	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])
	state := "e2e-test-state-123"

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
	if !strings.Contains(oidcRedirectURL, "/authorize") {
		t.Fatalf("authorize did not redirect to oidc-mock: %s", oidcRedirectURL)
	}

	parsedOIDC, err := url.Parse(oidcRedirectURL)
	if err != nil {
		t.Fatalf("parse oidc redirect URL: %v", err)
	}
	upstreamState := parsedOIDC.Query().Get("state")
	upstreamRedirectURI := parsedOIDC.Query().Get("redirect_uri")

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

	ourCallbackURL := oidcCallbackResp.Header.Get("Location")
	ourCallbackURL = strings.Replace(ourCallbackURL, "http://oidc-mock:8080", mcpServerURL, 1)
	ourCallbackURL = strings.Replace(ourCallbackURL, "http://localhost:28080", mcpServerURL, 1)

	callbackResp, err := client.Get(ourCallbackURL)
	if err != nil {
		t.Fatalf("our callback failed: %v", err)
	}
	callbackResp.Body.Close()

	if callbackResp.StatusCode != http.StatusFound && callbackResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("our callback: expected 302 or 303, got %d", callbackResp.StatusCode)
	}

	clientRedirectURL := callbackResp.Header.Get("Location")
	parsedClient, err := url.Parse(clientRedirectURL)
	if err != nil {
		t.Fatalf("parse client redirect: %v", err)
	}
	authCode := parsedClient.Query().Get("code")
	if authCode == "" {
		t.Fatalf("no auth code in client redirect: %s", clientRedirectURL)
	}

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

type mcpSession struct {
	accessToken string
	sessionID   string
	nextID      int
}

func initMCPSession(t *testing.T) *mcpSession {
	t.Helper()
	accessToken := fullOAuthFlow(t)

	jsonRPC := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"e2e-test","version":"1.0"}}}`
	req, _ := http.NewRequest("POST", mcpServerURL+"/mcp", strings.NewReader(jsonRPC))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("MCP initialize failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("MCP initialize: status %d; body: %s", resp.StatusCode, body)
	}

	sessionID := resp.Header.Get("Mcp-Session-Id")
	return &mcpSession{accessToken: accessToken, sessionID: sessionID, nextID: 2}
}

func (s *mcpSession) callTool(t *testing.T, toolName string, args map[string]any) map[string]any {
	t.Helper()
	id := s.nextID
	s.nextID++

	params := map[string]any{
		"name":      toolName,
		"arguments": args,
	}
	rpcReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  "tools/call",
		"params":  params,
	}
	body, _ := json.Marshal(rpcReq)

	req, _ := http.NewRequest("POST", mcpServerURL+"/mcp", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+s.accessToken)
	if s.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", s.sessionID)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("MCP tools/call %s failed: %v", toolName, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("MCP tools/call %s: status %d; body: %s", toolName, resp.StatusCode, respBody)
	}

	jsonData := respBody
	if strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		for _, line := range strings.Split(string(respBody), "\n") {
			if strings.HasPrefix(line, "data: ") {
				jsonData = []byte(strings.TrimPrefix(line, "data: "))
				break
			}
		}
	}

	var rpcResp map[string]any
	if err := json.Unmarshal(jsonData, &rpcResp); err != nil {
		t.Fatalf("MCP tools/call %s: decode response: %v; body: %s", toolName, err, respBody)
	}

	if rpcErr, ok := rpcResp["error"]; ok {
		t.Fatalf("MCP tools/call %s returned error: %v", toolName, rpcErr)
	}

	result, ok := rpcResp["result"].(map[string]any)
	if !ok {
		t.Fatalf("MCP tools/call %s: unexpected result type: %T", toolName, rpcResp["result"])
	}
	return result
}

func getTextContent(t *testing.T, result map[string]any) string {
	t.Helper()
	content, ok := result["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatal("no content in tool result")
	}
	first, ok := content[0].(map[string]any)
	if !ok {
		t.Fatal("unexpected content format")
	}
	text, ok := first["text"].(string)
	if !ok {
		t.Fatal("no text in content")
	}
	return text
}
