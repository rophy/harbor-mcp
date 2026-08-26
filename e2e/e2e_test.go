//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

var (
	mcpServerURL = envOr("MCP_SERVER_URL", "http://localhost:28080")
	harborURL    = envOr("HARBOR_URL", "http://localhost:8880")
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
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
	body := `{"redirect_uris": ["http://localhost:3000/callback"], "client_name": "e2e-test"}`
	resp, err := http.Post(mcpServerURL+"/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 201; body: %s", resp.StatusCode, body)
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}

	clientID, ok := result["client_id"].(string)
	if !ok || clientID == "" {
		t.Error("client_id should be a non-empty string")
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
