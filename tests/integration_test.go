//go:build integration

package tests

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

const serverURL = "http://localhost:8080"

func TestMetadataDiscovery(t *testing.T) {
	resp, err := http.Get(serverURL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var metadata map[string]any
	json.NewDecoder(resp.Body).Decode(&metadata)

	required := []string{"authorization_endpoint", "token_endpoint", "registration_endpoint"}
	for _, key := range required {
		if metadata[key] == nil {
			t.Errorf("missing %s in metadata", key)
		}
	}
}

func TestDynamicClientRegistration(t *testing.T) {
	body := `{"redirect_uris": ["http://localhost:3000/callback"], "client_name": "integration-test"}`
	resp, err := http.Post(serverURL+"/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)

	clientID, ok := result["client_id"].(string)
	if !ok || clientID == "" {
		t.Error("client_id should be a non-empty string")
	}
}
