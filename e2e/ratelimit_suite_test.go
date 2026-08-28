//go:build e2e

package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type RateLimitSuite struct {
	suite.Suite
	token string
}

func (s *RateLimitSuite) SetupSuite() {
	t := s.T()

	stop := exec.Command("docker", "compose", "-f", "docker-compose.yml", "stop", "harbor-mcp")
	stop.Dir = testDir()
	if out, err := stop.CombinedOutput(); err != nil {
		t.Fatalf("stop harbor-mcp: %v\n%s", err, out)
	}

	rm := exec.Command("docker", "compose", "-f", "docker-compose.yml", "rm", "-f", "harbor-mcp")
	rm.Dir = testDir()
	if out, err := rm.CombinedOutput(); err != nil {
		t.Fatalf("rm harbor-mcp: %v\n%s", err, out)
	}

	up := exec.Command("docker", "compose", "-f", "docker-compose.yml", "up", "-d", "--no-deps", "--build", "--force-recreate", "harbor-mcp")
	up.Dir = testDir()
	up.Env = append(os.Environ(),
		"RATE_LIMIT_ENABLED=true",
		"RATE_LIMIT_RPM=3",
		"RATE_LIMIT_BURST=0",
	)
	if out, err := up.CombinedOutput(); err != nil {
		t.Fatalf("start harbor-mcp with rate limit: %v\n%s", err, out)
	}

	// Wait for harbor-mcp to be ready
	for i := 0; i < 30; i++ {
		resp, err := http.Get(mcpServerURL + "/.well-known/oauth-authorization-server")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if i == 29 {
			t.Fatal("harbor-mcp did not become ready after restart with rate limiting")
		}
		time.Sleep(time.Second)
	}

	s.token = fullOAuthFlow(t)
}

func (s *RateLimitSuite) TearDownSuite() {
	// Restart harbor-mcp with default config (no rate limiting)
	stop := exec.Command("docker", "compose", "-f", "docker-compose.yml", "stop", "harbor-mcp")
	stop.Dir = testDir()
	stop.CombinedOutput()

	rm := exec.Command("docker", "compose", "-f", "docker-compose.yml", "rm", "-f", "harbor-mcp")
	rm.Dir = testDir()
	rm.CombinedOutput()

	up := exec.Command("docker", "compose", "-f", "docker-compose.yml", "up", "-d", "--no-deps", "harbor-mcp")
	up.Dir = testDir()
	up.CombinedOutput()

	// Wait for it to be ready again
	for i := 0; i < 30; i++ {
		resp, err := http.Get(mcpServerURL + "/.well-known/oauth-authorization-server")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(time.Second)
	}
}

func (s *RateLimitSuite) TestReturns429WhenExceeded() {
	t := s.T()

	var got429 bool
	for i := 0; i < 10; i++ {
		req, _ := http.NewRequest("POST", mcpServerURL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Authorization", "Bearer "+s.token)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests {
			t.Logf("rate limited after %d requests", i+1)

			assert.NotEmpty(t, resp.Header.Get("Retry-After"), "429 response should have Retry-After header")

			var errBody map[string]any
			require.NoError(t, json.Unmarshal(body, &errBody))
			assert.Equal(t, "rate_limit_exceeded", errBody["error"])

			got429 = true
			break
		}
	}
	assert.True(t, got429, "expected 429 but never got rate limited after 10 requests")
}

func (s *RateLimitSuite) TestAllowsRequestsUnderLimit() {
	t := s.T()

	// Get a fresh token so we have a clean rate limit window
	token := fullOAuthFlow(t)

	req, _ := http.NewRequest("POST", mcpServerURL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	assert.NotEqual(t, http.StatusTooManyRequests, resp.StatusCode, "first request should not be rate limited")
}

func TestRateLimitSuite(t *testing.T) {
	suite.Run(t, new(RateLimitSuite))
}
