//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type DefaultSuite struct {
	suite.Suite
	session *mcpSession
}

func (s *DefaultSuite) SetupSuite() {
	s.session = initMCPSession(s.T())
}

func (s *DefaultSuite) TestHarborIsAccessible() {
	resp, err := http.Get(harborURL + "/api/v2.0/ping")
	require.NoError(s.T(), err)
	defer resp.Body.Close()
	assert.Equal(s.T(), http.StatusOK, resp.StatusCode)
}

func (s *DefaultSuite) TestHarborProjectExists() {
	req, _ := http.NewRequest("GET", harborURL+"/api/v2.0/projects?name=library", nil)
	req.SetBasicAuth("admin", "Harbor12345")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(s.T(), err)
	defer resp.Body.Close()
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)

	var projects []map[string]any
	require.NoError(s.T(), json.NewDecoder(resp.Body).Decode(&projects))

	found := false
	for _, p := range projects {
		if name, ok := p["name"].(string); ok && name == "library" {
			found = true
			break
		}
	}
	assert.True(s.T(), found, "test project 'library' not found")
}

func (s *DefaultSuite) TestHarborRobotAccountWorks() {
	robotName := os.Getenv("HARBOR_ROBOT_NAME")
	robotSecret := os.Getenv("HARBOR_ROBOT_SECRET")
	if robotName == "" || robotSecret == "" {
		s.T().Skip("HARBOR_ROBOT_NAME/HARBOR_ROBOT_SECRET not set")
	}

	req, _ := http.NewRequest("GET", harborURL+"/api/v2.0/projects", nil)
	req.SetBasicAuth(robotName, robotSecret)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(s.T(), err)
	defer resp.Body.Close()
	assert.Equal(s.T(), http.StatusOK, resp.StatusCode, "robot account should be able to list projects")
}

func (s *DefaultSuite) TestOAuthMetadataDiscovery() {
	resp, err := http.Get(mcpServerURL + "/.well-known/oauth-authorization-server")
	require.NoError(s.T(), err)
	defer resp.Body.Close()
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)

	var metadata map[string]any
	require.NoError(s.T(), json.NewDecoder(resp.Body).Decode(&metadata))

	for _, key := range []string{
		"authorization_endpoint",
		"token_endpoint",
		"registration_endpoint",
		"code_challenge_methods_supported",
	} {
		assert.NotNil(s.T(), metadata[key], "missing %s in metadata", key)
	}
}

func (s *DefaultSuite) TestDynamicClientRegistration() {
	clientID := registerClient(s.T(), "http://localhost:3000/callback")
	assert.NotEmpty(s.T(), clientID)
}

func (s *DefaultSuite) TestMCPEndpointRequiresAuth() {
	resp, err := http.Post(mcpServerURL+"/mcp", "application/json", strings.NewReader("{}"))
	require.NoError(s.T(), err)
	defer resp.Body.Close()
	assert.Equal(s.T(), http.StatusUnauthorized, resp.StatusCode)
}

func (s *DefaultSuite) TestMCPEndpointRejectsInvalidToken() {
	req, _ := http.NewRequest("POST", mcpServerURL+"/mcp", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer invalid-token-here")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(s.T(), err)
	defer resp.Body.Close()
	assert.Equal(s.T(), http.StatusUnauthorized, resp.StatusCode)
}

func (s *DefaultSuite) TestFullOAuthFlowAndMCPAccess() {
	accessToken := fullOAuthFlow(s.T())

	jsonRPC := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"e2e-test","version":"1.0"}}}`
	req, _ := http.NewRequest("POST", mcpServerURL+"/mcp", strings.NewReader(jsonRPC))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(s.T(), err)
	defer resp.Body.Close()
	assert.Equal(s.T(), http.StatusOK, resp.StatusCode)
}

func (s *DefaultSuite) TestMCPTool_ListProjects() {
	result := s.session.callTool(s.T(), "list_projects", map[string]any{})
	text := getTextContent(s.T(), result)

	var projects []map[string]any
	require.NoError(s.T(), json.Unmarshal([]byte(text), &projects))
	require.NotEmpty(s.T(), projects)

	found := false
	for _, p := range projects {
		if p["name"] == "library" {
			found = true
		}
	}
	assert.True(s.T(), found, "list_projects should include 'library' project")
}

func (s *DefaultSuite) TestMCPTool_GetProject() {
	result := s.session.callTool(s.T(), "get_project", map[string]any{"project_name": "library"})
	text := getTextContent(s.T(), result)

	var project map[string]any
	require.NoError(s.T(), json.Unmarshal([]byte(text), &project))
	assert.Equal(s.T(), "library", project["name"])
	assert.NotZero(s.T(), project["project_id"])
}

func (s *DefaultSuite) TestMCPTool_ListRepositories() {
	result := s.session.callTool(s.T(), "list_repositories", map[string]any{"project_name": "library"})
	text := getTextContent(s.T(), result)

	var repos []map[string]any
	require.NoError(s.T(), json.Unmarshal([]byte(text), &repos))
	require.NotEmpty(s.T(), repos)

	found := false
	for _, r := range repos {
		name, _ := r["name"].(string)
		if strings.Contains(name, "test") {
			found = true
		}
	}
	assert.True(s.T(), found, "list_repositories should include a test repo")
}

func (s *DefaultSuite) TestMCPTool_ListArtifacts() {
	result := s.session.callTool(s.T(), "list_artifacts", map[string]any{
		"project_name":    "library",
		"repository_name": "test-image",
	})
	text := getTextContent(s.T(), result)

	var artifacts []map[string]any
	require.NoError(s.T(), json.Unmarshal([]byte(text), &artifacts))
	require.NotEmpty(s.T(), artifacts)

	digest, _ := artifacts[0]["digest"].(string)
	assert.True(s.T(), strings.HasPrefix(digest, "sha256:"), "artifact digest should start with sha256:")
}

func (s *DefaultSuite) TestMCPTool_GetArtifact() {
	result := s.session.callTool(s.T(), "get_artifact", map[string]any{
		"project_name":    "library",
		"repository_name": "test-image",
		"reference":       "v1",
	})
	text := getTextContent(s.T(), result)

	var artifact map[string]any
	require.NoError(s.T(), json.Unmarshal([]byte(text), &artifact))

	digest, _ := artifact["digest"].(string)
	assert.True(s.T(), strings.HasPrefix(digest, "sha256:"), "artifact digest should start with sha256:")

	tags, _ := artifact["tags"].([]any)
	require.NotEmpty(s.T(), tags)
	tag0, _ := tags[0].(map[string]any)
	assert.Equal(s.T(), "v1", tag0["name"])
}

func (s *DefaultSuite) TestMCPTool_GetVulnerabilities() {
	result := s.session.callTool(s.T(), "get_vulnerabilities", map[string]any{
		"project_name":    "library",
		"repository_name": "test-image",
		"reference":       "v1",
	})

	isError, _ := result["isError"].(bool)
	text := getTextContent(s.T(), result)
	assert.True(s.T(), isError || strings.Contains(text, "404"),
		"get_vulnerabilities should return an error (no scanner)")
}

func (s *DefaultSuite) TestMCPTool_Search() {
	result := s.session.callTool(s.T(), "search", map[string]any{"query": "test"})
	text := getTextContent(s.T(), result)

	var searchResult map[string]any
	require.NoError(s.T(), json.Unmarshal([]byte(text), &searchResult))

	repos, ok := searchResult["repository"].([]any)
	require.True(s.T(), ok, "search result should contain 'repository' key")
	require.NotEmpty(s.T(), repos, "search for 'test' should find repositories")

	found := false
	for _, r := range repos {
		repo, _ := r.(map[string]any)
		repoName, _ := repo["repository_name"].(string)
		if strings.Contains(repoName, "test") {
			found = true
		}
	}
	assert.True(s.T(), found, "search should find repository containing 'test'")
}

func (s *DefaultSuite) TestMCPTool_ListRepositoriesWithQuery() {
	result := s.session.callTool(s.T(), "list_repositories", map[string]any{
		"project_name": "library",
		"query":        "name=~test",
	})
	text := getTextContent(s.T(), result)

	var repos []map[string]any
	require.NoError(s.T(), json.Unmarshal([]byte(text), &repos))
	require.NotEmpty(s.T(), repos, "query filter name=~test should return results")

	for _, r := range repos {
		name, _ := r["name"].(string)
		assert.Contains(s.T(), name, "test", "filtered repos should contain 'test' in name")
	}
}

func (s *DefaultSuite) TestMCPTool_ListArtifactsWithQuery() {
	result := s.session.callTool(s.T(), "list_artifacts", map[string]any{
		"project_name":    "library",
		"repository_name": "test-image",
		"query":           "tags=~v1",
	})
	text := getTextContent(s.T(), result)

	var artifacts []map[string]any
	require.NoError(s.T(), json.Unmarshal([]byte(text), &artifacts))
	require.NotEmpty(s.T(), artifacts, "query filter tags=~v1 should return artifacts")

	tagFound := false
	for _, a := range artifacts {
		tags, _ := a["tags"].([]any)
		for _, t := range tags {
			tag, _ := t.(map[string]any)
			if tag["name"] == "v1" {
				tagFound = true
			}
		}
	}
	assert.True(s.T(), tagFound, "filtered artifacts should include tag v1")
}

func TestDefaultSuite(t *testing.T) {
	suite.Run(t, new(DefaultSuite))
}
