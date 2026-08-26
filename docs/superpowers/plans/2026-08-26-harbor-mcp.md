# Harbor MCP Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a read-only MCP server for browsing Docker images in Harbor, with a built-in OAuth 2.1 authorization server that proxies to an upstream OIDC provider.

**Architecture:** Go MCP server using `modelcontextprotocol/go-sdk` for streamable-HTTP transport and tool registration, `ory/fosite` for the OAuth 2.1 authorization server (auth code + PKCE), and direct `net/http` calls to Harbor's v2 REST API with basic auth (robot account). The server acts as its own OAuth AS — MCP clients authenticate against it, and it proxies user authentication to an upstream OIDC provider.

**Tech Stack:** Go 1.23+, modelcontextprotocol/go-sdk, ory/fosite, net/http

**Spec:** `docs/superpowers/specs/2026-08-26-harbor-mcp-design.md`

## Global Constraints

- Go 1.23+ (for stdlib HTTP routing patterns)
- Only `modelcontextprotocol/go-sdk` and `ory/fosite` as non-stdlib dependencies (plus their transitive deps)
- No Harbor client library — direct HTTP calls via `net/http`
- All configuration via environment variables
- Read-only tools only — no write operations
- OAuth 2.1: authorization code grant only, PKCE enforced (S256), no implicit, no ROPC
- JWT signing: RS256

---

### Task 1: Project Scaffolding and Configuration

**Files:**
- Create: `go.mod`
- Create: `cmd/harbor-mcp/main.go`
- Create: `internal/config/config.go`
- Test: `internal/config/config_test.go`

**Interfaces:**
- Consumes: nothing
- Produces: `config.Config` struct with fields `HarborURL string`, `HarborRobotName string`, `HarborRobotSecret string`, `OAuthUpstreamIssuer string`, `OAuthUpstreamClientID string`, `OAuthUpstreamClientSecret string`, `OAuthSigningKey string`, `ServerBaseURL string`, `ServerPort int`. Function `config.Load() (*Config, error)`.

- [ ] **Step 1: Initialize Go module**

```bash
cd /home/rophy/projects/harbor-mcp
go mod init github.com/rophy/harbor-mcp
```

- [ ] **Step 2: Write config test**

Create `internal/config/config_test.go`:

```go
package config_test

import (
	"os"
	"testing"

	"github.com/rophy/harbor-mcp/internal/config"
)

func TestLoad_AllSet(t *testing.T) {
	t.Setenv("HARBOR_URL", "https://harbor.example.com")
	t.Setenv("HARBOR_ROBOT_NAME", "robot$reader")
	t.Setenv("HARBOR_ROBOT_SECRET", "secret123")
	t.Setenv("OAUTH_UPSTREAM_ISSUER", "https://keycloak.example.com/realms/harbor")
	t.Setenv("OAUTH_UPSTREAM_CLIENT_ID", "harbor-mcp")
	t.Setenv("OAUTH_UPSTREAM_CLIENT_SECRET", "client-secret")
	t.Setenv("SERVER_BASE_URL", "http://localhost:8080")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.HarborURL != "https://harbor.example.com" {
		t.Errorf("HarborURL = %q, want %q", cfg.HarborURL, "https://harbor.example.com")
	}
	if cfg.ServerPort != 8080 {
		t.Errorf("ServerPort = %d, want 8080", cfg.ServerPort)
	}
}

func TestLoad_MissingRequired(t *testing.T) {
	os.Clearenv()
	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error for missing required vars")
	}
}

func TestLoad_CustomPort(t *testing.T) {
	t.Setenv("HARBOR_URL", "https://harbor.example.com")
	t.Setenv("HARBOR_ROBOT_NAME", "robot$reader")
	t.Setenv("HARBOR_ROBOT_SECRET", "secret123")
	t.Setenv("OAUTH_UPSTREAM_ISSUER", "https://keycloak.example.com/realms/harbor")
	t.Setenv("OAUTH_UPSTREAM_CLIENT_ID", "harbor-mcp")
	t.Setenv("OAUTH_UPSTREAM_CLIENT_SECRET", "client-secret")
	t.Setenv("SERVER_BASE_URL", "http://localhost:9090")
	t.Setenv("SERVER_PORT", "9090")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ServerPort != 9090 {
		t.Errorf("ServerPort = %d, want 9090", cfg.ServerPort)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

```bash
go test ./internal/config/ -v
```

Expected: compilation error — `config` package doesn't exist.

- [ ] **Step 4: Implement config package**

Create `internal/config/config.go`:

```go
package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	HarborURL                string
	HarborRobotName          string
	HarborRobotSecret        string
	OAuthUpstreamIssuer      string
	OAuthUpstreamClientID    string
	OAuthUpstreamClientSecret string
	OAuthSigningKey          string
	ServerBaseURL            string
	ServerPort               int
}

func Load() (*Config, error) {
	cfg := &Config{
		ServerPort: 8080,
	}

	required := map[string]*string{
		"HARBOR_URL":                  &cfg.HarborURL,
		"HARBOR_ROBOT_NAME":           &cfg.HarborRobotName,
		"HARBOR_ROBOT_SECRET":         &cfg.HarborRobotSecret,
		"OAUTH_UPSTREAM_ISSUER":       &cfg.OAuthUpstreamIssuer,
		"OAUTH_UPSTREAM_CLIENT_ID":    &cfg.OAuthUpstreamClientID,
		"OAUTH_UPSTREAM_CLIENT_SECRET": &cfg.OAuthUpstreamClientSecret,
		"SERVER_BASE_URL":             &cfg.ServerBaseURL,
	}

	for env, ptr := range required {
		val := os.Getenv(env)
		if val == "" {
			return nil, fmt.Errorf("required environment variable %s is not set", env)
		}
		*ptr = val
	}

	cfg.OAuthSigningKey = os.Getenv("OAUTH_SIGNING_KEY")

	if p := os.Getenv("SERVER_PORT"); p != "" {
		port, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("SERVER_PORT is not a valid integer: %w", err)
		}
		cfg.ServerPort = port
	}

	return cfg, nil
}
```

- [ ] **Step 5: Run tests**

```bash
go test ./internal/config/ -v
```

Expected: all 3 tests pass.

- [ ] **Step 6: Create main.go skeleton**

Create `cmd/harbor-mcp/main.go`:

```go
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/rophy/harbor-mcp/internal/config"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}
	fmt.Fprintf(os.Stderr, "harbor-mcp starting on port %d\n", cfg.ServerPort)
}
```

- [ ] **Step 7: Verify it compiles**

```bash
go build ./cmd/harbor-mcp/
```

- [ ] **Step 8: Commit**

```bash
git add go.mod cmd/ internal/config/
git commit -m "feat: project scaffolding with config package"
```

---

### Task 2: Harbor API Client and Types

**Files:**
- Create: `internal/harbor/types.go`
- Create: `internal/harbor/client.go`
- Test: `internal/harbor/client_test.go`

**Interfaces:**
- Consumes: nothing (standalone HTTP client)
- Produces:
  - Types: `Project`, `Repository`, `Artifact`, `Tag`, `ScanOverview`, `VulnerabilityReport`, `VulnerabilityItem`
  - Interface: `Client` with methods:
    - `ListProjects(ctx context.Context, opts ListProjectsOpts) ([]Project, error)`
    - `GetProject(ctx context.Context, name string) (*Project, error)`
    - `ListRepositories(ctx context.Context, projectName string, opts ListOpts) ([]Repository, error)`
    - `ListArtifacts(ctx context.Context, projectName, repoName string, opts ListOpts) ([]Artifact, error)`
    - `GetArtifact(ctx context.Context, projectName, repoName, reference string) (*Artifact, error)`
    - `GetVulnerabilities(ctx context.Context, projectName, repoName, reference string) (*VulnerabilityReport, error)`
  - Constructor: `NewClient(baseURL, robotName, robotSecret string) *HTTPClient`

- [ ] **Step 1: Write types**

Create `internal/harbor/types.go`:

```go
package harbor

import "time"

type Project struct {
	ProjectID    int       `json:"project_id"`
	Name         string    `json:"name"`
	RepoCount    int       `json:"repo_count"`
	CreationTime time.Time `json:"creation_time"`
	Metadata     struct {
		Public   string `json:"public"`
		AutoScan string `json:"auto_scan,omitempty"`
		Severity string `json:"severity,omitempty"`
	} `json:"metadata"`
}

type Repository struct {
	Name          string    `json:"name"`
	ArtifactCount int       `json:"artifact_count"`
	PullCount     int       `json:"pull_count"`
	CreationTime  time.Time `json:"creation_time"`
}

type Tag struct {
	Name     string    `json:"name"`
	PushTime time.Time `json:"push_time"`
}

type ScanOverview map[string]ScanSummary

type ScanSummary struct {
	Severity        string         `json:"severity"`
	Complete        bool           `json:"complete_percent"`
	Summary         map[string]int `json:"summary"`
}

type Artifact struct {
	Digest       string       `json:"digest"`
	Tags         []Tag        `json:"tags"`
	Size         int64        `json:"size"`
	PushTime     time.Time    `json:"push_time"`
	PullTime     time.Time    `json:"pull_time"`
	ScanOverview ScanOverview `json:"scan_overview"`
	ExtraAttrs   struct {
		OS           string `json:"os,omitempty"`
		Architecture string `json:"architecture,omitempty"`
	} `json:"extra_attrs"`
	Labels []struct {
		Name string `json:"name"`
	} `json:"labels"`
}

type VulnerabilityReport struct {
	GeneratedAt time.Time           `json:"generated_at"`
	Severity    string              `json:"severity"`
	Summary     map[string]int      `json:"summary"`
	Vulnerabilities []VulnerabilityItem `json:"vulnerabilities"`
}

type VulnerabilityItem struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Package     string `json:"package"`
	Version     string `json:"version"`
	FixVersion  string `json:"fix_version,omitempty"`
	Description string `json:"description"`
}

type ListOpts struct {
	Page     int
	PageSize int
}

type ListProjectsOpts struct {
	ListOpts
	Name string
}
```

- [ ] **Step 2: Write client interface and implementation**

Create `internal/harbor/client.go`:

```go
package harbor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type Client interface {
	ListProjects(ctx context.Context, opts ListProjectsOpts) ([]Project, error)
	GetProject(ctx context.Context, name string) (*Project, error)
	ListRepositories(ctx context.Context, projectName string, opts ListOpts) ([]Repository, error)
	ListArtifacts(ctx context.Context, projectName, repoName string, opts ListOpts) ([]Artifact, error)
	GetArtifact(ctx context.Context, projectName, repoName, reference string) (*Artifact, error)
	GetVulnerabilities(ctx context.Context, projectName, repoName, reference string) (*VulnerabilityReport, error)
}

type HTTPClient struct {
	baseURL    string
	httpClient *http.Client
	robotName  string
	robotSecret string
}

func NewClient(baseURL, robotName, robotSecret string) *HTTPClient {
	return &HTTPClient{
		baseURL:     strings.TrimRight(baseURL, "/"),
		httpClient:  &http.Client{},
		robotName:   robotName,
		robotSecret: robotSecret,
	}
}

func (c *HTTPClient) do(ctx context.Context, path string, query url.Values, result any) error {
	u := c.baseURL + "/api/v2.0" + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.SetBasicAuth(c.robotName, c.robotSecret)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("harbor API returned status %d for %s", resp.StatusCode, path)
	}

	if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	return nil
}

func paginationQuery(opts ListOpts) url.Values {
	q := url.Values{}
	if opts.Page > 0 {
		q.Set("page", strconv.Itoa(opts.Page))
	}
	if opts.PageSize > 0 {
		q.Set("page_size", strconv.Itoa(opts.PageSize))
	}
	return q
}

func (c *HTTPClient) ListProjects(ctx context.Context, opts ListProjectsOpts) ([]Project, error) {
	q := paginationQuery(opts.ListOpts)
	if opts.Name != "" {
		q.Set("name", opts.Name)
	}
	var projects []Project
	if err := c.do(ctx, "/projects", q, &projects); err != nil {
		return nil, err
	}
	return projects, nil
}

func (c *HTTPClient) GetProject(ctx context.Context, name string) (*Project, error) {
	var project Project
	if err := c.do(ctx, "/projects/"+url.PathEscape(name), nil, &project); err != nil {
		return nil, err
	}
	return &project, nil
}

func (c *HTTPClient) ListRepositories(ctx context.Context, projectName string, opts ListOpts) ([]Repository, error) {
	var repos []Repository
	path := fmt.Sprintf("/projects/%s/repositories", url.PathEscape(projectName))
	if err := c.do(ctx, path, paginationQuery(opts), &repos); err != nil {
		return nil, err
	}
	return repos, nil
}

func (c *HTTPClient) ListArtifacts(ctx context.Context, projectName, repoName string, opts ListOpts) ([]Artifact, error) {
	var artifacts []Artifact
	path := fmt.Sprintf("/projects/%s/repositories/%s/artifacts",
		url.PathEscape(projectName), url.PathEscape(repoName))
	if err := c.do(ctx, path, paginationQuery(opts), &artifacts); err != nil {
		return nil, err
	}
	return artifacts, nil
}

func (c *HTTPClient) GetArtifact(ctx context.Context, projectName, repoName, reference string) (*Artifact, error) {
	var artifact Artifact
	path := fmt.Sprintf("/projects/%s/repositories/%s/artifacts/%s",
		url.PathEscape(projectName), url.PathEscape(repoName), url.PathEscape(reference))
	if err := c.do(ctx, path, nil, &artifact); err != nil {
		return nil, err
	}
	return &artifact, nil
}

func (c *HTTPClient) GetVulnerabilities(ctx context.Context, projectName, repoName, reference string) (*VulnerabilityReport, error) {
	var report VulnerabilityReport
	path := fmt.Sprintf("/projects/%s/repositories/%s/artifacts/%s/additions/vulnerabilities",
		url.PathEscape(projectName), url.PathEscape(repoName), url.PathEscape(reference))
	if err := c.do(ctx, path, nil, &report); err != nil {
		return nil, err
	}
	return &report, nil
}
```

- [ ] **Step 3: Write client tests with mock HTTP server**

Create `internal/harbor/client_test.go`:

```go
package harbor_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rophy/harbor-mcp/internal/harbor"
)

func setupMockServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, harbor.Client) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	client := harbor.NewClient(srv.URL, "robot$test", "secret")
	return srv, client
}

func TestListProjects(t *testing.T) {
	_, client := setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2.0/projects" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != "robot$test" || pass != "secret" {
			t.Error("missing or wrong basic auth")
		}
		json.NewEncoder(w).Encode([]harbor.Project{
			{ProjectID: 1, Name: "library", RepoCount: 5},
		})
	})

	projects, err := client.ListProjects(context.Background(), harbor.ListProjectsOpts{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(projects) != 1 {
		t.Fatalf("got %d projects, want 1", len(projects))
	}
	if projects[0].Name != "library" {
		t.Errorf("Name = %q, want %q", projects[0].Name, "library")
	}
}

func TestGetProject(t *testing.T) {
	_, client := setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2.0/projects/library" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(harbor.Project{ProjectID: 1, Name: "library", RepoCount: 5})
	})

	project, err := client.GetProject(context.Background(), "library")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if project.Name != "library" {
		t.Errorf("Name = %q, want %q", project.Name, "library")
	}
}

func TestListRepositories(t *testing.T) {
	_, client := setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2.0/projects/library/repositories" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode([]harbor.Repository{
			{Name: "library/nginx", ArtifactCount: 3},
		})
	})

	repos, err := client.ListRepositories(context.Background(), "library", harbor.ListOpts{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(repos) != 1 || repos[0].Name != "library/nginx" {
		t.Errorf("unexpected repos: %+v", repos)
	}
}

func TestListArtifacts(t *testing.T) {
	_, client := setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2.0/projects/library/repositories/nginx/artifacts" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode([]harbor.Artifact{
			{Digest: "sha256:abc123", Size: 12345},
		})
	})

	artifacts, err := client.ListArtifacts(context.Background(), "library", "nginx", harbor.ListOpts{Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(artifacts) != 1 || artifacts[0].Digest != "sha256:abc123" {
		t.Errorf("unexpected artifacts: %+v", artifacts)
	}
}

func TestAPIError(t *testing.T) {
	_, client := setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	_, err := client.GetProject(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/harbor/ -v
```

Expected: all 5 tests pass.

- [ ] **Step 5: Commit**

```bash
git add internal/harbor/
git commit -m "feat: harbor API client with types and tests"
```

---

### Task 3: Fosite In-Memory Storage and OAuth 2.1 Provider

**Files:**
- Create: `internal/auth/storage.go`
- Create: `internal/auth/provider.go`
- Test: `internal/auth/provider_test.go`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `NewMemoryStore() *MemoryStore` — fosite-compatible in-memory storage
  - `MemoryStore.RegisterClient(id string, redirectURIs []string)` — for DCR
  - `NewOAuthProvider(store *MemoryStore, signingKey *rsa.PrivateKey) fosite.OAuth2Provider`

- [ ] **Step 1: Add fosite dependency**

```bash
go get github.com/ory/fosite@latest
go get github.com/ory/fosite/compose@latest
go get github.com/ory/fosite/handler/oauth2@latest
go get github.com/ory/fosite/handler/pkce@latest
go get github.com/ory/fosite/token/jwt@latest
go get github.com/ory/fosite/storage@latest
```

- [ ] **Step 2: Write in-memory storage**

Create `internal/auth/storage.go`:

```go
package auth

import (
	"context"
	"sync"
	"time"

	"github.com/ory/fosite"
)

type MemoryStore struct {
	mu              sync.RWMutex
	clients         map[string]fosite.Client
	authCodes       map[string]fosite.Requester
	accessTokens    map[string]fosite.Requester
	refreshTokens   map[string]fosite.Requester
	pkces           map[string]fosite.Requester
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		clients:       make(map[string]fosite.Client),
		authCodes:     make(map[string]fosite.Requester),
		accessTokens:  make(map[string]fosite.Requester),
		refreshTokens: make(map[string]fosite.Requester),
		pkces:         make(map[string]fosite.Requester),
	}
}

func (s *MemoryStore) RegisterClient(id string, redirectURIs []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[id] = &fosite.DefaultClient{
		ID:            id,
		Public:        true,
		RedirectURIs:  redirectURIs,
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"harbor:read"},
	}
}

func (s *MemoryStore) GetClient(_ context.Context, id string) (fosite.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	client, ok := s.clients[id]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return client, nil
}

func (s *MemoryStore) CreateAuthorizeCodeSession(_ context.Context, code string, req fosite.Requester) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authCodes[code] = req
	return nil
}

func (s *MemoryStore) GetAuthorizeCodeSession(_ context.Context, code string, _ fosite.Session) (fosite.Requester, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	req, ok := s.authCodes[code]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return req, nil
}

func (s *MemoryStore) InvalidateAuthorizeCodeSession(_ context.Context, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.authCodes, code)
	return nil
}

func (s *MemoryStore) CreatePKCERequestSession(_ context.Context, code string, req fosite.Requester) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pkces[code] = req
	return nil
}

func (s *MemoryStore) GetPKCERequestSession(_ context.Context, code string, _ fosite.Session) (fosite.Requester, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	req, ok := s.pkces[code]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return req, nil
}

func (s *MemoryStore) DeletePKCERequestSession(_ context.Context, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pkces, code)
	return nil
}

func (s *MemoryStore) CreateAccessTokenSession(_ context.Context, sig string, req fosite.Requester) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accessTokens[sig] = req
	return nil
}

func (s *MemoryStore) GetAccessTokenSession(_ context.Context, sig string, _ fosite.Session) (fosite.Requester, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	req, ok := s.accessTokens[sig]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return req, nil
}

func (s *MemoryStore) DeleteAccessTokenSession(_ context.Context, sig string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.accessTokens, sig)
	return nil
}

func (s *MemoryStore) CreateRefreshTokenSession(_ context.Context, sig string, req fosite.Requester) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshTokens[sig] = req
	return nil
}

func (s *MemoryStore) GetRefreshTokenSession(_ context.Context, sig string, _ fosite.Session) (fosite.Requester, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	req, ok := s.refreshTokens[sig]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return req, nil
}

func (s *MemoryStore) DeleteRefreshTokenSession(_ context.Context, sig string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.refreshTokens, sig)
	return nil
}

func (s *MemoryStore) RevokeRefreshToken(_ context.Context, requestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for sig, req := range s.refreshTokens {
		if req.GetID() == requestID {
			delete(s.refreshTokens, sig)
		}
	}
	return nil
}

func (s *MemoryStore) RevokeRefreshTokenMaybeGracePeriod(_ context.Context, requestID string, _ string) error {
	return s.RevokeRefreshToken(context.Background(), requestID)
}

func (s *MemoryStore) RevokeAccessToken(_ context.Context, requestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for sig, req := range s.accessTokens {
		if req.GetID() == requestID {
			delete(s.accessTokens, sig)
		}
	}
	return nil
}

var _ fosite.Storage = (*MemoryStore)(nil)
```

- [ ] **Step 3: Write OAuth provider setup**

Create `internal/auth/provider.go`:

```go
package auth

import (
	"crypto/rsa"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	fjwt "github.com/ory/fosite/token/jwt"
)

func NewOAuthProvider(store *MemoryStore, signingKey *rsa.PrivateKey) fosite.OAuth2Provider {
	config := &fosite.Config{
		AccessTokenLifespan:         time.Hour,
		RefreshTokenLifespan:        24 * time.Hour,
		AuthorizeCodeLifespan:       10 * time.Minute,
		EnforcePKCE:                 true,
		EnforcePKCEForPublicClients: true,
		TokenURL:                    "/token",
		SendDebugMessagesToClients:  false,
	}

	return compose.Compose(
		config,
		store,
		&compose.CommonStrategy{
			CoreStrategy: compose.NewOAuth2JWTStrategy(
				fjwt.MustRSAKey(signingKey), fjwt.NewSigner(nil), config,
			),
		},
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2PKCEFactory,
		compose.OAuth2RefreshTokenGrantFactory,
	)
}
```

- [ ] **Step 4: Write provider test**

Create `internal/auth/provider_test.go`:

```go
package auth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/rophy/harbor-mcp/internal/auth"
)

func TestNewOAuthProvider(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	store := auth.NewMemoryStore()
	provider := auth.NewOAuthProvider(store, key)
	if provider == nil {
		t.Fatal("provider is nil")
	}
}

func TestMemoryStore_RegisterAndGetClient(t *testing.T) {
	store := auth.NewMemoryStore()
	store.RegisterClient("test-client", []string{"http://localhost:3000/callback"})

	client, err := store.GetClient(nil, "test-client")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.GetID() != "test-client" {
		t.Errorf("ID = %q, want %q", client.GetID(), "test-client")
	}
}

func TestMemoryStore_GetClient_NotFound(t *testing.T) {
	store := auth.NewMemoryStore()
	_, err := store.GetClient(nil, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent client")
	}
}
```

- [ ] **Step 5: Run tests**

```bash
go test ./internal/auth/ -v
```

Expected: all 3 tests pass.

- [ ] **Step 6: Commit**

```bash
git add internal/auth/storage.go internal/auth/provider.go internal/auth/provider_test.go go.mod go.sum
git commit -m "feat: fosite in-memory storage and OAuth 2.1 provider"
```

---

### Task 4: Upstream OIDC Discovery and Proxy

**Files:**
- Create: `internal/auth/upstream.go`
- Test: `internal/auth/upstream_test.go`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `UpstreamOIDC` struct with fields `Issuer`, `ClientID`, `ClientSecret`, `AuthorizationEndpoint`, `TokenEndpoint`
  - `NewUpstreamOIDC(issuer, clientID, clientSecret string) (*UpstreamOIDC, error)` — performs OIDC discovery
  - `(u *UpstreamOIDC) AuthorizationURL(state, callbackURL string) string`
  - `(u *UpstreamOIDC) ExchangeCode(ctx context.Context, code, callbackURL string) (*UpstreamTokens, error)`
  - `UpstreamTokens` struct: `AccessToken`, `IDToken`, `RefreshToken string`

- [ ] **Step 1: Write upstream OIDC client**

Create `internal/auth/upstream.go`:

```go
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type UpstreamOIDC struct {
	Issuer                string
	ClientID              string
	ClientSecret          string
	AuthorizationEndpoint string
	TokenEndpoint         string
}

type UpstreamTokens struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
}

type oidcDiscovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

func NewUpstreamOIDC(issuer, clientID, clientSecret string) (*UpstreamOIDC, error) {
	discoveryURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	resp, err := http.Get(discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC discovery returned status %d", resp.StatusCode)
	}

	var disc oidcDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		return nil, fmt.Errorf("decoding OIDC discovery: %w", err)
	}

	if disc.AuthorizationEndpoint == "" || disc.TokenEndpoint == "" {
		return nil, fmt.Errorf("OIDC discovery missing required endpoints")
	}

	return &UpstreamOIDC{
		Issuer:                issuer,
		ClientID:              clientID,
		ClientSecret:          clientSecret,
		AuthorizationEndpoint: disc.AuthorizationEndpoint,
		TokenEndpoint:         disc.TokenEndpoint,
	}, nil
}

func (u *UpstreamOIDC) AuthorizationURL(state, callbackURL string) string {
	v := url.Values{
		"response_type": {"code"},
		"client_id":     {u.ClientID},
		"redirect_uri":  {callbackURL},
		"state":         {state},
		"scope":         {"openid profile email"},
	}
	return u.AuthorizationEndpoint + "?" + v.Encode()
}

func (u *UpstreamOIDC) ExchangeCode(ctx context.Context, code, callbackURL string) (*UpstreamTokens, error) {
	data := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {callbackURL},
		"client_id":    {u.ClientID},
		"client_secret": {u.ClientSecret},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange returned status %d", resp.StatusCode)
	}

	var tokens UpstreamTokens
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		return nil, fmt.Errorf("decoding token response: %w", err)
	}
	return &tokens, nil
}
```

- [ ] **Step 2: Write upstream OIDC tests with mock IdP**

Create `internal/auth/upstream_test.go`:

```go
package auth_test

import (
	"context"
	"encoding/json"
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

	upstream, err := auth.NewUpstreamOIDC(idp.URL, "client-id", "client-secret")
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

	_, err := auth.NewUpstreamOIDC(idp.URL, "client-id", "client-secret")
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
```

- [ ] **Step 3: Run tests**

```bash
go test ./internal/auth/ -v
```

Expected: all tests pass (both provider_test.go and upstream_test.go).

- [ ] **Step 4: Commit**

```bash
git add internal/auth/upstream.go internal/auth/upstream_test.go
git commit -m "feat: upstream OIDC discovery and token exchange"
```

---

### Task 5: OAuth HTTP Handlers

**Files:**
- Create: `internal/auth/handlers.go`
- Test: `internal/auth/handlers_test.go`

**Interfaces:**
- Consumes:
  - `auth.NewOAuthProvider(store, key) fosite.OAuth2Provider` from Task 3
  - `auth.NewMemoryStore() *MemoryStore` from Task 3
  - `auth.UpstreamOIDC` from Task 4
- Produces:
  - `NewOAuthHandlers(provider fosite.OAuth2Provider, store *MemoryStore, upstream *UpstreamOIDC, baseURL string) *OAuthHandlers`
  - `(h *OAuthHandlers) RegisterRoutes(mux *http.ServeMux)` — registers all OAuth endpoints on the mux

- [ ] **Step 1: Write OAuth handlers**

Create `internal/auth/handlers.go`:

```go
package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
)

type OAuthHandlers struct {
	provider  fosite.OAuth2Provider
	store     *MemoryStore
	upstream  *UpstreamOIDC
	baseURL   string
	mu        sync.Mutex
	pending   map[string]*pendingAuth // state -> pending authorization
}

type pendingAuth struct {
	fositeReq  fosite.AuthorizeRequester
	upstreamState string
}

func NewOAuthHandlers(provider fosite.OAuth2Provider, store *MemoryStore, upstream *UpstreamOIDC, baseURL string) *OAuthHandlers {
	return &OAuthHandlers{
		provider: provider,
		store:    store,
		upstream: upstream,
		baseURL:  strings.TrimRight(baseURL, "/"),
		pending:  make(map[string]*pendingAuth),
	}
}

func (h *OAuthHandlers) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", h.handleMetadata)
	mux.HandleFunc("POST /register", h.handleRegister)
	mux.HandleFunc("GET /authorize", h.handleAuthorize)
	mux.HandleFunc("GET /auth/callback", h.handleCallback)
	mux.HandleFunc("POST /token", h.handleToken)
}

func (h *OAuthHandlers) handleMetadata(w http.ResponseWriter, r *http.Request) {
	metadata := map[string]any{
		"issuer":                 h.baseURL,
		"authorization_endpoint": h.baseURL + "/authorize",
		"token_endpoint":         h.baseURL + "/token",
		"registration_endpoint":  h.baseURL + "/register",
		"response_types_supported": []string{"code"},
		"grant_types_supported":    []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported": []string{"S256"},
		"scopes_supported":        []string{"harbor:read"},
		"token_endpoint_auth_methods_supported": []string{"none"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metadata)
}

func (h *OAuthHandlers) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RedirectURIs []string `json:"redirect_uris"`
		ClientName   string   `json:"client_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if len(req.RedirectURIs) == 0 {
		http.Error(w, "redirect_uris required", http.StatusBadRequest)
		return
	}

	clientID := generateID()
	h.store.RegisterClient(clientID, req.RedirectURIs)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"client_id":                clientID,
		"client_name":              req.ClientName,
		"redirect_uris":            req.RedirectURIs,
		"grant_types":              []string{"authorization_code", "refresh_token"},
		"response_types":           []string{"code"},
		"token_endpoint_auth_method": "none",
	})
}

func (h *OAuthHandlers) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ar, err := h.provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		h.provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	ar.GrantScope("harbor:read")

	state := generateID()
	h.mu.Lock()
	h.pending[state] = &pendingAuth{
		fositeReq:     ar,
		upstreamState: state,
	}
	h.mu.Unlock()

	callbackURL := h.baseURL + "/auth/callback"
	upstreamURL := h.upstream.AuthorizationURL(state, callbackURL)
	http.Redirect(w, r, upstreamURL, http.StatusFound)
}

func (h *OAuthHandlers) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	if state == "" || code == "" {
		http.Error(w, "missing state or code", http.StatusBadRequest)
		return
	}

	h.mu.Lock()
	p, ok := h.pending[state]
	if ok {
		delete(h.pending, state)
	}
	h.mu.Unlock()

	if !ok {
		http.Error(w, "unknown state parameter", http.StatusBadRequest)
		return
	}

	callbackURL := h.baseURL + "/auth/callback"
	_, err := h.upstream.ExchangeCode(ctx, code, callbackURL)
	if err != nil {
		http.Error(w, fmt.Sprintf("upstream token exchange failed: %v", err), http.StatusBadGateway)
		return
	}

	session := &openid.DefaultSession{}
	response, err := h.provider.NewAuthorizeResponse(ctx, p.fositeReq, session)
	if err != nil {
		h.provider.WriteAuthorizeError(ctx, w, p.fositeReq, err)
		return
	}

	h.provider.WriteAuthorizeResponse(ctx, w, p.fositeReq, response)
}

func (h *OAuthHandlers) handleToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := &openid.DefaultSession{}

	ar, err := h.provider.NewAccessRequest(ctx, r, session)
	if err != nil {
		h.provider.WriteAccessError(ctx, w, ar, err)
		return
	}

	ar.GrantScope("harbor:read")

	response, err := h.provider.NewAccessResponse(ctx, ar)
	if err != nil {
		h.provider.WriteAccessError(ctx, w, ar, err)
		return
	}

	h.provider.WriteAccessResponse(ctx, w, ar, response)
}

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
```

- [ ] **Step 2: Write handler tests**

Create `internal/auth/handlers_test.go`:

```go
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
```

- [ ] **Step 3: Run tests**

```bash
go test ./internal/auth/ -v
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add internal/auth/handlers.go internal/auth/handlers_test.go
git commit -m "feat: OAuth 2.1 HTTP handlers with DCR and metadata"
```

---

### Task 6: MCP Server and Tool Registration

**Files:**
- Create: `internal/server/server.go`
- Create: `internal/server/tools.go`
- Test: `internal/server/tools_test.go`

**Interfaces:**
- Consumes:
  - `harbor.Client` interface from Task 2
- Produces:
  - `NewMCPServer(harborClient harbor.Client) *mcp.Server`

- [ ] **Step 1: Add go-sdk dependency**

```bash
go get github.com/modelcontextprotocol/go-sdk@latest
```

- [ ] **Step 2: Write tool input types and handlers**

Create `internal/server/tools.go`:

```go
package server

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rophy/harbor-mcp/internal/harbor"
)

type ListProjectsInput struct {
	Page     int    `json:"page,omitempty" jsonschema:"description=Page number (default 1)"`
	PageSize int    `json:"page_size,omitempty" jsonschema:"description=Items per page (default 10)"`
	Name     string `json:"name,omitempty" jsonschema:"description=Filter projects by name"`
}

type GetProjectInput struct {
	ProjectName string `json:"project_name" jsonschema:"description=Name of the project,required"`
}

type ListRepositoriesInput struct {
	ProjectName string `json:"project_name" jsonschema:"description=Name of the project,required"`
	Page        int    `json:"page,omitempty" jsonschema:"description=Page number (default 1)"`
	PageSize    int    `json:"page_size,omitempty" jsonschema:"description=Items per page (default 10)"`
}

type ListArtifactsInput struct {
	ProjectName    string `json:"project_name" jsonschema:"description=Name of the project,required"`
	RepositoryName string `json:"repository_name" jsonschema:"description=Name of the repository,required"`
	Page           int    `json:"page,omitempty" jsonschema:"description=Page number (default 1)"`
	PageSize       int    `json:"page_size,omitempty" jsonschema:"description=Items per page (default 10)"`
}

type ArtifactRefInput struct {
	ProjectName    string `json:"project_name" jsonschema:"description=Name of the project,required"`
	RepositoryName string `json:"repository_name" jsonschema:"description=Name of the repository,required"`
	Reference      string `json:"reference" jsonschema:"description=Tag name or digest (e.g. latest or sha256:abc...),required"`
}

func toTextResult(v any) (*mcp.CallToolResult, any, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling result: %w", err)
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{mcp.NewTextContent(string(data))},
	}, nil, nil
}

func listProjectsHandler(client harbor.Client) func(context.Context, *mcp.CallToolRequest, ListProjectsInput) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, input ListProjectsInput) (*mcp.CallToolResult, any, error) {
		projects, err := client.ListProjects(ctx, harbor.ListProjectsOpts{
			ListOpts: harbor.ListOpts{Page: input.Page, PageSize: input.PageSize},
			Name:     input.Name,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("listing projects: %w", err)
		}
		return toTextResult(projects)
	}
}

func getProjectHandler(client harbor.Client) func(context.Context, *mcp.CallToolRequest, GetProjectInput) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, input GetProjectInput) (*mcp.CallToolResult, any, error) {
		project, err := client.GetProject(ctx, input.ProjectName)
		if err != nil {
			return nil, nil, fmt.Errorf("getting project: %w", err)
		}
		return toTextResult(project)
	}
}

func listRepositoriesHandler(client harbor.Client) func(context.Context, *mcp.CallToolRequest, ListRepositoriesInput) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, input ListRepositoriesInput) (*mcp.CallToolResult, any, error) {
		repos, err := client.ListRepositories(ctx, input.ProjectName, harbor.ListOpts{
			Page: input.Page, PageSize: input.PageSize,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("listing repositories: %w", err)
		}
		return toTextResult(repos)
	}
}

func listArtifactsHandler(client harbor.Client) func(context.Context, *mcp.CallToolRequest, ListArtifactsInput) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, input ListArtifactsInput) (*mcp.CallToolResult, any, error) {
		artifacts, err := client.ListArtifacts(ctx, input.ProjectName, input.RepositoryName, harbor.ListOpts{
			Page: input.Page, PageSize: input.PageSize,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("listing artifacts: %w", err)
		}
		return toTextResult(artifacts)
	}
}

func getArtifactHandler(client harbor.Client) func(context.Context, *mcp.CallToolRequest, ArtifactRefInput) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, input ArtifactRefInput) (*mcp.CallToolResult, any, error) {
		artifact, err := client.GetArtifact(ctx, input.ProjectName, input.RepositoryName, input.Reference)
		if err != nil {
			return nil, nil, fmt.Errorf("getting artifact: %w", err)
		}
		return toTextResult(artifact)
	}
}

func getVulnerabilitiesHandler(client harbor.Client) func(context.Context, *mcp.CallToolRequest, ArtifactRefInput) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, input ArtifactRefInput) (*mcp.CallToolResult, any, error) {
		report, err := client.GetVulnerabilities(ctx, input.ProjectName, input.RepositoryName, input.Reference)
		if err != nil {
			return nil, nil, fmt.Errorf("getting vulnerabilities: %w", err)
		}
		return toTextResult(report)
	}
}
```

- [ ] **Step 3: Write server setup**

Create `internal/server/server.go`:

```go
package server

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rophy/harbor-mcp/internal/harbor"
)

func NewMCPServer(harborClient harbor.Client) *mcp.Server {
	srv := mcp.NewServer(
		&mcp.Implementation{Name: "harbor-mcp", Version: "0.1.0"},
		nil,
	)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_projects",
		Description: "List Harbor projects accessible to the configured account",
	}, listProjectsHandler(harborClient))

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_project",
		Description: "Get details of a specific Harbor project",
	}, getProjectHandler(harborClient))

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_repositories",
		Description: "List repositories in a Harbor project",
	}, listRepositoriesHandler(harborClient))

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_artifacts",
		Description: "List artifacts (container images) in a repository",
	}, listArtifactsHandler(harborClient))

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_artifact",
		Description: "Get detailed information about a specific artifact (image)",
	}, getArtifactHandler(harborClient))

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_vulnerabilities",
		Description: "Get vulnerability scan report for an artifact",
	}, getVulnerabilitiesHandler(harborClient))

	return srv
}
```

- [ ] **Step 4: Write tool handler tests**

Create `internal/server/tools_test.go`:

```go
package server_test

import (
	"context"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rophy/harbor-mcp/internal/harbor"
	"github.com/rophy/harbor-mcp/internal/server"
)

type mockHarborClient struct{}

func (m *mockHarborClient) ListProjects(_ context.Context, opts harbor.ListProjectsOpts) ([]harbor.Project, error) {
	projects := []harbor.Project{
		{ProjectID: 1, Name: "library", RepoCount: 3},
		{ProjectID: 2, Name: "staging", RepoCount: 1},
	}
	if opts.Name != "" {
		var filtered []harbor.Project
		for _, p := range projects {
			if p.Name == opts.Name {
				filtered = append(filtered, p)
			}
		}
		return filtered, nil
	}
	return projects, nil
}

func (m *mockHarborClient) GetProject(_ context.Context, name string) (*harbor.Project, error) {
	return &harbor.Project{ProjectID: 1, Name: name, RepoCount: 3}, nil
}

func (m *mockHarborClient) ListRepositories(_ context.Context, projectName string, opts harbor.ListOpts) ([]harbor.Repository, error) {
	return []harbor.Repository{
		{Name: projectName + "/nginx", ArtifactCount: 5, PullCount: 100},
	}, nil
}

func (m *mockHarborClient) ListArtifacts(_ context.Context, projectName, repoName string, opts harbor.ListOpts) ([]harbor.Artifact, error) {
	return []harbor.Artifact{
		{Digest: "sha256:abc123", Size: 54321, Tags: []harbor.Tag{{Name: "latest"}}},
	}, nil
}

func (m *mockHarborClient) GetArtifact(_ context.Context, projectName, repoName, reference string) (*harbor.Artifact, error) {
	return &harbor.Artifact{
		Digest:   "sha256:abc123",
		Size:     54321,
		PushTime: time.Now(),
		Tags:     []harbor.Tag{{Name: reference}},
	}, nil
}

func (m *mockHarborClient) GetVulnerabilities(_ context.Context, projectName, repoName, reference string) (*harbor.VulnerabilityReport, error) {
	return &harbor.VulnerabilityReport{
		Severity: "High",
		Summary:  map[string]int{"High": 2, "Medium": 5},
		Vulnerabilities: []harbor.VulnerabilityItem{
			{ID: "CVE-2024-1234", Severity: "High", Package: "openssl", Version: "1.1.1"},
		},
	}, nil
}

func TestNewMCPServer(t *testing.T) {
	mock := &mockHarborClient{}
	srv := server.NewMCPServer(mock)
	if srv == nil {
		t.Fatal("server is nil")
	}
}

func TestListProjectsTool(t *testing.T) {
	mock := &mockHarborClient{}
	srv := server.NewMCPServer(mock)

	result, err := srv.CallTool(context.Background(), &mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "list_projects",
			Arguments: map[string]any{},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Content) == 0 {
		t.Fatal("expected content in result")
	}
}

func TestGetVulnerabilitiesTool(t *testing.T) {
	mock := &mockHarborClient{}
	srv := server.NewMCPServer(mock)

	result, err := srv.CallTool(context.Background(), &mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "get_vulnerabilities",
			Arguments: map[string]any{
				"project_name":    "library",
				"repository_name": "nginx",
				"reference":       "latest",
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Content) == 0 {
		t.Fatal("expected content in result")
	}
}
```

- [ ] **Step 5: Run tests**

```bash
go test ./internal/server/ -v
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add internal/server/
git commit -m "feat: MCP server with Harbor browsing tools"
```

---

### Task 7: Main Wiring and Auth Middleware

**Files:**
- Create: `internal/auth/middleware.go`
- Modify: `cmd/harbor-mcp/main.go`

**Interfaces:**
- Consumes:
  - `config.Load() (*Config, error)` from Task 1
  - `harbor.NewClient(url, name, secret) *HTTPClient` from Task 2
  - `auth.NewMemoryStore() *MemoryStore` from Task 3
  - `auth.NewOAuthProvider(store, key) fosite.OAuth2Provider` from Task 3
  - `auth.NewUpstreamOIDC(issuer, clientID, clientSecret string) (*UpstreamOIDC, error)` from Task 4
  - `auth.NewOAuthHandlers(provider, store, upstream, baseURL) *OAuthHandlers` from Task 5
  - `(h *OAuthHandlers) RegisterRoutes(mux *http.ServeMux)` from Task 5
  - `server.NewMCPServer(client) *mcp.Server` from Task 6
- Produces:
  - `auth.RequireBearerToken(provider fosite.OAuth2Provider, next http.Handler) http.Handler` — middleware
  - Runnable binary

- [ ] **Step 1: Write bearer token validation middleware**

Create `internal/auth/middleware.go`:

```go
package auth

import (
	"net/http"
	"strings"

	"github.com/ory/fosite"
)

func RequireBearerToken(provider fosite.OAuth2Provider, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		ctx := r.Context()

		_, _, err := provider.IntrospectToken(ctx, token, fosite.AccessToken, new(fosite.DefaultSession))
		if err != nil {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}
```

- [ ] **Step 2: Write main.go with full wiring**

Replace `cmd/harbor-mcp/main.go` with:

```go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rophy/harbor-mcp/internal/auth"
	"github.com/rophy/harbor-mcp/internal/config"
	"github.com/rophy/harbor-mcp/internal/harbor"
	"github.com/rophy/harbor-mcp/internal/server"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	signingKey, err := loadOrGenerateKey(cfg.OAuthSigningKey)
	if err != nil {
		log.Fatalf("failed to load signing key: %v", err)
	}

	upstream, err := auth.NewUpstreamOIDC(
		cfg.OAuthUpstreamIssuer,
		cfg.OAuthUpstreamClientID,
		cfg.OAuthUpstreamClientSecret,
	)
	if err != nil {
		log.Fatalf("failed to discover upstream OIDC: %v", err)
	}

	store := auth.NewMemoryStore()
	provider := auth.NewOAuthProvider(store, signingKey)
	oauthHandlers := auth.NewOAuthHandlers(provider, store, upstream, cfg.ServerBaseURL)

	harborClient := harbor.NewClient(cfg.HarborURL, cfg.HarborRobotName, cfg.HarborRobotSecret)
	mcpServer := server.NewMCPServer(harborClient)

	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(r *http.Request) *mcp.Server { return mcpServer },
		&mcp.StreamableHTTPOptions{},
	)

	httpMux := http.NewServeMux()
	oauthHandlers.RegisterRoutes(httpMux)
	httpMux.Handle("/mcp", auth.RequireBearerToken(provider, mcpHandler))

	addr := fmt.Sprintf(":%d", cfg.ServerPort)
	log.Printf("harbor-mcp listening on %s", addr)
	if err := http.ListenAndServe(addr, httpMux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func loadOrGenerateKey(pemData string) (*rsa.PrivateKey, error) {
	if pemData != "" {
		block, _ := pem.Decode([]byte(pemData))
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM signing key")
		}
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	log.Println("no OAUTH_SIGNING_KEY set, generating ephemeral RSA key")
	return rsa.GenerateKey(rand.Reader, 2048)
}
```

- [ ] **Step 2: Verify it compiles**

```bash
go build ./cmd/harbor-mcp/
```

Expected: builds successfully.

- [ ] **Step 3: Commit**

```bash
git add internal/auth/middleware.go cmd/harbor-mcp/main.go
git commit -m "feat: wire main entrypoint with OAuth + MCP server"
```

---

### Task 8: Docker-Compose Test Environment and Integration Tests

**Files:**
- Create: `docker-compose.yml`
- Create: `Dockerfile`
- Create: `tests/integration_test.go`

**Interfaces:**
- Consumes: all previous tasks (full running server)
- Produces: working docker-compose environment, integration test suite

- [ ] **Step 1: Create Dockerfile**

Create `Dockerfile`:

```dockerfile
FROM golang:1.23 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /harbor-mcp ./cmd/harbor-mcp/

FROM gcr.io/distroless/static-debian12
COPY --from=builder /harbor-mcp /harbor-mcp
ENTRYPOINT ["/harbor-mcp"]
```

- [ ] **Step 2: Create docker-compose.yml**

Create `docker-compose.yml`:

Harbor requires its official installer to generate configs. For a dev/test environment, we use the offline installer approach with pre-generated configs. However, since the Harbor installer is complex, use a minimal setup that starts Harbor via the official `goharbor/harbor-core` images with the required supporting services.

```yaml
version: "3.8"

services:
  harbor-db:
    image: goharbor/harbor-db:v2.12.0
    environment:
      POSTGRES_PASSWORD: root123
    volumes:
      - harbor-db-data:/var/lib/postgresql/data

  harbor-redis:
    image: goharbor/redis-photon:v2.12.0

  harbor-registry:
    image: goharbor/registry-photon:v2.12.0
    volumes:
      - registry-data:/storage

  harbor-core:
    image: goharbor/harbor-core:v2.12.0
    depends_on:
      - harbor-db
      - harbor-redis
      - harbor-registry
    environment:
      DATABASE_TYPE: postgresql
      POSTGRESQL_HOST: harbor-db
      POSTGRESQL_PORT: 5432
      POSTGRESQL_USERNAME: postgres
      POSTGRESQL_PASSWORD: root123
      POSTGRESQL_DATABASE: registry
      _REDIS_URL_CORE: redis://harbor-redis:6379/0
      HARBOR_ADMIN_PASSWORD: Harbor12345
      CONFIG_PATH: /etc/core/app.conf
    ports:
      - "8880:8080"

  keycloak:
    image: quay.io/keycloak/keycloak:26.0
    command: start-dev
    environment:
      KC_HTTP_PORT: 8080
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin
    ports:
      - "8880:8080"

volumes:
  harbor-db-data:
  registry-data:
```

Note: This is a starting-point docker-compose. Harbor's official installer generates `harbor.yml` → `docker-compose.yml` with many more config files. The integration test setup will likely need to use the official Harbor installer (`install.sh`) or a pre-built docker-compose from the Harbor release. Adjust container names, ports, and config paths during implementation based on what the installer generates.

- [ ] **Step 3: Write integration test**

Create `tests/integration_test.go`:

```go
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
```

- [ ] **Step 4: Verify Dockerfile builds**

```bash
docker build -t harbor-mcp:test .
```

Expected: image builds successfully.

- [ ] **Step 5: Commit**

```bash
git add Dockerfile docker-compose.yml tests/
git commit -m "feat: docker-compose test environment and integration tests"
```
