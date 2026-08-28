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
	Search(ctx context.Context, query string) (*SearchResult, error)
	ListProjects(ctx context.Context, opts ListProjectsOpts) ([]Project, error)
	GetProject(ctx context.Context, name string) (*Project, error)
	ListRepositories(ctx context.Context, projectName string, opts ListOpts) ([]Repository, error)
	ListArtifacts(ctx context.Context, projectName, repoName string, opts ListOpts) ([]Artifact, error)
	GetArtifact(ctx context.Context, projectName, repoName, reference string) (*Artifact, error)
	GetVulnerabilities(ctx context.Context, projectName, repoName, reference string) (*VulnerabilityReport, error)
}

type HTTPClient struct {
	baseURL     string
	httpClient  *http.Client
	robotName   string
	robotSecret string
}

func NewClient(baseURL, robotName, robotSecret string, opts ...ClientOption) *HTTPClient {
	c := &HTTPClient{
		baseURL:     strings.TrimRight(baseURL, "/"),
		httpClient:  &http.Client{},
		robotName:   robotName,
		robotSecret: robotSecret,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

type ClientOption func(*HTTPClient)

func WithHTTPClient(hc *http.Client) ClientOption {
	return func(c *HTTPClient) {
		c.httpClient = hc
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
	if opts.Query != "" {
		q.Set("q", opts.Query)
	}
	return q
}

func (c *HTTPClient) Search(ctx context.Context, query string) (*SearchResult, error) {
	var result SearchResult
	q := url.Values{"q": {query}}
	if err := c.do(ctx, "/search", q, &result); err != nil {
		return nil, err
	}
	return &result, nil
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
