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

func connect(ctx context.Context, srv *mcp.Server) (*mcp.ClientSession, error) {
	t1, t2 := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, t1, nil); err != nil {
		return nil, err
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v0.0.1"}, nil)
	return client.Connect(ctx, t2, nil)
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

	ctx := context.Background()
	session, err := connect(ctx, srv)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_projects",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Content) == 0 {
		t.Fatal("expected content in result")
	}
}

func TestGetProjectTool(t *testing.T) {
	mock := &mockHarborClient{}
	srv := server.NewMCPServer(mock)

	ctx := context.Background()
	session, err := connect(ctx, srv)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_project",
		Arguments: map[string]any{"project_name": "library"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Content) == 0 {
		t.Fatal("expected content in result")
	}
}

func TestListRepositoriesTool(t *testing.T) {
	mock := &mockHarborClient{}
	srv := server.NewMCPServer(mock)

	ctx := context.Background()
	session, err := connect(ctx, srv)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_repositories",
		Arguments: map[string]any{"project_name": "library"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Content) == 0 {
		t.Fatal("expected content in result")
	}
}

func TestListArtifactsTool(t *testing.T) {
	mock := &mockHarborClient{}
	srv := server.NewMCPServer(mock)

	ctx := context.Background()
	session, err := connect(ctx, srv)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "list_artifacts",
		Arguments: map[string]any{
			"project_name":    "library",
			"repository_name": "nginx",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Content) == 0 {
		t.Fatal("expected content in result")
	}
}

func TestGetArtifactTool(t *testing.T) {
	mock := &mockHarborClient{}
	srv := server.NewMCPServer(mock)

	ctx := context.Background()
	session, err := connect(ctx, srv)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "get_artifact",
		Arguments: map[string]any{
			"project_name":    "library",
			"repository_name": "nginx",
			"reference":       "latest",
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

	ctx := context.Background()
	session, err := connect(ctx, srv)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "get_vulnerabilities",
		Arguments: map[string]any{
			"project_name":    "library",
			"repository_name": "nginx",
			"reference":       "latest",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Content) == 0 {
		t.Fatal("expected content in result")
	}
}
