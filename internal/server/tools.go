package server

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rophy/harbor-mcp/internal/harbor"
)

type SearchInput struct {
	Query string `json:"query" jsonschema:"Search keyword to find projects and repositories across all of Harbor"`
}

type ListProjectsInput struct {
	Page     int    `json:"page,omitempty" jsonschema:"Page number (default 1)"`
	PageSize int    `json:"page_size,omitempty" jsonschema:"Items per page (default 10)"`
	Name     string `json:"name,omitempty" jsonschema:"Filter projects by name"`
}

type GetProjectInput struct {
	ProjectName string `json:"project_name" jsonschema:"Name of the project"`
}

type ListRepositoriesInput struct {
	ProjectName string `json:"project_name" jsonschema:"Name of the project"`
	Page        int    `json:"page,omitempty" jsonschema:"Page number (default 1)"`
	PageSize    int    `json:"page_size,omitempty" jsonschema:"Items per page (default 10)"`
	Query       string `json:"query,omitempty" jsonschema:"Filter query (e.g. name=~nginx for fuzzy match)"`
}

type ListArtifactsInput struct {
	ProjectName    string `json:"project_name" jsonschema:"Name of the project"`
	RepositoryName string `json:"repository_name" jsonschema:"Name of the repository"`
	Page           int    `json:"page,omitempty" jsonschema:"Page number (default 1)"`
	PageSize       int    `json:"page_size,omitempty" jsonschema:"Items per page (default 10)"`
	Query          string `json:"query,omitempty" jsonschema:"Filter query (e.g. tags=~v1 for fuzzy tag match, tags=nil for untagged)"`
}

type ArtifactRefInput struct {
	ProjectName    string `json:"project_name" jsonschema:"Name of the project"`
	RepositoryName string `json:"repository_name" jsonschema:"Name of the repository"`
	Reference      string `json:"reference" jsonschema:"Tag name or digest (e.g. latest or sha256:abc...)"`
}

func toTextResult(v any) (*mcp.CallToolResult, any, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling result: %w", err)
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
	}, nil, nil
}

func searchHandler(client harbor.Client) func(context.Context, *mcp.CallToolRequest, SearchInput) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, input SearchInput) (*mcp.CallToolResult, any, error) {
		result, err := client.Search(ctx, input.Query)
		if err != nil {
			return nil, nil, fmt.Errorf("searching: %w", err)
		}
		return toTextResult(result)
	}
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
			Page: input.Page, PageSize: input.PageSize, Query: input.Query,
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
			Page: input.Page, PageSize: input.PageSize, Query: input.Query,
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
