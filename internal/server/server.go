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
