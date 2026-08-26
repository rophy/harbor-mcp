# harbor-mcp

An [MCP](https://modelcontextprotocol.io/) server that exposes [Harbor](https://goharbor.io/) container registry operations as tools. Connects AI assistants (Claude, etc.) to your Harbor instance so they can browse projects, repositories, artifacts, and vulnerability reports.

## Tools

| Tool | Description |
|------|-------------|
| `list_projects` | List projects (with optional name filter and pagination) |
| `get_project` | Get details of a specific project |
| `list_repositories` | List repositories in a project |
| `list_artifacts` | List artifacts (images) in a repository |
| `get_artifact` | Get details of a specific artifact by tag or digest |
| `get_vulnerabilities` | Get vulnerability scan report for an artifact |

## Auth

harbor-mcp implements OAuth 2.1 with PKCE as required by the MCP spec. Users authenticate via an upstream OIDC provider (Keycloak, Dex, etc.) — harbor-mcp acts as an OAuth authorization server that delegates identity to your existing IDP.

Harbor API access uses a robot account (read-only), configured separately from user auth.

## Quick Start

### Docker Compose

```yaml
services:
  harbor-mcp:
    image: ghcr.io/rophy/harbor-mcp:latest
    ports:
      - "8080:8080"
    environment:
      HARBOR_URL: https://harbor.example.com
      HARBOR_ROBOT_NAME: robot$mcp-reader
      HARBOR_ROBOT_SECRET: <robot-secret>
      OAUTH_UPSTREAM_ISSUER: https://idp.example.com/realms/main
      OAUTH_UPSTREAM_CLIENT_ID: harbor-mcp
      OAUTH_UPSTREAM_CLIENT_SECRET: <client-secret>
      SERVER_BASE_URL: https://harbor-mcp.example.com
    volumes:
      - harbor-mcp-data:/data

volumes:
  harbor-mcp-data:
```

### Claude Code

```bash
claude mcp add harbor-mcp --transport http https://harbor-mcp.example.com/mcp
```

Then use MCP tools like `list_projects`, `get_artifact`, etc. Claude Code handles the OAuth login flow automatically.

## Configuration

| Variable | Required | Description |
|----------|----------|-------------|
| `HARBOR_URL` | yes | Harbor API base URL |
| `HARBOR_ROBOT_NAME` | yes | Robot account username |
| `HARBOR_ROBOT_SECRET` | yes | Robot account secret |
| `OAUTH_UPSTREAM_ISSUER` | yes | OIDC issuer URL (must serve `/.well-known/openid-configuration`) |
| `OAUTH_UPSTREAM_CLIENT_ID` | yes | Client ID registered with the upstream IDP |
| `OAUTH_UPSTREAM_CLIENT_SECRET` | yes | Client secret for the upstream IDP |
| `SERVER_BASE_URL` | yes | Public URL of this server (used in OAuth redirects) |
| `SERVER_PORT` | no | Listen port (default: `8080`) |
| `DATA_DIR` | no | Directory for SQLite database (default: `/data`) |
| `OAUTH_SIGNING_KEY` | no | PEM-encoded RSA private key for JWT signing (auto-generated if unset) |
| `OAUTH_UPSTREAM_EXTERNAL_URL` | no | Browser-reachable URL for upstream IDP if different from issuer |

### Harbor Robot Account

Create a system-level robot account with read-only permissions:

```bash
curl -u admin:Harbor12345 -X POST https://harbor.example.com/api/v2.0/robots \
  -H "Content-Type: application/json" \
  -d '{
    "name": "mcp-reader",
    "duration": -1,
    "level": "system",
    "permissions": [{
      "namespace": "*",
      "kind": "project",
      "access": [
        {"resource": "repository", "action": "list"},
        {"resource": "repository", "action": "pull"},
        {"resource": "artifact", "action": "read"},
        {"resource": "artifact", "action": "list"},
        {"resource": "tag", "action": "list"},
        {"resource": "scan", "action": "read"}
      ]
    }]
  }'
```

## Development

```bash
# Run unit tests
go test ./...

# Run e2e tests (requires Docker)
cd e2e && ./setup.sh
go test -tags e2e ./e2e/

# Tear down
cd e2e && ./teardown.sh
```
