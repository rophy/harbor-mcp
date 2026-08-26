# Harbor MCP Server — Design Spec

## Overview

An MCP server for browsing Docker images in Harbor, implemented in Go. The server exposes read-only tools over streamable-HTTP transport, with OAuth 2.1 authentication built into the server using ory/fosite.

## Architecture

```
MCP Client (e.g. Claude Code)
    │
    │  OAuth 2.1 Authorization Code + PKCE
    │  (against MCP server's own /authorize, /token, /register)
    ▼
harbor-mcp (Go, streamable-http)
    ├── OAuth 2.1 Authorization Server (fosite)
    │     ├── /.well-known/oauth-authorization-server
    │     ├── /authorize → proxies to upstream OIDC provider
    │     ├── /auth/callback ← receives upstream callback
    │     ├── /token (issues own JWTs)
    │     └── /register (Dynamic Client Registration)
    ├── MCP Server (go-sdk)
    │     └── /mcp (streamable-http, bearer token required)
    └── Harbor API v2 Client
          └── basic auth with robot account credentials
```

### Two-tier auth flow

1. MCP client discovers OAuth metadata via `/.well-known/oauth-authorization-server`
2. MCP client registers dynamically via `/register` (DCR)
3. MCP client initiates OAuth 2.1 Authorization Code + PKCE flow against `/authorize`
4. Server redirects user to upstream OIDC provider (e.g. Keycloak) for authentication
5. OIDC provider redirects back to `/auth/callback` with auth code
6. Server exchanges code for upstream tokens, stores them
7. Server issues its own JWT to the MCP client
8. MCP client presents JWT as Bearer token on `/mcp` requests
9. Server validates JWT via fosite, then calls Harbor API with robot account credentials

## Dependencies

| Dependency | Purpose | Version |
|---|---|---|
| `github.com/modelcontextprotocol/go-sdk` | MCP server framework, streamable-HTTP, tool registration | latest |
| `github.com/ory/fosite` | OAuth 2.1 authorization server (auth code, PKCE, token issuance, refresh) | v0.47+ |
| `net/http` (stdlib) | HTTP server, routing | stdlib |

No Harbor client library — Harbor v2 REST API is called directly via `net/http`. The read-only scope (6 endpoints) doesn't justify an external dependency.

## MCP Tools (read-only)

### `list_projects`
- **Description:** List Harbor projects accessible to the configured robot account
- **Input:** `page` (int, optional), `page_size` (int, optional), `name` (string, optional — filter by name)
- **Output:** List of projects with name, project_id, repo_count, creation_time, public status

### `get_project`
- **Description:** Get details of a specific project
- **Input:** `project_name` (string, required)
- **Output:** Project metadata including name, project_id, repo_count, metadata (public, auto_scan, severity), creation_time

### `list_repositories`
- **Description:** List repositories in a project
- **Input:** `project_name` (string, required), `page` (int, optional), `page_size` (int, optional)
- **Output:** List of repositories with name, artifact_count, pull_count, creation_time

### `list_artifacts`
- **Description:** List artifacts (images) in a repository
- **Input:** `project_name` (string, required), `repository_name` (string, required), `page` (int, optional), `page_size` (int, optional)
- **Output:** List of artifacts with digest, tags, size, push_time, pull_time, scan_overview (summary)

### `get_artifact`
- **Description:** Get detailed information about a specific artifact
- **Input:** `project_name` (string, required), `repository_name` (string, required), `reference` (string, required — tag or digest)
- **Output:** Full artifact details including digest, tags, size, push_time, labels, scan_overview, extra_attrs (os, architecture)

### `get_vulnerabilities`
- **Description:** Get vulnerability report for an artifact
- **Input:** `project_name` (string, required), `repository_name` (string, required), `reference` (string, required — tag or digest)
- **Output:** Vulnerability report with summary (critical/high/medium/low counts) and list of CVEs with severity, package, version, fix_version, description

## OAuth 2.1 Implementation

### Fosite configuration
- Grant types: Authorization Code only (no implicit, no ROPC — OAuth 2.1)
- PKCE: enforced for all clients (S256 only)
- Token format: signed JWTs (RS256 — asymmetric so clients can verify without the signing key)
- Token lifetimes: access token 1h, refresh token 24h
- Storage: in-memory (sufficient for single-instance deployment)

### Endpoints
- `GET /.well-known/oauth-authorization-server` — server metadata (RFC 8414)
- `POST /register` — Dynamic Client Registration (RFC 7591), stores client_id + redirect_uris in memory
- `GET /authorize` — starts auth flow, redirects to upstream OIDC provider
- `GET /auth/callback` — receives upstream OIDC callback, exchanges code, issues JWT
- `POST /token` — token exchange (auth code → JWT) and refresh

### Upstream OIDC proxy
The server proxies user authentication to a configured upstream OIDC provider:
- `OAUTH_UPSTREAM_ISSUER` — OIDC provider issuer URL (e.g. `https://keycloak.example.com/realms/harbor`)
- `OAUTH_UPSTREAM_CLIENT_ID` — pre-registered client ID at the OIDC provider
- `OAUTH_UPSTREAM_CLIENT_SECRET` — client secret

The server uses OIDC discovery (`/.well-known/openid-configuration`) to find the upstream authorization and token endpoints.

## Configuration

All via environment variables:

### Harbor connection
- `HARBOR_URL` — Harbor instance URL (e.g. `https://harbor.example.com`)
- `HARBOR_ROBOT_NAME` — robot account name
- `HARBOR_ROBOT_SECRET` — robot account secret

### OAuth / OIDC
- `OAUTH_UPSTREAM_ISSUER` — upstream OIDC provider issuer URL
- `OAUTH_UPSTREAM_CLIENT_ID` — client ID at the OIDC provider
- `OAUTH_UPSTREAM_CLIENT_SECRET` — client secret
- `OAUTH_SIGNING_KEY` — key for signing JWTs (generated if not provided)
- `SERVER_BASE_URL` — public URL of this MCP server (for callback URLs)

### Server
- `SERVER_PORT` — HTTP listen port (default: 8080)

## Project Structure

```
cmd/harbor-mcp/
    main.go                 # entry point, wires everything together
internal/
    server/
        server.go           # MCP server setup, tool registration
        tools.go            # tool handler implementations
    harbor/
        client.go           # Harbor v2 API client (net/http, basic auth)
        types.go            # Harbor API response types
    auth/
        oauth.go            # fosite setup, OAuth 2.1 AS configuration
        handlers.go         # /authorize, /token, /register, /callback HTTP handlers
        storage.go          # in-memory client + token storage for fosite
        upstream.go         # upstream OIDC provider proxy logic
docker-compose.yml          # Harbor + PostgreSQL + Redis + Keycloak for testing
go.mod
go.sum
```

## Docker-Compose Test Environment

```yaml
services:
  # Harbor core
  harbor-core:
    image: goharbor/harbor-core:v2.12.0
  harbor-portal:
    image: goharbor/harbor-portal:v2.12.0
  harbor-registry:
    image: goharbor/registry-photon:v2.12.0
  harbor-db:
    image: goharbor/harbor-db:v2.12.0
  harbor-redis:
    image: goharbor/redis-photon:v2.12.0

  # OIDC Provider
  keycloak:
    image: quay.io/keycloak/keycloak:26.0
    # Pre-configured realm with:
    # - harbor-mcp client (for MCP server upstream auth)
    # - Harbor OIDC client (for Harbor OIDC login)
    # - Test user

  # MCP Server (built from source)
  harbor-mcp:
    build: .
    environment:
      HARBOR_URL: http://harbor-core:8080
      HARBOR_ROBOT_NAME: robot$mcp-reader
      HARBOR_ROBOT_SECRET: <generated>
      OAUTH_UPSTREAM_ISSUER: http://keycloak:8080/realms/harbor
      OAUTH_UPSTREAM_CLIENT_ID: harbor-mcp
      OAUTH_UPSTREAM_CLIENT_SECRET: <configured>
      SERVER_BASE_URL: http://localhost:8080
```

Note: Harbor's docker-compose setup is complex (10+ containers). We'll use the official Harbor installer's `docker-compose.yml` as a base and add Keycloak + harbor-mcp on top.

## Testing Strategy

### Unit tests
- Tool handlers with mocked Harbor client (interface-based)
- OAuth flow logic with mocked upstream OIDC
- JWT issuance and validation

### Integration tests
- Full OAuth 2.1 flow against the running server (programmatic client)
- Harbor API calls against docker-compose Harbor instance
- End-to-end: authenticate via OAuth → call MCP tools → verify Harbor data

## Out of Scope (future phases)

- Write operations (create project, delete artifact, etc.)
- Additional tools (users, replication, webhooks, robot accounts, labels)
- stdio transport
- Persistent token storage (database-backed)
- Multi-instance / HA deployment
- TLS termination (assumed handled by reverse proxy)
