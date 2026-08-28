# harbor-mcp

An [MCP](https://modelcontextprotocol.io/) server that exposes [Harbor](https://goharbor.io/) container registry operations as tools. Connects AI assistants (Claude, etc.) to your Harbor instance so they can browse projects, repositories, artifacts, and vulnerability reports.

## Tools

| Tool | Description |
|------|-------------|
| `search` | Search across all projects and repositories by keyword |
| `list_projects` | List projects (with optional name filter and pagination) |
| `get_project` | Get details of a specific project |
| `list_repositories` | List repositories in a project (supports `query` filter, e.g. `name=~nginx`) |
| `list_artifacts` | List artifacts (images) in a repository (supports `query` filter, e.g. `tags=~v1`, `tags=nil`) |
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
      HARBOR_ROBOT_NAME: 'robot$mcp-reader'
      HARBOR_ROBOT_SECRET: <robot-secret>
      OAUTH_UPSTREAM_ISSUER: https://idp.example.com/realms/main
      OAUTH_UPSTREAM_CLIENT_ID: harbor-mcp
      OAUTH_UPSTREAM_CLIENT_SECRET: <client-secret>
      SERVER_BASE_URL: https://harbor-mcp.example.com
      # Set this if the OIDC issuer uses an internal hostname not reachable from the browser:
      # OAUTH_UPSTREAM_EXTERNAL_URL: https://idp-external.example.com/realms/main
    volumes:
      - harbor-mcp-data:/data

volumes:
  harbor-mcp-data:
```

**OIDC provider setup:** The upstream IDP must have `SERVER_BASE_URL/auth/callback` (e.g. `https://harbor-mcp.example.com/auth/callback`) registered as an allowed redirect URI for the `OAUTH_UPSTREAM_CLIENT_ID` client.

The container runs the `serve` subcommand by default. Use `docker run <image> help` to view the full documentation.

The `/data` volume stores the SQLite database containing registered OAuth clients and authorization state. Without a persistent volume, all client registrations and tokens are lost on container restart — MCP clients will need to re-register and re-authenticate.

**Docker networking:** harbor-mcp must be able to reach both the Harbor API (`HARBOR_URL`) and the OIDC provider's token/JWKS endpoints (from the OIDC discovery document).

- **Same Docker network (recommended):** put harbor-mcp on the same network as Harbor and the OIDC provider so it can resolve their internal hostnames. Use internal ports (e.g. `http://harbor-nginx:8080` rather than the host-mapped port).
- **Host network (`--network host`):** only works if the OIDC provider's discovery document returns `localhost`-reachable URLs for `token_endpoint` and `jwks_uri`. If the discovery document returns internal Docker hostnames (e.g. `http://oidc-mock:8080`), server-side token exchange will fail — use the same Docker network instead.

### Connect an MCP Client

The MCP endpoint is at `/mcp` using Streamable HTTP transport with OAuth 2.1 authentication.

**Claude Code:**
```bash
claude mcp add harbor-mcp --transport http https://harbor-mcp.example.com/mcp
```

**OpenCode:**
```bash
opencode mcp add harbor-mcp --url https://harbor-mcp.example.com/mcp
```

**Other MCP clients:** add the server URL `https://harbor-mcp.example.com/mcp` with HTTP transport. The client handles the OAuth login flow automatically via the `.well-known/oauth-authorization-server` discovery endpoint.

## Configuration

| Variable | Required | Description |
|----------|----------|-------------|
| `HARBOR_URL` | yes | Harbor API base URL |
| `HARBOR_ROBOT_NAME` | yes | Robot account username (e.g. `robot$mcp-reader` — see below) |
| `HARBOR_ROBOT_SECRET` | yes | Robot account secret |
| `OAUTH_UPSTREAM_ISSUER` | yes | OIDC issuer URL (must serve `/.well-known/openid-configuration`) |
| `OAUTH_UPSTREAM_CLIENT_ID` | yes | Client ID registered with the upstream IDP (must allow redirect to `SERVER_BASE_URL/auth/callback`) |
| `OAUTH_UPSTREAM_CLIENT_SECRET` | yes | Client secret for the upstream IDP |
| `SERVER_BASE_URL` | yes | Public URL of this server (used in OAuth redirects) |
| `SERVER_PORT` | no | Listen port (default: `8080`) |
| `DATA_DIR` | no | Directory for SQLite database (default: `/data`) |
| `OAUTH_SIGNING_KEY` | no | PEM-encoded RSA private key for JWT signing (auto-generated if unset) |
| `OAUTH_UPSTREAM_EXTERNAL_URL` | no | Browser-reachable URL for upstream IDP (see below) |
| `TLS_SKIP_VERIFY` | no | Skip TLS certificate verification for Harbor and OIDC endpoints (default: `false`) |
| `RATE_LIMIT_ENABLED` | no | Enable per-user rate limiting (default: `false`) |
| `RATE_LIMIT_RPM` | no | Requests per minute per user (default: `60`) |
| `RATE_LIMIT_BURST` | no | Extra burst allowance on top of RPM (default: `20`) |

### OAUTH_UPSTREAM_EXTERNAL_URL

Set this when the OIDC issuer URL is not reachable from the user's browser — typically in Docker/Kubernetes where the issuer advertises an internal hostname (e.g., `http://keycloak:8080`). harbor-mcp rewrites browser-facing redirects to use this external URL instead.

**Note:** harbor-mcp performs server-side token exchange and key verification using endpoint URLs from the upstream OIDC discovery document (`/.well-known/openid-configuration`). This variable only rewrites browser redirects — it does not affect server-side calls. harbor-mcp must be able to reach the `token_endpoint` and `jwks_uri` hostnames returned by the discovery document. If those return internal hostnames (e.g. `http://keycloak:8080`), ensure harbor-mcp has network access to them (e.g. same Docker network).

Example: issuer is `http://keycloak:8080` (internal), external URL is `https://keycloak.example.com`.

### Harbor Robot Account

Create a system-level robot account with read-only permissions. The API returns the full robot name (prefixed with `robot$`) and a generated secret — use those as `HARBOR_ROBOT_NAME` and `HARBOR_ROBOT_SECRET`.

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

The response contains `{"name": "robot$mcp-reader", "secret": "..."}`. Use the full name including the `robot$` prefix as `HARBOR_ROBOT_NAME`. Harbor always prefixes robot account names with `robot$` — if you created a robot named `mcp-reader`, the login username is `robot$mcp-reader`. If you have a pre-existing robot account, check whether the name already includes the `robot$` prefix and use it as-is.

## Headless / CI Authentication

MCP clients normally handle the OAuth flow with a browser. For headless environments (CI/CD, scripts), you can complete the flow manually.

1. **Discover endpoints:** `GET /.well-known/oauth-authorization-server` returns `registration_endpoint`, `authorization_endpoint`, and `token_endpoint`.
2. **Register a client:** `POST /register` with `{"redirect_uris": ["http://localhost:0/callback"], "client_name": "my-client"}`. Returns `client_id`.
3. **Authorize:** `GET /authorize?client_id=<id>&redirect_uri=<uri>&response_type=code&code_challenge=<S256 challenge>&code_challenge_method=S256&state=<state>&nonce=<random>&scope=harbor:read`. The `state` must be at least 8 characters. The `nonce` parameter is accepted but not used by harbor-mcp — include it if your OIDC provider requires it. This returns a 302 redirect to the upstream OIDC login page.
4. **Complete OIDC login:** Follow the redirect to your OIDC provider and authenticate. The provider redirects back to harbor-mcp's `/auth/callback` with the `state` and an authorization code. harbor-mcp then redirects to your `redirect_uri` with a `code` parameter. In headless environments, do not follow redirects automatically — capture each redirect to extract the `code` from the final redirect URL.
5. **Exchange code for token:** `POST /token` with `grant_type=authorization_code&code=<code>&redirect_uri=<uri>&client_id=<id>&code_verifier=<verifier>`. Returns an access token.

harbor-mcp tracks the PKCE challenge and authorization state server-side using the `state` parameter — no cookies are required. If `OAUTH_UPSTREAM_EXTERNAL_URL` is set, harbor-mcp rewrites the OIDC redirect to use the external URL.

## Monitoring

Prometheus metrics are exposed at `GET /metrics`. Tracked metrics include HTTP request count, request duration, and rate limit hits.

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
