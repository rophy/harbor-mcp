# E2E Test Environment

Docker-compose setup for testing harbor-mcp against a real Harbor instance with oidc-mock as the upstream OIDC provider.

## Architecture

```
localhost:8080  →  harbor-mcp (MCP server + OAuth 2.1 AS)
                    ├── upstream OIDC → oidc-mock:8080
                    └── Harbor API   → harbor-nginx:8080 → harbor-core:8080
localhost:8880  →  Harbor UI/API (via nginx proxy)
localhost:8090  →  oidc-mock (user picker UI)
```

## Services

| Service | Image | Purpose |
|---------|-------|---------|
| harbor-db | goharbor/harbor-db:v2.15.2 | PostgreSQL |
| harbor-redis | goharbor/valkey-photon:v2.15.2 | Redis/Valkey |
| harbor-registry | goharbor/registry-photon:v2.15.2 | Docker registry |
| harbor-registryctl | goharbor/harbor-registryctl:v2.15.2 | Registry controller |
| harbor-core | goharbor/harbor-core:v2.15.2 | Harbor API |
| harbor-jobservice | goharbor/harbor-jobservice:v2.15.2 | Async jobs |
| harbor-portal | goharbor/harbor-portal:v2.15.2 | Web UI |
| harbor-nginx | goharbor/nginx-photon:v2.15.2 | Reverse proxy |
| oidc-mock | ghcr.io/rophy/oidc-mock | Mock OIDC provider |
| harbor-mcp | (built from source) | Our MCP server |

## Usage

```bash
# Start everything (takes ~2 minutes for Harbor to initialize)
./setup.sh

# Run e2e tests
cd .. && go test -tags e2e ./e2e/

# Tear down
./teardown.sh
```

## Config

Config files in `config/` were extracted from Harbor Helm chart v1.19.2 (Harbor v2.15.2) rendered with `helm template`. They are static and pinned to this Harbor version.

## Credentials

- Harbor admin: `admin` / `Harbor12345`
- OIDC mock users: alice (admin), bob (viewer) — no password needed, user picker UI
- Robot account: created by `setup.sh`, credentials written to `.env`
