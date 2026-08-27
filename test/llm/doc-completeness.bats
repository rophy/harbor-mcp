#!/usr/bin/env bats

# LLM doc-completeness test for harbor-mcp.
#
# An AI agent is given the harbor-mcp binary and dependency endpoints.
# It must read the help output to figure out how to configure and
# deploy harbor-mcp. The test independently verifies the server is
# running — it never trusts the AI's self-report.
#
# Requires:
#   - Docker (for Harbor + OIDC mock)
#   - claude CLI with API key
#   - curl, jq
#
# Run: bats test/llm/doc-completeness.bats

HARBOR_URL="${HARBOR_URL:-http://localhost:8880}"
HARBOR_ADMIN_USER="${HARBOR_ADMIN_USER:-admin}"
HARBOR_ADMIN_PASS="${HARBOR_ADMIN_PASS:-Harbor12345}"
OIDC_ISSUER_URL="${OIDC_ISSUER_URL:-http://localhost:28090}"
OIDC_CLIENT_ID="${OIDC_CLIENT_ID:-harbor-mcp}"
OIDC_CLIENT_SECRET="${OIDC_CLIENT_SECRET:-test-secret}"

E2E_DIR="${BATS_TEST_DIRNAME}/../../e2e"
ENV_FILE="${E2E_DIR}/.env"

ensure_infra() {
  # Start Harbor + OIDC mock if not already running (skip harbor-mcp)
  if ! curl -sf "${HARBOR_URL}/api/v2.0/ping" > /dev/null 2>&1; then
    echo "Starting Harbor + OIDC mock..." >&3
    docker compose -f "${E2E_DIR}/docker-compose.yml" up -d \
      harbor-nginx oidc-mock

    for i in $(seq 1 120); do
      if curl -sf "${HARBOR_URL}/api/v2.0/ping" > /dev/null 2>&1; then
        break
      fi
      if [ "$i" -eq 120 ]; then
        echo "ERROR: Harbor did not become healthy within 120s" >&2
        return 1
      fi
      sleep 1
    done
  fi
}

ensure_robot_account() {
  # Create robot account if .env doesn't exist
  if [ -f "$ENV_FILE" ]; then
    return 0
  fi

  echo "Creating robot account..." >&3
  local ROBOT_RESPONSE
  ROBOT_RESPONSE=$(curl -sf -u "${HARBOR_ADMIN_USER}:${HARBOR_ADMIN_PASS}" \
    -H "Content-Type: application/json" \
    -X POST "${HARBOR_URL}/api/v2.0/robots" \
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
    }')

  local ROBOT_NAME ROBOT_SECRET
  ROBOT_NAME=$(echo "$ROBOT_RESPONSE" | jq -r '.name')
  ROBOT_SECRET=$(echo "$ROBOT_RESPONSE" | jq -r '.secret')

  cat > "$ENV_FILE" <<EOF
HARBOR_ROBOT_NAME=${ROBOT_NAME}
HARBOR_ROBOT_SECRET=${ROBOT_SECRET}
EOF
}

ensure_test_project() {
  # Create library project if it doesn't exist
  curl -sf -u "${HARBOR_ADMIN_USER}:${HARBOR_ADMIN_PASS}" \
    -H "Content-Type: application/json" \
    -X POST "${HARBOR_URL}/api/v2.0/projects" \
    -d '{"project_name":"library","public":true}' > /dev/null 2>&1 || true
}

setup_file() {
  export LOG_DIR="${BATS_TEST_DIRNAME}/logs"
  mkdir -p "$LOG_DIR"

  local TIMESTAMP
  TIMESTAMP=$(date +%Y%m%d-%H%M%S)
  export GAPS_FILE="${LOG_DIR}/gaps-${TIMESTAMP}.txt"
  export CLAUDE_LOG="${LOG_DIR}/claude-${TIMESTAMP}.log"

  command -v claude >/dev/null 2>&1 || skip "claude CLI not found"
  command -v jq >/dev/null 2>&1 || skip "jq not found"
  command -v docker >/dev/null 2>&1 || skip "docker not found"

  ensure_infra
  ensure_test_project
  ensure_robot_account

  # shellcheck disable=SC1090
  source "$ENV_FILE"
  export HARBOR_ROBOT_NAME HARBOR_ROBOT_SECRET

  # Build the binary
  export BINARY="${BATS_TEST_DIRNAME}/../../harbor-mcp"
  go build -o "${BINARY}" ./cmd/harbor-mcp/
}

teardown_file() {
  pkill -f "harbor-mcp serve" 2>/dev/null || true
}

@test "AI deploys harbor-mcp from help output alone" {
  local PROMPT
  PROMPT="$(cat <<PROMPT_EOF
You have a binary at: ${BINARY}

Run it to discover what it does and how to configure it.

You have the following infrastructure already running:

  Harbor registry:
    URL: ${HARBOR_URL}
    Robot account: ${HARBOR_ROBOT_NAME} / ${HARBOR_ROBOT_SECRET}

  OIDC provider:
    Issuer URL: ${OIDC_ISSUER_URL}
    Client ID: ${OIDC_CLIENT_ID}
    Client secret: ${OIDC_CLIENT_SECRET}

  OIDC mock login (no human involved):
    The OIDC authorize endpoint shows a user-picker HTML page.
    To log in programmatically, POST to ${OIDC_ISSUER_URL}/authorize/callback
    with form-encoded fields: sub=alice, client_id, redirect_uri, state, nonce
    (use the same values from the authorize URL query params).
    It returns a 302 redirect with the authorization code.

Your task:
1. Run the binary to read its documentation
2. Configure and start harbor-mcp on port 18080 (background process)
3. Verify it is running and working end-to-end (complete the OAuth flow
   and confirm you can reach the MCP endpoint with a valid token)

Rules:
- Figure out configuration from the binary's help output ONLY
- Do NOT read any source code, test files, or docker-compose files
- Do NOT read any files in this repository except the binary output
- If documentation is unclear or missing information, note gaps in ${GAPS_FILE}
- Use SERVER_BASE_URL=http://localhost:18080 when configuring harbor-mcp
PROMPT_EOF
)"

  claude -p "$PROMPT" \
    --dangerously-skip-permissions \
    --max-budget-usd 3 \
    --allowedTools "Bash Read Write" \
    2>&1 | tee "${CLAUDE_LOG}"
}

# --- Independent verification ---
# These tests verify actual state, not the AI's claims.

@test "harbor-mcp is running on port 18080" {
  run curl -sf http://localhost:18080/.well-known/oauth-authorization-server
  [ "$status" -eq 0 ]
  echo "$output" | jq -e '.authorization_endpoint' > /dev/null
}

@test "OAuth metadata has correct base URL" {
  run curl -sf http://localhost:18080/.well-known/oauth-authorization-server
  [ "$status" -eq 0 ]
  echo "$output" | jq -e '.authorization_endpoint | startswith("http://localhost:18080")' > /dev/null
}

@test "dynamic client registration works" {
  run curl -sf -X POST http://localhost:18080/register \
    -H "Content-Type: application/json" \
    -d '{"redirect_uris":["http://localhost:19999/callback"]}'
  [ "$status" -eq 0 ]
  echo "$output" | jq -e '.client_id' > /dev/null
}

@test "MCP endpoint is protected" {
  run curl -s -o /dev/null -w "%{http_code}" http://localhost:18080/mcp
  [ "$output" = "401" ]
}

@test "documentation gaps report" {
  if [ -f "${GAPS_FILE}" ] && [ -s "${GAPS_FILE}" ]; then
    echo "=== Documentation gaps found ==="
    cat "${GAPS_FILE}"
    echo "================================"
  else
    echo "No documentation gaps reported"
  fi
}
