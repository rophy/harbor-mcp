#!/usr/bin/env bats

# LLM doc-completeness test for harbor-mcp.
#
# An AI agent is given a container image and dependency endpoints.
# It must run the image to read the help output, then figure out how
# to deploy harbor-mcp and connect an MCP client (opencode).
# The test independently verifies the results — it never trusts the
# AI's self-report.
#
# Requires:
#   - Docker (for Harbor + OIDC mock + building the image)
#   - claude CLI with API key
#   - opencode CLI
#   - curl, jq
#
# Run: bats test/llm/doc-completeness.bats

HARBOR_URL="${HARBOR_URL:-http://localhost:8880}"
HARBOR_ADMIN_USER="${HARBOR_ADMIN_USER:-admin}"
HARBOR_ADMIN_PASS="${HARBOR_ADMIN_PASS:-Harbor12345}"
OIDC_ISSUER_URL="${OIDC_ISSUER_URL:-http://localhost:28090}"
OIDC_CLIENT_ID="${OIDC_CLIENT_ID:-harbor-mcp}"
OIDC_CLIENT_SECRET="${OIDC_CLIENT_SECRET:-test-secret}"

IMAGE_NAME="harbor-mcp:llm-test"
OPENCODE_CONFIG="${HOME}/.config/opencode/opencode.jsonc"
OPENCODE_AUTH="${HOME}/.local/share/opencode/mcp-auth.json"

E2E_DIR="${BATS_TEST_DIRNAME}/../../e2e"
ENV_FILE="${E2E_DIR}/.env"

ensure_infra() {
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
  curl -sf -u "${HARBOR_ADMIN_USER}:${HARBOR_ADMIN_PASS}" \
    -H "Content-Type: application/json" \
    -X POST "${HARBOR_URL}/api/v2.0/projects" \
    -d '{"project_name":"library","public":true}' > /dev/null 2>&1 || true
}

clean_opencode() {
  if [ -f "$OPENCODE_CONFIG" ]; then
    local tmp
    tmp=$(jq 'del(.mcp["harbor-mcp"])' "$OPENCODE_CONFIG" 2>/dev/null)
    if [ -n "$tmp" ]; then
      echo "$tmp" > "$OPENCODE_CONFIG"
    fi
  fi
  if [ -f "$OPENCODE_AUTH" ]; then
    local tmp
    tmp=$(jq 'del(.["harbor-mcp"])' "$OPENCODE_AUTH" 2>/dev/null)
    if [ -n "$tmp" ]; then
      echo "$tmp" > "$OPENCODE_AUTH"
    fi
  fi
}

setup_file() {
  export LOG_DIR="${BATS_TEST_DIRNAME}/logs"
  mkdir -p "$LOG_DIR"

  local TIMESTAMP
  TIMESTAMP=$(date +%Y%m%d-%H%M%S)
  export GAPS_FILE="${LOG_DIR}/gaps-${TIMESTAMP}.txt"
  export CLAUDE_LOG="${LOG_DIR}/claude-${TIMESTAMP}.log"

  command -v claude >/dev/null 2>&1 || skip "claude CLI not found"
  command -v opencode >/dev/null 2>&1 || skip "opencode CLI not found"
  command -v jq >/dev/null 2>&1 || skip "jq not found"
  command -v docker >/dev/null 2>&1 || skip "docker not found"

  # Clean up port 18080 from any previous run
  docker ps -q --filter "publish=18080" | xargs -r docker rm -f 2>/dev/null || true
  fuser -k 18080/tcp 2>/dev/null || true
  sleep 1
  if curl -sf http://localhost:18080/ > /dev/null 2>&1; then
    echo "ERROR: port 18080 is still in use after cleanup" >&2
    return 1
  fi

  ensure_infra
  ensure_test_project
  ensure_robot_account
  clean_opencode

  # shellcheck disable=SC1090
  source "$ENV_FILE"
  export HARBOR_ROBOT_NAME HARBOR_ROBOT_SECRET

  # Build the container image
  local REPO_ROOT="${BATS_TEST_DIRNAME}/../.."
  echo "Building container image ${IMAGE_NAME}..." >&3
  docker build -t "${IMAGE_NAME}" -f "${REPO_ROOT}/Dockerfile" "${REPO_ROOT}" > /dev/null 2>&1
}

teardown_file() {
  docker ps -q --filter "publish=18080" | xargs -r docker rm -f 2>/dev/null || true
  fuser -k 18080/tcp 2>/dev/null || true
}

@test "AI deploys harbor-mcp and connects opencode" {
  local PROMPT
  PROMPT="$(cat <<PROMPT_EOF
You have a container image: ${IMAGE_NAME}

Run it to discover what it does and how to configure it.

You have the following infrastructure already running on the host:

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
1. Run the container image to read its documentation
2. Deploy harbor-mcp on port 18080 using Docker
3. Verify it is running (check the OAuth discovery endpoint)
4. Add harbor-mcp to opencode using: opencode mcp add
5. Authenticate opencode with harbor-mcp. Since there is no browser,
   you cannot use 'opencode mcp auth'. Instead:
   a. Complete the OAuth flow yourself (register client, authorize, exchange code for token)
   b. Write the token directly to ~/.local/share/opencode/mcp-auth.json:
      {
        "harbor-mcp": {
          "tokens": {
            "accessToken": "<your token>",
            "expiresAt": <unix timestamp>,
            "scope": "harbor:read"
          },
          "clientInfo": {
            "clientId": "<your client id>"
          },
          "serverUrl": "http://localhost:18080/mcp"
        }
      }
6. Verify opencode can connect: run 'timeout 10 opencode mcp list'
   and confirm harbor-mcp shows as connected

Important:
- The container needs --network host to reach Harbor and the OIDC provider
  on localhost ports, OR use host.docker.internal
- Use SERVER_BASE_URL=http://localhost:18080 when configuring harbor-mcp

Rules:
- Figure out harbor-mcp configuration from the container's help output ONLY
- Do NOT read any source code, test files, or docker-compose files
- Do NOT read any files in this repository
- You MUST write ${GAPS_FILE} when done. List every place where the
  documentation was unclear, incomplete, or where you had to guess.
  If the documentation was perfectly clear, write "No gaps found." to
  the file. The file must exist when you finish.
PROMPT_EOF
)"

  claude -p "$PROMPT" \
    --dangerously-skip-permissions \
    --max-budget-usd 5 \
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

@test "opencode has harbor-mcp configured" {
  [ -f "$OPENCODE_CONFIG" ]
  run jq -e '.mcp["harbor-mcp"].url' "$OPENCODE_CONFIG"
  [ "$status" -eq 0 ]
  echo "$output" | grep -q "18080"
}

@test "opencode has valid auth token" {
  [ -f "$OPENCODE_AUTH" ]
  run jq -e '.["harbor-mcp"].tokens.accessToken' "$OPENCODE_AUTH"
  [ "$status" -eq 0 ]
  [ "$output" != "null" ]
}

@test "opencode can connect to harbor-mcp" {
  run timeout 10 opencode mcp list
  [ "$status" -eq 0 ]
  echo "$output" | grep -q "harbor-mcp"
  echo "$output" | grep -q "connected"
}

@test "gaps file was written" {
  [ -f "${GAPS_FILE}" ]
}

@test "documentation gaps report" {
  if [ -f "${GAPS_FILE}" ] && [ -s "${GAPS_FILE}" ]; then
    echo "=== Gaps file contents ==="
    cat "${GAPS_FILE}"
    echo "========================="
    # Fail if there are real gaps (not just "no gaps found")
    if ! grep -qi "no gaps" "${GAPS_FILE}"; then
      echo "Documentation gaps found — review and fix README"
      return 1
    fi
  fi
}
