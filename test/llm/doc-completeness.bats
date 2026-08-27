#!/usr/bin/env bats

# LLM doc-completeness test for harbor-mcp.
#
# An AI agent is given the harbor-mcp binary and dependency endpoints.
# It must read the help output to figure out how to configure and
# deploy harbor-mcp. The test independently verifies the server is
# running — it never trusts the AI's self-report.
#
# Requires:
#   - E2E environment running (cd e2e && ./setup.sh)
#     (provides Harbor at :8880, OIDC mock at :28090, robot account)
#   - claude CLI with API key
#   - curl, jq
#
# Run: bats test/llm/doc-completeness.bats

HARBOR_URL="${HARBOR_URL:-http://localhost:8880}"
OIDC_ISSUER_URL="${OIDC_ISSUER_URL:-http://localhost:28090}"
OIDC_CLIENT_ID="${OIDC_CLIENT_ID:-harbor-mcp}"
OIDC_CLIENT_SECRET="${OIDC_CLIENT_SECRET:-test-secret}"

setup_file() {
  export LOG_DIR="${BATS_TEST_DIRNAME}/logs"
  mkdir -p "$LOG_DIR"

  local TIMESTAMP
  TIMESTAMP=$(date +%Y%m%d-%H%M%S)
  export GAPS_FILE="${LOG_DIR}/gaps-${TIMESTAMP}.txt"
  export CLAUDE_LOG="${LOG_DIR}/claude-${TIMESTAMP}.log"

  command -v claude >/dev/null 2>&1 || skip "claude CLI not found"
  command -v jq >/dev/null 2>&1 || skip "jq not found"

  # Verify dependencies are running
  curl -sf "${HARBOR_URL}/api/v2.0/ping" > /dev/null 2>&1 \
    || skip "Harbor not running at ${HARBOR_URL}"
  curl -sf "${OIDC_ISSUER_URL}/.well-known/openid-configuration" > /dev/null 2>&1 \
    || skip "OIDC provider not running at ${OIDC_ISSUER_URL}"

  # Read robot credentials from e2e .env (created by setup.sh)
  local ENV_FILE="${BATS_TEST_DIRNAME}/../../e2e/.env"
  [ -f "$ENV_FILE" ] || skip "e2e/.env not found — run 'cd e2e && ./setup.sh' first"
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

Your task:
1. Run the binary to read its documentation
2. Configure and start harbor-mcp on port 18080 (background process)
3. Verify it is running and healthy

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
