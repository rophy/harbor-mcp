#!/usr/bin/env bats

# LLM doc-completeness test for harbor-mcp.
#
# An AI agent is given only the harbor-mcp binary and dependency
# endpoints (Harbor, OIDC). It must read the help output to figure
# out how to configure, deploy, and use harbor-mcp.
# The test independently verifies the results — it never trusts the
# AI's self-report.
#
# Requires:
#   - E2E environment running (cd e2e && ./setup.sh)
#     (provides Harbor at :8880 and OIDC mock at :28090)
#   - claude CLI with API key
#   - harbor-mcp binary built
#   - curl, jq
#
# Run: bats test/llm/doc-completeness.bats

HARBOR_URL="${HARBOR_URL:-http://localhost:8880}"
HARBOR_ADMIN_USER="${HARBOR_ADMIN_USER:-admin}"
HARBOR_ADMIN_PASS="${HARBOR_ADMIN_PASS:-Harbor12345}"
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
  export RESULT_FILE="${LOG_DIR}/result-${TIMESTAMP}.json"

  command -v claude >/dev/null 2>&1 || skip "claude CLI not found"
  command -v jq >/dev/null 2>&1 || skip "jq not found"

  # Verify dependencies are running
  curl -sf "${HARBOR_URL}/api/v2.0/ping" > /dev/null 2>&1 \
    || skip "Harbor not running at ${HARBOR_URL}"
  curl -sf "${OIDC_ISSUER_URL}/.well-known/openid-configuration" > /dev/null 2>&1 \
    || skip "OIDC provider not running at ${OIDC_ISSUER_URL}"

  # Build the binary
  export BINARY="${BATS_TEST_DIRNAME}/../../harbor-mcp"
  go build -o "${BINARY}" ./cmd/harbor-mcp/
}

teardown_file() {
  # Kill any harbor-mcp process the AI may have started
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
    Admin credentials: ${HARBOR_ADMIN_USER} / ${HARBOR_ADMIN_PASS}

  OIDC provider:
    Issuer URL: ${OIDC_ISSUER_URL}
    Client ID: ${OIDC_CLIENT_ID}
    Client secret: ${OIDC_CLIENT_SECRET}
    (auto-approves all auth requests, no login page)

Your task:
1. Run the binary to read its documentation
2. Create a Harbor robot account for harbor-mcp (following the docs)
3. Configure and start harbor-mcp on port 18080 (background process)
4. Verify it is running by checking its OAuth discovery endpoint
5. Connect to harbor-mcp as an MCP client:
   a. Register a dynamic OAuth client
   b. Complete the OAuth flow to get an access token
   c. Call the 'list_projects' tool
   d. Call the 'list_repositories' tool for the 'library' project
6. Write results to ${RESULT_FILE} as JSON:
   {
     "list_projects": <raw tool result>,
     "list_repositories": <raw tool result>
   }

Rules:
- Figure out EVERYTHING from the binary's help output
- Do NOT read any source code, test files, or docker-compose files
- Do NOT read any files in this repository except the binary itself
- If documentation is unclear or missing information, note gaps in ${GAPS_FILE}
- The OIDC provider's authorize endpoint auto-redirects (no login page)
  so follow redirects manually with curl to capture auth codes
- Use SERVER_BASE_URL=http://localhost:18080 when configuring harbor-mcp
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

@test "result file exists and is valid JSON" {
  [ -f "${RESULT_FILE}" ]
  run jq empty "${RESULT_FILE}"
  [ "$status" -eq 0 ]
}

@test "list_projects returned the library project" {
  run jq -r '.list_projects' "${RESULT_FILE}"
  [ "$status" -eq 0 ]
  [ "$output" != "null" ]
  echo "$output" | grep -q "library"
}

@test "list_repositories found test-image" {
  run jq -r '.list_repositories' "${RESULT_FILE}"
  [ "$status" -eq 0 ]
  [ "$output" != "null" ]
  echo "$output" | grep -q "test"
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
