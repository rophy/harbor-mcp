#!/usr/bin/env bats

# LLM doc-completeness test for harbor-mcp.
#
# An AI agent is given only the harbor-mcp help output and must figure
# out how to interact with an already-running harbor-mcp instance.
# The test independently verifies the results — it never trusts the
# AI's self-report.
#
# Requires:
#   - E2E environment running (cd e2e && ./setup.sh)
#   - claude CLI with API key
#   - curl, jq
#
# Run: bats test/llm/doc-completeness.bats

MCP_URL="${MCP_URL:-http://localhost:28080}"
OIDC_MOCK_URL="${OIDC_MOCK_URL:-http://localhost:28090}"

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

  # Verify e2e environment is running
  curl -sf "${MCP_URL}/.well-known/oauth-authorization-server" > /dev/null 2>&1 \
    || skip "harbor-mcp not running at ${MCP_URL} — run 'cd e2e && ./setup.sh' first"

  # Build the binary to get help output
  export HELP_OUTPUT
  HELP_OUTPUT=$(go run ./cmd/harbor-mcp/ help 2>&1)
}

@test "AI uses harbor-mcp tools from help output alone" {
  local PROMPT
  PROMPT="$(cat <<PROMPT_EOF
You have access to a running harbor-mcp server.

Here is the complete output of 'harbor-mcp help':
---
${HELP_OUTPUT}
---

The server is running at: ${MCP_URL}
The OIDC provider at ${OIDC_MOCK_URL} auto-approves all auth requests.

Your task:
Using ONLY the documentation above, figure out how to call the MCP tools
exposed by this server. You must complete the OAuth flow to get an access
token, then call MCP tools via the /mcp endpoint.

Specifically:
1. Register a dynamic OAuth client
2. Complete the OAuth authorization flow to get an access token
3. Call the 'list_projects' tool and save the result
4. Call the 'get_project' tool for the 'library' project and save the result
5. Call the 'list_repositories' tool for the 'library' project and save the result

Important details about the OIDC mock:
- Its authorize endpoint auto-redirects with a code (no login page)
- Follow redirects manually with curl -v to capture the auth code from Location headers

Write your results as JSON to ${RESULT_FILE} in this format:
{
  "list_projects": <raw tool result>,
  "get_project": <raw tool result>,
  "list_repositories": <raw tool result>
}

Rules:
- Use ONLY the help output above for figuring out the OAuth flow and MCP protocol
- Do NOT read any source code files in this repository
- Do NOT read docker-compose.yml or any e2e test files
- If you encounter documentation gaps, note them in ${GAPS_FILE}
- Use curl for HTTP requests
PROMPT_EOF
)"

  claude -p "$PROMPT" \
    --dangerously-skip-permissions \
    --max-budget-usd 3 \
    --allowedTools "Bash Read Write" \
    2>&1 | tee "${CLAUDE_LOG}"
}

# --- Independent verification ---
# These tests verify the AI produced correct results.
# They don't rely on anything the AI claimed.

@test "result file exists and is valid JSON" {
  [ -f "${RESULT_FILE}" ]
  jq empty "${RESULT_FILE}"
}

@test "list_projects returned the library project" {
  local result
  result=$(jq -r '.list_projects' "${RESULT_FILE}")
  [ "$result" != "null" ]

  echo "$result" | jq -e '.[] | select(.name == "library")' > /dev/null 2>&1 \
    || echo "$result" | grep -q "library"
}

@test "get_project returned project details" {
  local result
  result=$(jq -r '.get_project' "${RESULT_FILE}")
  [ "$result" != "null" ]

  echo "$result" | jq -e '.name == "library" or .project_id' > /dev/null 2>&1 \
    || echo "$result" | grep -q "library"
}

@test "list_repositories found test-image" {
  local result
  result=$(jq -r '.list_repositories' "${RESULT_FILE}")
  [ "$result" != "null" ]

  echo "$result" | jq -e '.[] | select(.name | contains("test"))' > /dev/null 2>&1 \
    || echo "$result" | grep -q "test"
}

@test "documentation gaps file" {
  if [ -f "${GAPS_FILE}" ] && [ -s "${GAPS_FILE}" ]; then
    echo "Documentation gaps found:"
    cat "${GAPS_FILE}"
    # Don't fail — gaps are informational, not a test failure
  else
    echo "No documentation gaps reported"
  fi
}
