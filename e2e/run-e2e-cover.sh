#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

COVDATA_DIR="$(pwd)/covdata"
COVER_COMPOSE=(-f docker-compose.yml -f docker-compose.cover.yml)

cleanup() {
  echo ""
  echo "==> Stopping harbor-mcp gracefully (flushing coverage)..."
  docker compose "${COVER_COMPOSE[@]}" stop -t 10 harbor-mcp

  echo ""
  echo "==> Generating coverage report..."
  if ls "$COVDATA_DIR"/cov*.* 1>/dev/null 2>&1; then
    go tool covdata textfmt -i="$COVDATA_DIR" -o=coverage-e2e.out
    echo "--- Coverage by function ---"
    go tool cover -func=coverage-e2e.out
    echo ""
    echo "    Coverage profile: $(pwd)/coverage-e2e.out"
    echo "    HTML report:      go tool cover -html=coverage-e2e.out -o coverage-e2e.html"
  else
    echo "    WARNING: No coverage data found in $COVDATA_DIR"
    echo "    Check that GOCOVERDIR is set and harbor-mcp was stopped gracefully"
  fi

  echo ""
  echo "==> Tearing down..."
  docker compose "${COVER_COMPOSE[@]}" down -v
  rm -f .env
}
trap cleanup EXIT

echo "==> Cleaning previous coverage data..."
rm -rf "$COVDATA_DIR"
mkdir -p "$COVDATA_DIR"

echo "==> Starting e2e environment with coverage instrumentation..."
docker compose "${COVER_COMPOSE[@]}" up -d --build

echo "==> Waiting for Harbor to be healthy..."
for i in $(seq 1 120); do
  if curl -sf "http://localhost:8880/api/v2.0/ping" > /dev/null 2>&1; then
    echo "    Harbor is ready (after ${i}s)"
    break
  fi
  if [ "$i" -eq 120 ]; then
    echo "    ERROR: Harbor did not become healthy within 120s"
    docker compose "${COVER_COMPOSE[@]}" logs harbor-core
    exit 1
  fi
  sleep 1
done

ADMIN_USER="admin"
ADMIN_PASS="Harbor12345"

echo "==> Creating test project 'library'..."
curl -sf -u "${ADMIN_USER}:${ADMIN_PASS}" \
  -H "Content-Type: application/json" \
  -X POST "http://localhost:8880/api/v2.0/projects" \
  -d '{"project_name":"library","public":true}' \
  -o /dev/null -w "    HTTP %{http_code}\n" || true

echo "==> Creating robot account 'mcp-reader'..."
ROBOT_RESPONSE=$(curl -sf -u "${ADMIN_USER}:${ADMIN_PASS}" \
  -H "Content-Type: application/json" \
  -X POST "http://localhost:8880/api/v2.0/robots" \
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

ROBOT_NAME=$(echo "$ROBOT_RESPONSE" | jq -r '.name')
ROBOT_SECRET=$(echo "$ROBOT_RESPONSE" | jq -r '.secret')
echo "    Robot created: ${ROBOT_NAME}"

printf "HARBOR_ROBOT_NAME='%s'\nHARBOR_ROBOT_SECRET='%s'\n" "$ROBOT_NAME" "$ROBOT_SECRET" > .env

echo "==> Pushing test image to Harbor..."
docker pull busybox:1.37 2>/dev/null || true
docker tag busybox:1.37 localhost:8880/library/test-image:v1
echo "${ADMIN_PASS}" | docker login localhost:8880 -u "${ADMIN_USER}" --password-stdin 2>/dev/null
docker push localhost:8880/library/test-image:v1

echo "==> Restarting harbor-mcp with robot credentials..."
docker compose "${COVER_COMPOSE[@]}" up -d harbor-mcp

echo "==> Waiting for harbor-mcp to be ready..."
for i in $(seq 1 30); do
  if curl -sf "http://localhost:28080/.well-known/oauth-authorization-server" > /dev/null 2>&1; then
    echo "    harbor-mcp is ready (after ${i}s)"
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "    ERROR: harbor-mcp did not become healthy within 30s"
    docker compose "${COVER_COMPOSE[@]}" logs harbor-mcp
    exit 1
  fi
  sleep 1
done

echo ""
echo "==> Running e2e tests..."
go test -tags e2e ./. -v -count=1 2>&1 | tee test-output.log
exit ${PIPESTATUS[0]}
