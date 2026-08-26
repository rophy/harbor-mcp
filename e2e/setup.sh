#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

HARBOR_URL="http://localhost:8880"
ADMIN_USER="admin"
ADMIN_PASS="Harbor12345"

echo "==> Starting Harbor + oidc-mock + harbor-mcp..."
docker compose up -d --build

echo "==> Waiting for Harbor to be healthy..."
for i in $(seq 1 120); do
  if curl -sf "${HARBOR_URL}/api/v2.0/ping" > /dev/null 2>&1; then
    echo "    Harbor is ready (after ${i}s)"
    break
  fi
  if [ "$i" -eq 120 ]; then
    echo "    ERROR: Harbor did not become healthy within 120s"
    docker compose logs harbor-core
    exit 1
  fi
  sleep 1
done

echo "==> Creating test project 'library'..."
curl -sf -u "${ADMIN_USER}:${ADMIN_PASS}" \
  -H "Content-Type: application/json" \
  -X POST "${HARBOR_URL}/api/v2.0/projects" \
  -d '{"project_name":"library","public":true}' \
  -o /dev/null -w "    HTTP %{http_code}\n" || true

echo "==> Creating robot account 'mcp-reader'..."
ROBOT_RESPONSE=$(curl -sf -u "${ADMIN_USER}:${ADMIN_PASS}" \
  -H "Content-Type: application/json" \
  -X POST "${HARBOR_URL}/api/v2.0/robots" \
  -d '{
    "name": "mcp-reader",
    "description": "Robot account for harbor-mcp e2e tests",
    "duration": -1,
    "level": "system",
    "permissions": [
      {
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
      }
    ]
  }')

ROBOT_NAME=$(echo "$ROBOT_RESPONSE" | jq -r '.name')
ROBOT_SECRET=$(echo "$ROBOT_RESPONSE" | jq -r '.secret')

echo "    Robot created: ${ROBOT_NAME}"

echo "==> Writing robot credentials to .env..."
cat > .env <<EOF
HARBOR_ROBOT_NAME=${ROBOT_NAME}
HARBOR_ROBOT_SECRET=${ROBOT_SECRET}
EOF

echo "==> Pushing test image to Harbor..."
docker pull busybox:1.37
docker tag busybox:1.37 localhost:8880/library/test-image:v1
echo "${ADMIN_PASS}" | docker login localhost:8880 -u "${ADMIN_USER}" --password-stdin
docker push localhost:8880/library/test-image:v1
echo "    Test image pushed: library/test-image:v1"

echo "==> Restarting harbor-mcp with robot credentials..."
docker compose up -d harbor-mcp

echo "==> Waiting for harbor-mcp to be ready..."
for i in $(seq 1 30); do
  if curl -sf "http://localhost:28080/.well-known/oauth-authorization-server" > /dev/null 2>&1; then
    echo "    harbor-mcp is ready (after ${i}s)"
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "    ERROR: harbor-mcp did not become healthy within 30s"
    docker compose logs harbor-mcp
    exit 1
  fi
  sleep 1
done

echo ""
echo "==> E2E environment is ready!"
echo "    Harbor:     ${HARBOR_URL} (admin / ${ADMIN_PASS})"
echo "    OIDC Mock:  http://localhost:28090"
echo "    harbor-mcp: http://localhost:28080"
echo "    Robot:      ${ROBOT_NAME}"
echo ""
echo "    Run tests:  go test -tags e2e ./e2e/"
