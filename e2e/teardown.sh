#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "==> Stopping and removing all e2e containers..."
docker compose down -v

echo "==> Cleaning up .env..."
rm -f .env

echo "==> Done."
