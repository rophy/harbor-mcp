.DEFAULT_GOAL := help
.PHONY: help lint unit-test e2e-test

help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

lint: ## Run linter (go vet)
	go vet ./...

unit-test: ## Run unit tests with coverage summary
	@go test -coverprofile=coverage.out ./... && \
	echo "" && \
	echo "=== Coverage ===" && \
	go tool cover -func=coverage.out | tail -1 && \
	rm -f coverage.out

e2e-test: ## Run e2e tests with coverage instrumentation
	@rm -rf e2e/coverdata && mkdir -p e2e/coverdata
	@echo "==> Rebuilding harbor-mcp with coverage instrumentation..."
	cd e2e && COVER=true docker compose up -d --no-deps --build --force-recreate harbor-mcp
	@echo "==> Waiting for harbor-mcp to be ready..."
	@for i in $$(seq 1 30); do \
		curl -sf http://localhost:28080/.well-known/oauth-authorization-server > /dev/null 2>&1 && break; \
		sleep 1; \
	done
	@echo "==> Running e2e tests..."
	COVER=true go test -tags e2e -count=1 ./e2e/ || true
	@echo "==> Stopping harbor-mcp to flush coverage..."
	cd e2e && docker compose stop harbor-mcp
	@echo ""
	@echo "=== E2E Coverage ==="
	@go tool covdata percent -i=e2e/coverdata
	@echo ""
	@echo "==> Restarting harbor-mcp without coverage..."
	cd e2e && docker compose up -d --no-deps --build --force-recreate harbor-mcp
