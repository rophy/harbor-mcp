# harbor-mcp

## Testing Policy

After any code change:
1. Run linter: `go vet ./...`
2. Run unit tests: `go test ./...`

Before creating a PR:
3. Run e2e tests: `go test -tags e2e -count=1 ./e2e/`

All test failures must be fixed. There is no such thing as a "pre-existing error" — if a test fails, fix it before proceeding.

When running tests, redirect full output to a temp file first, then grep for summary. Never pipe test output directly through grep.

## E2E Environment

E2e tests require the docker-compose stack in `e2e/`. Start it with `cd e2e && ./setup.sh`. Tear down with `cd e2e && ./teardown.sh`.

## Kubectl

Use context `kind-kind` for kubectl commands targeting this project's test infrastructure.
