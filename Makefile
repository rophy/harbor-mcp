.PHONY: lint unit-test e2e-test

lint:
	go vet ./...

unit-test:
	@go test -coverprofile=coverage.out ./... && \
	echo "" && \
	echo "=== Coverage ===" && \
	go tool cover -func=coverage.out | tail -1 && \
	rm -f coverage.out

e2e-test:
	go test -tags e2e -count=1 ./e2e/
