.PHONY: test test-unit

# Run all tests and quality checks
test: quality test-unit

# Run unit tests only
test-unit:
	@go test -v ./...

# Run all code quality checks
quality: fmt-check mod-check lint
	@echo "All code quality checks passed!"

# Run linting with golangci-lint
lint:
	golangci-lint run --timeout=5m

# Run linting with golangci-lint (install if not present)
lint-install:
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "Installing golangci-lint..."; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	fi
	golangci-lint run --timeout=5m

# Check code formatting
fmt-check:
	@if [ "$(shell gofmt -s -l . | wc -l)" -gt 0 ]; then \
		echo "Code is not formatted. Please run 'gofmt -s -w .'"; \
		gofmt -s -l .; \
		exit 1; \
	fi
	@echo "Code formatting is correct"

# Format code
fmt:
	gofmt -s -w .

# Check go mod tidy
mod-check:
	@echo "Checking go.mod and go.sum..."
	@git diff --quiet go.mod || (echo "go.mod or go.sum has uncommitted changes. Please commit them first." && exit 1)
	go mod tidy
	@git diff --quiet go.mod || (echo "go.mod or go.sum is not tidy. Please run 'go mod tidy' and commit changes." && git diff go.mod go.sum && exit 1)
	@echo "Go modules are tidy"


# Show help
help:
	@echo "Available targets:"
	@echo "  test               - Run all tests (integration tests)"
	@echo "  test-unit          - Show unit test status"
	@echo ""
	@echo "Code Quality:"
	@echo "  quality            - Run all code quality checks"
	@echo "  lint               - Run golangci-lint (requires golangci-lint)"
	@echo "  lint-install       - Install golangci-lint and run linting"
	@echo "  fmt-check          - Check code formatting"
	@echo "  fmt                - Format code with gofmt"
	@echo "  mod-check          - Check if go.mod is tidy"
	@echo ""
	@echo "Other:"
	@echo "  help               - Show this help"
