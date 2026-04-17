.PHONY: generate build unit-tests integration-tests script-tests test cover bench clean help

# Version info injected at build time via ldflags.
# Falls back to safe defaults outside a git repo.
VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT     := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS    := -X main.Version=$(VERSION) -X main.Commit=$(COMMIT) -X main.BuildDate=$(BUILD_DATE)

# Default target
help:
	@echo "AIProxy Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  make generate      - Generate templ Go files"
	@echo "  make build         - Build the aiproxy binary (runs generate first)"
	@echo "  make unit-tests    - Run Go unit tests only"
	@echo "  make integration-tests - Run Go integration tests only"
	@echo "  make script-tests   - Run script tests (requires pre-built binary)"
	@echo "  make test          - Run unit, integration, and manual tests (CI/CD target)"
	@echo "  make cover         - Run all tests and show combined coverage report"
	@echo "  make bench         - Run benchmarks (reqrules package)"
	@echo "  make clean         - Remove build artifacts and test directories"
	@echo ""

# Generate templ Go files
generate:
	@echo "Generating templ files..."
	@go run github.com/a-h/templ/cmd/templ@latest generate ./internal/webui/templates/

# Build binary (templ generation must run first)
build: generate
	@echo "Building aiproxy..."
	@CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o aiproxy ./cmd/aiproxy

# Run Go unit tests only
unit-tests:
	@echo "Running unit tests..."
	@go test -race ./...

# Run Go integration tests only
integration-tests:
	@echo "Running integration tests..."
	@go test -tags=integration -race ./internal/integration_tests/...

# Run script tests (requires pre-built binary)
script-tests:
	@echo "Cleaning test directories..."
	@rm -rf scripts/rm-*.d
	@./scripts/test.sh

# Run all tests: unit tests, integration tests, then manual tests (recommended for CI/CD)
test: unit-tests integration-tests script-tests
	@echo ""
	@echo "All tests completed successfully!"

# Run all tests and show combined unit + integration coverage report
cover:
	@echo "Running unit tests with coverage..."
	@go test -race -coverprofile=coverage_unit.out -covermode=atomic -coverpkg=./... ./...
	@echo "Running integration tests with coverage..."
	@go test -tags=integration -race -coverprofile=coverage_integration.out -covermode=atomic -coverpkg=./... ./internal/integration_tests/...
	@echo "Merging coverage profiles..."
	@echo "mode: atomic" > coverage.out
	@grep -h -v "^mode:" coverage_unit.out coverage_integration.out >> coverage.out
	@rm -f coverage_unit.out coverage_integration.out
	@echo ""
	@echo "Coverage report:"
	@go tool cover -func=coverage.out
	@echo ""
	@echo "Run 'go tool cover -html=coverage.out' to open the HTML report."

# Run benchmarks
bench:
	@echo "Running benchmarks..."
	@go test -bench=. -benchmem -benchtime=3s ./internal/reqrules

# Clean build artifacts and test directories
clean:
	@echo "Cleaning..."
	@rm -f aiproxy
	@rm -rf scripts/rm-*.d
	@rm -f coverage.out coverage_unit.out coverage_integration.out
	@go clean -testcache
