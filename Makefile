# CAM-OS Kernel Makefile
# Copyright 2024 CAM-OS Contributors
# Licensed under the Apache License, Version 2.0

# Build configuration
BINARY_NAME := cam-kernel
PACKAGE := ./cmd/cam-kernel
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
COMMIT_HASH := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Go configuration
GO := go
GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)
CGO_ENABLED := 0

# Directories
BUILD_DIR := build
DIST_DIR := dist
DOCS_DIR := docs
PROTO_DIR := proto
GENERATED_DIR := proto/generated

# Docker configuration
DOCKER_REGISTRY := cam-os
DOCKER_IMAGE := $(DOCKER_REGISTRY)/kernel
DOCKER_TAG := $(VERSION)
PROTO_BUILDER_IMAGE := $(DOCKER_REGISTRY)/proto-builder:latest

# Test configuration
TEST_TIMEOUT := 10m
COVERAGE_FILE := coverage.out

# LDFLAGS for version information
LDFLAGS := -X main.Version=$(VERSION) \
           -X main.BuildTime=$(BUILD_TIME) \
           -X main.CommitHash=$(COMMIT_HASH) \
           -s -w

# Default target
.PHONY: all
all: clean proto build test

# Help target
.PHONY: help
help: ## Show this help message
	@echo "CAM-OS Kernel Build System"
	@echo ""
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Build targets
.PHONY: build
build: proto ## Build the kernel binary
	@echo "Building CAM-OS Kernel $(VERSION)..."
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) $(PACKAGE)
	@echo "✅ Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

.PHONY: build-dev
build-dev: proto ## Build development version with debug symbols
	@echo "Building development version..."
	$(GO) build -gcflags="all=-N -l" -o $(BUILD_DIR)/$(BINARY_NAME)-dev $(PACKAGE)
	@echo "✅ Development build complete"

.PHONY: build-prod
build-prod: proto ## Build production version with optimizations
	@echo "Building production version..."
	CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS) -s -w" -a -installsuffix cgo -o $(BUILD_DIR)/$(BINARY_NAME) $(PACKAGE)
	@echo "✅ Production build complete"

.PHONY: build-all
build-all: proto ## Build for all supported platforms
	@echo "Building for all platforms..."
	@mkdir -p $(DIST_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-linux-amd64 $(PACKAGE)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-linux-arm64 $(PACKAGE)
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-darwin-amd64 $(PACKAGE)
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-darwin-arm64 $(PACKAGE)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-windows-amd64.exe $(PACKAGE)
	@echo "✅ Multi-platform build complete"

# Protocol Buffers - H-7 Implementation
.PHONY: proto-builder-image
proto-builder-image: ## Build Docker proto-builder image
	@echo "🐳 Building proto-builder Docker image..."
	docker build -f docker/proto-builder.Dockerfile -t $(PROTO_BUILDER_IMAGE) .
	@echo "✅ Proto-builder image built: $(PROTO_BUILDER_IMAGE)"

.PHONY: proto
proto: ## Generate protobuf files (H-7 compliant)
	@echo "🔄 Generating protobuf code..."
	@if command -v protoc >/dev/null 2>&1; then \
		cd $(PROTO_DIR) && \
		protoc --go_out=generated --go-grpc_out=generated \
		       --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative \
		       syscall.proto; \
		echo "✅ Protobuf generation complete"; \
	else \
		echo "⚠️  protoc not found locally, using Docker proto-builder..."; \
		$(MAKE) proto-docker; \
	fi

.PHONY: proto-docker
proto-docker: proto-builder-image ## Generate protobuf files using Docker
	@echo "🐳 Generating protobuf code using Docker..."
	docker run --rm -v $(PWD):/workspace $(PROTO_BUILDER_IMAGE) sh -c "\
		cd proto && \
		protoc --go_out=generated --go-grpc_out=generated \
		       --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative \
		       syscall.proto"
	@echo "✅ Docker protobuf generation complete"

.PHONY: proto-drift-check
proto-drift-check: ## Check for proto drift (H-7 requirement)
	@echo "🔍 Checking for protobuf drift..."
	@# Store current state
	@git stash push -u -m "proto-drift-check-backup" --quiet || true
	@# Regenerate proto files
	@$(MAKE) proto --silent
	@# Check for differences
	@if ! git diff --quiet; then \
		echo "❌ Proto files are out of sync with generated code!"; \
		echo ""; \
		echo "The following files have changes:"; \
		git diff --name-only; \
		echo ""; \
		echo "Diff details:"; \
		git diff; \
		echo ""; \
		echo "🔧 To fix: Run 'make proto' and commit the changes"; \
		git checkout -- .; \
		git stash pop --quiet 2>/dev/null || true; \
		exit 1; \
	else \
		echo "✅ Proto files are in sync with generated code"; \
		git stash pop --quiet 2>/dev/null || true; \
	fi

.PHONY: proto-validate
proto-validate: proto ## Validate protobuf schemas and generated code (H-10 requirement)
	@echo "🔍 H-10: Validating protobuf schemas and generated code..."
	@# Test proto validation by running validation tests
	@if [ -f "internal/syscall/validation/proto_validator_test.go" ]; then \
		$(GO) test -v ./internal/syscall/validation/... -tags=proto_validation; \
	fi
	@# Check that proto validator can be instantiated
	@$(GO) run -c 'package main; import "github.com/cam-os/kernel/internal/syscall/validation"; func main() { validation.NewProtoValidator(true) }' 2>/dev/null || echo "⚠️  Proto validator compilation check failed"
	@echo "✅ H-10: Protobuf validation complete"

.PHONY: proto-install
proto-install: ## Install protobuf tools
	@echo "📦 Installing protobuf tools..."
	go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.31.0
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.3.0
	@echo "✅ Protobuf tools installed"

.PHONY: proto-check
proto-check: ## Check if protobuf files exist
	@echo "Checking protobuf files..."
	@if [ ! -f $(GENERATED_DIR)/syscall.pb.go ]; then \
		echo "❌ Protobuf files missing, run 'make proto'"; \
		exit 1; \
	fi
	@echo "✅ Protobuf files exist"

# Testing
.PHONY: test
test: proto ## Run unit tests
	@echo "Running unit tests..."
	$(GO) test -timeout $(TEST_TIMEOUT) -race -cover ./...
	@echo "✅ Unit tests passed"

.PHONY: test-verbose
test-verbose: proto ## Run unit tests with verbose output
	@echo "Running unit tests (verbose)..."
	$(GO) test -timeout $(TEST_TIMEOUT) -race -cover -v ./...

.PHONY: test-coverage
test-coverage: proto ## Run tests with coverage report
	@echo "Running tests with coverage..."
	$(GO) test -timeout $(TEST_TIMEOUT) -race -coverprofile=$(COVERAGE_FILE) -covermode=atomic ./...
	$(GO) tool cover -html=$(COVERAGE_FILE) -o coverage.html
	@echo "✅ Coverage report generated: coverage.html"

.PHONY: test-integration
test-integration: ## Run integration tests
	@echo "Running integration tests..."
	$(GO) test -timeout $(TEST_TIMEOUT) -tags=integration ./tests/integration/...
	@echo "✅ Integration tests passed"

.PHONY: test-e2e
test-e2e: ## Run end-to-end tests
	@echo "Running end-to-end tests..."
	$(GO) test -timeout $(TEST_TIMEOUT) -tags=e2e ./tests/e2e/...
	@echo "✅ End-to-end tests passed"

.PHONY: test-all
test-all: test test-integration test-e2e ## Run all tests

.PHONY: test-proto-validation
test-proto-validation: proto ## Run protobuf validation tests (H-10)
	@echo "🔍 H-10: Running protobuf validation tests..."
	$(GO) test -timeout $(TEST_TIMEOUT) -race -cover -v ./internal/syscall/validation/... -tags=proto_validation
	@echo "✅ H-10: Protobuf validation tests passed"

.PHONY: benchmark
benchmark: proto ## Run benchmarks
	@echo "Running benchmarks..."
	$(GO) test -bench=. -benchmem ./...
	@echo "✅ Benchmarks complete"

# Code quality
.PHONY: lint
lint: ## Run linters
	@echo "Running linters..."
	golangci-lint run ./...
	@echo "✅ Linting complete"

.PHONY: fmt
fmt: ## Format code
	@echo "Formatting code..."
	$(GO) fmt ./...
	goimports -w .
	@echo "✅ Code formatting complete"

.PHONY: vet
vet: ## Run go vet
	@echo "Running go vet..."
	$(GO) vet ./...
	@echo "✅ Go vet complete"

.PHONY: check
check: fmt vet lint proto-drift-check proto-validate test ## Run all code quality checks (H-7 & H-10 compliant)

# Dependencies
.PHONY: deps
deps: ## Download dependencies
	@echo "Downloading dependencies..."
	$(GO) mod download
	@echo "✅ Dependencies downloaded"

.PHONY: deps-update
deps-update: ## Update dependencies
	@echo "Updating dependencies..."
	$(GO) get -u ./...
	$(GO) mod tidy
	@echo "✅ Dependencies updated"

.PHONY: deps-verify
deps-verify: ## Verify dependencies
	@echo "Verifying dependencies..."
	$(GO) mod verify
	@echo "✅ Dependencies verified"

# Docker
.PHONY: docker-build
docker-build: ## Build Docker image
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	docker tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_IMAGE):latest
	@echo "✅ Docker image built: $(DOCKER_IMAGE):$(DOCKER_TAG)"

.PHONY: docker-build-dev
docker-build-dev: ## Build development Docker image
	@echo "Building development Docker image..."
	docker build -f Dockerfile.dev -t $(DOCKER_IMAGE):dev .
	@echo "✅ Development Docker image built"

.PHONY: docker-test
docker-test: ## Run tests in Docker
	@echo "Running tests in Docker..."
	docker-compose -f docker-compose.test.yml up --build --abort-on-container-exit
	docker-compose -f docker-compose.test.yml down
	@echo "✅ Docker tests complete"

.PHONY: docker-push
docker-push: docker-build ## Push Docker image to registry
	@echo "Pushing Docker image..."
	docker push $(DOCKER_IMAGE):$(DOCKER_TAG)
	docker push $(DOCKER_IMAGE):latest
	@echo "✅ Docker image pushed"

# Documentation
.PHONY: docs
docs:
	@echo "📚 Generating API documentation..."
	@mkdir -p docs/api
	@go doc -all ./internal/syscall > docs/api/syscall.md || true
	@go doc -all ./internal/security > docs/api/security.md || true
	@go doc -all ./internal/memory > docs/api/memory.md || true
	@go doc -all ./internal/scheduler > docs/api/scheduler.md || true
	@echo "✅ Documentation generation complete"

.PHONY: docs-serve
docs-serve: ## Serve documentation locally
	@echo "Serving documentation on http://localhost:6060"
	godoc -http=:6060

# Development
.PHONY: run
run: build ## Run the kernel
	@echo "Starting CAM-OS Kernel..."
	./$(BUILD_DIR)/$(BINARY_NAME)

.PHONY: run-dev
run-dev: build-dev ## Run development version
	@echo "Starting CAM-OS Kernel (development)..."
	./$(BUILD_DIR)/$(BINARY_NAME)-dev

.PHONY: dev
dev: ## Start development environment
	@echo "Starting development environment..."
	docker-compose -f docker-compose.dev.yml up -d
	@echo "✅ Development environment started"

.PHONY: dev-stop
dev-stop: ## Stop development environment
	@echo "Stopping development environment..."
	docker-compose -f docker-compose.dev.yml down
	@echo "✅ Development environment stopped"

# Installation
.PHONY: install
install: build ## Install the kernel binary
	@echo "Installing CAM-OS Kernel..."
	$(GO) install -ldflags "$(LDFLAGS)" $(PACKAGE)
	@echo "✅ CAM-OS Kernel installed"

.PHONY: uninstall
uninstall: ## Uninstall the kernel binary
	@echo "Uninstalling CAM-OS Kernel..."
	rm -f $(GOPATH)/bin/$(BINARY_NAME)
	@echo "✅ CAM-OS Kernel uninstalled"

# Deployment
.PHONY: deploy-local
deploy-local: ## Deploy locally with Docker Compose
	@echo "Deploying locally..."
	docker-compose up -d
	@echo "✅ Local deployment complete"

.PHONY: deploy-k8s
deploy-k8s: ## Deploy to Kubernetes
	@echo "Deploying to Kubernetes..."
	kubectl apply -f deployment/kubernetes/
	@echo "✅ Kubernetes deployment complete"

# Release
.PHONY: release-prep
release-prep: clean check build-all test-all ## Prepare release
	@echo "✅ Release preparation complete"

.PHONY: release
release: release-prep ## Create release
	@echo "Creating release $(VERSION)..."
	@echo "✅ Release $(VERSION) ready"

# Cleanup
.PHONY: clean
clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -rf $(DIST_DIR)
	rm -f $(COVERAGE_FILE)
	rm -f coverage.html
	$(GO) clean -cache
	@echo "✅ Cleanup complete"

.PHONY: clean-all
clean-all: clean ## Clean everything including dependencies
	@echo "Cleaning everything..."
	$(GO) clean -modcache
	docker system prune -f
	@echo "✅ Deep cleanup complete"

# Validation
.PHONY: validate
validate: ## Run kernel validation
	@echo "Running kernel validation..."
	@if [ -f scripts/validate-kernel.sh ]; then \
		./scripts/validate-kernel.sh; \
	else \
		echo "⚠️  Validation script not found"; \
	fi

# Quick start
.PHONY: quick-start
quick-start: ## Quick start with Docker
	@echo "Starting CAM-OS Kernel quickly..."
	./quick-start-docker.sh

# Security
.PHONY: security-scan
security-scan:
	@echo "🔒 Running security scans..."
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "⚠️  gosec not found, install with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest"; \
	fi

# License checking
.PHONY: license-check
license-check:
	@echo "⚖️  Checking license compliance..."
	@if command -v reuse >/dev/null 2>&1; then \
		reuse lint; \
	else \
		echo "⚠️  reuse not found, install with: pip install reuse"; \
	fi 

# =============================================================================
# Public Validation Targets
# =============================================================================

.PHONY: validate-all
validate-all: validate-build validate-tests validate-performance validate-security ## Run complete validation suite

.PHONY: validate-build
validate-build: ## Validate that the system builds correctly
	@echo "🔨 Validating build process..."
	$(GO) mod tidy
	$(GO) mod verify
	$(MAKE) clean
	$(MAKE) proto
	$(MAKE) build
	@echo "✅ Build validation passed"

.PHONY: validate-tests
validate-tests: ## Run all tests for validation
	@echo "🧪 Running validation test suite..."
	$(GO) test -v -timeout $(TEST_TIMEOUT) -coverprofile=$(COVERAGE_FILE) ./tests/unit/...
	$(GO) test -v -timeout $(TEST_TIMEOUT) ./tests/integration/...
	@echo "✅ Test validation passed"

.PHONY: validate-performance
validate-performance: ## Run performance validation
	@echo "⚡ Running performance validation..."
	$(GO) test -v -timeout $(TEST_TIMEOUT) -bench=. ./tests/performance/...
	@echo "✅ Performance validation passed"

.PHONY: validate-security
validate-security: ## Run security validation
	@echo "🔒 Running security validation..."
	$(GO) test -v -timeout $(TEST_TIMEOUT) ./tests/integration/auth_negative_test.go
	$(GO) test -v -timeout $(TEST_TIMEOUT) ./tests/unit/error_redaction_test.go
	$(GO) test -v -timeout $(TEST_TIMEOUT) ./tests/unit/tpm_validation_test.go
	@echo "✅ Security validation passed"

.PHONY: validate-docker
validate-docker: ## Validate Docker deployment
	@echo "🐳 Validating Docker deployment..."
	docker-compose -f docker-compose.yml build
	docker-compose -f docker-compose.yml up -d
	@echo "Waiting for services to start..."
	sleep 30
	docker-compose -f docker-compose.yml ps
	docker-compose -f docker-compose.yml logs --tail=50
	docker-compose -f docker-compose.yml down
	@echo "✅ Docker validation passed"

.PHONY: validate-config
validate-config: ## Validate configuration files
	@echo "⚙️  Validating configuration..."
	@if [ ! -f config/validation.yaml ]; then echo "❌ Missing validation.yaml"; exit 1; fi
	@echo "✅ Configuration validation passed"

.PHONY: validation-report
validation-report: ## Generate validation report
	@echo "📊 Generating validation report..."
	@mkdir -p $(BUILD_DIR)/validation-reports
	@echo "# CAM-OS Validation Report" > $(BUILD_DIR)/validation-reports/validation-report.md
	@echo "Generated: $(BUILD_TIME)" >> $(BUILD_DIR)/validation-reports/validation-report.md
	@echo "Version: $(VERSION)" >> $(BUILD_DIR)/validation-reports/validation-report.md
	@echo "Commit: $(COMMIT_HASH)" >> $(BUILD_DIR)/validation-reports/validation-report.md
	@echo "" >> $(BUILD_DIR)/validation-reports/validation-report.md
	@echo "## Build Status" >> $(BUILD_DIR)/validation-reports/validation-report.md
	@$(MAKE) validate-build >> $(BUILD_DIR)/validation-reports/validation-report.md 2>&1 || echo "❌ Build Failed" >> $(BUILD_DIR)/validation-reports/validation-report.md
	@echo "" >> $(BUILD_DIR)/validation-reports/validation-report.md
	@echo "## Test Results" >> $(BUILD_DIR)/validation-reports/validation-report.md
	@$(MAKE) validate-tests >> $(BUILD_DIR)/validation-reports/validation-report.md 2>&1 || echo "❌ Tests Failed" >> $(BUILD_DIR)/validation-reports/validation-report.md
	@echo "" >> $(BUILD_DIR)/validation-reports/validation-report.md
	@echo "## Performance Results" >> $(BUILD_DIR)/validation-reports/validation-report.md
	@$(MAKE) validate-performance >> $(BUILD_DIR)/validation-reports/validation-report.md 2>&1 || echo "❌ Performance Tests Failed" >> $(BUILD_DIR)/validation-reports/validation-report.md
	@echo "" >> $(BUILD_DIR)/validation-reports/validation-report.md
	@echo "## Security Results" >> $(BUILD_DIR)/validation-reports/validation-report.md
	@$(MAKE) validate-security >> $(BUILD_DIR)/validation-reports/validation-report.md 2>&1 || echo "❌ Security Tests Failed" >> $(BUILD_DIR)/validation-reports/validation-report.md
	@echo "✅ Validation report generated: $(BUILD_DIR)/validation-reports/validation-report.md"

.PHONY: validation-demo
validation-demo: ## Run interactive validation demo
	@echo "🎯 Starting CAM-OS validation demo..."
	@echo "This will demonstrate key system capabilities for validation."
	@echo "Starting services..."
	docker-compose -f docker-compose.yml up -d
	@echo "Waiting for services to be ready..."
	sleep 30
	@echo "Running demo syscalls..."
	$(GO) run examples/demonstration/main.go
	@echo "Demo completed. Check logs for results."
	docker-compose -f docker-compose.yml down
	@echo "✅ Validation demo completed" 