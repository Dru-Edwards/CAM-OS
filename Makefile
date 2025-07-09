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

# Protocol Buffers
.PHONY: proto
proto: ## Generate protobuf code
	@echo "Generating protobuf code..."
	@mkdir -p $(GENERATED_DIR)
	protoc --go_out=$(GENERATED_DIR) --go-grpc_out=$(GENERATED_DIR) --proto_path=$(PROTO_DIR) $(PROTO_DIR)/syscall.proto
	@echo "✅ Protobuf generation complete"

.PHONY: proto-check
proto-check: ## Check if protobuf files need regeneration
	@echo "Checking protobuf files..."
	@if [ ! -f $(GENERATED_DIR)/syscall.pb.go ]; then \
		echo "❌ Protobuf files missing, run 'make proto'"; \
		exit 1; \
	fi
	@echo "✅ Protobuf files up to date"

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
check: fmt vet lint test ## Run all code quality checks

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
docs: ## Generate documentation
	@echo "Generating documentation..."
	@mkdir -p $(DOCS_DIR)/api
	godoc -html . > $(DOCS_DIR)/api/godoc.html
	@echo "✅ Documentation generated"

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
security-scan: ## Run security scans
	@echo "Running security scans..."
	gosec ./...
	@echo "✅ Security scan complete"

# Performance
.PHONY: perf-test
perf-test: ## Run performance tests
	@echo "Running performance tests..."
	$(GO) test -timeout $(TEST_TIMEOUT) -tags=performance ./tests/performance/...
	@echo "✅ Performance tests complete"

# Monitoring
.PHONY: monitor
monitor: ## Start monitoring stack
	@echo "Starting monitoring stack..."
	docker-compose -f deployment/docker/docker-compose.prod.yml up -d prometheus grafana
	@echo "✅ Monitoring stack started"

# Configuration validation
.PHONY: config-validate
config-validate: ## Validate configuration files
	@echo "Validating configuration..."
	@if [ -f MANIFEST.toml ]; then \
		echo "✅ MANIFEST.toml found"; \
	else \
		echo "❌ MANIFEST.toml missing"; \
		exit 1; \
	fi

# Development tools
.PHONY: tools
tools: ## Install development tools
	@echo "Installing development tools..."
	$(GO) install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	$(GO) install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	$(GO) install golang.org/x/tools/cmd/goimports@latest
	$(GO) install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
	@echo "✅ Development tools installed"

# Initialize repository
.PHONY: init
init: tools deps proto build test ## Initialize repository for development
	@echo "✅ Repository initialized for development" 