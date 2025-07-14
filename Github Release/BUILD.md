# CAM-OS v1.1.0 Build Guide

Complete guide for building CAM-OS v1.1.0 from source code.

## 🛠️ Prerequisites

### System Requirements
- **Operating System**: Linux (Ubuntu 20.04+), macOS (11.0+), Windows (WSL2)
- **CPU**: x86_64 or ARM64 architecture
- **Memory**: 4GB+ RAM for building
- **Storage**: 10GB+ available space
- **Network**: Internet connection for dependencies

### Required Tools

#### Core Build Tools
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y build-essential git curl wget

# macOS (with Homebrew)
brew install git curl wget

# Windows (WSL2)
sudo apt update
sudo apt install -y build-essential git curl wget
```

#### Go Programming Language
```bash
# Install Go 1.21+
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz

# Add to PATH
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# Verify installation
go version
```

#### Protocol Buffers
```bash
# Install protoc compiler
# Ubuntu/Debian
sudo apt install -y protobuf-compiler

# macOS
brew install protobuf

# Install Go plugins
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```

#### Docker (Optional)
```bash
# Ubuntu/Debian
sudo apt install -y docker.io docker-compose
sudo usermod -aG docker $USER

# macOS
brew install docker docker-compose

# Start Docker
sudo systemctl start docker
sudo systemctl enable docker
```

#### Additional Tools
```bash
# Install additional build dependencies
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install github.com/securecodewarrior/sast-scan@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
```

## 📥 Source Code

### Clone Repository
```bash
# Clone the main repository
git clone https://github.com/Dru-Edwards/CAM-OS.git
cd CAM-OS

# Checkout v1.1.0 tag
git checkout v1.1.0

# Verify you're on the correct version
git describe --tags
```

### Verify Source Integrity
```bash
# Verify GPG signature (if available)
git verify-tag v1.1.0

# Check source code integrity
sha256sum -c checksums.txt
```

## 🔧 Build Configuration

### Environment Variables
```bash
# Set build environment
export CGO_ENABLED=0
export GOOS=linux
export GOARCH=amd64
export GO111MODULE=on

# Build configuration
export CAM_OS_VERSION=v1.1.0
export CAM_OS_BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S')
export CAM_OS_COMMIT_HASH=$(git rev-parse --short HEAD)

# Optional: Enable debug symbols
export CAM_OS_DEBUG=false
```

### Build Flags
```bash
# Performance build flags
export LDFLAGS="-X main.Version=$CAM_OS_VERSION \
                -X main.BuildTime=$CAM_OS_BUILD_TIME \
                -X main.CommitHash=$CAM_OS_COMMIT_HASH \
                -s -w"

# Debug build flags (for development)
export LDFLAGS_DEBUG="-X main.Version=$CAM_OS_VERSION \
                      -X main.BuildTime=$CAM_OS_BUILD_TIME \
                      -X main.CommitHash=$CAM_OS_COMMIT_HASH"
```

## 🏗️ Build Process

### Quick Build
```bash
# Build with default settings
make build

# Verify build
./build/cam-os version
```

### Full Build Process
```bash
# 1. Clean previous builds
make clean

# 2. Download dependencies
go mod download
go mod verify

# 3. Generate protocol buffers
make proto

# 4. Run code generation
make generate

# 5. Run static analysis
make lint

# 6. Run tests
make test

# 7. Build binary
make build

# 8. Run security scan
make security-scan
```

### Cross-Platform Builds
```bash
# Build for all supported platforms
make build-all

# Build for specific platforms
make build-linux-amd64
make build-linux-arm64
make build-darwin-amd64
make build-darwin-arm64
make build-windows-amd64
```

### Docker Build
```bash
# Build Docker image
make docker-build

# Build multi-architecture images
make docker-build-multiarch

# Verify Docker image
docker run --rm cam-os:v1.1.0 version
```

## 🧪 Testing

### Unit Tests
```bash
# Run unit tests
make test

# Run tests with coverage
make test-coverage

# Run tests with race detection
make test-race

# Generate coverage report
make coverage-report
```

### Integration Tests
```bash
# Run integration tests
make test-integration

# Run end-to-end tests
make test-e2e

# Run performance tests
make test-performance
```

### Security Tests
```bash
# Run security scan
make security-scan

# Run vulnerability check
make vuln-check

# Run dependency audit
make audit
```

## 📦 Packaging

### Binary Packaging
```bash
# Create binary packages
make package

# Create platform-specific packages
make package-linux
make package-darwin
make package-windows

# Verify packages
ls -la dist/
```

### Container Packaging
```bash
# Build container images
make docker-build

# Export container images
make docker-export

# Build Helm charts
make helm-package
```

### Distribution Packages
```bash
# Build DEB package (Ubuntu/Debian)
make package-deb

# Build RPM package (CentOS/RHEL)
make package-rpm

# Build Homebrew formula (macOS)
make package-brew
```

## ⚙️ Configuration

### Build Configuration Files

#### `.goreleaser.yml`
```yaml
# Release configuration
project_name: cam-os
dist: dist

builds:
  - id: cam-os
    main: ./cmd/cam-kernel
    binary: cam-os
    env:
      - CGO_ENABLED=0
    goos:
      - linux
      - darwin
      - windows
    goarch:
      - amd64
      - arm64
    ldflags:
      - -s -w
      - -X main.Version={{.Version}}
      - -X main.BuildTime={{.Date}}
      - -X main.CommitHash={{.Commit}}

archives:
  - id: cam-os
    format: tar.gz
    format_overrides:
      - goos: windows
        format: zip
    files:
      - LICENSE
      - README.md
      - config/*
      - docs/*
```

#### `Makefile` Configuration
```makefile
# Build configuration
BINARY_NAME := cam-os
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

# LDFLAGS
LDFLAGS := -X main.Version=$(VERSION) \
           -X main.BuildTime=$(BUILD_TIME) \
           -X main.CommitHash=$(COMMIT_HASH) \
           -s -w
```

### Custom Build Scripts

#### `scripts/build.sh`
```bash
#!/bin/bash
# Custom build script

set -e

# Configuration
VERSION=${VERSION:-$(git describe --tags --always --dirty)}
BUILD_TIME=${BUILD_TIME:-$(date -u '+%Y-%m-%d_%H:%M:%S')}
COMMIT_HASH=${COMMIT_HASH:-$(git rev-parse --short HEAD)}

# Build flags
LDFLAGS="-X main.Version=$VERSION -X main.BuildTime=$BUILD_TIME -X main.CommitHash=$COMMIT_HASH -s -w"

# Build binary
echo "Building CAM-OS $VERSION..."
CGO_ENABLED=0 go build -ldflags "$LDFLAGS" -o build/cam-os ./cmd/cam-kernel

echo "Build completed successfully!"
echo "Binary: build/cam-os"
echo "Version: $VERSION"
echo "Build Time: $BUILD_TIME"
echo "Commit: $COMMIT_HASH"
```

## 🔍 Verification

### Build Verification
```bash
# Verify binary works
./build/cam-os version
./build/cam-os --help

# Check binary size
ls -lh build/cam-os

# Check dependencies
ldd build/cam-os  # Linux
otool -L build/cam-os  # macOS
```

### Security Verification
```bash
# Check for security issues
make security-scan

# Verify signatures
gpg --verify build/cam-os.sig build/cam-os

# Check for hardening
checksec --file=build/cam-os
```

### Performance Verification
```bash
# Run benchmarks
make bench

# Check startup time
time ./build/cam-os --help

# Memory usage check
valgrind --tool=memcheck ./build/cam-os version
```

## 🐛 Troubleshooting

### Common Build Issues

#### Go Module Issues
```bash
# Clear module cache
go clean -modcache

# Reinstall dependencies
rm go.sum
go mod download
go mod tidy
```

#### Protocol Buffer Issues
```bash
# Regenerate proto files
rm -rf proto/generated/*
make proto

# Check protoc version
protoc --version
```

#### Docker Build Issues
```bash
# Clear Docker cache
docker system prune -a

# Build without cache
docker build --no-cache -t cam-os:v1.1.0 .
```

#### Permission Issues
```bash
# Fix permissions
chmod +x scripts/*.sh
sudo chown -R $USER:$USER .
```

### Build Environment Issues

#### Missing Dependencies
```bash
# Install missing Go tools
go install -a std
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Update dependencies
go get -u all
go mod tidy
```

#### Version Conflicts
```bash
# Check Go version
go version

# Update Go
sudo rm -rf /usr/local/go
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
```

## 📊 Build Optimization

### Faster Builds
```bash
# Parallel builds
make -j$(nproc) build

# Use build cache
export GOCACHE=/tmp/go-build-cache

# Enable module proxy
export GOPROXY=https://proxy.golang.org,direct
```

### Smaller Binaries
```bash
# Strip symbols
go build -ldflags "-s -w" -o build/cam-os ./cmd/cam-kernel

# Use UPX compression (optional)
upx --best build/cam-os
```

### Build Caching
```bash
# Enable Go build cache
export GOCACHE=$HOME/.cache/go-build

# Enable module cache
export GOMODCACHE=$HOME/go/pkg/mod

# Docker layer caching
docker build --cache-from cam-os:latest -t cam-os:v1.1.0 .
```

## 🚀 Production Builds

### Release Build Process
```bash
# 1. Tag release
git tag -a v1.1.0 -m "CAM-OS v1.1.0"

# 2. Clean build environment
make clean

# 3. Security scan
make security-scan

# 4. Full test suite
make test-all

# 5. Build all platforms
make build-all

# 6. Package releases
make package-all

# 7. Generate checksums
make checksums

# 8. Sign binaries
make sign
```

### Continuous Integration
```yaml
# .github/workflows/build.yml
name: Build
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v3
        with:
          go-version: '1.21'
      - run: make test
      - run: make build
      - run: make security-scan
```

## 📚 Additional Resources

### Documentation
- **Makefile**: Complete build targets and options
- **Docker**: Container build and deployment
- **Scripts**: Automation scripts and utilities
- **CI/CD**: Continuous integration workflows

### Build Tools
- **Go**: https://golang.org/doc/install
- **Protocol Buffers**: https://protobuf.dev/
- **Docker**: https://docs.docker.com/
- **Make**: https://www.gnu.org/software/make/

### Support
- **Build Issues**: https://github.com/Dru-Edwards/CAM-OS/issues
- **Documentation**: https://docs.cam-os.dev/build
- **Community**: https://community.cam-os.dev

---

**CAM-OS v1.1.0 Build Guide** | Build from Source | December 2024 