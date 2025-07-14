#!/bin/bash

# CAM-OS Kernel GitHub Repository Preparation Script
# This script prepares the repository for publication on GitHub

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Check if we're in the right directory
check_directory() {
    if [[ ! -f "go.mod" ]] || [[ ! -f "MANIFEST.toml" ]]; then
        error "This script must be run from the CAM-OS kernel root directory"
    fi
    log "✓ Repository root directory confirmed"
}

# Clean up temporary and generated files
cleanup_repository() {
    log "Cleaning up repository..."
    
    # Remove build artifacts
    rm -rf build/ dist/ bin/ || true
    rm -f *.log *.out *.prof || true
    rm -rf tmp/ temp/ .cache/ || true
    
    # Remove IDE files
    rm -rf .vscode/ .idea/ || true
    rm -f *.swp *.swo *~ || true
    
    # Remove OS files
    find . -name ".DS_Store" -delete || true
    find . -name "Thumbs.db" -delete || true
    
    # Remove development overrides
    rm -f MANIFEST.toml.local config.local.toml || true
    rm -f docker-compose.override.yml docker-compose.local.yml || true
    
    success "Repository cleaned up"
}

# Validate Go modules and dependencies
validate_go_modules() {
    log "Validating Go modules..."
    
    if ! command -v go &> /dev/null; then
        error "Go is not installed or not in PATH"
    fi
    
    # Check Go version
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    if [[ "$(printf '%s\n' "1.21" "$GO_VERSION" | sort -V | head -n1)" != "1.21" ]]; then
        error "Go 1.21 or later is required (found: $GO_VERSION)"
    fi
    
    # Validate modules
    go mod verify || error "Go module verification failed"
    go mod tidy || error "Go module tidy failed"
    
    success "Go modules validated"
}

# Generate protobuf code
generate_protobuf() {
    log "Generating Protocol Buffer code..."
    
    if ! command -v protoc &> /dev/null; then
        error "protoc (Protocol Buffer compiler) is not installed"
    fi
    
    # Create output directory
    mkdir -p proto/generated
    
    # Generate Go code
    protoc --go_out=proto/generated --go-grpc_out=proto/generated --proto_path=proto proto/syscall.proto
    
    if [[ ! -f "proto/generated/syscall.pb.go" ]]; then
        error "Failed to generate protobuf code"
    fi
    
    success "Protocol Buffer code generated"
}

# Format code
format_code() {
    log "Formatting Go code..."
    
    # Format all Go files
    go fmt ./... || error "Code formatting failed"
    
    # Import formatting (if goimports is available)
    if command -v goimports &> /dev/null; then
        goimports -w . || warning "goimports formatting failed"
    fi
    
    success "Code formatted"
}

# Run linters
run_linters() {
    log "Running code linters..."
    
    # Go vet
    go vet ./... || error "go vet failed"
    
    # golangci-lint (if available)
    if command -v golangci-lint &> /dev/null; then
        golangci-lint run ./... || warning "golangci-lint found issues (non-fatal)"
    else
        warning "golangci-lint not found, skipping advanced linting"
    fi
    
    success "Linting completed"
}

# Run tests
run_tests() {
    log "Running test suite..."
    
    # Unit tests
    go test -race -cover ./... || error "Unit tests failed"
    
    success "All tests passed"
}

# Build the kernel
build_kernel() {
    log "Building CAM-OS Kernel..."
    
    # Create build directory
    mkdir -p build
    
    # Build for current platform
    go build -ldflags "-X main.Version=dev -X main.BuildTime=$(date -u '+%Y-%m-%d_%H:%M:%S') -X main.CommitHash=$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')" \
        -o build/cam-kernel ./cmd/cam-kernel
    
    if [[ ! -f "build/cam-kernel" ]]; then
        error "Kernel build failed"
    fi
    
    success "Kernel built successfully"
}

# Validate Docker setup
validate_docker() {
    log "Validating Docker configuration..."
    
    if ! command -v docker &> /dev/null; then
        warning "Docker not found, skipping Docker validation"
        return
    fi
    
    # Check Dockerfile syntax
    if ! docker build --no-cache -f Dockerfile . -t cam-os-kernel:test > /dev/null 2>&1; then
        error "Dockerfile build failed"
    fi
    
    # Clean up test image
    docker rmi cam-os-kernel:test > /dev/null 2>&1 || true
    
    success "Docker configuration validated"
}

# Check security best practices
security_check() {
    log "Running security checks..."
    
    # Check for common security issues
    local issues=0
    
    # Check for hardcoded secrets (basic patterns)
    if grep -r -i "password\s*=" --include="*.go" --include="*.toml" --include="*.yaml" --include="*.yml" . | grep -v "_test.go" | grep -v "example" > /dev/null; then
        warning "Potential hardcoded passwords found"
        ((issues++))
    fi
    
    if grep -r "api_key\|secret_key\|private_key" --include="*.go" --include="*.toml" . | grep -v "_test.go" | grep -v "example" > /dev/null; then
        warning "Potential hardcoded API keys found"
        ((issues++))
    fi
    
    # Check file permissions
    if find . -name "*.sh" -not -perm -u+x -print | grep -q .; then
        warning "Some shell scripts are not executable"
        ((issues++))
    fi
    
    if [[ $issues -eq 0 ]]; then
        success "Security check passed"
    else
        warning "Security check found $issues potential issues"
    fi
}

# Validate documentation
validate_documentation() {
    log "Validating documentation..."
    
    local missing_docs=()
    
    # Check for essential documentation files
    [[ ! -f "README.md" ]] && missing_docs+=("README.md")
    [[ ! -f "LICENSE" ]] && missing_docs+=("LICENSE")
    [[ ! -f "CONTRIBUTING.md" ]] && missing_docs+=("CONTRIBUTING.md")
    [[ ! -f "CODE_OF_CONDUCT.md" ]] && missing_docs+=("CODE_OF_CONDUCT.md")
    [[ ! -f "SECURITY.md" ]] && missing_docs+=("SECURITY.md")
    
    if [[ ${#missing_docs[@]} -gt 0 ]]; then
        error "Missing documentation files: ${missing_docs[*]}"
    fi
    
    # Check if documentation is substantial (not just placeholder)
    if [[ $(wc -l < README.md) -lt 50 ]]; then
        warning "README.md seems too short (less than 50 lines)"
    fi
    
    success "Documentation validated"
}

# Check GitHub Actions workflow
validate_github_actions() {
    log "Validating GitHub Actions workflows..."
    
    if [[ ! -d ".github/workflows" ]]; then
        warning "No GitHub Actions workflows found"
        return
    fi
    
    # Check if CI workflow exists
    if [[ ! -f ".github/workflows/ci.yml" ]]; then
        warning "No CI workflow found"
        return
    fi
    
    # Basic YAML syntax check (if yq is available)
    if command -v yq &> /dev/null; then
        if ! yq eval . .github/workflows/ci.yml > /dev/null 2>&1; then
            error "GitHub Actions CI workflow has invalid YAML syntax"
        fi
    fi
    
    success "GitHub Actions workflows validated"
}

# Generate repository statistics
generate_stats() {
    log "Generating repository statistics..."
    
    local go_files=$(find . -name "*.go" -not -path "./vendor/*" | wc -l)
    local go_lines=$(find . -name "*.go" -not -path "./vendor/*" -exec wc -l {} \; | awk '{sum += $1} END {print sum}')
    local test_files=$(find . -name "*_test.go" | wc -l)
    local proto_files=$(find . -name "*.proto" | wc -l)
    
    echo "📊 Repository Statistics:"
    echo "   Go files: $go_files"
    echo "   Lines of Go code: $go_lines"
    echo "   Test files: $test_files"
    echo "   Protocol buffer files: $proto_files"
    echo "   Total commits: $(git rev-list --count HEAD 2>/dev/null || echo 'unknown')"
    echo "   Contributors: $(git shortlog -sn 2>/dev/null | wc -l || echo 'unknown')"
    
    success "Statistics generated"
}

# Create release checklist
create_release_checklist() {
    log "Creating release checklist..."
    
    cat > RELEASE_CHECKLIST.md << 'EOF'
# CAM-OS Kernel Release Checklist

## Pre-Release
- [ ] All tests pass (`make test-all`)
- [ ] Code is formatted (`make fmt`)
- [ ] Linting passes (`make lint`)
- [ ] Security scan passes (`make security-scan`)
- [ ] Performance benchmarks meet targets (`make benchmark`)
- [ ] Documentation is up to date
- [ ] CHANGELOG.md is updated
- [ ] Version is bumped appropriately

## Release Process
- [ ] Create release branch
- [ ] Update version in go.mod and other files
- [ ] Generate release notes
- [ ] Create GitHub release
- [ ] Build and publish Docker images
- [ ] Update deployment templates
- [ ] Notify stakeholders

## Post-Release
- [ ] Verify release artifacts
- [ ] Monitor deployment health
- [ ] Update website/documentation
- [ ] Prepare next milestone
EOF
    
    success "Release checklist created"
}

# Main execution
main() {
    echo "🧠 CAM-OS Kernel GitHub Repository Preparation"
    echo "=============================================="
    echo ""
    
    check_directory
    cleanup_repository
    validate_go_modules
    generate_protobuf
    format_code
    run_linters
    run_tests
    build_kernel
    validate_docker
    security_check
    validate_documentation
    validate_github_actions
    generate_stats
    create_release_checklist
    
    echo ""
    echo "🎉 Repository preparation completed successfully!"
    echo ""
    echo "Next steps:"
    echo "1. Review and commit any changes"
    echo "2. Create GitHub repository"
    echo "3. Push code to GitHub"
    echo "4. Configure GitHub settings (branch protection, etc.)"
    echo "5. Set up GitHub Actions secrets if needed"
    echo "6. Create initial release"
    echo ""
    echo "Repository is ready for GitHub! 🚀"
}

# Run main function
main "$@" 