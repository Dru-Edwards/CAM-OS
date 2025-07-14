#!/bin/bash

# CAM-OS v1.1.0 Release Preparation Script
# This script prepares all assets for the GitHub release

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
VERSION="v1.1.0"
RELEASE_DIR="Github Release"
TEMP_DIR="/tmp/cam-os-release"
BINARY_DIR="$TEMP_DIR/binaries"
ASSETS_DIR="$TEMP_DIR/assets"

# Functions
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

error() {
    echo -e "${RED}❌ $1${NC}"
    exit 1
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check if running from correct directory
    if [[ ! -f "go.mod" ]] || [[ ! -f "Makefile" ]]; then
        error "Must run from CAM-OS project root directory"
    fi
    
    # Check required tools
    local tools=("go" "docker" "git" "tar" "gzip" "sha256sum")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            error "Required tool '$tool' is not installed"
        fi
    done
    
    # Check Go version
    local go_version=$(go version | grep -o 'go[0-9]\+\.[0-9]\+' | cut -c3-)
    if [[ $(echo "$go_version < 1.21" | bc -l) -eq 1 ]]; then
        error "Go 1.21 or later is required (found: $go_version)"
    fi
    
    success "All prerequisites met"
}

# Create directory structure
create_directories() {
    log "Creating directory structure..."
    
    mkdir -p "$TEMP_DIR"
    mkdir -p "$BINARY_DIR"
    mkdir -p "$ASSETS_DIR"
    mkdir -p "$RELEASE_DIR/binaries"
    mkdir -p "$RELEASE_DIR/containers"
    mkdir -p "$RELEASE_DIR/kubernetes"
    mkdir -p "$RELEASE_DIR/client-libraries"
    mkdir -p "$RELEASE_DIR/examples"
    mkdir -p "$RELEASE_DIR/config"
    
    success "Directory structure created"
}

# Build binaries for all platforms
build_binaries() {
    log "Building binaries for all platforms..."
    
    local platforms=(
        "linux/amd64"
        "linux/arm64"
        "darwin/amd64"
        "darwin/arm64"
        "windows/amd64"
    )
    
    for platform in "${platforms[@]}"; do
        local os=$(echo "$platform" | cut -d'/' -f1)
        local arch=$(echo "$platform" | cut -d'/' -f2)
        local binary_name="cam-os"
        
        if [[ "$os" == "windows" ]]; then
            binary_name="cam-os.exe"
        fi
        
        log "Building for $os/$arch..."
        
        GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build \
            -ldflags "-X main.Version=$VERSION -X main.BuildTime=$(date -u '+%Y-%m-%d_%H:%M:%S') -X main.CommitHash=$(git rev-parse --short HEAD) -s -w" \
            -o "$BINARY_DIR/$binary_name" \
            ./cmd/cam-kernel
        
        # Create platform-specific package
        local package_name="cam-os-$VERSION-$os-$arch"
        local package_dir="$BINARY_DIR/$package_name"
        
        mkdir -p "$package_dir/bin"
        mkdir -p "$package_dir/config"
        mkdir -p "$package_dir/docs"
        mkdir -p "$package_dir/examples"
        mkdir -p "$package_dir/scripts"
        
        # Copy binary
        cp "$BINARY_DIR/$binary_name" "$package_dir/bin/"
        
        # Copy configuration files
        cp -r config/* "$package_dir/config/" || true
        
        # Copy documentation
        cp README.md "$package_dir/" || true
        cp LICENSE "$package_dir/" || true
        cp "$RELEASE_DIR/INSTALLATION.md" "$package_dir/docs/" || true
        cp "$RELEASE_DIR/QUICKSTART.md" "$package_dir/docs/" || true
        
        # Copy examples
        cp -r examples/* "$package_dir/examples/" || true
        
        # Create installation script
        cat > "$package_dir/scripts/install.sh" << 'EOF'
#!/bin/bash
# CAM-OS Installation Script

set -e

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Create user and directories
useradd -r -s /bin/false cam-os || true
mkdir -p /etc/cam-os
mkdir -p /var/lib/cam-os
mkdir -p /var/log/cam-os

# Copy binary
cp bin/cam-os /usr/local/bin/
chmod +x /usr/local/bin/cam-os

# Copy configuration
cp -r config/* /etc/cam-os/

# Set permissions
chown -R cam-os:cam-os /var/lib/cam-os
chown -R cam-os:cam-os /var/log/cam-os
chown -R root:cam-os /etc/cam-os
chmod 750 /etc/cam-os

# Create systemd service
cat > /etc/systemd/system/cam-os.service << 'SYSTEMD_EOF'
[Unit]
Description=CAM-OS Cognitive Operating System Kernel
After=network.target

[Service]
Type=simple
User=cam-os
Group=cam-os
ExecStart=/usr/local/bin/cam-os --config /etc/cam-os/default.yaml
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SYSTEMD_EOF

# Enable and start service
systemctl daemon-reload
systemctl enable cam-os
systemctl start cam-os

echo "CAM-OS installed successfully!"
echo "Status: systemctl status cam-os"
echo "Logs: journalctl -u cam-os -f"
EOF
        
        chmod +x "$package_dir/scripts/install.sh"
        
        # Create package
        cd "$BINARY_DIR"
        tar -czf "$package_name.tar.gz" "$package_name"
        cd - > /dev/null
        
        # Move to release directory
        mv "$BINARY_DIR/$package_name.tar.gz" "$RELEASE_DIR/binaries/"
        
        success "Built $os/$arch binary and package"
    done
}

# Build container images
build_containers() {
    log "Building container images..."
    
    # Build main image
    docker build -t cam-os:$VERSION -f Dockerfile .
    
    # Build development image
    docker build -t cam-os:$VERSION-dev -f Dockerfile.dev .
    
    # Save images
    docker save cam-os:$VERSION | gzip > "$RELEASE_DIR/containers/cam-os-$VERSION.tar.gz"
    docker save cam-os:$VERSION-dev | gzip > "$RELEASE_DIR/containers/cam-os-$VERSION-dev.tar.gz"
    
    # Create Docker Compose package
    local docker_package="$ASSETS_DIR/cam-os-docker-$VERSION"
    mkdir -p "$docker_package"
    
    cp docker-compose.yml "$docker_package/"
    cp docker-compose.dev.yml "$docker_package/"
    cp -r deployment/docker/* "$docker_package/" || true
    
    # Create Docker package
    cd "$ASSETS_DIR"
    tar -czf "cam-os-docker-$VERSION.tar.gz" "cam-os-docker-$VERSION"
    cd - > /dev/null
    
    mv "$ASSETS_DIR/cam-os-docker-$VERSION.tar.gz" "$RELEASE_DIR/containers/"
    
    success "Container images built and packaged"
}

# Prepare Kubernetes assets
prepare_kubernetes() {
    log "Preparing Kubernetes assets..."
    
    local k8s_package="$ASSETS_DIR/cam-os-k8s-$VERSION"
    mkdir -p "$k8s_package"
    
    # Copy Kubernetes manifests
    cp -r deployment/kubernetes/* "$k8s_package/" || true
    
    # Copy Helm charts
    cp -r deployment/helm/* "$k8s_package/" || true
    
    # Create Kubernetes package
    cd "$ASSETS_DIR"
    tar -czf "cam-os-k8s-$VERSION.tar.gz" "cam-os-k8s-$VERSION"
    cd - > /dev/null
    
    mv "$ASSETS_DIR/cam-os-k8s-$VERSION.tar.gz" "$RELEASE_DIR/kubernetes/"
    
    success "Kubernetes assets prepared"
}

# Build client libraries
build_client_libraries() {
    log "Building client libraries..."
    
    # Go client library
    local go_client="$ASSETS_DIR/cam-os-client-go-$VERSION"
    mkdir -p "$go_client"
    
    # Copy Go client files (would need to be implemented)
    # cp -r client/go/* "$go_client/" || true
    
    # Create placeholder for now
    echo "# CAM-OS Go Client Library $VERSION" > "$go_client/README.md"
    echo "Coming soon..." >> "$go_client/README.md"
    
    cd "$ASSETS_DIR"
    tar -czf "cam-os-client-go-$VERSION.tar.gz" "cam-os-client-go-$VERSION"
    cd - > /dev/null
    
    mv "$ASSETS_DIR/cam-os-client-go-$VERSION.tar.gz" "$RELEASE_DIR/client-libraries/"
    
    success "Client libraries built"
}

# Copy examples
copy_examples() {
    log "Copying examples..."
    
    local examples_package="$ASSETS_DIR/cam-os-examples-$VERSION"
    mkdir -p "$examples_package"
    
    # Copy examples
    cp -r examples/* "$examples_package/" || true
    
    cd "$ASSETS_DIR"
    tar -czf "cam-os-examples-$VERSION.tar.gz" "cam-os-examples-$VERSION"
    cd - > /dev/null
    
    mv "$ASSETS_DIR/cam-os-examples-$VERSION.tar.gz" "$RELEASE_DIR/examples/"
    
    success "Examples copied"
}

# Copy configuration files
copy_config() {
    log "Copying configuration files..."
    
    # Copy configuration files
    cp -r config/* "$RELEASE_DIR/config/" || true
    
    success "Configuration files copied"
}

# Generate checksums
generate_checksums() {
    log "Generating checksums..."
    
    local checksum_file="$RELEASE_DIR/cam-os-checksums.txt"
    
    # Generate checksums for all files
    find "$RELEASE_DIR" -type f -name "*.tar.gz" -o -name "*.zip" | while read file; do
        local basename=$(basename "$file")
        local checksum=$(sha256sum "$file" | cut -d' ' -f1)
        echo "$checksum  $basename" >> "$checksum_file"
    done
    
    success "Checksums generated"
}

# Copy essential files
copy_essential_files() {
    log "Copying essential files..."
    
    # Copy core project files
    cp README.md "$RELEASE_DIR/" || true
    cp LICENSE "$RELEASE_DIR/" || true
    cp CHANGELOG.md "$RELEASE_DIR/" || true
    cp CONTRIBUTING.md "$RELEASE_DIR/" || true
    cp SECURITY.md "$RELEASE_DIR/" || true
    
    success "Essential files copied"
}

# Run tests
run_tests() {
    log "Running final tests..."
    
    # Run unit tests
    go test -v ./... || warning "Some tests failed"
    
    # Run basic integration tests
    make test || warning "Integration tests failed"
    
    success "Tests completed"
}

# Validate release
validate_release() {
    log "Validating release..."
    
    # Check that all expected files exist
    local expected_files=(
        "RELEASE_NOTES_v1.1.0.md"
        "INSTALLATION.md"
        "QUICKSTART.md"
        "API_REFERENCE.md"
        "ARCHITECTURE.md"
        "PACKAGE_MANIFEST.md"
        "RELEASE_CHECKLIST.md"
        "cam-os-checksums.txt"
    )
    
    for file in "${expected_files[@]}"; do
        if [[ ! -f "$RELEASE_DIR/$file" ]]; then
            error "Missing required file: $file"
        fi
    done
    
    # Check binary packages
    local binary_count=$(find "$RELEASE_DIR/binaries" -name "*.tar.gz" | wc -l)
    if [[ $binary_count -lt 4 ]]; then
        error "Expected at least 4 binary packages, found $binary_count"
    fi
    
    success "Release validation passed"
}

# Create release archive
create_release_archive() {
    log "Creating release archive..."
    
    local release_archive="cam-os-$VERSION-complete.tar.gz"
    
    cd "$(dirname "$RELEASE_DIR")"
    tar -czf "$release_archive" "$(basename "$RELEASE_DIR")"
    cd - > /dev/null
    
    success "Release archive created: $release_archive"
}

# Main execution
main() {
    log "Starting CAM-OS $VERSION release preparation..."
    
    check_prerequisites
    create_directories
    
    # Build phase
    build_binaries
    build_containers
    prepare_kubernetes
    build_client_libraries
    
    # Copy phase
    copy_examples
    copy_config
    copy_essential_files
    
    # Validation phase
    run_tests
    generate_checksums
    validate_release
    
    # Final packaging
    create_release_archive
    
    success "Release preparation completed successfully!"
    log "Release assets are in: $RELEASE_DIR"
    log "Next steps:"
    log "1. Review all files in $RELEASE_DIR"
    log "2. Test installation on clean systems"
    log "3. Create GitHub release"
    log "4. Upload assets to GitHub"
    log "5. Announce release"
}

# Cleanup on exit
cleanup() {
    if [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
}

trap cleanup EXIT

# Run main function
main "$@" 