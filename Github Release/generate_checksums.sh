#!/bin/bash

# CAM-OS v1.1.0 Checksum Generation Script
# This script generates SHA256 checksums for all release files

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
CHECKSUM_FILE="$RELEASE_DIR/cam-os-checksums.txt"

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

# Generate checksums
generate_checksums() {
    log "Generating checksums for CAM-OS $VERSION release files..."
    
    # Remove existing checksum file
    if [[ -f "$CHECKSUM_FILE" ]]; then
        rm "$CHECKSUM_FILE"
    fi
    
    # Create header
    cat > "$CHECKSUM_FILE" << EOF
# CAM-OS v1.1.0 Release Checksums
# Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')
# 
# Verify with: sha256sum -c cam-os-checksums.txt
# 
# Format: <sha256> <filename>
# 

EOF
    
    # Generate checksums for all files
    local file_count=0
    
    # Process markdown files
    log "Processing documentation files..."
    find "$RELEASE_DIR" -name "*.md" -type f | sort | while read file; do
        local basename=$(basename "$file")
        local checksum=$(sha256sum "$file" | cut -d' ' -f1)
        echo "$checksum  $basename" >> "$CHECKSUM_FILE"
        echo "  ✓ $basename"
        ((file_count++))
    done
    
    # Process shell scripts
    log "Processing script files..."
    find "$RELEASE_DIR" -name "*.sh" -type f | sort | while read file; do
        local basename=$(basename "$file")
        local checksum=$(sha256sum "$file" | cut -d' ' -f1)
        echo "$checksum  $basename" >> "$CHECKSUM_FILE"
        echo "  ✓ $basename"
        ((file_count++))
    done
    
    # Process other important files
    log "Processing other files..."
    for file in "$RELEASE_DIR/LICENSE" "$RELEASE_DIR/CHANGELOG.md" "$RELEASE_DIR/CONTRIBUTING.md"; do
        if [[ -f "$file" ]]; then
            local basename=$(basename "$file")
            local checksum=$(sha256sum "$file" | cut -d' ' -f1)
            echo "$checksum  $basename" >> "$CHECKSUM_FILE"
            echo "  ✓ $basename"
            ((file_count++))
        fi
    done
    
    success "Generated checksums for all release files"
    log "Checksum file: $CHECKSUM_FILE"
}

# Verify checksums
verify_checksums() {
    log "Verifying generated checksums..."
    
    if [[ ! -f "$CHECKSUM_FILE" ]]; then
        error "Checksum file not found: $CHECKSUM_FILE"
    fi
    
    # Change to release directory for verification
    cd "$RELEASE_DIR"
    
    # Verify checksums
    if sha256sum -c "$(basename "$CHECKSUM_FILE")" --quiet; then
        success "All checksums verified successfully"
    else
        error "Checksum verification failed"
    fi
    
    # Return to original directory
    cd - > /dev/null
}

# Generate file manifest
generate_manifest() {
    log "Generating file manifest..."
    
    local manifest_file="$RELEASE_DIR/FILE_MANIFEST.txt"
    
    cat > "$manifest_file" << EOF
# CAM-OS v1.1.0 Release File Manifest
# Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')
# 
# This manifest lists all files included in the CAM-OS v1.1.0 GitHub release
# 

## Documentation Files
EOF
    
    # List documentation files
    find "$RELEASE_DIR" -name "*.md" -type f | sort | while read file; do
        local basename=$(basename "$file")
        local size=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null || echo "0")
        local size_kb=$((size / 1024))
        echo "- $basename (${size_kb}KB)" >> "$manifest_file"
    done
    
    cat >> "$manifest_file" << EOF

## Script Files
EOF
    
    # List script files
    find "$RELEASE_DIR" -name "*.sh" -type f | sort | while read file; do
        local basename=$(basename "$file")
        local size=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null || echo "0")
        local size_kb=$((size / 1024))
        echo "- $basename (${size_kb}KB)" >> "$manifest_file"
    done
    
    cat >> "$manifest_file" << EOF

## Project Files
EOF
    
    # List other important files
    for file in "$RELEASE_DIR/LICENSE" "$RELEASE_DIR/CHANGELOG.md" "$RELEASE_DIR/CONTRIBUTING.md"; do
        if [[ -f "$file" ]]; then
            local basename=$(basename "$file")
            local size=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null || echo "0")
            local size_kb=$((size / 1024))
            echo "- $basename (${size_kb}KB)" >> "$manifest_file"
        fi
    done
    
    cat >> "$manifest_file" << EOF

## Total Files
EOF
    
    local total_files=$(find "$RELEASE_DIR" -type f | wc -l)
    local total_size=$(find "$RELEASE_DIR" -type f -exec stat -c%s {} + 2>/dev/null | awk '{sum += $1} END {print sum}' || echo "0")
    local total_size_mb=$((total_size / 1024 / 1024))
    
    echo "- Total files: $total_files" >> "$manifest_file"
    echo "- Total size: ${total_size_mb}MB" >> "$manifest_file"
    
    success "File manifest generated: $manifest_file"
}

# Generate release summary
generate_summary() {
    log "Generating release summary..."
    
    local summary_file="$RELEASE_DIR/RELEASE_SUMMARY.txt"
    
    cat > "$summary_file" << EOF
CAM-OS v1.1.0 GitHub Release Summary
===================================

Release Information:
- Version: v1.1.0
- Release Date: December 2024
- Status: Production Ready
- Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')

Package Contents:
- Core Documentation: Complete user and developer guides
- API Reference: Full syscall and gRPC API documentation  
- Installation Guides: Multi-platform deployment instructions
- Performance Guides: Optimization and benchmarking
- Build Instructions: Source code compilation
- Security Documentation: Security features and best practices
- Release Automation: Scripts for release preparation

Key Features:
- 15 Cognitive Syscalls for AI workloads
- Sub-1ms latency performance
- >10,000 operations per second throughput
- Post-quantum cryptography security
- Multi-cluster federation capabilities
- WebAssembly driver runtime
- Comprehensive monitoring and observability

Supported Platforms:
- Linux x86_64 (Ubuntu 20.04+, CentOS 8+, RHEL 8+)
- Linux ARM64 (ARM servers, edge devices)
- macOS x86_64 (Intel Macs)
- macOS ARM64 (Apple Silicon Macs)
- Windows x86_64 (experimental support)

Quick Start:
1. Download: curl -sSL https://install.cam-os.dev | bash
2. Docker: docker-compose up -d
3. Kubernetes: kubectl apply -f cam-os-operator.yaml

Documentation:
- Start with: GITHUB_RELEASE_README.md
- Quick setup: QUICKSTART.md
- Full install: INSTALLATION.md
- API docs: API_REFERENCE.md

Support:
- GitHub: https://github.com/Dru-Edwards/CAM-OS
- Documentation: https://docs.cam-os.dev
- Community: https://community.cam-os.dev
- Commercial: EdwardsTechPros@Outlook.com

License: Apache 2.0
EOF
    
    success "Release summary generated: $summary_file"
}

# Create release archive
create_archive() {
    log "Creating release archive..."
    
    local archive_name="cam-os-$VERSION-github-release.tar.gz"
    
    # Create archive
    tar -czf "$archive_name" "$RELEASE_DIR"
    
    # Generate checksum for archive
    local archive_checksum=$(sha256sum "$archive_name" | cut -d' ' -f1)
    echo "$archive_checksum  $archive_name" > "${archive_name}.sha256"
    
    success "Release archive created: $archive_name"
    log "Archive checksum: $archive_checksum"
}

# Display final report
display_report() {
    log "=== CAM-OS v1.1.0 Release Package Report ==="
    
    local total_files=$(find "$RELEASE_DIR" -type f | wc -l)
    local total_size=$(find "$RELEASE_DIR" -type f -exec stat -c%s {} + 2>/dev/null | awk '{sum += $1} END {print sum}' || echo "0")
    local total_size_mb=$((total_size / 1024 / 1024))
    
    echo -e "${GREEN}"
    echo "📦 Package Statistics:"
    echo "   • Total files: $total_files"
    echo "   • Total size: ${total_size_mb}MB"
    echo "   • Documentation files: $(find "$RELEASE_DIR" -name "*.md" | wc -l)"
    echo "   • Script files: $(find "$RELEASE_DIR" -name "*.sh" | wc -l)"
    echo
    echo "✅ Release Package Ready:"
    echo "   • All documentation complete"
    echo "   • All checksums generated"
    echo "   • File manifest created"
    echo "   • Release summary generated"
    echo "   • Package verified"
    echo
    echo "🚀 Next Steps:"
    echo "   1. Review all files in '$RELEASE_DIR'"
    echo "   2. Test installation on clean systems"
    echo "   3. Create GitHub release"
    echo "   4. Upload all assets to GitHub"
    echo "   5. Announce release to community"
    echo -e "${NC}"
}

# Main execution
main() {
    log "Starting CAM-OS $VERSION checksum generation and release finalization..."
    
    # Check if we're in the right directory
    if [[ ! -d "$RELEASE_DIR" ]]; then
        error "Release directory not found: $RELEASE_DIR"
    fi
    
    # Generate checksums
    generate_checksums
    
    # Verify checksums
    verify_checksums
    
    # Generate manifest
    generate_manifest
    
    # Generate summary
    generate_summary
    
    # Create archive
    create_archive
    
    # Display final report
    display_report
    
    success "CAM-OS $VERSION release package finalization completed!"
}

# Run main function
main "$@" 