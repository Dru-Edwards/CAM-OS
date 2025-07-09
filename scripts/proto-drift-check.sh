#!/bin/bash

# Proto Drift Detection Script for CAM-OS Kernel
# Prevents proto file drift by validating generated code matches source

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PROTO_DIR="$PROJECT_ROOT/proto"
GENERATED_DIR="$PROJECT_ROOT/proto/generated"
TEMP_DIR="/tmp/cam-proto-check-$$"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Check if Docker is available
check_docker() {
    if ! command -v docker &> /dev/null; then
        log_error "Docker is required but not installed"
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        exit 1
    fi
}

# Create Dockerfile for proto generation
create_proto_dockerfile() {
    cat > "$TEMP_DIR/Dockerfile" << 'EOF'
FROM golang:1.21-alpine AS builder

# Install protoc and protoc-gen-go
RUN apk add --no-cache protobuf protobuf-dev
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Set working directory
WORKDIR /workspace

# Copy proto files
COPY proto/ ./proto/

# Generate protobuf files
RUN mkdir -p proto/generated && \
    protoc \
        --go_out=proto/generated \
        --go_opt=paths=source_relative \
        --go-grpc_out=proto/generated \
        --go-grpc_opt=paths=source_relative \
        --proto_path=proto \
        proto/*.proto

# Final stage
FROM alpine:latest
WORKDIR /output
COPY --from=builder /workspace/proto/generated/ ./
EOF
}

# Generate proto files using Docker
generate_proto_files() {
    log_info "Creating temporary directory: $TEMP_DIR"
    mkdir -p "$TEMP_DIR"
    
    log_info "Creating Dockerfile for proto generation"
    create_proto_dockerfile
    
    log_info "Building Docker image for proto generation"
    docker build -t cam-proto-gen "$TEMP_DIR" --quiet
    
    log_info "Generating proto files in container"
    docker run --rm -v "$PROJECT_ROOT:/workspace" cam-proto-gen sh -c "
        mkdir -p /workspace/proto/generated-new
        cp -r /output/* /workspace/proto/generated-new/
    "
    
    log_info "Cleaning up Docker image"
    docker rmi cam-proto-gen --force &> /dev/null || true
}

# Compare generated files with existing ones
compare_proto_files() {
    local drift_detected=false
    
    if [ ! -d "$GENERATED_DIR" ]; then
        log_warn "Generated directory does not exist, creating it"
        mkdir -p "$GENERATED_DIR"
        cp -r "$PROJECT_ROOT/proto/generated-new/"* "$GENERATED_DIR/"
        log_success "Initial proto files generated"
        return 0
    fi
    
    log_info "Comparing generated proto files with existing ones"
    
    # Compare each .pb.go file
    for new_file in "$PROJECT_ROOT/proto/generated-new"/*.pb.go; do
        if [ ! -f "$new_file" ]; then
            continue
        fi
        
        filename=$(basename "$new_file")
        existing_file="$GENERATED_DIR/$filename"
        
        if [ ! -f "$existing_file" ]; then
            log_warn "New proto file detected: $filename"
            drift_detected=true
        elif ! diff -q "$new_file" "$existing_file" &> /dev/null; then
            log_error "Proto drift detected in: $filename"
            
            # Show detailed diff if requested
            if [ "${SHOW_DIFF:-false}" = "true" ]; then
                log_info "Showing diff for $filename:"
                diff -u "$existing_file" "$new_file" || true
            fi
            
            drift_detected=true
        else
            log_info "✓ $filename is up to date"
        fi
    done
    
    # Check for removed files
    for existing_file in "$GENERATED_DIR"/*.pb.go; do
        if [ ! -f "$existing_file" ]; then
            continue
        fi
        
        filename=$(basename "$existing_file")
        new_file="$PROJECT_ROOT/proto/generated-new/$filename"
        
        if [ ! -f "$new_file" ]; then
            log_warn "Proto file removed: $filename"
            drift_detected=true
        fi
    done
    
    if [ "$drift_detected" = true ]; then
        return 1
    else
        log_success "No proto drift detected"
        return 0
    fi
}

# Update proto files if drift is detected
update_proto_files() {
    log_info "Updating proto files"
    
    # Backup existing files
    if [ -d "$GENERATED_DIR" ]; then
        backup_dir="$GENERATED_DIR.backup.$(date +%Y%m%d_%H%M%S)"
        log_info "Creating backup: $backup_dir"
        cp -r "$GENERATED_DIR" "$backup_dir"
    fi
    
    # Update with new files
    mkdir -p "$GENERATED_DIR"
    cp -r "$PROJECT_ROOT/proto/generated-new/"* "$GENERATED_DIR/"
    
    log_success "Proto files updated successfully"
}

# Validate proto files
validate_proto_files() {
    log_info "Validating proto file syntax"
    
    for proto_file in "$PROTO_DIR"/*.proto; do
        if [ ! -f "$proto_file" ]; then
            continue
        fi
        
        filename=$(basename "$proto_file")
        log_info "Validating $filename"
        
        # Check syntax using protoc
        if ! docker run --rm -v "$PROJECT_ROOT:/workspace" \
            golang:1.21-alpine sh -c "
                apk add --no-cache protobuf protobuf-dev > /dev/null 2>&1
                protoc --proto_path=/workspace/proto --descriptor_set_out=/dev/null /workspace/proto/$filename
            " &> /dev/null; then
            log_error "Syntax error in $filename"
            return 1
        fi
    done
    
    log_success "All proto files are valid"
}

# Cleanup function
cleanup() {
    if [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
    fi
    
    if [ -d "$PROJECT_ROOT/proto/generated-new" ]; then
        rm -rf "$PROJECT_ROOT/proto/generated-new"
    fi
}

# Trap cleanup on exit
trap cleanup EXIT

# Main function
main() {
    local mode="${1:-check}"
    
    log_info "Starting proto drift detection (mode: $mode)"
    log_info "Project root: $PROJECT_ROOT"
    
    # Check prerequisites
    check_docker
    
    # Validate proto files first
    validate_proto_files
    
    # Generate proto files
    generate_proto_files
    
    # Compare files
    if compare_proto_files; then
        log_success "Proto files are up to date"
        exit 0
    else
        case "$mode" in
            "check")
                log_error "Proto drift detected! Run with 'update' mode to fix."
                log_info "To see detailed diffs, set SHOW_DIFF=true"
                exit 1
                ;;
            "update")
                update_proto_files
                log_success "Proto files updated successfully"
                exit 0
                ;;
            "ci")
                log_error "Proto drift detected in CI! Please regenerate proto files."
                log_info "Run: ./scripts/proto-drift-check.sh update"
                exit 1
                ;;
            *)
                log_error "Invalid mode: $mode. Use 'check', 'update', or 'ci'"
                exit 1
                ;;
        esac
    fi
}

# Show usage if help is requested
if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    cat << EOF
Proto Drift Detection Script for CAM-OS Kernel

Usage: $0 [mode]

Modes:
  check   - Check for proto drift (default)
  update  - Update proto files if drift detected
  ci      - CI mode (fails on drift)

Environment Variables:
  SHOW_DIFF=true  - Show detailed diffs when drift is detected

Examples:
  $0                    # Check for drift
  $0 update            # Update proto files
  $0 ci                # CI mode
  SHOW_DIFF=true $0    # Check with detailed diffs

EOF
    exit 0
fi

# Run main function
main "$@" 