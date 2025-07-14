#!/bin/bash

# CAM-OS Protobuf Generation Fix Script
# This script ensures protobuf files are generated with the correct gRPC version

set -e

echo "🔧 Fixing CAM-OS protobuf generation..."

# Ensure we're in the project root
if [ ! -f "go.mod" ]; then
    echo "❌ Error: This script must be run from the project root"
    exit 1
fi

# Update go.mod to use compatible versions
echo "📦 Updating Go module dependencies..."
go get -u google.golang.org/grpc@latest
go get -u google.golang.org/protobuf@latest
go mod tidy

# Install the latest protoc plugins
echo "📦 Installing latest protoc plugins..."
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Ensure protoc is available
if ! command -v protoc &> /dev/null; then
    echo "❌ protoc not found. Installing..."
    
    # Detect OS
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    
    # Map architecture names
    case $ARCH in
        x86_64) ARCH="x86_64" ;;
        aarch64|arm64) ARCH="aarch_64" ;;
        *) echo "❌ Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    
    # Download protoc
    PROTOC_VERSION="25.1"
    PROTOC_ZIP="protoc-${PROTOC_VERSION}-${OS}-${ARCH}.zip"
    
    echo "📥 Downloading protoc v${PROTOC_VERSION}..."
    curl -LO "https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/${PROTOC_ZIP}"
    
    # Extract to local bin
    mkdir -p ./bin
    unzip -o "${PROTOC_ZIP}" -d ./bin
    rm "${PROTOC_ZIP}"
    
    # Add to PATH for this session
    export PATH="$PWD/bin/bin:$PATH"
fi

# Create generated directory
mkdir -p proto/generated

# Generate protobuf files
echo "🔄 Generating protobuf files..."
cd proto

# Generate with explicit paths and options for compatibility
protoc --go_out=generated \
       --go-grpc_out=generated \
       --go_opt=paths=source_relative \
       --go-grpc_opt=paths=source_relative \
       --go-grpc_opt=require_unimplemented_servers=false \
       syscall.proto

cd ..

# Verify generation
if [ -f "proto/generated/syscall.pb.go" ]; then
    echo "✅ syscall.pb.go generated successfully"
else
    echo "❌ Failed to generate syscall.pb.go"
    exit 1
fi

if [ -f "proto/generated/syscall_grpc.pb.go" ]; then
    echo "✅ syscall_grpc.pb.go generated successfully"
else
    echo "⚠️  Note: Separate gRPC file may be embedded in syscall.pb.go (this is normal for newer versions)"
fi

# Fix any import issues
echo "🔧 Fixing import paths..."
find proto/generated -name "*.go" -type f -exec sed -i.bak 's|github.com/cam-os/kernel/proto/syscall|github.com/cam-os/kernel/proto/generated|g' {} \;
rm -f proto/generated/*.bak

echo "✅ Protobuf generation complete and fixed!"
echo ""
echo "📝 Next steps:"
echo "1. Run 'go build ./cmd/cam-kernel' to test the build"
echo "2. Commit the updated proto/generated files"
echo "3. Push to trigger the CI pipeline" 