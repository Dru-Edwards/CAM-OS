#!/bin/bash

# CAM-OS Protobuf Generation Script
# This script generates Go protobuf and gRPC files from the proto definitions

set -e

echo "🔄 Generating CAM-OS protobuf files..."

# Check if protoc is installed
if ! command -v protoc &> /dev/null; then
    echo "❌ protoc not found. Please install Protocol Buffers compiler:"
    echo "   - Ubuntu/Debian: sudo apt-get install protobuf-compiler"
    echo "   - macOS: brew install protobuf"
    echo "   - Windows: Download from https://github.com/protocolbuffers/protobuf/releases"
    exit 1
fi

# Check if Go protobuf plugins are installed
if ! command -v protoc-gen-go &> /dev/null; then
    echo "📦 Installing protoc-gen-go..."
    go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
fi

if ! command -v protoc-gen-go-grpc &> /dev/null; then
    echo "📦 Installing protoc-gen-go-grpc..."
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
fi

# Create output directory if it doesn't exist
mkdir -p proto/generated

# Change to proto directory
cd proto

echo "🔄 Generating protobuf files..."

# Generate Go protobuf and gRPC files
protoc --go_out=generated \
       --go-grpc_out=generated \
       --go_opt=paths=source_relative \
       --go-grpc_opt=paths=source_relative \
       syscall.proto

echo "✅ Protobuf generation complete!"
echo "   Generated files:"
echo "   - proto/generated/syscall.pb.go"
echo "   - proto/generated/syscall_grpc.pb.go"

# Verify the generated files exist
if [ -f "generated/syscall.pb.go" ] && [ -f "generated/syscall_grpc.pb.go" ]; then
    echo "✅ All protobuf files generated successfully"
else
    echo "❌ Some protobuf files were not generated"
    exit 1
fi 