# CAM-OS Protobuf Generation Script (PowerShell)
# This script generates Go protobuf and gRPC files from the proto definitions

Write-Host "🔄 Generating CAM-OS protobuf files..." -ForegroundColor Green

# Check if protoc is installed
try {
    $null = Get-Command protoc -ErrorAction Stop
} catch {
    Write-Host "❌ protoc not found. Please install Protocol Buffers compiler:" -ForegroundColor Red
    Write-Host "   Download from https://github.com/protocolbuffers/protobuf/releases" -ForegroundColor Yellow
    Write-Host "   Extract and add to PATH" -ForegroundColor Yellow
    exit 1
}

# Check if Go protobuf plugins are installed
try {
    $null = Get-Command protoc-gen-go -ErrorAction Stop
} catch {
    Write-Host "📦 Installing protoc-gen-go..." -ForegroundColor Yellow
    go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
}

try {
    $null = Get-Command protoc-gen-go-grpc -ErrorAction Stop
} catch {
    Write-Host "📦 Installing protoc-gen-go-grpc..." -ForegroundColor Yellow
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
}

# Create output directory if it doesn't exist
if (!(Test-Path "proto/generated")) {
    New-Item -Path "proto/generated" -ItemType Directory -Force | Out-Null
}

# Change to proto directory
Push-Location proto

Write-Host "🔄 Generating protobuf files..." -ForegroundColor Green

try {
    # Generate Go protobuf and gRPC files
    & protoc --go_out=generated `
             --go-grpc_out=generated `
             --go_opt=paths=source_relative `
             --go-grpc_opt=paths=source_relative `
             syscall.proto

    Write-Host "✅ Protobuf generation complete!" -ForegroundColor Green
    Write-Host "   Generated files:" -ForegroundColor Cyan
    Write-Host "   - proto/generated/syscall.pb.go" -ForegroundColor Cyan
    Write-Host "   - proto/generated/syscall_grpc.pb.go" -ForegroundColor Cyan

    # Verify the generated files exist
    if ((Test-Path "generated/syscall.pb.go") -and (Test-Path "generated/syscall_grpc.pb.go")) {
        Write-Host "✅ All protobuf files generated successfully" -ForegroundColor Green
    } else {
        Write-Host "❌ Some protobuf files were not generated" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "❌ Failed to generate protobuf files: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
} finally {
    Pop-Location
} 