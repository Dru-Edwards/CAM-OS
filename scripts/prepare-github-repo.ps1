# CAM-OS Kernel GitHub Repository Preparation Script (PowerShell)
# This script prepares the repository for publication on GitHub

param(
    [switch]$SkipTests,
    [switch]$SkipDocker,
    [switch]$Verbose
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Colors for output
function Write-Info($message) {
    Write-Host "[INFO] $message" -ForegroundColor Blue
}

function Write-Success($message) {
    Write-Host "[SUCCESS] $message" -ForegroundColor Green
}

function Write-Warning($message) {
    Write-Host "[WARNING] $message" -ForegroundColor Yellow
}

function Write-Error($message) {
    Write-Host "[ERROR] $message" -ForegroundColor Red
    exit 1
}

# Check if we're in the right directory
function Test-RepositoryRoot {
    if (!(Test-Path "go.mod") -or !(Test-Path "MANIFEST.toml")) {
        Write-Error "This script must be run from the CAM-OS kernel root directory"
    }
    Write-Info "✓ Repository root directory confirmed"
}

# Clean up temporary and generated files
function Clear-Repository {
    Write-Info "Cleaning up repository..."
    
    # Remove build artifacts
    @("build", "dist", "bin") | ForEach-Object {
        if (Test-Path $_) { Remove-Item $_ -Recurse -Force }
    }
    
    # Remove log and profile files
    Get-ChildItem -Filter "*.log" | Remove-Item -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Filter "*.out" | Remove-Item -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Filter "*.prof" | Remove-Item -Force -ErrorAction SilentlyContinue
    
    # Remove temporary directories
    @("tmp", "temp", ".cache") | ForEach-Object {
        if (Test-Path $_) { Remove-Item $_ -Recurse -Force }
    }
    
    # Remove IDE files
    @(".vscode", ".idea") | ForEach-Object {
        if (Test-Path $_) { Remove-Item $_ -Recurse -Force }
    }
    
    # Remove editor files
    Get-ChildItem -Filter "*.swp" | Remove-Item -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Filter "*.swo" | Remove-Item -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Filter "*~" | Remove-Item -Force -ErrorAction SilentlyContinue
    
    # Remove OS files
    Get-ChildItem -Filter ".DS_Store" -Recurse | Remove-Item -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Filter "Thumbs.db" -Recurse | Remove-Item -Force -ErrorAction SilentlyContinue
    
    # Remove development overrides
    @("MANIFEST.toml.local", "config.local.toml", "docker-compose.override.yml", "docker-compose.local.yml") | ForEach-Object {
        if (Test-Path $_) { Remove-Item $_ -Force }
    }
    
    Write-Success "Repository cleaned up"
}

# Validate Go modules and dependencies
function Test-GoModules {
    Write-Info "Validating Go modules..."
    
    # Check if Go is installed
    try {
        $goVersion = go version
        Write-Info "Found Go: $goVersion"
    }
    catch {
        Write-Error "Go is not installed or not in PATH"
    }
    
    # Check Go version
    $versionString = (go version).Split()[2] -replace "go", ""
    $version = [Version]$versionString
    $minVersion = [Version]"1.21.0"
    
    if ($version -lt $minVersion) {
        Write-Error "Go 1.21 or later is required (found: $versionString)"
    }
    
    # Validate modules
    try {
        go mod verify
        go mod tidy
    }
    catch {
        Write-Error "Go module validation failed: $_"
    }
    
    Write-Success "Go modules validated"
}

# Generate protobuf code
function New-ProtobufCode {
    Write-Info "Generating Protocol Buffer code..."
    
    # Check if protoc is installed
    try {
        protoc --version | Out-Null
    }
    catch {
        Write-Error "protoc (Protocol Buffer compiler) is not installed"
    }
    
    # Create output directory
    if (!(Test-Path "proto/generated")) {
        New-Item -ItemType Directory -Path "proto/generated" -Force | Out-Null
    }
    
    # Generate Go code
    try {
        protoc --go_out=proto/generated --go-grpc_out=proto/generated --proto_path=proto proto/syscall.proto
    }
    catch {
        Write-Error "Failed to generate protobuf code: $_"
    }
    
    if (!(Test-Path "proto/generated/syscall.pb.go")) {
        Write-Error "Failed to generate protobuf code"
    }
    
    Write-Success "Protocol Buffer code generated"
}

# Format code
function Format-Code {
    Write-Info "Formatting Go code..."
    
    try {
        go fmt ./...
    }
    catch {
        Write-Error "Code formatting failed: $_"
    }
    
    # Import formatting (if goimports is available)
    try {
        goimports -w .
    }
    catch {
        Write-Warning "goimports not found or failed, skipping import formatting"
    }
    
    Write-Success "Code formatted"
}

# Run linters
function Invoke-Linters {
    Write-Info "Running code linters..."
    
    # Go vet
    try {
        go vet ./...
    }
    catch {
        Write-Error "go vet failed: $_"
    }
    
    # golangci-lint (if available)
    try {
        golangci-lint run ./...
    }
    catch {
        Write-Warning "golangci-lint not found or failed, skipping advanced linting"
    }
    
    Write-Success "Linting completed"
}

# Run tests
function Invoke-Tests {
    if ($SkipTests) {
        Write-Info "Skipping tests (SkipTests flag set)"
        return
    }
    
    Write-Info "Running test suite..."
    
    try {
        go test -race -cover ./...
    }
    catch {
        Write-Error "Unit tests failed: $_"
    }
    
    Write-Success "All tests passed"
}

# Build the kernel
function Build-Kernel {
    Write-Info "Building CAM-OS Kernel..."
    
    # Create build directory
    if (!(Test-Path "build")) {
        New-Item -ItemType Directory -Path "build" -Force | Out-Null
    }
    
    # Get build information
    $buildTime = Get-Date -Format "yyyy-MM-dd_HH:mm:ss" -AsUTC
    try {
        $commitHash = git rev-parse --short HEAD
    }
    catch {
        $commitHash = "unknown"
    }
    
    # Build for current platform
    $ldflags = "-X main.Version=dev -X main.BuildTime=$buildTime -X main.CommitHash=$commitHash"
    
    try {
        go build -ldflags $ldflags -o build/cam-kernel.exe ./cmd/cam-kernel
    }
    catch {
        Write-Error "Kernel build failed: $_"
    }
    
    if (!(Test-Path "build/cam-kernel.exe")) {
        Write-Error "Kernel build failed - executable not found"
    }
    
    Write-Success "Kernel built successfully"
}

# Validate Docker setup
function Test-Docker {
    if ($SkipDocker) {
        Write-Info "Skipping Docker validation (SkipDocker flag set)"
        return
    }
    
    Write-Info "Validating Docker configuration..."
    
    # Check if Docker is available
    try {
        docker --version | Out-Null
    }
    catch {
        Write-Warning "Docker not found, skipping Docker validation"
        return
    }
    
    # Check Dockerfile syntax
    try {
        docker build --no-cache -f Dockerfile . -t cam-os-kernel:test | Out-Null
        docker rmi cam-os-kernel:test | Out-Null
    }
    catch {
        Write-Error "Dockerfile build failed: $_"
    }
    
    Write-Success "Docker configuration validated"
}

# Check security best practices
function Test-Security {
    Write-Info "Running security checks..."
    
    $issues = 0
    
    # Check for hardcoded secrets (basic patterns)
    $passwordMatches = Select-String -Path "*.go", "*.toml", "*.yaml", "*.yml" -Pattern "password\s*=" -Exclude "*_test.go", "*example*" -ErrorAction SilentlyContinue
    if ($passwordMatches) {
        Write-Warning "Potential hardcoded passwords found"
        $issues++
    }
    
    $keyMatches = Select-String -Path "*.go", "*.toml" -Pattern "api_key|secret_key|private_key" -Exclude "*_test.go", "*example*" -ErrorAction SilentlyContinue
    if ($keyMatches) {
        Write-Warning "Potential hardcoded API keys found"
        $issues++
    }
    
    if ($issues -eq 0) {
        Write-Success "Security check passed"
    }
    else {
        Write-Warning "Security check found $issues potential issues"
    }
}

# Validate documentation
function Test-Documentation {
    Write-Info "Validating documentation..."
    
    $missingDocs = @()
    $requiredDocs = @("README.md", "LICENSE", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "SECURITY.md")
    
    foreach ($doc in $requiredDocs) {
        if (!(Test-Path $doc)) {
            $missingDocs += $doc
        }
    }
    
    if ($missingDocs.Count -gt 0) {
        Write-Error "Missing documentation files: $($missingDocs -join ', ')"
    }
    
    # Check if README is substantial
    $readmeLines = (Get-Content "README.md" | Measure-Object -Line).Lines
    if ($readmeLines -lt 50) {
        Write-Warning "README.md seems too short (less than 50 lines)"
    }
    
    Write-Success "Documentation validated"
}

# Check GitHub Actions workflow
function Test-GitHubActions {
    Write-Info "Validating GitHub Actions workflows..."
    
    if (!(Test-Path ".github/workflows")) {
        Write-Warning "No GitHub Actions workflows found"
        return
    }
    
    if (!(Test-Path ".github/workflows/ci.yml")) {
        Write-Warning "No CI workflow found"
        return
    }
    
    Write-Success "GitHub Actions workflows validated"
}

# Generate repository statistics
function Get-RepositoryStats {
    Write-Info "Generating repository statistics..."
    
    $goFiles = (Get-ChildItem -Recurse -Filter "*.go" | Where-Object { $_.FullName -notlike "*vendor*" }).Count
    $goLines = (Get-ChildItem -Recurse -Filter "*.go" | Where-Object { $_.FullName -notlike "*vendor*" } | Get-Content | Measure-Object -Line).Lines
    $testFiles = (Get-ChildItem -Recurse -Filter "*_test.go").Count
    $protoFiles = (Get-ChildItem -Recurse -Filter "*.proto").Count
    
    try {
        $totalCommits = git rev-list --count HEAD
        $contributors = (git shortlog -sn | Measure-Object -Line).Lines
    }
    catch {
        $totalCommits = "unknown"
        $contributors = "unknown"
    }
    
    Write-Host "📊 Repository Statistics:" -ForegroundColor Cyan
    Write-Host "   Go files: $goFiles"
    Write-Host "   Lines of Go code: $goLines"
    Write-Host "   Test files: $testFiles"
    Write-Host "   Protocol buffer files: $protoFiles"
    Write-Host "   Total commits: $totalCommits"
    Write-Host "   Contributors: $contributors"
    
    Write-Success "Statistics generated"
}

# Create release checklist
function New-ReleaseChecklist {
    Write-Info "Creating release checklist..."
    
    $checklist = @"
# CAM-OS Kernel Release Checklist

## Pre-Release
- [ ] All tests pass (``make test-all``)
- [ ] Code is formatted (``make fmt``)
- [ ] Linting passes (``make lint``)
- [ ] Security scan passes (``make security-scan``)
- [ ] Performance benchmarks meet targets (``make benchmark``)
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
"@
    
    $checklist | Out-File -FilePath "RELEASE_CHECKLIST.md" -Encoding UTF8
    
    Write-Success "Release checklist created"
}

# Main execution
function Main {
    Write-Host "🧠 CAM-OS Kernel GitHub Repository Preparation" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
    
    Test-RepositoryRoot
    Clear-Repository
    Test-GoModules
    New-ProtobufCode
    Format-Code
    Invoke-Linters
    Invoke-Tests
    Build-Kernel
    Test-Docker
    Test-Security
    Test-Documentation
    Test-GitHubActions
    Get-RepositoryStats
    New-ReleaseChecklist
    
    Write-Host ""
    Write-Host "🎉 Repository preparation completed successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "1. Review and commit any changes"
    Write-Host "2. Create GitHub repository"
    Write-Host "3. Push code to GitHub"
    Write-Host "4. Configure GitHub settings (branch protection, etc.)"
    Write-Host "5. Set up GitHub Actions secrets if needed"
    Write-Host "6. Create initial release"
    Write-Host ""
    Write-Host "Repository is ready for GitHub! 🚀" -ForegroundColor Green
}

# Run main function
try {
    Main
}
catch {
    Write-Error "Script failed: $_"
} 