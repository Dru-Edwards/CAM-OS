# CAM-OS Kernel Quick Start Script for Windows
# This script helps you quickly set up and run the CAM-OS kernel for demonstration purposes

# Colors for better readability
$Green = @{ ForegroundColor = 'Green' }
$Blue = @{ ForegroundColor = 'Blue' }
$Yellow = @{ ForegroundColor = 'Yellow' }
$Red = @{ ForegroundColor = 'Red' }

Write-Host "============================================" @Blue
Write-Host "   CAM-OS Kernel - Quick Start Demo Script   " @Blue
Write-Host "============================================" @Blue
Write-Host ""

# Check if Docker is installed
try {
    $dockerVersion = docker --version
} catch {
    Write-Host "Error: Docker is not installed. Please install Docker first." @Red
    Write-Host "Visit https://docs.docker.com/get-docker/ for installation instructions."
    exit 1
}

# Check if Docker Compose is installed
try {
    $dockerComposeVersion = docker-compose --version
} catch {
    Write-Host "Error: Docker Compose is not installed. Please install Docker Compose first." @Red
    Write-Host "Visit https://docs.docker.com/compose/install/ for installation instructions."
    exit 1
}

# Check if grpcurl is available (for testing)
try {
    $grpcurlVersion = grpcurl --version
} catch {
    Write-Host "Note: grpcurl is not installed. You can install it to test the kernel." @Yellow
    Write-Host "Visit https://github.com/fullstorydev/grpcurl for installation instructions."
}

# Create .env file if it doesn't exist
if (-not (Test-Path .env)) {
    Write-Host "Creating .env file with demo settings..." @Yellow
    @"
# CAM-OS Kernel Demo Environment
# For production use, replace these with your actual settings

# Kernel Configuration
CAM_LOG_LEVEL=info
CAM_GRPC_PORT=8080
CAM_METRICS_PORT=9090
CAM_DEVELOPMENT=true

# Redis Configuration
CAM_REDIS_URL=redis://redis:6379

# Database Configuration
CAM_POSTGRES_URL=postgres://cam_user:cam_password@postgres:5432/cam_db

# Security Configuration (Demo Mode)
CAM_SECURITY_ENABLED=false
CAM_TPM_ENABLED=false
CAM_POST_QUANTUM_ENABLED=false
"@ | Out-File -FilePath .env -Encoding utf8
    Write-Host "Created .env file with demo settings." @Green
}

# Create necessary directories
New-Item -ItemType Directory -Force -Path drivers | Out-Null
New-Item -ItemType Directory -Force -Path monitoring/prometheus | Out-Null
New-Item -ItemType Directory -Force -Path monitoring/grafana/provisioning/datasources | Out-Null
New-Item -ItemType Directory -Force -Path monitoring/grafana/provisioning/dashboards | Out-Null
New-Item -ItemType Directory -Force -Path monitoring/grafana/dashboards | Out-Null

# Create basic prometheus config for kernel metrics
if (-not (Test-Path monitoring/prometheus/prometheus.yml)) {
    Write-Host "Creating Prometheus configuration for kernel metrics..." @Yellow
    @"
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'cam-kernel'
    static_configs:
      - targets: ['cam-kernel:9090']
    metrics_path: '/metrics'

  - job_name: 'driver-runtime'
    static_configs:
      - targets: ['driver-runtime:8081']
    metrics_path: '/metrics'

  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
"@ | Out-File -FilePath monitoring/prometheus/prometheus.yml -Encoding utf8
    Write-Host "Created Prometheus configuration." @Green
}

# Create Grafana datasource config
if (-not (Test-Path monitoring/grafana/provisioning/datasources/datasource.yml)) {
    Write-Host "Creating Grafana datasource configuration..." @Yellow
    @"
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    orgId: 1
    url: http://prometheus:9090
    isDefault: true
    version: 1
    editable: false
"@ | Out-File -FilePath monitoring/grafana/provisioning/datasources/datasource.yml -Encoding utf8
    Write-Host "Created Grafana datasource configuration." @Green
}

# Create Grafana dashboard provisioning config
if (-not (Test-Path monitoring/grafana/provisioning/dashboards/dashboards.yml)) {
    Write-Host "Creating Grafana dashboard provisioning configuration..." @Yellow
    @"
apiVersion: 1

providers:
  - name: 'CAM-OS Kernel'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    allowUiUpdates: true
    options:
      path: /var/lib/grafana/dashboards
      foldersFromFilesStructure: true
"@ | Out-File -FilePath monitoring/grafana/provisioning/dashboards/dashboards.yml -Encoding utf8
    Write-Host "Created Grafana dashboard provisioning configuration." @Green
}

# Create basic CAM-OS kernel manifest if it doesn't exist
if (-not (Test-Path MANIFEST.toml)) {
    Write-Host "Using existing kernel manifest..." @Yellow
    Write-Host "Kernel manifest already exists." @Green
}

Write-Host "Starting CAM-OS kernel services..." @Yellow
docker-compose up -d

Write-Host ""
Write-Host "=== CAM-OS Kernel Demo is now running! ===" @Green
Write-Host ""
Write-Host "Access the following services:"
Write-Host "  - CAM-OS Kernel gRPC API: localhost:8080" @Blue
Write-Host "  - Kernel Metrics: http://localhost:9090" @Blue
Write-Host "  - Driver Runtime: http://localhost:8081" @Blue
Write-Host "  - Grafana Dashboard: http://localhost:3000 (admin/admin)" @Blue
Write-Host "  - Prometheus: http://localhost:9091" @Blue
Write-Host "  - Redis: localhost:6379" @Blue
Write-Host "  - PostgreSQL: localhost:5432" @Blue
Write-Host ""
Write-Host "Try test syscalls (requires grpcurl):" @Yellow
Write-Host "# Health check syscall"
Write-Host 'grpcurl -plaintext -d "{}" localhost:8080 syscall.SyscallService/HealthCheck'
Write-Host ""
Write-Host "# Arbitration syscall"
Write-Host 'grpcurl -plaintext -d "{\"task_id\": \"test-001\", \"options\": {\"provider\": \"demo\"}}" localhost:8080 syscall.SyscallService/Arbitrate'
Write-Host ""
Write-Host "View kernel logs:" @Yellow
Write-Host "docker logs cam-kernel -f"
Write-Host ""
Write-Host "To stop the demo:" @Yellow
Write-Host "docker-compose down"
Write-Host ""
Write-Host "============================================" @Blue
Write-Host "   Thank you for trying CAM-OS Kernel!     " @Blue
Write-Host "============================================" @Blue
