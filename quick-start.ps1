# CAM Protocol Quick Start Script for Windows
# This script helps you quickly set up and run the CAM Protocol for demonstration purposes

# Colors for better readability
$Green = @{ ForegroundColor = 'Green' }
$Blue = @{ ForegroundColor = 'Blue' }
$Yellow = @{ ForegroundColor = 'Yellow' }
$Red = @{ ForegroundColor = 'Red' }

Write-Host "============================================" @Blue
Write-Host "   CAM Protocol - Quick Start Demo Script   " @Blue
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

# Create .env file if it doesn't exist
if (-not (Test-Path .env)) {
    Write-Host "Creating .env file with demo settings..." @Yellow
    @"
# CAM Protocol Demo Environment
# For production use, replace these with your actual API keys

# API Keys (demo mode uses mock services)
OPENAI_API_KEY=demo-key-replace-me
ANTHROPIC_API_KEY=demo-key-replace-me

# Service Configuration
NODE_ENV=development
LOG_LEVEL=info
PORT=8080

# Database Configuration
DB_HOST=postgres
DB_PORT=5432
DB_USER=cam_user
DB_PASSWORD=cam_password
DB_NAME=cam_db

# Redis Configuration
REDIS_HOST=redis
REDIS_PORT=6379
"@ | Out-File -FilePath .env -Encoding utf8
    Write-Host "Created .env file with demo settings." @Green
}

# Create necessary directories
New-Item -ItemType Directory -Force -Path config | Out-Null
New-Item -ItemType Directory -Force -Path monitoring/prometheus | Out-Null
New-Item -ItemType Directory -Force -Path monitoring/grafana/provisioning/datasources | Out-Null
New-Item -ItemType Directory -Force -Path monitoring/grafana/provisioning/dashboards | Out-Null
New-Item -ItemType Directory -Force -Path monitoring/grafana/dashboards | Out-Null

# Create basic prometheus config if it doesn't exist
if (-not (Test-Path monitoring/prometheus/prometheus.yml)) {
    Write-Host "Creating basic Prometheus configuration..." @Yellow
    @"
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'cam-core'
    static_configs:
      - targets: ['cam-core:8080']
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
  - name: 'CAM Protocol'
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

Write-Host "Starting CAM Protocol services..." @Yellow
docker-compose up -d

Write-Host ""
Write-Host "=== CAM Protocol Demo is now running! ===" @Green
Write-Host ""
Write-Host "Access the following services:"
Write-Host "  - CAM Protocol API: http://localhost:8080" @Blue
Write-Host "  - Mock OpenAI API: http://localhost:8081" @Blue
Write-Host "  - Mock Anthropic API: http://localhost:8082" @Blue
Write-Host "  - Grafana Dashboard: http://localhost:3000 (admin/admin)" @Blue
Write-Host "  - Prometheus: http://localhost:9090" @Blue
Write-Host ""
Write-Host "Try a test request:" @Yellow
Write-Host 'curl -X POST http://localhost:8080/mesh/chat -H "Content-Type: application/json" -d "{\"message\": \"Hello world\", \"options\": {\"routing\": \"auto\"}}"'
Write-Host ""
Write-Host "To stop the demo:" @Yellow
Write-Host "docker-compose down"
Write-Host ""
Write-Host "============================================" @Blue
Write-Host "   Thank you for trying the CAM Protocol!   " @Blue
Write-Host "============================================" @Blue
