# CAM Protocol Docker Deployment Script for Windows PowerShell
# This script handles Docker-based deployment of CAM Protocol

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("dev", "staging", "production")]
    [string]$Environment = "dev",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("deploy", "start", "stop", "restart", "logs", "status", "cleanup")]
    [string]$Command = "deploy",
    
    [Parameter(Mandatory=$false)]
    [switch]$Verbose = $false
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Configuration
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$PROJECT_ROOT = Split-Path -Parent $SCRIPT_DIR
$DEPLOYMENT_DIR = Join-Path $PROJECT_ROOT "deployment\docker"

# Docker Compose files
$COMPOSE_FILES = @{
    "dev" = "docker-compose.dev.yml"
    "staging" = "docker-compose.prod.yml"
    "production" = "docker-compose.prod.yml"
}

# Colors for output (PowerShell)
$Colors = @{
    Red = "Red"
    Green = "Green"
    Yellow = "Yellow"
    Blue = "Blue"
    White = "White"
}

# Logging functions
function Write-LogInfo {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor $Colors.Blue
}

function Write-LogSuccess {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor $Colors.Green
}

function Write-LogWarning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor $Colors.Yellow
}

function Write-LogError {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor $Colors.Red
}

# Check prerequisites
function Test-Prerequisites {
    Write-LogInfo "Checking prerequisites..."
    
    # Check Docker
    try {
        $dockerVersion = docker --version
        Write-LogInfo "Docker version: $dockerVersion"
    }
    catch {
        Write-LogError "Docker is not installed or not in PATH"
        exit 1
    }
    
    # Check Docker Compose
    try {
        $composeVersion = docker compose version
        Write-LogInfo "Docker Compose version: $composeVersion"
    }
    catch {
        Write-LogError "Docker Compose is not installed or not in PATH"
        exit 1
    }
    
    # Check if Docker daemon is running
    try {
        docker info | Out-Null
    }
    catch {
        Write-LogError "Docker daemon is not running"
        exit 1
    }
    
    Write-LogSuccess "Prerequisites check completed"
}

# Setup environment
function Initialize-Environment {
    Write-LogInfo "Setting up environment for: $Environment"
    
    # Create .env file based on environment
    $envFile = Join-Path $PROJECT_ROOT ".env.$Environment"
    $defaultEnvFile = Join-Path $PROJECT_ROOT ".env"
    
    if (Test-Path $envFile) {
        Copy-Item $envFile $defaultEnvFile -Force
        Write-LogInfo "Environment file copied: $envFile -> $defaultEnvFile"
    } else {
        Write-LogWarning "Environment file not found: $envFile"
        Write-LogInfo "Creating default environment file..."
        
        $defaultEnvContent = @"
NODE_ENV=$Environment
CAM_LOG_LEVEL=info
CAM_JWT_SECRET=cam-jwt-secret-change-in-production
CAM_API_RATE_LIMIT=1000
CAM_REDIS_URL=redis://redis:6379
CAM_DATABASE_URL=postgresql://cam_user:cam_password@postgres:5432/cam_db
"@
        Set-Content -Path $defaultEnvFile -Value $defaultEnvContent
        Write-LogInfo "Default environment file created"
    }
    
    Write-LogSuccess "Environment setup completed"
}

# Build Docker images
function Build-Images {
    Write-LogInfo "Building Docker images..."
    
    Push-Location $PROJECT_ROOT
    try {
        if ($Environment -eq "dev") {
            docker build -f "deployment\docker\Dockerfile.dev" -t "cam-arbitration-mesh:dev" .
        } else {
            docker build -t "cam-arbitration-mesh:latest" .
        }
        Write-LogSuccess "Docker images built successfully"
    }
    catch {
        Write-LogError "Failed to build Docker images: $_"
        exit 1
    }
    finally {
        Pop-Location
    }
}

# Deploy services
function Start-Services {
    Write-LogInfo "Starting services for environment: $Environment"
    
    $composeFile = $COMPOSE_FILES[$Environment]
    $composeFilePath = Join-Path $DEPLOYMENT_DIR $composeFile
    
    if (-not (Test-Path $composeFilePath)) {
        Write-LogError "Docker Compose file not found: $composeFilePath"
        exit 1
    }
    
    Push-Location $DEPLOYMENT_DIR
    try {
        # Pull latest images for production
        if ($Environment -ne "dev") {
            docker compose -f $composeFile pull
        }
        
        # Start services
        docker compose -f $composeFile up -d
        
        # Wait for services to be ready
        Write-LogInfo "Waiting for services to be ready..."
        Start-Sleep -Seconds 10
        
        # Check service health
        Test-ServiceHealth
        
        Write-LogSuccess "Services started successfully"
    }
    catch {
        Write-LogError "Failed to start services: $_"
        exit 1
    }
    finally {
        Pop-Location
    }
}

# Stop services
function Stop-Services {
    Write-LogInfo "Stopping services..."
    
    $composeFile = $COMPOSE_FILES[$Environment]
    
    Push-Location $DEPLOYMENT_DIR
    try {
        docker compose -f $composeFile down
        Write-LogSuccess "Services stopped successfully"
    }
    catch {
        Write-LogError "Failed to stop services: $_"
    }
    finally {
        Pop-Location
    }
}

# Restart services
function Restart-Services {
    Write-LogInfo "Restarting services..."
    Stop-Services
    Start-Sleep -Seconds 5
    Start-Services
}

# Show logs
function Show-Logs {
    Write-LogInfo "Showing logs for environment: $Environment"
    
    $composeFile = $COMPOSE_FILES[$Environment]
    
    Push-Location $DEPLOYMENT_DIR
    try {
        docker compose -f $composeFile logs -f
    }
    catch {
        Write-LogError "Failed to show logs: $_"
    }
    finally {
        Pop-Location
    }
}

# Show status
function Show-Status {
    Write-LogInfo "Current deployment status:"
    
    $composeFile = $COMPOSE_FILES[$Environment]
    
    Push-Location $DEPLOYMENT_DIR
    try {
        Write-Host "`nServices:" -ForegroundColor $Colors.White
        docker compose -f $composeFile ps
        
        Write-Host "`nRunning containers:" -ForegroundColor $Colors.White
        docker ps --filter "label=com.docker.compose.project=cam-arbitration-mesh"
        
        Write-Host "`nResource usage:" -ForegroundColor $Colors.White
        docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}"
    }
    catch {
        Write-LogError "Failed to show status: $_"
    }
    finally {
        Pop-Location
    }
}

# Test service health
function Test-ServiceHealth {
    Write-LogInfo "Testing service health..."
    
    $maxAttempts = 30
    $attempt = 0
    
    do {
        $attempt++
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:8080/health" -UseBasicParsing -TimeoutSec 5
            if ($response.StatusCode -eq 200) {
                Write-LogSuccess "Health check passed"
                return $true
            }
        }
        catch {
            if ($Verbose) {
                Write-LogInfo "Health check attempt $attempt failed: $_"
            }
        }
        
        if ($attempt -lt $maxAttempts) {
            Start-Sleep -Seconds 2
        }
    } while ($attempt -lt $maxAttempts)
    
    Write-LogError "Health check failed after $maxAttempts attempts"
    return $false
}

# Cleanup deployment
function Remove-Deployment {
    Write-LogInfo "Cleaning up deployment..."
    
    $confirmation = Read-Host "Are you sure you want to remove the entire CAM deployment? (y/N)"
    if ($confirmation -eq 'y' -or $confirmation -eq 'Y') {
        $composeFile = $COMPOSE_FILES[$Environment]
        
        Push-Location $DEPLOYMENT_DIR
        try {
            # Stop and remove containers
            docker compose -f $composeFile down -v --remove-orphans
            
            # Remove unused images
            docker image prune -f
            
            # Remove unused volumes
            docker volume prune -f
            
            Write-LogSuccess "Cleanup completed"
        }
        catch {
            Write-LogError "Failed to cleanup: $_"
        }
        finally {
            Pop-Location
        }
    } else {
        Write-LogInfo "Cleanup cancelled"
    }
}

# Main execution
function Main {
    Write-Host "CAM Protocol Docker Deployment Script" -ForegroundColor $Colors.White
    Write-Host "Environment: $Environment" -ForegroundColor $Colors.White
    Write-Host "Command: $Command" -ForegroundColor $Colors.White
    Write-Host ""
    
    switch ($Command) {
        "deploy" {
            Test-Prerequisites
            Initialize-Environment
            Build-Images
            Start-Services
            Write-LogSuccess "Deployment completed successfully!"
            Show-Status
        }
        "start" {
            Start-Services
        }
        "stop" {
            Stop-Services
        }
        "restart" {
            Restart-Services
        }
        "logs" {
            Show-Logs
        }
        "status" {
            Show-Status
        }
        "cleanup" {
            Remove-Deployment
        }
        default {
            Write-Host "Usage: .\deploy-docker.ps1 -Environment <env> -Command <cmd>" -ForegroundColor $Colors.White
            Write-Host "Environments: dev, staging, production" -ForegroundColor $Colors.White
            Write-Host "Commands: deploy, start, stop, restart, logs, status, cleanup" -ForegroundColor $Colors.White
            exit 1
        }
    }
}

# Execute main function
Main
