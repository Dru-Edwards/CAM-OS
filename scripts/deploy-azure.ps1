#!/usr/bin/env pwsh

# Azure deployment script for Complete Arbitration Mesh
# This script automates the deployment process using Azure Developer CLI

param(
    [Parameter(Mandatory=$true)]
    [string]$EnvironmentName,
    
    [Parameter(Mandatory=$true)]
    [string]$Location,
    
    [Parameter(Mandatory=$false)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipBuild,
    
    [Parameter(Mandatory=$false)]
    [switch]$Production
)

# Set error action preference
$ErrorActionPreference = "Stop"

Write-Host "🚀 Starting Complete Arbitration Mesh deployment..." -ForegroundColor Green

# Validate prerequisites
Write-Host "📋 Checking prerequisites..." -ForegroundColor Yellow

# Check if azd is installed
if (!(Get-Command "azd" -ErrorAction SilentlyContinue)) {
    Write-Error "Azure Developer CLI (azd) is not installed. Please install it from: https://aka.ms/azd-install"
    exit 1
}

# Check if az CLI is installed
if (!(Get-Command "az" -ErrorAction SilentlyContinue)) {
    Write-Error "Azure CLI (az) is not installed. Please install it from: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
    exit 1
}

# Check if docker is installed and running
if (!(Get-Command "docker" -ErrorAction SilentlyContinue)) {
    Write-Error "Docker is not installed. Please install it from: https://docs.docker.com/get-docker/"
    exit 1
}

try {
    docker version | Out-Null
} catch {
    Write-Error "Docker is not running. Please start Docker Desktop."
    exit 1
}

Write-Host "✅ Prerequisites check passed" -ForegroundColor Green

# Set environment variables
$env:AZURE_ENV_NAME = $EnvironmentName
$env:AZURE_LOCATION = $Location

if ($SubscriptionId) {
    $env:AZURE_SUBSCRIPTION_ID = $SubscriptionId
}

# Login to Azure if needed
Write-Host "🔐 Checking Azure authentication..." -ForegroundColor Yellow
$authStatus = az account show --query "state" -o tsv 2>$null
if ($authStatus -ne "Enabled") {
    Write-Host "Please log in to Azure..." -ForegroundColor Yellow
    az login
}

# Set subscription if provided
if ($SubscriptionId) {
    Write-Host "🎯 Setting subscription to $SubscriptionId..." -ForegroundColor Yellow
    az account set --subscription $SubscriptionId
}

# Initialize azd environment if not exists
if (!(Test-Path ".azure/$EnvironmentName")) {
    Write-Host "🏗️ Initializing azd environment..." -ForegroundColor Yellow
    azd env new $EnvironmentName
}

# Set azd environment
azd env select $EnvironmentName

# Generate JWT secret if not provided
$jwtSecret = $env:JWT_SECRET
if (!$jwtSecret) {
    Write-Host "🔑 Generating JWT secret..." -ForegroundColor Yellow
    $jwtSecret = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes([System.Guid]::NewGuid().ToString() + [System.Guid]::NewGuid().ToString()))
    azd env set JWT_SECRET $jwtSecret
}

# Build the application if not skipped
if (!$SkipBuild) {
    Write-Host "🔨 Building application..." -ForegroundColor Yellow
    npm run build
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Build failed"
        exit 1
    }
}

# Deploy infrastructure and application
Write-Host "☁️ Deploying to Azure..." -ForegroundColor Yellow

if ($Production) {
    # Production deployment with validation
    Write-Host "🏭 Production deployment - validating first..." -ForegroundColor Yellow
    azd provision --preview
    
    $confirmation = Read-Host "Do you want to proceed with the production deployment? (y/N)"
    if ($confirmation -ne "y" -and $confirmation -ne "Y") {
        Write-Host "❌ Deployment cancelled" -ForegroundColor Red
        exit 0
    }
}

# Deploy
azd up

if ($LASTEXITCODE -ne 0) {
    Write-Error "Deployment failed"
    exit 1
}

# Get deployment outputs
Write-Host "📊 Getting deployment information..." -ForegroundColor Yellow
$outputs = azd env get-values --output json | ConvertFrom-Json

# Display deployment summary
Write-Host "`n🎉 Deployment completed successfully!" -ForegroundColor Green
Write-Host "─────────────────────────────────────────" -ForegroundColor Gray
Write-Host "Environment: $EnvironmentName" -ForegroundColor Cyan
Write-Host "Location: $Location" -ForegroundColor Cyan
Write-Host "Resource Group: $($outputs.AZURE_RESOURCE_GROUP)" -ForegroundColor Cyan
Write-Host "Service URL: $($outputs.SERVICE_COMPLETE_ARBITRATION_MESH_URI)" -ForegroundColor Cyan
Write-Host "Container Registry: $($outputs.AZURE_CONTAINER_REGISTRY_NAME)" -ForegroundColor Cyan
Write-Host "─────────────────────────────────────────" -ForegroundColor Gray

# Verify deployment
Write-Host "🔍 Verifying deployment..." -ForegroundColor Yellow
$serviceUrl = $outputs.SERVICE_COMPLETE_ARBITRATION_MESH_URI
if ($serviceUrl) {
    try {
        $response = Invoke-RestMethod -Uri "$serviceUrl/health" -Method Get -TimeoutSec 30
        Write-Host "✅ Health check passed" -ForegroundColor Green
    } catch {
        Write-Warning "⚠️ Health check failed - service might still be starting up"
    }
}

Write-Host "`n🌟 Complete Arbitration Mesh is now running on Azure!" -ForegroundColor Green
Write-Host "Visit: $serviceUrl" -ForegroundColor Cyan
