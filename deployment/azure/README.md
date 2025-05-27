# Azure Deployment Guide

## Complete Arbitration Mesh on Azure

This guide provides comprehensive instructions for deploying the Complete Arbitration Mesh to Microsoft Azure using modern Infrastructure as Code practices.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Detailed Deployment](#detailed-deployment)
- [Configuration](#configuration)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)
- [Security](#security)
- [Scaling](#scaling)

## Prerequisites

### Required Tools

1. **Azure Developer CLI (azd)** - v1.5.0 or later
   ```powershell
   # Install via winget
   winget install microsoft.azd
   
   # Or via PowerShell
   powershell -ex AllSigned -c "Invoke-RestMethod 'https://aka.ms/install-azd.ps1' | Invoke-Expression"
   ```

2. **Azure CLI** - v2.50.0 or later
   ```powershell
   # Install via winget
   winget install Microsoft.AzureCLI
   ```

3. **Docker Desktop** - v4.0.0 or later
   ```powershell
   # Install via winget
   winget install Docker.DockerDesktop
   ```

4. **Node.js** - v18.0.0 or later
   ```powershell
   # Install via winget
   winget install OpenJS.NodeJS
   ```

### Azure Requirements

- **Azure Subscription** with the following permissions:
  - Contributor role or higher
  - Ability to create resource groups
  - Ability to assign roles

- **Resource Providers** (automatically registered):
  - Microsoft.App
  - Microsoft.ContainerRegistry
  - Microsoft.KeyVault
  - Microsoft.OperationalInsights
  - Microsoft.Insights

## Quick Start

### 1. Clone and Setup

```powershell
# Clone the repository
git clone https://github.com/cam-protocol/complete-arbitration-mesh.git
cd Complete-Arbitration-Mesh-Final

# Install dependencies
npm install
```

### 2. Authentication

```powershell
# Login to Azure
az login

# Set subscription (optional)
az account set --subscription "your-subscription-id"
```

### 3. Deploy

```powershell
# Quick deployment
./scripts/deploy-azure.ps1 -EnvironmentName "cam-prod" -Location "eastus2"

# Or use azd directly
azd up
```

## Detailed Deployment

### Step 1: Environment Configuration

```powershell
# Initialize a new environment
azd env new cam-production

# Configure environment variables
azd env set AZURE_LOCATION eastus2
azd env set JWT_SECRET $(New-Guid | ForEach-Object { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($_)) })

# Optional: Configure external services
azd env set REDIS_URL "your-redis-connection-string"
azd env set DATABASE_URL "your-database-connection-string"
```

### Step 2: Infrastructure Validation

```powershell
# Preview infrastructure changes
azd provision --preview

# Validate Bicep templates
az deployment group validate \
  --resource-group rg-cam-production \
  --template-file infra/main.bicep \
  --parameters @infra/main.parameters.json
```

### Step 3: Deployment

```powershell
# Deploy infrastructure only
azd provision

# Deploy application only
azd deploy

# Deploy everything
azd up
```

### Step 4: Verification

```powershell
# Check deployment status
azd show

# Test the service
$serviceUrl = azd env get-value SERVICE_COMPLETE_ARBITRATION_MESH_URI
Invoke-RestMethod -Uri "$serviceUrl/health"
```

## Configuration

### Environment Variables

| Variable | Required | Description | Default |
|----------|----------|-------------|---------|
| `NODE_ENV` | No | Node.js environment | `production` |
| `PORT` | No | Application port | `8080` |
| `CAM_LOG_LEVEL` | No | Logging level | `info` |
| `JWT_SECRET` | Yes | JWT signing secret | Auto-generated |
| `REDIS_URL` | No | Redis connection string | None |
| `DATABASE_URL` | No | Database connection string | None |

### Azure-Specific Configuration

```powershell
# Set custom container registry
azd env set AZURE_CONTAINER_REGISTRY_NAME "your-registry-name"

# Enable Redis cache
azd env set ENABLE_REDIS true

# Enable PostgreSQL database
azd env set ENABLE_DATABASE true
azd env set DATABASE_ADMIN_PASSWORD "your-secure-password"
```

### Resource Sizing

#### Development Environment
```yaml
# In infra/app.bicep - modify container resources
resources: {
  cpu: json('0.25')
  memory: '0.5Gi'
}
scale: {
  minReplicas: 1
  maxReplicas: 3
}
```

#### Production Environment
```yaml
# In infra/app.bicep - modify container resources
resources: {
  cpu: json('1.0')
  memory: '2.0Gi'
}
scale: {
  minReplicas: 2
  maxReplicas: 20
}
```

## Monitoring

### Built-in Monitoring

The deployment includes comprehensive monitoring:

- **Application Insights** for application telemetry
- **Log Analytics** for centralized logging
- **Metric Alerts** for proactive monitoring
- **Health Checks** for availability monitoring

### Custom Dashboards

```powershell
# Create custom dashboard
az portal dashboard create \
  --resource-group rg-cam-production \
  --name "CAM-Dashboard" \
  --input-path monitoring/dashboard.json
```

### Alert Configuration

Alerts are automatically configured for:
- High CPU usage (>80%)
- High memory usage (>85%)
- High request rate (>1000 req/min)
- Low availability (<95%)

## Security

### Managed Identity

The deployment uses Azure Managed Identity for secure authentication:

```bicep
# Automatic RBAC assignments
- Key Vault Secrets User (for the app)
- ACR Pull (for container images)
- Key Vault Administrator (for deployment user)
```

### Network Security

```powershell
# Optional: Enable private endpoints
azd env set ENABLE_PRIVATE_ENDPOINTS true

# Optional: Restrict ingress to specific IPs
azd env set ALLOWED_IPS "192.168.1.0/24,10.0.0.0/8"
```

### Secrets Management

All secrets are stored in Azure Key Vault:
- JWT signing key
- Database credentials
- External service API keys

## Scaling

### Horizontal Scaling

```powershell
# Update scaling rules in infra/app.bicep
rules: [
  {
    name: 'cpu-scale-rule'
    custom: {
      type: 'cpu'
      metadata: {
        type: 'Utilization'
        value: '70'
      }
    }
  }
  {
    name: 'memory-scale-rule'
    custom: {
      type: 'memory'
      metadata: {
        type: 'Utilization'
        value: '80'
      }
    }
  }
]
```

### Vertical Scaling

```powershell
# Update container resources
resources: {
  cpu: json('2.0')
  memory: '4.0Gi'
}
```

## Troubleshooting

### Common Issues

#### Deployment Failures

```powershell
# Check deployment logs
azd logs

# Check specific service logs
az containerapp logs show \
  --name complete-arbitration-mesh \
  --resource-group rg-cam-production
```

#### Authentication Issues

```powershell
# Refresh Azure credentials
az login --use-device-code

# Check permissions
az role assignment list --assignee $(az account show --query user.name -o tsv)
```

#### Container Issues

```powershell
# Check container app status
az containerapp show \
  --name complete-arbitration-mesh \
  --resource-group rg-cam-production \
  --query "properties.provisioningState"

# Check container logs
az containerapp logs show \
  --name complete-arbitration-mesh \
  --resource-group rg-cam-production \
  --follow
```

### Performance Issues

```powershell
# Check resource utilization
az monitor metrics list \
  --resource complete-arbitration-mesh \
  --resource-group rg-cam-production \
  --resource-type Microsoft.App/containerApps \
  --metric CpuPercentage,MemoryPercentage \
  --interval PT1M
```

### Recovery Procedures

#### Rollback Deployment

```powershell
# List revisions
az containerapp revision list \
  --name complete-arbitration-mesh \
  --resource-group rg-cam-production

# Activate previous revision
az containerapp revision activate \
  --name complete-arbitration-mesh \
  --resource-group rg-cam-production \
  --revision-name "previous-revision-name"
```

#### Disaster Recovery

```powershell
# Backup Key Vault secrets
az keyvault secret backup \
  --vault-name your-keyvault \
  --name jwt-secret \
  --file jwt-secret-backup.blob

# Restore in new region
az keyvault secret restore \
  --vault-name new-keyvault \
  --file jwt-secret-backup.blob
```

## Support

### Documentation
- [Azure Container Apps Documentation](https://docs.microsoft.com/en-us/azure/container-apps/)
- [Azure Developer CLI Documentation](https://docs.microsoft.com/en-us/azure/developer/azure-developer-cli/)
- [Complete Arbitration Mesh Documentation](../docs/README.md)

### Community
- [GitHub Issues](https://github.com/cam-protocol/complete-arbitration-mesh/issues)
- [Discussions](https://github.com/cam-protocol/complete-arbitration-mesh/discussions)

### Enterprise Support
For enterprise support and professional services, contact: enterprise@cam-protocol.com
