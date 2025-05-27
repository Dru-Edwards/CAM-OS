// Container App deployment for Complete Arbitration Mesh
// Deploys the CAM service as a Container App with proper configuration

param location string = resourceGroup().location
param environmentName string
param resourceToken string
param containerAppsEnvironmentName string
param containerRegistryName string
param applicationInsightsConnectionString string
param keyVaultName string
param managedIdentityName string

// Variables
var prefix = '${environmentName}-${resourceToken}'
var serviceName = '${prefix}-app'
var tags = {
  'azd-env-name': environmentName
  'cam-service': 'complete-arbitration-mesh'
}

// Reference existing resources
resource containerAppsEnvironment 'Microsoft.App/managedEnvironments@2024-03-01' existing = {
  name: containerAppsEnvironmentName
}

resource containerRegistry 'Microsoft.ContainerRegistry/registries@2023-07-01' existing = {
  name: containerRegistryName
}

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: keyVaultName
}

resource managedIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = {
  name: managedIdentityName
}

// Container App
resource containerApp 'Microsoft.App/containerApps@2024-03-01' = {
  name: serviceName
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${managedIdentity.id}': {}
    }
  }
  properties: {
    environmentId: containerAppsEnvironment.id
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        targetPort: 8080
        transport: 'auto'
        corsPolicy: {
          allowedOrigins: ['*']
          allowedMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
          allowedHeaders: ['*']
          allowCredentials: false
        }
        traffic: [
          {
            weight: 100
            latestRevision: true
          }
        ]
      }
      registries: [
        {
          server: containerRegistry.properties.loginServer
          identity: managedIdentity.id
        }
      ]
      secrets: [
        {
          name: 'applicationinsights-connection-string'
          value: applicationInsightsConnectionString
        }
        {
          name: 'jwt-secret'
          keyVaultUrl: '${keyVault.properties.vaultUri}secrets/jwt-secret'
          identity: managedIdentity.id
        }
        {
          name: 'redis-connection-string'
          keyVaultUrl: '${keyVault.properties.vaultUri}secrets/redis-connection-string'
          identity: managedIdentity.id
        }
        {
          name: 'database-connection-string'
          keyVaultUrl: '${keyVault.properties.vaultUri}secrets/database-connection-string'
          identity: managedIdentity.id
        }
      ]
    }
    template: {
      revisionSuffix: resourceToken
      containers: [
        {
          image: '${containerRegistry.properties.loginServer}/complete-arbitration-mesh:latest'
          name: 'complete-arbitration-mesh'
          env: [
            {
              name: 'NODE_ENV'
              value: 'production'
            }
            {
              name: 'PORT'
              value: '8080'
            }
            {
              name: 'CAM_LOG_LEVEL'
              value: 'info'
            }
            {
              name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
              secretRef: 'applicationinsights-connection-string'
            }
            {
              name: 'JWT_SECRET'
              secretRef: 'jwt-secret'
            }
            {
              name: 'REDIS_URL'
              secretRef: 'redis-connection-string'
            }
            {
              name: 'DATABASE_URL'
              secretRef: 'database-connection-string'
            }
          ]
          probes: [
            {
              type: 'Liveness'
              httpGet: {
                path: '/health'
                port: 8080
                scheme: 'HTTP'
              }
              initialDelaySeconds: 30
              periodSeconds: 30
              timeoutSeconds: 5
              failureThreshold: 3
            }
            {
              type: 'Readiness'
              httpGet: {
                path: '/ready'
                port: 8080
                scheme: 'HTTP'
              }
              initialDelaySeconds: 5
              periodSeconds: 10
              timeoutSeconds: 3
              failureThreshold: 3
            }
          ]
          resources: {
            cpu: json('0.5')
            memory: '1.0Gi'
          }
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 10
        rules: [
          {
            name: 'http-scale-rule'
            http: {
              metadata: {
                concurrentRequests: '50'
              }
            }
          }
        ]
      }
    }
  }
}

// Outputs
output serviceName string = containerApp.name
output serviceUri string = 'https://${containerApp.properties.configuration.ingress.fqdn}'
output serviceFqdn string = containerApp.properties.configuration.ingress.fqdn
