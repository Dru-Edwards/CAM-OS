// Main Bicep template for Complete Arbitration Mesh deployment
// This template creates a production-ready Container Apps environment with all required dependencies

targetScope = 'subscription'

@minLength(1)
@maxLength(64)
@description('Name of the the environment which is used to generate a short unique hash used in all resources.')
param environmentName string

@minLength(1)
@description('Primary location for all resources')
param location string

@description('Id of the user or app to assign application roles')
param principalId string = ''

@description('Name of the container registry (optional - will be generated if not provided)')
param containerRegistryName string = ''

@secure()
@description('JWT Secret for authentication')
param jwtSecret string

@secure()
@description('Redis connection string')
param redisConnectionString string = ''

@secure()
@description('Database connection string')
param databaseConnectionString string = ''

// Generate a unique suffix for resources
var resourceToken = toLower(uniqueString(subscription().id, environmentName, location))
var prefix = '${environmentName}-${resourceToken}'

// Create resource group
resource rg 'Microsoft.Resources/resourceGroups@2021-04-01' = {
  name: 'rg-${environmentName}'
  location: location
}

// Deploy core infrastructure
module resources 'resources.bicep' = {
  name: 'resources-deployment'
  scope: rg
  params: {
    location: location
    environmentName: environmentName
    resourceToken: resourceToken
    principalId: principalId
    containerRegistryName: containerRegistryName
    jwtSecret: jwtSecret
    redisConnectionString: redisConnectionString
    databaseConnectionString: databaseConnectionString
  }
}

// Deploy the application
module app 'app.bicep' = {
  name: 'app-deployment'
  scope: rg
  params: {
    location: location
    environmentName: environmentName
    resourceToken: resourceToken
    containerAppsEnvironmentName: resources.outputs.containerAppsEnvironmentName
    containerRegistryName: resources.outputs.containerRegistryName
    applicationInsightsConnectionString: resources.outputs.applicationInsightsConnectionString
    keyVaultName: resources.outputs.keyVaultName
    managedIdentityName: resources.outputs.managedIdentityName
  }
}

// Outputs
output AZURE_LOCATION string = location
output AZURE_TENANT_ID string = tenant().tenantId
output AZURE_RESOURCE_GROUP string = rg.name

output AZURE_CONTAINER_REGISTRY_ENDPOINT string = resources.outputs.containerRegistryLoginServer
output AZURE_CONTAINER_REGISTRY_NAME string = resources.outputs.containerRegistryName

output SERVICE_COMPLETE_ARBITRATION_MESH_IDENTITY_PRINCIPAL_ID string = resources.outputs.managedIdentityPrincipalId
output SERVICE_COMPLETE_ARBITRATION_MESH_NAME string = app.outputs.serviceName
output SERVICE_COMPLETE_ARBITRATION_MESH_URI string = app.outputs.serviceUri
