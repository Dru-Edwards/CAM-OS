// Optional Redis Cache for Complete Arbitration Mesh
// This template creates Azure Cache for Redis if needed

param location string = resourceGroup().location
param environmentName string
param resourceToken string
param enableRedis bool = false

// Variables
var prefix = '${environmentName}-${resourceToken}'
var redisName = '${prefix}-redis'
var tags = {
  'azd-env-name': environmentName
  'cam-service': 'complete-arbitration-mesh'
}

// Redis Cache (optional)
resource redisCache 'Microsoft.Cache/redis@2023-08-01' = if (enableRedis) {
  name: redisName
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'Basic'
      family: 'C'
      capacity: 0
    }
    enableNonSslPort: false
    minimumTlsVersion: '1.2'
    publicNetworkAccess: 'Enabled'
    redisConfiguration: {
      'maxmemory-policy': 'allkeys-lru'
    }
  }
}

// Outputs
output redisHostName string = enableRedis ? redisCache.properties.hostName : ''
output redisPrimaryKey string = enableRedis ? redisCache.listKeys().primaryKey : ''
output redisConnectionString string = enableRedis ? '${redisCache.properties.hostName}:6380,password=${redisCache.listKeys().primaryKey},ssl=True,abortConnect=False' : ''
