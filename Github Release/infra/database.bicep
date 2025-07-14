// Optional PostgreSQL database for Complete Arbitration Mesh
// This template creates Azure Database for PostgreSQL if needed

param location string = resourceGroup().location
param environmentName string
param resourceToken string
param enableDatabase bool = false
param databaseAdminLogin string = 'camadmin'

@secure()
param databaseAdminPassword string = ''

// Variables
var prefix = '${environmentName}-${resourceToken}'
var databaseServerName = '${prefix}-db'
var databaseName = 'cam_database'
var tags = {
  'azd-env-name': environmentName
  'cam-service': 'complete-arbitration-mesh'
}

// PostgreSQL Flexible Server (optional)
resource postgresqlServer 'Microsoft.DBforPostgreSQL/flexibleServers@2023-06-01-preview' = if (enableDatabase) {
  name: databaseServerName
  location: location
  tags: tags
  sku: {
    name: 'Standard_B1ms'
    tier: 'Burstable'
  }
  properties: {
    administratorLogin: databaseAdminLogin
    administratorLoginPassword: databaseAdminPassword
    storage: {
      storageSizeGB: 32
      autoGrow: 'Enabled'
    }
    backup: {
      backupRetentionDays: 7
      geoRedundantBackup: 'Disabled'
    }
    network: {
      publicNetworkAccess: 'Enabled'
    }
    highAvailability: {
      mode: 'Disabled'
    }
    version: '15'
  }
}

// Database
resource database 'Microsoft.DBforPostgreSQL/flexibleServers/databases@2023-06-01-preview' = if (enableDatabase) {
  parent: postgresqlServer
  name: databaseName
  properties: {
    charset: 'UTF8'
    collation: 'en_US.UTF8'
  }
}

// Firewall rule to allow Azure services
resource firewallRule 'Microsoft.DBforPostgreSQL/flexibleServers/firewallRules@2023-06-01-preview' = if (enableDatabase) {
  parent: postgresqlServer
  name: 'AllowAzureServices'
  properties: {
    startIpAddress: '0.0.0.0'
    endIpAddress: '0.0.0.0'
  }
}

// Outputs
output databaseServerName string = enableDatabase ? postgresqlServer.name : ''
output databaseName string = enableDatabase ? database.name : ''
output databaseConnectionString string = enableDatabase ? 'postgresql://${databaseAdminLogin}:${databaseAdminPassword}@${postgresqlServer.properties.fullyQualifiedDomainName}:5432/${databaseName}?sslmode=require' : ''
