# Complete Arbitration Mesh - Azure Terraform Module Outputs

# Resource Group
output "resource_group_name" {
  description = "Name of the resource group"
  value       = azurerm_resource_group.main.name
}

output "resource_group_id" {
  description = "ID of the resource group"
  value       = azurerm_resource_group.main.id
}

output "location" {
  description = "Azure region"
  value       = azurerm_resource_group.main.location
}

# Network Outputs
output "vnet_name" {
  description = "Name of the virtual network"
  value       = azurerm_virtual_network.main.name
}

output "vnet_id" {
  description = "ID of the virtual network"
  value       = azurerm_virtual_network.main.id
}

output "app_subnet_id" {
  description = "ID of the application subnet"
  value       = azurerm_subnet.app.id
}

output "db_subnet_id" {
  description = "ID of the database subnet"
  value       = azurerm_subnet.db.id
}

# Database Outputs
output "postgres_server_name" {
  description = "Name of the PostgreSQL server"
  value       = azurerm_postgresql_flexible_server.main.name
}

output "postgres_server_fqdn" {
  description = "FQDN of the PostgreSQL server"
  value       = azurerm_postgresql_flexible_server.main.fqdn
}

output "postgres_database_name" {
  description = "Name of the PostgreSQL database"
  value       = azurerm_postgresql_flexible_server_database.main.name
}

output "postgres_admin_username" {
  description = "PostgreSQL administrator username"
  value       = azurerm_postgresql_flexible_server.main.administrator_login
  sensitive   = true
}

# Redis Outputs
output "redis_cache_name" {
  description = "Name of the Redis cache"
  value       = azurerm_redis_cache.main.name
}

output "redis_hostname" {
  description = "Redis cache hostname"
  value       = azurerm_redis_cache.main.hostname
}

output "redis_ssl_port" {
  description = "Redis cache SSL port"
  value       = azurerm_redis_cache.main.ssl_port
}

output "redis_primary_access_key" {
  description = "Redis cache primary access key"
  value       = azurerm_redis_cache.main.primary_access_key
  sensitive   = true
}

# Container App Outputs
output "container_app_name" {
  description = "Name of the container app"
  value       = azurerm_container_app.main.name
}

output "container_app_fqdn" {
  description = "FQDN of the container app"
  value       = azurerm_container_app.main.latest_revision_fqdn
}

output "container_app_url" {
  description = "URL of the container app"
  value       = "https://${azurerm_container_app.main.latest_revision_fqdn}"
}

output "container_app_environment_name" {
  description = "Name of the container app environment"
  value       = azurerm_container_app_environment.main.name
}

# Container Registry Outputs
output "container_registry_name" {
  description = "Name of the container registry"
  value       = azurerm_container_registry.main.name
}

output "container_registry_login_server" {
  description = "Login server of the container registry"
  value       = azurerm_container_registry.main.login_server
}

output "container_registry_id" {
  description = "ID of the container registry"
  value       = azurerm_container_registry.main.id
}

# Storage Outputs
output "storage_account_name" {
  description = "Name of the storage account"
  value       = azurerm_storage_account.main.name
}

output "storage_account_primary_endpoint" {
  description = "Primary endpoint of the storage account"
  value       = azurerm_storage_account.main.primary_blob_endpoint
}

output "storage_container_name" {
  description = "Name of the storage container"
  value       = azurerm_storage_container.assets.name
}

# Key Vault Outputs
output "key_vault_name" {
  description = "Name of the Key Vault"
  value       = azurerm_key_vault.main.name
}

output "key_vault_uri" {
  description = "URI of the Key Vault"
  value       = azurerm_key_vault.main.vault_uri
}

output "key_vault_id" {
  description = "ID of the Key Vault"
  value       = azurerm_key_vault.main.id
}

# Monitoring Outputs
output "log_analytics_workspace_name" {
  description = "Name of the Log Analytics workspace"
  value       = azurerm_log_analytics_workspace.main.name
}

output "log_analytics_workspace_id" {
  description = "ID of the Log Analytics workspace"
  value       = azurerm_log_analytics_workspace.main.id
}

output "application_insights_name" {
  description = "Name of Application Insights"
  value       = azurerm_application_insights.main.name
}

output "application_insights_instrumentation_key" {
  description = "Application Insights instrumentation key"
  value       = azurerm_application_insights.main.instrumentation_key
  sensitive   = true
}

output "application_insights_connection_string" {
  description = "Application Insights connection string"
  value       = azurerm_application_insights.main.connection_string
  sensitive   = true
}

# Identity Outputs
output "user_assigned_identity_id" {
  description = "ID of the user assigned identity"
  value       = azurerm_user_assigned_identity.container_apps.id
}

output "user_assigned_identity_principal_id" {
  description = "Principal ID of the user assigned identity"
  value       = azurerm_user_assigned_identity.container_apps.principal_id
}

output "user_assigned_identity_client_id" {
  description = "Client ID of the user assigned identity"
  value       = azurerm_user_assigned_identity.container_apps.client_id
}

# DNS Outputs
output "private_dns_zone_name" {
  description = "Name of the private DNS zone"
  value       = azurerm_private_dns_zone.postgres.name
}

output "private_dns_zone_id" {
  description = "ID of the private DNS zone"
  value       = azurerm_private_dns_zone.postgres.id
}

# Security Outputs
output "network_security_group_id" {
  description = "ID of the database network security group"
  value       = azurerm_network_security_group.db.id
}

# Monitoring Action Group
output "action_group_id" {
  description = "ID of the monitoring action group"
  value       = var.enable_monitoring ? azurerm_monitor_action_group.main[0].id : null
}

# Connection Strings
output "database_connection_string" {
  description = "Database connection string"
  value       = "postgresql://${azurerm_postgresql_flexible_server.main.administrator_login}:${random_password.db_password.result}@${azurerm_postgresql_flexible_server.main.fqdn}:5432/${azurerm_postgresql_flexible_server_database.main.name}?sslmode=require"
  sensitive   = true
}

output "redis_connection_string" {
  description = "Redis connection string"
  value       = "rediss://:${azurerm_redis_cache.main.primary_access_key}@${azurerm_redis_cache.main.hostname}:${azurerm_redis_cache.main.ssl_port}"
  sensitive   = true
}

# Environment Information
output "environment" {
  description = "Environment name"
  value       = var.environment
}

output "project_name" {
  description = "Project name"
  value       = var.project_name
}

output "name_prefix" {
  description = "Name prefix used for resources"
  value       = local.name_prefix
}

output "common_tags" {
  description = "Common tags applied to resources"
  value       = local.common_tags
}

# Health Check URLs
output "health_check_urls" {
  description = "Health check URLs"
  value = {
    container_app = "https://${azurerm_container_app.main.latest_revision_fqdn}/health"
  }
}

# Backup Vault (if enabled)
output "backup_vault_name" {
  description = "Name of the backup vault"
  value       = var.enable_backup ? azurerm_data_protection_backup_vault.main[0].name : null
}

output "backup_vault_id" {
  description = "ID of the backup vault"
  value       = var.enable_backup ? azurerm_data_protection_backup_vault.main[0].id : null
}

# Resource Summary
output "resource_summary" {
  description = "Summary of created resources"
  value = {
    resource_group          = azurerm_resource_group.main.name
    virtual_network         = azurerm_virtual_network.main.name
    postgres_server         = azurerm_postgresql_flexible_server.main.name
    redis_cache            = azurerm_redis_cache.main.name
    container_app          = azurerm_container_app.main.name
    container_registry     = azurerm_container_registry.main.name
    storage_account        = azurerm_storage_account.main.name
    key_vault             = azurerm_key_vault.main.name
    log_analytics         = azurerm_log_analytics_workspace.main.name
    application_insights  = azurerm_application_insights.main.name
    environment           = var.environment
    location              = azurerm_resource_group.main.location
  }
}

# URLs and Endpoints
output "application_endpoints" {
  description = "Application endpoints"
  value = {
    main_app      = "https://${azurerm_container_app.main.latest_revision_fqdn}"
    health_check  = "https://${azurerm_container_app.main.latest_revision_fqdn}/health"
    container_registry = azurerm_container_registry.main.login_server
    storage_blob  = azurerm_storage_account.main.primary_blob_endpoint
  }
}

# Security Information
output "security_info" {
  description = "Security-related information"
  value = {
    key_vault_uri           = azurerm_key_vault.main.vault_uri
    user_identity_client_id = azurerm_user_assigned_identity.container_apps.client_id
    private_dns_zone       = azurerm_private_dns_zone.postgres.name
    network_security_group = azurerm_network_security_group.db.name
  }
}

# Costs and Billing
output "estimated_monthly_cost" {
  description = "Estimated monthly cost (informational)"
  value = "Estimate varies based on usage. Monitor costs in Azure Cost Management."
}
