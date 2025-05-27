# Complete Arbitration Mesh - Azure Terraform Module Variables

# Project Configuration
variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "cam"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "location" {
  description = "Azure region"
  type        = string
  default     = "East US"
}

# Network Configuration
variable "vnet_cidr" {
  description = "CIDR block for VNet"
  type        = string
  default     = "10.0.0.0/16"
}

variable "app_subnet_cidr" {
  description = "CIDR block for application subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "db_subnet_cidr" {
  description = "CIDR block for database subnet"
  type        = string
  default     = "10.0.2.0/24"
}

# Database Configuration
variable "postgres_version" {
  description = "PostgreSQL version"
  type        = string
  default     = "14"
}

variable "postgres_sku_name" {
  description = "PostgreSQL SKU name"
  type        = string
  default     = "B_Standard_B1ms"
}

variable "postgres_storage_mb" {
  description = "PostgreSQL storage in MB"
  type        = number
  default     = 32768
}

variable "postgres_backup_retention_days" {
  description = "PostgreSQL backup retention days"
  type        = number
  default     = 7
}

variable "postgres_geo_redundant_backup_enabled" {
  description = "Enable geo-redundant backup for PostgreSQL"
  type        = bool
  default     = false
}

variable "postgres_ha_enabled" {
  description = "Enable high availability for PostgreSQL"
  type        = bool
  default     = false
}

variable "postgres_availability_zone" {
  description = "Availability zone for PostgreSQL primary"
  type        = string
  default     = "1"
}

variable "postgres_standby_availability_zone" {
  description = "Availability zone for PostgreSQL standby"
  type        = string
  default     = "2"
}

variable "db_admin_username" {
  description = "Database administrator username"
  type        = string
  default     = "camadmin"
}

variable "database_name" {
  description = "Name of the database"
  type        = string
  default     = "cam_db"
}

# Redis Configuration
variable "redis_capacity" {
  description = "Redis cache capacity"
  type        = number
  default     = 0
}

variable "redis_family" {
  description = "Redis cache family"
  type        = string
  default     = "C"
}

variable "redis_sku_name" {
  description = "Redis cache SKU name"
  type        = string
  default     = "Basic"
}

# Container Configuration
variable "container_image" {
  description = "Container image for the CAM application"
  type        = string
  default     = "mcr.microsoft.com/azuredocs/containerapps-helloworld:latest"
}

variable "container_cpu" {
  description = "CPU allocation for container"
  type        = number
  default     = 0.25
}

variable "container_memory" {
  description = "Memory allocation for container"
  type        = string
  default     = "0.5Gi"
}

variable "app_port" {
  description = "Port the application listens on"
  type        = number
  default     = 8080
}

variable "min_replicas" {
  description = "Minimum number of replicas"
  type        = number
  default     = 0
}

variable "max_replicas" {
  description = "Maximum number of replicas"
  type        = number
  default     = 10
}

# Container Registry Configuration
variable "acr_sku" {
  description = "Azure Container Registry SKU"
  type        = string
  default     = "Basic"
  validation {
    condition     = contains(["Basic", "Standard", "Premium"], var.acr_sku)
    error_message = "ACR SKU must be Basic, Standard, or Premium."
  }
}

# Storage Configuration
variable "storage_replication_type" {
  description = "Storage account replication type"
  type        = string
  default     = "LRS"
  validation {
    condition     = contains(["LRS", "GRS", "RAGRS", "ZRS", "GZRS", "RAGZRS"], var.storage_replication_type)
    error_message = "Storage replication type must be one of: LRS, GRS, RAGRS, ZRS, GZRS, RAGZRS."
  }
}

# Monitoring Configuration
variable "enable_monitoring" {
  description = "Enable monitoring and alerting"
  type        = bool
  default     = true
}

variable "alert_email" {
  description = "Email address for alerts"
  type        = string
  default     = ""
}

variable "log_retention_days" {
  description = "Log retention period in days"
  type        = number
  default     = 30
}

variable "cpu_alert_threshold" {
  description = "CPU alert threshold percentage"
  type        = number
  default     = 80
}

variable "memory_alert_threshold" {
  description = "Memory alert threshold percentage"
  type        = number
  default     = 80
}

# Backup Configuration
variable "enable_backup" {
  description = "Enable backup configuration"
  type        = bool
  default     = false
}

variable "backup_redundancy" {
  description = "Backup vault redundancy"
  type        = string
  default     = "LocallyRedundant"
  validation {
    condition     = contains(["LocallyRedundant", "GeoRedundant"], var.backup_redundancy)
    error_message = "Backup redundancy must be LocallyRedundant or GeoRedundant."
  }
}

# Tags
variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}

# Feature Flags
variable "enable_private_endpoints" {
  description = "Enable private endpoints for services"
  type        = bool
  default     = false
}

variable "enable_diagnostic_settings" {
  description = "Enable diagnostic settings for resources"
  type        = bool
  default     = true
}

variable "enable_network_security_groups" {
  description = "Enable network security groups"
  type        = bool
  default     = true
}

# Scaling Configuration
variable "autoscale_enabled" {
  description = "Enable autoscaling for container apps"
  type        = bool
  default     = true
}

variable "cpu_scale_threshold" {
  description = "CPU threshold for scaling"
  type        = number
  default     = 70
}

variable "memory_scale_threshold" {
  description = "Memory threshold for scaling"
  type        = number
  default     = 70
}

# Security Configuration
variable "key_vault_sku" {
  description = "Key Vault SKU"
  type        = string
  default     = "standard"
  validation {
    condition     = contains(["standard", "premium"], var.key_vault_sku)
    error_message = "Key Vault SKU must be standard or premium."
  }
}

variable "enable_key_vault_firewall" {
  description = "Enable Key Vault firewall"
  type        = bool
  default     = false
}

variable "allowed_ip_ranges" {
  description = "IP ranges allowed to access resources"
  type        = list(string)
  default     = []
}

# Application Configuration
variable "app_environment_variables" {
  description = "Additional environment variables for the application"
  type        = map(string)
  default     = {}
}

variable "app_secrets" {
  description = "Application secrets to store in Key Vault"
  type        = map(string)
  default     = {}
  sensitive   = true
}

# DNS Configuration
variable "custom_domain" {
  description = "Custom domain for the application"
  type        = string
  default     = ""
}

variable "enable_cdn" {
  description = "Enable Azure CDN"
  type        = bool
  default     = false
}

# Compliance and Governance
variable "enable_policy_assignment" {
  description = "Enable Azure Policy assignments"
  type        = bool
  default     = false
}

variable "enable_resource_locks" {
  description = "Enable resource locks for critical resources"
  type        = bool
  default     = false
}

# Cost Management
variable "budget_amount" {
  description = "Budget amount for cost management"
  type        = number
  default     = 100
}

variable "enable_cost_alerts" {
  description = "Enable cost management alerts"
  type        = bool
  default     = false
}
