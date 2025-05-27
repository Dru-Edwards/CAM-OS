# Complete Arbitration Mesh - GCP Terraform Module Variables

# Project Configuration
variable "project_id" {
  description = "GCP project ID"
  type        = string
}

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

variable "region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "GCP zone"
  type        = string
  default     = "us-central1-a"
}

# Network Configuration
variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "subnet_cidr" {
  description = "CIDR block for subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "private_subnet_cidr" {
  description = "CIDR block for private subnet"
  type        = string
  default     = "10.0.2.0/24"
}

# Database Configuration
variable "db_instance_tier" {
  description = "Cloud SQL instance tier"
  type        = string
  default     = "db-f1-micro"
}

variable "db_disk_size" {
  description = "Database disk size in GB"
  type        = number
  default     = 20
}

variable "db_backup_enabled" {
  description = "Enable automated backups"
  type        = bool
  default     = true
}

variable "db_backup_retention_days" {
  description = "Backup retention period in days"
  type        = number
  default     = 7
}

variable "db_ha_enabled" {
  description = "Enable high availability for database"
  type        = bool
  default     = false
}

# Redis Configuration
variable "redis_memory_size_gb" {
  description = "Redis memory size in GB"
  type        = number
  default     = 1
}

variable "redis_tier" {
  description = "Redis service tier"
  type        = string
  default     = "BASIC"
  validation {
    condition     = contains(["BASIC", "STANDARD_HA"], var.redis_tier)
    error_message = "Redis tier must be BASIC or STANDARD_HA."
  }
}

variable "redis_version" {
  description = "Redis version"
  type        = string
  default     = "REDIS_6_X"
}

# Cloud Run Configuration
variable "app_image" {
  description = "Container image for the CAM application"
  type        = string
  default     = "gcr.io/cloudrun/hello"
}

variable "app_port" {
  description = "Port the application listens on"
  type        = number
  default     = 8080
}

variable "cpu_limit" {
  description = "CPU limit for Cloud Run service"
  type        = string
  default     = "1000m"
}

variable "memory_limit" {
  description = "Memory limit for Cloud Run service"
  type        = string
  default     = "512Mi"
}

variable "min_instances" {
  description = "Minimum number of instances"
  type        = number
  default     = 0
}

variable "max_instances" {
  description = "Maximum number of instances"
  type        = number
  default     = 10
}

variable "concurrency" {
  description = "Maximum concurrent requests per instance"
  type        = number
  default     = 80
}

# Load Balancer Configuration
variable "enable_cdn" {
  description = "Enable Cloud CDN"
  type        = bool
  default     = false
}

variable "ssl_policy" {
  description = "SSL policy for load balancer"
  type        = string
  default     = "MODERN"
}

variable "domain_name" {
  description = "Domain name for SSL certificate"
  type        = string
  default     = ""
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

# Security Configuration
variable "allowed_ingress_cidrs" {
  description = "CIDR blocks allowed for ingress"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "enable_private_google_access" {
  description = "Enable private Google access"
  type        = bool
  default     = true
}

variable "enable_flow_logs" {
  description = "Enable VPC flow logs"
  type        = bool
  default     = false
}

# Secrets Configuration
variable "database_password_secret" {
  description = "Secret Manager secret name for database password"
  type        = string
  default     = "db-password"
}

variable "jwt_secret_name" {
  description = "Secret Manager secret name for JWT secret"
  type        = string
  default     = "jwt-secret"
}

# Labels and Tags
variable "labels" {
  description = "Labels to apply to resources"
  type        = map(string)
  default     = {}
}

# Feature Flags
variable "enable_vpc_connector" {
  description = "Enable VPC connector for Cloud Run"
  type        = bool
  default     = true
}

variable "enable_cloud_armor" {
  description = "Enable Cloud Armor security policies"
  type        = bool
  default     = false
}

variable "enable_iap" {
  description = "Enable Identity-Aware Proxy"
  type        = bool
  default     = false
}

# Backup Configuration
variable "backup_schedule" {
  description = "Backup schedule cron expression"
  type        = string
  default     = "0 2 * * *"
}

variable "backup_location" {
  description = "Backup location/region"
  type        = string
  default     = "us"
}

# Scaling Configuration
variable "cpu_utilization_target" {
  description = "Target CPU utilization for autoscaling"
  type        = number
  default     = 70
}

variable "request_utilization_target" {
  description = "Target request utilization for autoscaling"
  type        = number
  default     = 60
}
