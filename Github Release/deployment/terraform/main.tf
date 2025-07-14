# Complete Arbitration Mesh - Main Terraform Configuration
# Multi-cloud deployment support for AWS, Azure, and GCP

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 4.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 4.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.1"
    }
  }

  # Backend configuration - can be customized per environment
  backend "s3" {
    bucket         = "cam-terraform-state"
    key            = "infrastructure/terraform.tfstate"
    region         = "us-west-2"
    encrypt        = true
    dynamodb_table = "cam-terraform-locks"
  }
}

# Variables
variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "prod"
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "cloud_provider" {
  description = "Cloud provider (aws, azure, gcp, multi)"
  type        = string
  default     = "aws"
  validation {
    condition     = contains(["aws", "azure", "gcp", "multi"], var.cloud_provider)
    error_message = "Cloud provider must be one of: aws, azure, gcp, multi."
  }
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "cam"
}

variable "region" {
  description = "Primary region for deployment"
  type        = string
  default     = "us-west-2"
}

variable "availability_zones" {
  description = "Availability zones to use"
  type        = list(string)
  default     = ["us-west-2a", "us-west-2b", "us-west-2c"]
}

variable "enable_monitoring" {
  description = "Enable monitoring and observability"
  type        = bool
  default     = true
}

variable "enable_backup" {
  description = "Enable backup solutions"
  type        = bool
  default     = true
}

variable "domain_name" {
  description = "Domain name for the application"
  type        = string
  default     = ""
}

variable "alert_email" {
  description = "Email address for alerts"
  type        = string
  default     = ""
}

variable "container_image" {
  description = "Container image for the application"
  type        = string
  default     = "cam/complete-arbitration-mesh:latest"
}

variable "instance_type" {
  description = "Instance type for compute resources"
  type        = string
  default     = "t3.medium"
}

variable "min_instances" {
  description = "Minimum number of instances"
  type        = number
  default     = 1
}

variable "max_instances" {
  description = "Maximum number of instances"
  type        = number
  default     = 10
}

variable "database_instance_class" {
  description = "Database instance class"
  type        = string
  default     = "db.t3.micro"
}

variable "redis_node_type" {
  description = "Redis node type"
  type        = string
  default     = "cache.t3.micro"
}

variable "enable_ssl" {
  description = "Enable SSL/TLS"
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  description = "Backup retention period in days"
  type        = number
  default     = 7
}

variable "log_retention_days" {
  description = "Log retention period in days"
  type        = number
  default     = 30
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}
  description = "Project name"
  type        = string
  default     = "cam-arbitration-mesh"
}

variable "region" {
  description = "Primary region"
  type        = string
  default     = "us-west-2"
}

variable "availability_zones" {
  description = "Availability zones"
  type        = list(string)
  default     = ["us-west-2a", "us-west-2b", "us-west-2c"]
}

variable "instance_count" {
  description = "Number of application instances"
  type        = number
  default     = 3
}

variable "database_instance_class" {
  description = "Database instance class"
  type        = string
  default     = "db.r6g.large"
}

variable "redis_node_type" {
  description = "Redis node type"
  type        = string
  default     = "cache.r6g.large"
}

variable "domain_name" {
  description = "Domain name for the application"
  type        = string
  default     = "cam-arbitration.com"
}

variable "enable_monitoring" {
  description = "Enable monitoring and logging"
  type        = bool
  default     = true
}

variable "enable_backup" {
  description = "Enable automated backups"
  type        = bool
  default     = true
}

variable "ssl_certificate_arn" {
  description = "SSL certificate ARN (AWS)"
  type        = string
  default     = ""
}

# Local values
locals {
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
    CreatedAt   = timestamp()
  }

  name_prefix = "${var.project_name}-${var.environment}"
}

# Data sources
data "aws_caller_identity" "current" {
  count = var.cloud_provider == "aws" || var.cloud_provider == "multi" ? 1 : 0
}

data "aws_region" "current" {
  count = var.cloud_provider == "aws" || var.cloud_provider == "multi" ? 1 : 0
}

data "azurerm_client_config" "current" {
  count = var.cloud_provider == "azure" || var.cloud_provider == "multi" ? 1 : 0
}

# Random passwords
resource "random_password" "database_password" {
  length  = 32
  special = true
}

resource "random_password" "jwt_secret" {
  length  = 64
  special = true
}

resource "random_password" "encryption_key" {
  length  = 32
  special = false
}

# AWS Provider Configuration
provider "aws" {
  count  = var.cloud_provider == "aws" || var.cloud_provider == "multi" ? 1 : 0
  region = var.region

  default_tags {
    tags = local.common_tags
  }
}

# Azure Provider Configuration
provider "azurerm" {
  count = var.cloud_provider == "azure" || var.cloud_provider == "multi" ? 1 : 0
  features {
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
    key_vault {
      purge_soft_delete_on_destroy    = true
      recover_soft_deleted_key_vaults = true
    }
  }
}

# GCP Provider Configuration
provider "google" {
  count   = var.cloud_provider == "gcp" || var.cloud_provider == "multi" ? 1 : 0
  region  = var.region
  zone    = "${var.region}-a"
  project = var.project_name
}

# Kubernetes Provider Configuration
provider "kubernetes" {
  count = var.cloud_provider == "aws" ? 1 : 0

  host                   = module.aws_infrastructure[0].cluster_endpoint
  cluster_ca_certificate = base64decode(module.aws_infrastructure[0].cluster_certificate_authority_data)
  token                  = module.aws_infrastructure[0].cluster_token

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.aws_infrastructure[0].cluster_name]
  }
}

# Helm Provider Configuration
provider "helm" {
  count = var.cloud_provider == "aws" ? 1 : 0

  kubernetes {
    host                   = module.aws_infrastructure[0].cluster_endpoint
    cluster_ca_certificate = base64decode(module.aws_infrastructure[0].cluster_certificate_authority_data)
    token                  = module.aws_infrastructure[0].cluster_token

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.aws_infrastructure[0].cluster_name]
    }
  }
}

# AWS Infrastructure Module
module "aws_infrastructure" {
  count  = var.cloud_provider == "aws" || var.cloud_provider == "multi" ? 1 : 0
  source = "./modules/aws"

  project_name         = var.project_name
  environment          = var.environment
  region               = var.region
  availability_zones   = var.availability_zones
  instance_count       = var.instance_count
  database_password    = random_password.database_password.result
  jwt_secret          = random_password.jwt_secret.result
  encryption_key      = random_password.encryption_key.result
  domain_name         = var.domain_name
  ssl_certificate_arn = var.ssl_certificate_arn
  enable_monitoring   = var.enable_monitoring
  enable_backup       = var.enable_backup

  tags = local.common_tags
}

# Azure Infrastructure Module
module "azure_infrastructure" {
  count  = var.cloud_provider == "azure" || var.cloud_provider == "multi" ? 1 : 0
  source = "./modules/azure"

  project_name      = var.project_name
  environment       = var.environment
  location          = var.region
  instance_count    = var.instance_count
  database_password = random_password.database_password.result
  jwt_secret       = random_password.jwt_secret.result
  encryption_key   = random_password.encryption_key.result
  domain_name      = var.domain_name
  enable_monitoring = var.enable_monitoring
  enable_backup     = var.enable_backup

  tags = local.common_tags
}

# GCP Infrastructure Module
module "gcp_infrastructure" {
  count  = var.cloud_provider == "gcp" || var.cloud_provider == "multi" ? 1 : 0
  source = "./modules/gcp"

  project_name      = var.project_name
  environment       = var.environment
  region            = var.region
  instance_count    = var.instance_count
  database_password = random_password.database_password.result
  jwt_secret       = random_password.jwt_secret.result
  encryption_key   = random_password.encryption_key.result
  domain_name      = var.domain_name
  enable_monitoring = var.enable_monitoring
  enable_backup     = var.enable_backup

  labels = local.common_tags
}

# Application Deployment Module
module "application_deployment" {
  count  = var.cloud_provider == "aws" ? 1 : 0
  source = "./modules/application"

  depends_on = [module.aws_infrastructure]

  project_name    = var.project_name
  environment     = var.environment
  cluster_name    = module.aws_infrastructure[0].cluster_name
  database_url    = module.aws_infrastructure[0].database_url
  redis_url       = module.aws_infrastructure[0].redis_url
  jwt_secret      = random_password.jwt_secret.result
  encryption_key  = random_password.encryption_key.result
  image_tag       = "latest"
  replica_count   = var.instance_count
}

# Monitoring Module
module "monitoring" {
  count  = var.enable_monitoring && var.cloud_provider == "aws" ? 1 : 0
  source = "./modules/monitoring"

  depends_on = [module.aws_infrastructure, module.application_deployment]

  project_name     = var.project_name
  environment      = var.environment
  cluster_name     = module.aws_infrastructure[0].cluster_name
  notification_email = "alerts@${var.domain_name}"
}

# Outputs
output "infrastructure_info" {
  description = "Infrastructure deployment information"
  value = {
    cloud_provider = var.cloud_provider
    environment    = var.environment
    region         = var.region
    
    aws_info = var.cloud_provider == "aws" || var.cloud_provider == "multi" ? {
      cluster_name     = try(module.aws_infrastructure[0].cluster_name, null)
      cluster_endpoint = try(module.aws_infrastructure[0].cluster_endpoint, null)
      load_balancer_dns = try(module.aws_infrastructure[0].load_balancer_dns, null)
      database_endpoint = try(module.aws_infrastructure[0].database_endpoint, null)
      redis_endpoint   = try(module.aws_infrastructure[0].redis_endpoint, null)
    } : null
    
    azure_info = var.cloud_provider == "azure" || var.cloud_provider == "multi" ? {
      resource_group_name = try(module.azure_infrastructure[0].resource_group_name, null)
      app_service_url     = try(module.azure_infrastructure[0].app_service_url, null)
      database_fqdn       = try(module.azure_infrastructure[0].database_fqdn, null)
      redis_hostname      = try(module.azure_infrastructure[0].redis_hostname, null)
    } : null
    
    gcp_info = var.cloud_provider == "gcp" || var.cloud_provider == "multi" ? {
      project_id       = try(module.gcp_infrastructure[0].project_id, null)
      service_url      = try(module.gcp_infrastructure[0].service_url, null)
      database_ip      = try(module.gcp_infrastructure[0].database_ip, null)
      redis_host       = try(module.gcp_infrastructure[0].redis_host, null)
    } : null
  }
  sensitive = true
}

output "application_urls" {
  description = "Application access URLs"
  value = {
    aws_url   = var.cloud_provider == "aws" || var.cloud_provider == "multi" ? try(module.aws_infrastructure[0].application_url, null) : null
    azure_url = var.cloud_provider == "azure" || var.cloud_provider == "multi" ? try(module.azure_infrastructure[0].application_url, null) : null
    gcp_url   = var.cloud_provider == "gcp" || var.cloud_provider == "multi" ? try(module.gcp_infrastructure[0].application_url, null) : null
  }
}

output "monitoring_dashboards" {
  description = "Monitoring dashboard URLs"
  value = var.enable_monitoring ? {
    aws_cloudwatch = var.cloud_provider == "aws" || var.cloud_provider == "multi" ? try(module.aws_infrastructure[0].cloudwatch_dashboard_url, null) : null
    azure_insights = var.cloud_provider == "azure" || var.cloud_provider == "multi" ? try(module.azure_infrastructure[0].app_insights_url, null) : null
    gcp_monitoring = var.cloud_provider == "gcp" || var.cloud_provider == "multi" ? try(module.gcp_infrastructure[0].monitoring_url, null) : null
  } : null
}

output "database_connections" {
  description = "Database connection information"
  value = {
    aws_postgres   = var.cloud_provider == "aws" || var.cloud_provider == "multi" ? try(module.aws_infrastructure[0].database_endpoint, null) : null
    azure_postgres = var.cloud_provider == "azure" || var.cloud_provider == "multi" ? try(module.azure_infrastructure[0].database_fqdn, null) : null
    gcp_postgres   = var.cloud_provider == "gcp" || var.cloud_provider == "multi" ? try(module.gcp_infrastructure[0].database_ip, null) : null
  }
  sensitive = true
}

output "redis_connections" {
  description = "Redis connection information"
  value = {
    aws_redis   = var.cloud_provider == "aws" || var.cloud_provider == "multi" ? try(module.aws_infrastructure[0].redis_endpoint, null) : null
    azure_redis = var.cloud_provider == "azure" || var.cloud_provider == "multi" ? try(module.azure_infrastructure[0].redis_hostname, null) : null
    gcp_redis   = var.cloud_provider == "gcp" || var.cloud_provider == "multi" ? try(module.gcp_infrastructure[0].redis_host, null) : null
  }
  sensitive = true
}
