# Complete Arbitration Mesh - GCP Terraform Module Outputs

# Project Information
output "project_id" {
  description = "GCP project ID"
  value       = var.project_id
}

output "region" {
  description = "GCP region"
  value       = var.region
}

# Network Outputs
output "vpc_network_name" {
  description = "Name of the VPC network"
  value       = google_compute_network.vpc.name
}

output "vpc_network_id" {
  description = "ID of the VPC network"
  value       = google_compute_network.vpc.id
}

output "vpc_network_self_link" {
  description = "Self link of the VPC network"
  value       = google_compute_network.vpc.self_link
}

output "subnet_name" {
  description = "Name of the main subnet"
  value       = google_compute_subnetwork.subnet.name
}

output "subnet_id" {
  description = "ID of the main subnet"
  value       = google_compute_subnetwork.subnet.id
}

output "private_subnet_name" {
  description = "Name of the private subnet"
  value       = google_compute_subnetwork.private_subnet.name
}

output "private_subnet_id" {
  description = "ID of the private subnet"
  value       = google_compute_subnetwork.private_subnet.id
}

# VPC Connector
output "vpc_connector_name" {
  description = "Name of the VPC connector"
  value       = var.enable_vpc_connector ? google_vpc_access_connector.connector[0].name : null
}

output "vpc_connector_id" {
  description = "ID of the VPC connector"
  value       = var.enable_vpc_connector ? google_vpc_access_connector.connector[0].id : null
}

# Database Outputs
output "database_instance_name" {
  description = "Name of the Cloud SQL instance"
  value       = google_sql_database_instance.postgres.name
}

output "database_instance_connection_name" {
  description = "Connection name of the Cloud SQL instance"
  value       = google_sql_database_instance.postgres.connection_name
}

output "database_private_ip" {
  description = "Private IP address of the database"
  value       = google_sql_database_instance.postgres.private_ip_address
}

output "database_public_ip" {
  description = "Public IP address of the database"
  value       = google_sql_database_instance.postgres.public_ip_address
}

output "database_name" {
  description = "Name of the database"
  value       = google_sql_database.database.name
}

output "database_user" {
  description = "Database user name"
  value       = google_sql_user.user.name
  sensitive   = true
}

# Redis Outputs
output "redis_instance_id" {
  description = "ID of the Redis instance"
  value       = google_redis_instance.cache.id
}

output "redis_host" {
  description = "Redis instance host"
  value       = google_redis_instance.cache.host
}

output "redis_port" {
  description = "Redis instance port"
  value       = google_redis_instance.cache.port
}

output "redis_memory_size_gb" {
  description = "Redis memory size in GB"
  value       = google_redis_instance.cache.memory_size_gb
}

# Cloud Run Outputs
output "cloud_run_service_name" {
  description = "Name of the Cloud Run service"
  value       = google_cloud_run_service.app.name
}

output "cloud_run_service_url" {
  description = "URL of the Cloud Run service"
  value       = google_cloud_run_service.app.status[0].url
}

output "cloud_run_service_location" {
  description = "Location of the Cloud Run service"
  value       = google_cloud_run_service.app.location
}

# Load Balancer Outputs
output "load_balancer_ip" {
  description = "External IP address of the load balancer"
  value       = google_compute_global_address.default.address
}

output "load_balancer_url" {
  description = "URL of the load balancer"
  value       = "https://${google_compute_global_address.default.address}"
}

output "domain_url" {
  description = "Domain URL if domain name is provided"
  value       = var.domain_name != "" ? "https://${var.domain_name}" : null
}

# SSL Certificate
output "ssl_certificate_name" {
  description = "Name of the SSL certificate"
  value       = var.domain_name != "" ? google_compute_managed_ssl_certificate.default[0].name : null
}

# Secrets
output "database_password_secret_id" {
  description = "ID of the database password secret"
  value       = google_secret_manager_secret.db_password.secret_id
}

output "jwt_secret_id" {
  description = "ID of the JWT secret"
  value       = google_secret_manager_secret.jwt_secret.secret_id
}

# Service Account
output "cloud_run_service_account_email" {
  description = "Email of the Cloud Run service account"
  value       = google_service_account.cloud_run.email
}

output "cloud_run_service_account_id" {
  description = "ID of the Cloud Run service account"
  value       = google_service_account.cloud_run.id
}

# Monitoring
output "monitoring_notification_channel_name" {
  description = "Name of the monitoring notification channel"
  value       = var.enable_monitoring ? google_monitoring_notification_channel.email[0].name : null
}

# Security
output "firewall_rules" {
  description = "Names of created firewall rules"
  value = [
    google_compute_firewall.allow_http.name,
    google_compute_firewall.allow_https.name,
    google_compute_firewall.allow_internal.name,
    google_compute_firewall.allow_health_check.name
  ]
}

# IAM
output "iam_service_accounts" {
  description = "Created service accounts"
  value = {
    cloud_run = google_service_account.cloud_run.email
  }
}

# Storage
output "storage_bucket_name" {
  description = "Name of the storage bucket"
  value       = google_storage_bucket.app_storage.name
}

output "storage_bucket_url" {
  description = "URL of the storage bucket"
  value       = google_storage_bucket.app_storage.url
}

# APIs
output "enabled_apis" {
  description = "List of enabled APIs"
  value       = [for api in google_project_service.required_apis : api.service]
}

# Private Service Connection
output "private_vpc_connection_name" {
  description = "Name of the private VPC connection"
  value       = google_service_networking_connection.private_vpc_connection.network
}

# Environment Information
output "environment" {
  description = "Environment name"
  value       = var.environment
}

output "name_prefix" {
  description = "Name prefix used for resources"
  value       = local.name_prefix
}

output "labels" {
  description = "Labels applied to resources"
  value       = local.labels
}

# Health Check URLs
output "health_check_urls" {
  description = "Health check URLs"
  value = {
    load_balancer = "https://${google_compute_global_address.default.address}/health"
    cloud_run     = "${google_cloud_run_service.app.status[0].url}/health"
  }
}

# Connection Strings (for application configuration)
output "database_connection_string" {
  description = "Database connection string template"
  value       = "postgresql://${google_sql_user.user.name}:PASSWORD@${google_sql_database_instance.postgres.private_ip_address}:5432/${google_sql_database.database.name}"
  sensitive   = true
}

output "redis_connection_string" {
  description = "Redis connection string"
  value       = "redis://${google_redis_instance.cache.host}:${google_redis_instance.cache.port}"
}

# Resource Summary
output "resource_summary" {
  description = "Summary of created resources"
  value = {
    vpc_network         = google_compute_network.vpc.name
    database           = google_sql_database_instance.postgres.name
    redis              = google_redis_instance.cache.name
    cloud_run_service  = google_cloud_run_service.app.name
    load_balancer_ip   = google_compute_global_address.default.address
    environment        = var.environment
    region             = var.region
  }
}
