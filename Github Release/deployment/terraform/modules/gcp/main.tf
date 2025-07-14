# Complete Arbitration Mesh - GCP Terraform Module

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 4.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 4.0"
    }
  }
}

# Local values
locals {
  name_prefix = "${var.project_name}-${var.environment}"
  
  labels = merge(var.labels, {
    project     = var.project_name
    environment = var.environment
    managed_by  = "terraform"
  })
}

# Enable required APIs
resource "google_project_service" "required_apis" {
  for_each = toset([
    "compute.googleapis.com",
    "run.googleapis.com",
    "sqladmin.googleapis.com",
    "redis.googleapis.com",
    "monitoring.googleapis.com",
    "logging.googleapis.com",
    "secretmanager.googleapis.com",
    "servicenetworking.googleapis.com",
    "vpcaccess.googleapis.com",
    "cloudbuild.googleapis.com",
    "container.googleapis.com",
    "cloudresourcemanager.googleapis.com"
  ])

  service                    = each.value
  disable_dependent_services = false
  disable_on_destroy         = false
}

# VPC Network
resource "google_compute_network" "vpc" {
  name                    = "${local.name_prefix}-vpc"
  description             = "VPC network for Complete Arbitration Mesh"
  auto_create_subnetworks = false
  routing_mode           = "REGIONAL"

  depends_on = [google_project_service.required_apis]
}

# Subnet
resource "google_compute_subnetwork" "subnet" {
  name          = "${local.name_prefix}-subnet"
  description   = "Subnet for CAM services"
  ip_cidr_range = "10.0.0.0/24"
  region        = var.region
  network       = google_compute_network.vpc.id

  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = "10.1.0.0/16"
  }

  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = "10.2.0.0/16"
  }

  private_ip_google_access = true
}

# Private Service Networking for Cloud SQL
resource "google_compute_global_address" "private_ip_range" {
  name          = "${local.name_prefix}-private-ip"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.vpc.id
}

resource "google_service_networking_connection" "private_vpc_connection" {
  network                 = google_compute_network.vpc.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip_range.name]
}

# VPC Connector for Cloud Run
resource "google_vpc_access_connector" "connector" {
  name          = "${local.name_prefix}-connector"
  region        = var.region
  ip_cidr_range = "10.3.0.0/28"
  network       = google_compute_network.vpc.name
  min_throughput = 200
  max_throughput = 1000

  depends_on = [google_project_service.required_apis]
}

# Service Account for Cloud Run
resource "google_service_account" "cloud_run" {
  account_id   = "${local.name_prefix}-cloud-run"
  display_name = "CAM Cloud Run Service Account"
  description  = "Service account for Complete Arbitration Mesh Cloud Run service"
}

# IAM bindings for service account
resource "google_project_iam_member" "cloud_run_sql_client" {
  role   = "roles/cloudsql.client"
  member = "serviceAccount:${google_service_account.cloud_run.email}"
}

resource "google_project_iam_member" "cloud_run_secret_accessor" {
  role   = "roles/secretmanager.secretAccessor"
  member = "serviceAccount:${google_service_account.cloud_run.email}"
}

resource "google_project_iam_member" "cloud_run_redis_editor" {
  role   = "roles/redis.editor"
  member = "serviceAccount:${google_service_account.cloud_run.email}"
}

# Random database password
resource "random_password" "db_password" {
  length  = 32
  special = true
}

# Cloud SQL Instance
resource "google_sql_database_instance" "postgres" {
  name             = "${local.name_prefix}-postgres"
  database_version = "POSTGRES_15"
  region           = var.region
  deletion_protection = var.environment == "prod"

  settings {
    tier                        = var.environment == "prod" ? "db-custom-2-7680" : "db-f1-micro"
    availability_type          = var.environment == "prod" ? "REGIONAL" : "ZONAL"
    disk_size                  = var.environment == "prod" ? 100 : 10
    disk_type                  = "PD_SSD"
    disk_autoresize           = true
    disk_autoresize_limit     = var.environment == "prod" ? 1000 : 100

    backup_configuration {
      enabled                        = true
      start_time                     = "03:00"
      point_in_time_recovery_enabled = true
      backup_retention_settings {
        retained_backups = var.environment == "prod" ? 30 : 7
        retention_unit   = "COUNT"
      }
    }

    maintenance_window {
      day  = 7
      hour = 3
    }

    database_flags {
      name  = "log_statement"
      value = "all"
    }

    database_flags {
      name  = "log_min_duration_statement"
      value = "100"
    }

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.vpc.id
      require_ssl     = true
    }
  }

  depends_on = [
    google_service_networking_connection.private_vpc_connection,
    google_project_service.required_apis
  ]
}

# Database
resource "google_sql_database" "database" {
  name     = "camarbitration"
  instance = google_sql_database_instance.postgres.name
  charset  = "UTF8"
}

# Database user
resource "google_sql_user" "user" {
  name     = "camadmin"
  instance = google_sql_database_instance.postgres.name
  password = var.database_password
}

# Redis Instance
resource "google_redis_instance" "cache" {
  name               = "${local.name_prefix}-redis"
  display_name       = "CAM Redis Cache"
  tier               = var.environment == "prod" ? "STANDARD_HA" : "BASIC"
  memory_size_gb     = var.environment == "prod" ? 4 : 1
  region             = var.region
  redis_version      = "REDIS_7_0"
  auth_enabled       = true
  transit_encryption_mode = "SERVER_AUTHENTICATION"
  authorized_network = google_compute_network.vpc.id
  connect_mode       = "PRIVATE_SERVICE_ACCESS"

  redis_configs = {
    maxmemory-policy = "allkeys-lru"
    timeout         = "300"
  }

  depends_on = [
    google_service_networking_connection.private_vpc_connection,
    google_project_service.required_apis
  ]
}

# Secret Manager secrets
resource "google_secret_manager_secret" "app_secrets" {
  secret_id = "${local.name_prefix}-app-secrets"
  
  replication {
    automatic = true
  }

  depends_on = [google_project_service.required_apis]
}

resource "google_secret_manager_secret_version" "app_secrets" {
  secret = google_secret_manager_secret.app_secrets.id
  secret_data = jsonencode({
    jwt_secret = var.jwt_secret
    encryption_key = var.encryption_key
    redis_url = "redis://:${google_redis_instance.cache.auth_string}@${google_redis_instance.cache.host}:${google_redis_instance.cache.port}"
  })
}

resource "google_secret_manager_secret" "database_credentials" {
  secret_id = "${local.name_prefix}-db-credentials"
  
  replication {
    automatic = true
  }

  depends_on = [google_project_service.required_apis]
}

resource "google_secret_manager_secret_version" "database_credentials" {
  secret = google_secret_manager_secret.database_credentials.id
  secret_data = jsonencode({
    database_url = "postgresql://${google_sql_user.user.name}:${google_sql_user.user.password}@${google_sql_database_instance.postgres.private_ip_address}:5432/${google_sql_database.database.name}"
  })
}

# Cloud Run Service
resource "google_cloud_run_service" "app" {
  name     = "${local.name_prefix}-app"
  location = var.region

  template {
    metadata {
      annotations = {
        "autoscaling.knative.dev/maxScale" = var.environment == "prod" ? "50" : "10"
        "autoscaling.knative.dev/minScale" = var.environment == "prod" ? "2" : "0"
        "run.googleapis.com/cloudsql-instances" = google_sql_database_instance.postgres.connection_name
        "run.googleapis.com/vpc-access-connector" = google_vpc_access_connector.connector.name
        "run.googleapis.com/vpc-access-egress" = "private-ranges-only"
        "run.googleapis.com/execution-environment" = "gen2"
        "run.googleapis.com/cpu-throttling" = "false"
      }
    }

    spec {
      container_concurrency = 80
      timeout_seconds      = 300
      service_account_name = google_service_account.cloud_run.email

      containers {
        image = "gcr.io/${var.project_name}/cam-arbitration-mesh:latest"
        
        ports {
          container_port = 8080
        }

        env {
          name  = "NODE_ENV"
          value = "production"
        }

        env {
          name  = "PORT"
          value = "8080"
        }

        env {
          name  = "LOG_LEVEL"
          value = var.environment == "prod" ? "info" : "debug"
        }

        env {
          name = "DATABASE_URL"
          value_from {
            secret_key_ref {
              name = google_secret_manager_secret.database_credentials.secret_id
              key  = "database_url"
            }
          }
        }

        env {
          name = "REDIS_URL"
          value_from {
            secret_key_ref {
              name = google_secret_manager_secret.app_secrets.secret_id
              key  = "redis_url"
            }
          }
        }

        env {
          name = "JWT_SECRET"
          value_from {
            secret_key_ref {
              name = google_secret_manager_secret.app_secrets.secret_id
              key  = "jwt_secret"
            }
          }
        }

        resources {
          limits = {
            cpu    = var.environment == "prod" ? "2" : "1"
            memory = var.environment == "prod" ? "2Gi" : "512Mi"
          }
          requests = {
            cpu    = var.environment == "prod" ? "1" : "0.5"
            memory = var.environment == "prod" ? "1Gi" : "256Mi"
          }
        }

        liveness_probe {
          http_get {
            path = "/health"
            port = 8080
          }
          initial_delay_seconds = 30
          period_seconds       = 30
          timeout_seconds      = 5
        }

        readiness_probe {
          http_get {
            path = "/health"
            port = 8080
          }
          initial_delay_seconds = 5
          period_seconds       = 10
          timeout_seconds      = 5
        }
      }
    }
  }

  traffic {
    percent         = 100
    latest_revision = true
  }

  depends_on = [
    google_project_service.required_apis,
    google_vpc_access_connector.connector
  ]
}

# Allow unauthenticated access
resource "google_cloud_run_service_iam_member" "public_access" {
  count = var.enable_public_access ? 1 : 0
  
  service  = google_cloud_run_service.app.name
  location = google_cloud_run_service.app.location
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# Global IP address for load balancer
resource "google_compute_global_address" "default" {
  count = var.domain_name != "" ? 1 : 0
  name  = "${local.name_prefix}-lb-ip"
}

# SSL certificate
resource "google_compute_managed_ssl_certificate" "default" {
  count = var.domain_name != "" ? 1 : 0
  name  = "${local.name_prefix}-ssl-cert"

  managed {
    domains = [var.domain_name]
  }
}

# Cloud Monitoring Notification Channel
resource "google_monitoring_notification_channel" "email" {
  count = var.enable_monitoring ? 1 : 0
  
  display_name = "CAM Alerts Email"
  type         = "email"
  
  labels = {
    email_address = var.alert_email
  }
}

# Monitoring alerts
resource "google_monitoring_alert_policy" "high_error_rate" {
  count = var.enable_monitoring ? 1 : 0
  
  display_name = "${local.name_prefix} High Error Rate"
  combiner     = "OR"
  
  conditions {
    display_name = "High 5xx error rate"
    
    condition_threshold {
      filter         = "resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"${google_cloud_run_service.app.name}\""
      duration       = "300s"
      comparison     = "COMPARISON_GT"
      threshold_value = 0.05
      
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }
  
  notification_channels = [google_monitoring_notification_channel.email[0].name]
}

# Labels
resource "google_compute_instance_template" "labels" {
  name = "${local.name_prefix}-labels"
  
  tags = ["cam", var.environment]
  
  labels = local.labels
  
  lifecycle {
    create_before_destroy = true
  }
}
