#!/bin/bash
# grafana-provisioning.sh
# Script to provision Grafana with CAM dashboards and data sources

set -euo pipefail

# Configuration
GRAFANA_URL="${GRAFANA_URL:-http://localhost:3000}"
GRAFANA_USER="${GRAFANA_USER:-admin}"
GRAFANA_PASSWORD="${GRAFANA_PASSWORD:-admin}"
PROMETHEUS_URL="${PROMETHEUS_URL:-http://prometheus:9090}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DASHBOARDS_DIR="${SCRIPT_DIR}/dashboards"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Grafana is accessible
check_grafana_availability() {
    log_info "Checking Grafana availability at ${GRAFANA_URL}..."
    
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s -f "${GRAFANA_URL}/api/health" > /dev/null 2>&1; then
            log_success "Grafana is accessible"
            return 0
        fi
        
        log_info "Attempt ${attempt}/${max_attempts}: Waiting for Grafana..."
        sleep 10
        ((attempt++))
    done
    
    log_error "Grafana is not accessible after ${max_attempts} attempts"
    return 1
}

# Create Prometheus data source
create_prometheus_datasource() {
    log_info "Creating Prometheus data source..."
    
    local datasource_payload=$(cat <<EOF
{
  "name": "CAM-Prometheus",
  "type": "prometheus",
  "url": "${PROMETHEUS_URL}",
  "access": "proxy",
  "isDefault": true,
  "jsonData": {
    "httpMethod": "POST",
    "manageAlerts": true,
    "prometheusType": "Prometheus",
    "prometheusVersion": "2.40.0"
  }
}
EOF
)
    
    local response
    response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -u "${GRAFANA_USER}:${GRAFANA_PASSWORD}" \
        -d "${datasource_payload}" \
        "${GRAFANA_URL}/api/datasources" 2>&1)
    
    if echo "${response}" | grep -q "error"; then
        if echo "${response}" | grep -q "already exists"; then
            log_warning "Prometheus data source already exists"
        else
            log_error "Failed to create Prometheus data source: ${response}"
            return 1
        fi
    else
        log_success "Prometheus data source created successfully"
    fi
}

# Import dashboard
import_dashboard() {
    local dashboard_file="$1"
    local dashboard_name=$(basename "${dashboard_file}" .json)
    
    log_info "Importing dashboard: ${dashboard_name}"
    
    if [ ! -f "${dashboard_file}" ]; then
        log_error "Dashboard file not found: ${dashboard_file}"
        return 1
    fi
    
    # Wrap the dashboard in the required format for import
    local import_payload
    import_payload=$(jq -n --argjson dashboard "$(cat "${dashboard_file}")" '{
        dashboard: $dashboard.dashboard,
        overwrite: true,
        inputs: [
            {
                name: "DS_PROMETHEUS",
                type: "datasource",
                pluginId: "prometheus",
                value: "CAM-Prometheus"
            }
        ]
    }')
    
    local response
    response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -u "${GRAFANA_USER}:${GRAFANA_PASSWORD}" \
        -d "${import_payload}" \
        "${GRAFANA_URL}/api/dashboards/import" 2>&1)
    
    if echo "${response}" | grep -q "success"; then
        log_success "Dashboard ${dashboard_name} imported successfully"
    else
        log_error "Failed to import dashboard ${dashboard_name}: ${response}"
        return 1
    fi
}

# Create folder for CAM dashboards
create_dashboard_folder() {
    log_info "Creating CAM dashboard folder..."
    
    local folder_payload='{"title": "CAM Monitoring", "uid": "cam-monitoring"}'
    
    local response
    response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -u "${GRAFANA_USER}:${GRAFANA_PASSWORD}" \
        -d "${folder_payload}" \
        "${GRAFANA_URL}/api/folders" 2>&1)
    
    if echo "${response}" | grep -q "error"; then
        if echo "${response}" | grep -q "already exists"; then
            log_warning "CAM dashboard folder already exists"
        else
            log_error "Failed to create dashboard folder: ${response}"
            return 1
        fi
    else
        log_success "CAM dashboard folder created successfully"
    fi
}

# Import all dashboards
import_all_dashboards() {
    log_info "Importing all CAM dashboards..."
    
    if [ ! -d "${DASHBOARDS_DIR}" ]; then
        log_error "Dashboards directory not found: ${DASHBOARDS_DIR}"
        return 1
    fi
    
    local dashboard_count=0
    local success_count=0
    
    for dashboard_file in "${DASHBOARDS_DIR}"/*.json; do
        if [ -f "${dashboard_file}" ]; then
            ((dashboard_count++))
            if import_dashboard "${dashboard_file}"; then
                ((success_count++))
            fi
        fi
    done
    
    log_info "Imported ${success_count}/${dashboard_count} dashboards"
    
    if [ ${success_count} -eq ${dashboard_count} ]; then
        log_success "All dashboards imported successfully"
    else
        log_warning "Some dashboards failed to import"
    fi
}

# Configure alert notification channels
configure_alert_channels() {
    log_info "Configuring alert notification channels..."
    
    # Slack notification channel (if configured)
    if [ -n "${SLACK_WEBHOOK_URL:-}" ]; then
        local slack_payload=$(cat <<EOF
{
  "name": "cam-alerts-slack",
  "type": "slack",
  "settings": {
    "url": "${SLACK_WEBHOOK_URL}",
    "username": "Grafana",
    "channel": "#cam-alerts",
    "title": "CAM Alert",
    "text": "{{ range .Alerts }}{{ .Annotations.summary }}{{ end }}"
  }
}
EOF
)
        
        curl -s -X POST \
            -H "Content-Type: application/json" \
            -u "${GRAFANA_USER}:${GRAFANA_PASSWORD}" \
            -d "${slack_payload}" \
            "${GRAFANA_URL}/api/alert-notifications" > /dev/null
        
        log_success "Slack notification channel configured"
    fi
    
    # Email notification channel (if configured)
    if [ -n "${SMTP_HOST:-}" ] && [ -n "${ALERT_EMAIL:-}" ]; then
        local email_payload=$(cat <<EOF
{
  "name": "cam-alerts-email",
  "type": "email",
  "settings": {
    "addresses": "${ALERT_EMAIL}",
    "subject": "CAM Alert - {{ .CommonLabels.alertname }}",
    "body": "{{ range .Alerts }}{{ .Annotations.description }}{{ end }}"
  }
}
EOF
)
        
        curl -s -X POST \
            -H "Content-Type: application/json" \
            -u "${GRAFANA_USER}:${GRAFANA_PASSWORD}" \
            -d "${email_payload}" \
            "${GRAFANA_URL}/api/alert-notifications" > /dev/null
        
        log_success "Email notification channel configured"
    fi
}

# Set up organization and users
configure_organization() {
    log_info "Configuring Grafana organization..."
    
    # Update organization name
    local org_payload='{"name": "CAM Organization"}'
    curl -s -X PUT \
        -H "Content-Type: application/json" \
        -u "${GRAFANA_USER}:${GRAFANA_PASSWORD}" \
        -d "${org_payload}" \
        "${GRAFANA_URL}/api/org" > /dev/null
    
    log_success "Organization configured"
}

# Main function
main() {
    log_info "Starting Grafana provisioning for CAM monitoring..."
    
    # Check dependencies
    if ! command -v curl &> /dev/null; then
        log_error "curl is required but not installed"
        exit 1
    fi
    
    if ! command -v jq &> /dev/null; then
        log_error "jq is required but not installed"
        exit 1
    fi
    
    # Execute provisioning steps
    check_grafana_availability || exit 1
    create_prometheus_datasource || exit 1
    create_dashboard_folder || exit 1
    import_all_dashboards || exit 1
    configure_alert_channels
    configure_organization
    
    log_success "Grafana provisioning completed successfully!"
    log_info "Access Grafana at: ${GRAFANA_URL}"
    log_info "Username: ${GRAFANA_USER}"
    log_info "Password: ${GRAFANA_PASSWORD}"
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
