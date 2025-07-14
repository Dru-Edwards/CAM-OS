#!/bin/bash
# monitoring-health-check.sh
# Comprehensive health check script for CAM monitoring infrastructure

set -euo pipefail

# Configuration
PROMETHEUS_URL="${PROMETHEUS_URL:-http://localhost:9090}"
GRAFANA_URL="${GRAFANA_URL:-http://localhost:3000}"
ALERTMANAGER_URL="${ALERTMANAGER_URL:-http://localhost:9093}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Health check results
HEALTH_CHECKS=()
FAILED_CHECKS=0
TOTAL_CHECKS=0

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

# Add health check result
add_check_result() {
    local service="$1"
    local check="$2"
    local status="$3"
    local details="$4"
    
    ((TOTAL_CHECKS++))
    
    if [ "$status" = "PASS" ]; then
        HEALTH_CHECKS+=("✅ $service - $check: $details")
        log_success "$service - $check: $details"
    elif [ "$status" = "WARN" ]; then
        HEALTH_CHECKS+=("⚠️  $service - $check: $details")
        log_warning "$service - $check: $details"
    else
        HEALTH_CHECKS+=("❌ $service - $check: $details")
        log_error "$service - $check: $details"
        ((FAILED_CHECKS++))
    fi
}

# Check service availability
check_service_availability() {
    local service_name="$1"
    local service_url="$2"
    local endpoint="${3:-/}"
    
    log_info "Checking $service_name availability..."
    
    if curl -s -f "${service_url}${endpoint}" > /dev/null 2>&1; then
        add_check_result "$service_name" "Availability" "PASS" "Service is accessible"
        return 0
    else
        add_check_result "$service_name" "Availability" "FAIL" "Service is not accessible"
        return 1
    fi
}

# Check Prometheus health
check_prometheus_health() {
    log_info "Running Prometheus health checks..."
    
    # Basic availability
    if ! check_service_availability "Prometheus" "$PROMETHEUS_URL" "/-/healthy"; then
        return 1
    fi
    
    # Check if Prometheus is ready
    if curl -s -f "${PROMETHEUS_URL}/-/ready" > /dev/null 2>&1; then
        add_check_result "Prometheus" "Readiness" "PASS" "Service is ready"
    else
        add_check_result "Prometheus" "Readiness" "FAIL" "Service is not ready"
    fi
    
    # Check target health
    local targets_response
    targets_response=$(curl -s "${PROMETHEUS_URL}/api/v1/targets" 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        local active_targets
        active_targets=$(echo "$targets_response" | jq -r '.data.activeTargets | length' 2>/dev/null || echo "0")
        
        local healthy_targets
        healthy_targets=$(echo "$targets_response" | jq -r '.data.activeTargets | map(select(.health == "up")) | length' 2>/dev/null || echo "0")
        
        if [ "$active_targets" -gt 0 ]; then
            local health_ratio=$((healthy_targets * 100 / active_targets))
            if [ "$health_ratio" -ge 80 ]; then
                add_check_result "Prometheus" "Targets" "PASS" "$healthy_targets/$active_targets targets healthy ($health_ratio%)"
            elif [ "$health_ratio" -ge 50 ]; then
                add_check_result "Prometheus" "Targets" "WARN" "$healthy_targets/$active_targets targets healthy ($health_ratio%)"
            else
                add_check_result "Prometheus" "Targets" "FAIL" "$healthy_targets/$active_targets targets healthy ($health_ratio%)"
            fi
        else
            add_check_result "Prometheus" "Targets" "WARN" "No active targets configured"
        fi
    else
        add_check_result "Prometheus" "Targets" "FAIL" "Unable to query targets API"
    fi
    
    # Check storage and retention
    local config_response
    config_response=$(curl -s "${PROMETHEUS_URL}/api/v1/status/config" 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        add_check_result "Prometheus" "Configuration" "PASS" "Configuration accessible"
    else
        add_check_result "Prometheus" "Configuration" "FAIL" "Unable to access configuration"
    fi
}

# Check Grafana health
check_grafana_health() {
    log_info "Running Grafana health checks..."
    
    # Basic availability
    if ! check_service_availability "Grafana" "$GRAFANA_URL" "/api/health"; then
        return 1
    fi
    
    # Check data sources
    local datasources_response
    datasources_response=$(curl -s "${GRAFANA_URL}/api/datasources" 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        local datasource_count
        datasource_count=$(echo "$datasources_response" | jq '. | length' 2>/dev/null || echo "0")
        
        if [ "$datasource_count" -gt 0 ]; then
            add_check_result "Grafana" "Data Sources" "PASS" "$datasource_count data sources configured"
        else
            add_check_result "Grafana" "Data Sources" "WARN" "No data sources configured"
        fi
    else
        add_check_result "Grafana" "Data Sources" "FAIL" "Unable to query data sources"
    fi
    
    # Check dashboards
    local dashboards_response
    dashboards_response=$(curl -s "${GRAFANA_URL}/api/search?type=dash-db" 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        local dashboard_count
        dashboard_count=$(echo "$dashboards_response" | jq '. | length' 2>/dev/null || echo "0")
        
        if [ "$dashboard_count" -gt 0 ]; then
            add_check_result "Grafana" "Dashboards" "PASS" "$dashboard_count dashboards available"
        else
            add_check_result "Grafana" "Dashboards" "WARN" "No dashboards found"
        fi
    else
        add_check_result "Grafana" "Dashboards" "FAIL" "Unable to query dashboards"
    fi
}

# Check Alertmanager health
check_alertmanager_health() {
    log_info "Running Alertmanager health checks..."
    
    # Basic availability
    if ! check_service_availability "Alertmanager" "$ALERTMANAGER_URL" "/-/healthy"; then
        return 1
    fi
    
    # Check if Alertmanager is ready
    if curl -s -f "${ALERTMANAGER_URL}/-/ready" > /dev/null 2>&1; then
        add_check_result "Alertmanager" "Readiness" "PASS" "Service is ready"
    else
        add_check_result "Alertmanager" "Readiness" "FAIL" "Service is not ready"
    fi
    
    # Check alert status
    local alerts_response
    alerts_response=$(curl -s "${ALERTMANAGER_URL}/api/v1/alerts" 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        local alert_count
        alert_count=$(echo "$alerts_response" | jq '.data | length' 2>/dev/null || echo "0")
        
        local firing_alerts
        firing_alerts=$(echo "$alerts_response" | jq '.data | map(select(.status.state == "active")) | length' 2>/dev/null || echo "0")
        
        if [ "$firing_alerts" -eq 0 ]; then
            add_check_result "Alertmanager" "Alerts" "PASS" "No firing alerts ($alert_count total alerts)"
        else
            add_check_result "Alertmanager" "Alerts" "WARN" "$firing_alerts firing alerts ($alert_count total)"
        fi
    else
        add_check_result "Alertmanager" "Alerts" "FAIL" "Unable to query alerts API"
    fi
}

# Check CAM-specific metrics
check_cam_metrics() {
    log_info "Running CAM-specific health checks..."
    
    # Check if CAM metrics are being scraped
    local metrics_query="up{job=~\".*cam.*\"}"
    local metrics_response
    metrics_response=$(curl -s -G "${PROMETHEUS_URL}/api/v1/query" --data-urlencode "query=${metrics_query}" 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        local result_count
        result_count=$(echo "$metrics_response" | jq '.data.result | length' 2>/dev/null || echo "0")
        
        if [ "$result_count" -gt 0 ]; then
            local up_count
            up_count=$(echo "$metrics_response" | jq '.data.result | map(select(.value[1] == "1")) | length' 2>/dev/null || echo "0")
            
            if [ "$up_count" -eq "$result_count" ]; then
                add_check_result "CAM" "Metrics Collection" "PASS" "All $result_count CAM instances reporting metrics"
            elif [ "$up_count" -gt 0 ]; then
                add_check_result "CAM" "Metrics Collection" "WARN" "$up_count/$result_count CAM instances reporting metrics"
            else
                add_check_result "CAM" "Metrics Collection" "FAIL" "No CAM instances reporting metrics"
            fi
        else
            add_check_result "CAM" "Metrics Collection" "FAIL" "No CAM metrics found"
        fi
    else
        add_check_result "CAM" "Metrics Collection" "FAIL" "Unable to query CAM metrics"
    fi
    
    # Check key CAM metrics availability
    local key_metrics=("cam_requests_total" "cam_arbitration_duration_seconds" "cam_mesh_size")
    
    for metric in "${key_metrics[@]}"; do
        local metric_response
        metric_response=$(curl -s -G "${PROMETHEUS_URL}/api/v1/query" --data-urlencode "query=${metric}" 2>/dev/null)
        
        if [ $? -eq 0 ]; then
            local has_data
            has_data=$(echo "$metric_response" | jq '.data.result | length > 0' 2>/dev/null || echo "false")
            
            if [ "$has_data" = "true" ]; then
                add_check_result "CAM" "Metric: $metric" "PASS" "Metric data available"
            else
                add_check_result "CAM" "Metric: $metric" "WARN" "No data for metric"
            fi
        else
            add_check_result "CAM" "Metric: $metric" "FAIL" "Unable to query metric"
        fi
    done
}

# Check disk space for monitoring components
check_disk_space() {
    log_info "Checking disk space for monitoring components..."
    
    # Check Prometheus data directory (if running locally)
    if [ -d "/prometheus" ]; then
        local usage
        usage=$(df /prometheus | tail -1 | awk '{print $5}' | sed 's/%//')
        
        if [ "$usage" -lt 80 ]; then
            add_check_result "Storage" "Prometheus Data" "PASS" "${usage}% used"
        elif [ "$usage" -lt 90 ]; then
            add_check_result "Storage" "Prometheus Data" "WARN" "${usage}% used"
        else
            add_check_result "Storage" "Prometheus Data" "FAIL" "${usage}% used"
        fi
    fi
    
    # Check Grafana data directory (if running locally)
    if [ -d "/var/lib/grafana" ]; then
        local usage
        usage=$(df /var/lib/grafana | tail -1 | awk '{print $5}' | sed 's/%//')
        
        if [ "$usage" -lt 80 ]; then
            add_check_result "Storage" "Grafana Data" "PASS" "${usage}% used"
        elif [ "$usage" -lt 90 ]; then
            add_check_result "Storage" "Grafana Data" "WARN" "${usage}% used"
        else
            add_check_result "Storage" "Grafana Data" "FAIL" "${usage}% used"
        fi
    fi
}

# Generate health report
generate_health_report() {
    log_info "Generating health report..."
    
    local report_file="${SCRIPT_DIR}/../reports/health-check-$(date +%Y%m%d-%H%M%S).txt"
    mkdir -p "$(dirname "$report_file")"
    
    {
        echo "CAM Monitoring Health Check Report"
        echo "Generated: $(date)"
        echo "======================================"
        echo ""
        echo "Summary:"
        echo "  Total Checks: $TOTAL_CHECKS"
        echo "  Failed Checks: $FAILED_CHECKS"
        echo "  Success Rate: $(( (TOTAL_CHECKS - FAILED_CHECKS) * 100 / TOTAL_CHECKS ))%"
        echo ""
        echo "Detailed Results:"
        echo "=================="
        
        for check in "${HEALTH_CHECKS[@]}"; do
            echo "$check"
        done
        
        echo ""
        echo "Recommendations:"
        echo "================"
        
        if [ "$FAILED_CHECKS" -gt 0 ]; then
            echo "- Address failed health checks immediately"
            echo "- Review service logs for error details"
            echo "- Verify network connectivity between components"
        else
            echo "- All health checks passed"
            echo "- Continue regular monitoring"
        fi
        
    } > "$report_file"
    
    log_info "Health report saved to: $report_file"
}

# Send alerts if critical issues found
send_alerts() {
    if [ "$FAILED_CHECKS" -gt 0 ]; then
        log_warning "Found $FAILED_CHECKS failed health checks"
        
        # Send Slack alert if webhook is configured
        if [ -n "${SLACK_WEBHOOK_URL:-}" ]; then
            local slack_payload=$(cat <<EOF
{
    "text": "🚨 CAM Monitoring Health Check Alert",
    "attachments": [
        {
            "color": "danger",
            "fields": [
                {
                    "title": "Failed Checks",
                    "value": "$FAILED_CHECKS",
                    "short": true
                },
                {
                    "title": "Total Checks",
                    "value": "$TOTAL_CHECKS",
                    "short": true
                }
            ]
        }
    ]
}
EOF
)
            
            curl -X POST -H 'Content-type: application/json' \
                --data "$slack_payload" \
                "$SLACK_WEBHOOK_URL" > /dev/null 2>&1
            
            log_info "Slack alert sent"
        fi
    fi
}

# Main function
main() {
    log_info "Starting CAM monitoring health check..."
    
    # Check dependencies
    if ! command -v curl &> /dev/null; then
        log_error "curl is required but not installed"
        exit 1
    fi
    
    if ! command -v jq &> /dev/null; then
        log_error "jq is required but not installed"
        exit 1
    fi
    
    # Run health checks
    check_prometheus_health
    check_grafana_health
    check_alertmanager_health
    check_cam_metrics
    check_disk_space
    
    # Generate report and send alerts
    generate_health_report
    send_alerts
    
    # Exit with appropriate code
    if [ "$FAILED_CHECKS" -eq 0 ]; then
        log_success "All health checks passed!"
        exit 0
    else
        log_error "$FAILED_CHECKS health checks failed"
        exit 1
    fi
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
