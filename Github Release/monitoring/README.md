# CAM Monitoring and Observability

This directory contains comprehensive monitoring and observability components for the Complete Arbitration Mesh Final system.

## Overview

The monitoring infrastructure provides:

- **Real-time Metrics Collection**: Prometheus-based metrics gathering from all CAM components
- **Visual Dashboards**: Grafana dashboards for system overview, performance analysis, and troubleshooting
- **Automated Health Checks**: Scripts to verify monitoring infrastructure health
- **Alert Management**: Alertmanager integration for proactive issue detection
- **Multi-environment Support**: Configurations for development, staging, and production environments

## Directory Structure

```
monitoring/
├── dashboards/                 # Grafana dashboard definitions
│   ├── cam-overview-dashboard.json
│   ├── cam-arbitration-performance-dashboard.json
│   ├── cam-agent-collaboration-dashboard.json
│   └── cam-infrastructure-dashboard.json
├── scripts/                    # Automation and health check scripts
│   ├── grafana-provisioning.sh
│   └── monitoring-health-check.sh
├── alerts/                     # Alert rule definitions
├── config/                     # Monitoring configuration files
├── reports/                    # Generated health reports
└── README.md
```

## Dashboards

### 1. CAM System Overview
**File**: `cam-overview-dashboard.json`

Provides high-level system health and performance metrics:
- System health status across all instances
- Mesh size and connectivity metrics
- Request processing rates and response times
- Error rates and system reliability
- Consensus algorithm performance
- Agent collaboration activity
- Resource utilization summary

**Key Metrics**:
- `cam_up` - Service availability
- `cam_mesh_size` - Number of active nodes
- `cam_requests_total` - Request volume and status
- `cam_arbitration_duration_seconds` - Response time percentiles
- `cam_consensus_rounds` - Consensus performance

### 2. CAM Arbitration Performance
**File**: `cam-arbitration-performance-dashboard.json`

Detailed analysis of arbitration engine performance:
- Arbitration success rates and timing
- Provider response time comparisons
- Queue depth and throughput analysis
- Decision breakdown by type
- Cost analysis per arbitration
- Latency distribution heatmaps

**Key Metrics**:
- `cam_arbitration_requests_total` - Arbitration volume
- `cam_provider_response_time_seconds` - Provider latency
- `cam_arbitration_queue_depth` - Queue management
- `cam_arbitration_cost_total` - Cost tracking

### 3. CAM Agent Collaboration
**File**: `cam-agent-collaboration-dashboard.json`

Multi-agent system monitoring and analysis:
- Active agent counts and status
- Collaboration session management
- Communication patterns and rates
- Task completion metrics
- Network topology visualization
- Resource sharing efficiency

**Key Metrics**:
- `cam_agent_status` - Agent health
- `cam_collaboration_sessions` - Active collaborations
- `cam_agent_messages_total` - Communication volume
- `cam_agent_performance_score` - Performance tracking

### 4. CAM Infrastructure
**File**: `cam-infrastructure-dashboard.json`

Infrastructure and resource monitoring:
- Kubernetes cluster resource usage
- Pod resource requests vs limits
- Network and disk I/O patterns
- Persistent volume utilization
- Node-level metrics
- Container performance

**Key Metrics**:
- `node_cpu_seconds_total` - CPU utilization
- `container_memory_working_set_bytes` - Memory usage
- `kube_pod_status_phase` - Pod health
- `kubelet_volume_stats_used_bytes` - Storage usage

## Scripts

### Grafana Provisioning Script
**File**: `scripts/grafana-provisioning.sh`

Automated Grafana setup and configuration:

```bash
# Basic usage
./scripts/grafana-provisioning.sh

# With custom configuration
GRAFANA_URL=http://grafana.example.com:3000 \
GRAFANA_USER=admin \
GRAFANA_PASSWORD=secure_password \
PROMETHEUS_URL=http://prometheus.example.com:9090 \
./scripts/grafana-provisioning.sh
```

**Features**:
- Automatic Prometheus data source creation
- Dashboard folder organization
- Bulk dashboard import
- Alert notification channel setup
- Organization configuration

### Health Check Script
**File**: `scripts/monitoring-health-check.sh`

Comprehensive monitoring infrastructure health verification:

```bash
# Run health checks
./scripts/monitoring-health-check.sh

# With custom endpoints
PROMETHEUS_URL=http://prometheus.example.com:9090 \
GRAFANA_URL=http://grafana.example.com:3000 \
ALERTMANAGER_URL=http://alertmanager.example.com:9093 \
./scripts/monitoring-health-check.sh
```

**Checks Include**:
- Service availability and readiness
- Data source connectivity
- Metrics collection validation
- Dashboard availability
- Alert system status
- Storage utilization
- CAM-specific metric validation

## Quick Start

### 1. Deploy Monitoring Stack

Using Helm (recommended):
```bash
# Install Prometheus and Grafana
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update

# Install monitoring stack
helm install cam-monitoring prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --create-namespace \
  --values ../deployment/helm/cam-chart/values.yaml
```

Using Docker Compose:
```bash
# From the deployment directory
docker-compose -f docker-compose.monitoring.yml up -d
```

### 2. Provision Dashboards

```bash
# Set environment variables
export GRAFANA_URL=http://localhost:3000
export GRAFANA_USER=admin
export GRAFANA_PASSWORD=admin
export PROMETHEUS_URL=http://localhost:9090

# Run provisioning script
./scripts/grafana-provisioning.sh
```

### 3. Verify Health

```bash
# Run comprehensive health check
./scripts/monitoring-health-check.sh

# Check specific components
curl -f http://localhost:9090/-/healthy  # Prometheus
curl -f http://localhost:3000/api/health # Grafana
```

### 4. Access Dashboards

1. Open Grafana: http://localhost:3000
2. Login with configured credentials
3. Navigate to "CAM Monitoring" folder
4. Select desired dashboard

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PROMETHEUS_URL` | Prometheus server URL | `http://localhost:9090` |
| `GRAFANA_URL` | Grafana server URL | `http://localhost:3000` |
| `ALERTMANAGER_URL` | Alertmanager URL | `http://localhost:9093` |
| `GRAFANA_USER` | Grafana admin username | `admin` |
| `GRAFANA_PASSWORD` | Grafana admin password | `admin` |
| `SLACK_WEBHOOK_URL` | Slack webhook for alerts | (optional) |
| `ALERT_EMAIL` | Email for alert notifications | (optional) |

### Custom Metrics

CAM exposes the following custom metrics:

**System Metrics**:
- `cam_up` - Service health (0/1)
- `cam_build_info` - Build and version information
- `cam_mesh_size` - Number of active mesh nodes
- `cam_mesh_connectivity_score` - Mesh connectivity health

**Request Metrics**:
- `cam_requests_total` - Total requests by status
- `cam_request_duration_seconds` - Request latency histogram
- `cam_active_connections` - Current active connections

**Arbitration Metrics**:
- `cam_arbitration_requests_total` - Arbitration requests
- `cam_arbitration_duration_seconds` - Arbitration latency
- `cam_arbitration_queue_depth` - Queue depth
- `cam_consensus_rounds` - Consensus algorithm rounds
- `cam_consensus_time_seconds` - Consensus completion time

**Agent Metrics**:
- `cam_agent_status` - Agent health status
- `cam_agent_messages_total` - Inter-agent messages
- `cam_collaboration_sessions` - Active collaborations
- `cam_agent_performance_score` - Agent performance rating

**Provider Metrics**:
- `cam_provider_requests_total` - Provider API calls
- `cam_provider_response_time_seconds` - Provider latency
- `cam_provider_availability_score` - Provider health score
- `cam_provider_cost_total` - Provider usage costs

## Alert Rules

The monitoring system includes pre-configured alert rules:

**Critical Alerts**:
- Service downtime (>1 minute)
- High error rate (>5% for 5 minutes)
- Consensus failure
- Database connectivity issues

**Warning Alerts**:
- High CPU usage (>80% for 10 minutes)
- High memory usage (>90% for 5 minutes)
- Queue depth (>100 requests)
- Storage usage (>85%)

**Info Alerts**:
- Deployment events
- Configuration changes
- Performance degradation

## Troubleshooting

### Common Issues

1. **Dashboards not loading**:
   - Verify Prometheus data source connection
   - Check network connectivity
   - Validate metric names and labels

2. **Missing metrics**:
   - Ensure CAM services expose `/metrics` endpoint
   - Verify Prometheus scrape configuration
   - Check service discovery labels

3. **High resource usage**:
   - Adjust Prometheus retention settings
   - Optimize dashboard queries
   - Review scrape intervals

### Debug Commands

```bash
# Check Prometheus targets
curl -s http://localhost:9090/api/v1/targets | jq '.data.activeTargets'

# Query specific metrics
curl -s "http://localhost:9090/api/v1/query?query=cam_up" | jq '.data.result'

# Validate dashboard JSON
jq '.' dashboards/cam-overview-dashboard.json

# Test Grafana API
curl -u admin:admin http://localhost:3000/api/datasources
```

## Integration with CAM Deployment

The monitoring components integrate seamlessly with CAM deployment:

- **Helm Charts**: Monitoring enabled via values configuration
- **Kubernetes**: ServiceMonitor and PrometheusRule resources
- **Docker Compose**: Monitoring services in development stack
- **Cloud Deployments**: Platform-specific monitoring integrations

## Performance Considerations

- **Metrics Retention**: Configure based on storage capacity and compliance requirements
- **Scrape Intervals**: Balance freshness with resource usage
- **Dashboard Queries**: Optimize for fast loading and minimal resource consumption
- **Alert Frequency**: Avoid alert fatigue with appropriate thresholds

## Security

- **Authentication**: Secure Grafana with strong passwords and RBAC
- **Network Security**: Use TLS for all monitoring communications
- **Data Privacy**: Ensure metrics don't expose sensitive information
- **Access Control**: Implement role-based dashboard access

## Support

For monitoring-related issues:

1. Run health check script for diagnostics
2. Review generated health reports
3. Check component logs for error details
4. Consult troubleshooting section
5. Contact support for Enterprise-Elite customers

---

**Note**: This monitoring infrastructure is designed for production use with high availability, security, and performance considerations. Customize configurations based on your specific requirements and environment constraints.
