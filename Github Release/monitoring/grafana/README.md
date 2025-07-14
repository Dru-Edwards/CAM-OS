# CAM-OS Grafana Dashboards

This directory contains Grafana dashboards and configurations for monitoring CAM-OS.

## Dashboards

### Overview Dashboard
- **[cam_overview.json](./dashboards/cam_overview.json)**: A comprehensive overview dashboard for monitoring CAM-OS performance, resource utilization, and business metrics.

## Features

The dashboards provide real-time monitoring of:

- **Syscall Performance**: Latency, throughput, and error rates
- **Memory Context**: Context operations, versioning, and storage metrics
- **Security**: Authentication, authorization, and threat detection
- **Scheduler**: Task queue, priority distribution, and resource allocation
- **Driver Ecosystem**: Driver loading, performance, and marketplace metrics
- **Federation**: Multi-cluster synchronization and CRDT operations
- **System Resources**: CPU, memory, and network utilization

## Setup

1. Import the dashboard JSON files into your Grafana instance
2. Configure Prometheus as a data source
3. Set up alerting rules for critical metrics
4. Customize panels and thresholds as needed

## Dashboard Details

The CAM-OS Overview dashboard includes:

- **System Health**: Overall system status and uptime
- **Performance Metrics**: Response times, throughput, and resource usage
- **Security Monitoring**: Authentication events and security violations
- **Business Metrics**: Driver marketplace revenue and usage statistics
- **Operational Insights**: Logs, traces, and debugging information

## Customization

To customize the dashboards:

1. Edit the JSON files directly
2. Import modified dashboards into Grafana
3. Save changes to preserve customizations
4. Export updated dashboards for version control

## Integration

The dashboards integrate with:

- **Prometheus**: Primary metrics collection
- **Loki**: Log aggregation and analysis
- **Jaeger**: Distributed tracing
- **Alertmanager**: Alert notification and management
