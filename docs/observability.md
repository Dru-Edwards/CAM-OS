# CAM Protocol Observability

This document outlines the observability features of the CAM Protocol, including metrics, monitoring, and alerting.

## Metrics Endpoint

CAM Protocol exposes a `/metrics` endpoint that provides Prometheus-compatible metrics. This endpoint is available on port 8080 by default.

### Available Metrics

The following metrics are available:

#### Performance Metrics

- `http_request_duration_seconds`: Histogram of HTTP request durations (in seconds)
- `http_requests_total`: Counter of HTTP requests, labeled by status code and route
- `routing_decisions_total`: Counter of routing decisions, labeled by result (accepted/rejected)
- `agent_response_time_seconds`: Histogram of agent response times (in seconds)
- `mesh_resolution_time_seconds`: Histogram of mesh resolution times (in seconds)

#### Resource Utilization Metrics

- `process_cpu_seconds_total`: Total user and system CPU time spent in seconds
- `process_resident_memory_bytes`: Resident memory size in bytes
- `process_heap_bytes`: Process heap size in bytes
- `nodejs_eventloop_lag_seconds`: Node.js event loop lag in seconds

#### Business Metrics

- `api_cost_total`: Counter of API costs in USD
- `tokens_processed_total`: Counter of tokens processed, labeled by model
- `connections_current`: Gauge of current connections
- `active_sessions`: Gauge of active sessions
- `cache_hit_ratio`: Gauge of cache hit ratio

## Monitoring with Grafana

CAM Protocol includes a Grafana dashboard for monitoring performance and resource utilization. The dashboard is available in the `monitoring/grafana/dashboards/cam_overview.json` file.

### Dashboard Features

- Overview of key performance indicators
- Request rate and latency graphs
- Error rate monitoring
- Resource utilization graphs
- Cost tracking
- Agent performance comparison

## Alerting with Prometheus

CAM Protocol includes Prometheus alert rules for monitoring and alerting on critical metrics. The alert rules are available in the `monitoring/prometheus/rules/alerts.yml` file.

### Available Alerts

- High latency detection
- High error rate detection
- Service health monitoring
- Resource utilization alerts
- Cost monitoring

## Setting Up Observability

### Prerequisites

- Docker and Docker Compose
- Prometheus
- Grafana

### Quick Setup

1. Start the CAM Protocol with monitoring enabled:

```bash
docker-compose up -d
```

2. Access the Grafana dashboard at `http://localhost:3000`

3. Default credentials:
   - Username: admin
   - Password: admin

4. Import the CAM Protocol dashboard from `monitoring/grafana/dashboards/cam_overview.json`

### Custom Configuration

To customize the monitoring setup, modify the following files:

- `docker-compose.yml`: Update the Prometheus and Grafana configuration
- `monitoring/prometheus/rules/alerts.yml`: Customize alert rules
- `monitoring/grafana/dashboards/cam_overview.json`: Customize the dashboard

## Best Practices

1. **Set up alerting**: Configure alert notifications via email, Slack, or other channels
2. **Retention policies**: Configure appropriate data retention policies for metrics
3. **Dashboard access**: Restrict dashboard access to authorized users
4. **Regular reviews**: Regularly review metrics and alerts to identify optimization opportunities

## Troubleshooting

If you encounter issues with the metrics endpoint or monitoring setup, check the following:

1. Ensure the CAM Protocol service is running
2. Verify that Prometheus can access the metrics endpoint
3. Check Prometheus logs for scraping errors
4. Verify that Grafana can connect to Prometheus
