# CAM-OS Observability

This document outlines the observability features of CAM-OS, including metrics, monitoring, and alerting.

## Metrics

CAM-OS exposes a `/metrics` endpoint that provides Prometheus-compatible metrics. This endpoint is available on port 8080 by default.

### Syscall Metrics

- `cam_os_syscall_duration_seconds`: Histogram of syscall execution times
- `cam_os_syscall_total`: Counter of total syscalls executed
- `cam_os_syscall_errors_total`: Counter of syscall errors

### Memory Context Metrics

- `cam_os_memory_context_operations_total`: Counter of memory operations
- `cam_os_memory_context_size_bytes`: Gauge of memory context size
- `cam_os_memory_context_versions_total`: Counter of context versions

### Security Metrics

- `cam_os_security_tpm_operations_total`: Counter of TPM operations
- `cam_os_security_auth_failures_total`: Counter of authentication failures
- `cam_os_security_rate_limit_hits_total`: Counter of rate limit hits

### Performance Metrics

- `cam_os_scheduler_queue_size`: Gauge of scheduler queue size
- `cam_os_scheduler_priority_distribution`: Histogram of priority distribution
- `cam_os_driver_load_time_seconds`: Histogram of driver load times

## Monitoring

CAM-OS includes a Grafana dashboard for monitoring performance and resource utilization. The dashboard is available in the `monitoring/grafana/dashboards/cam_overview.json` file.

### Dashboard Features

- **System Health**: Overall system status and uptime
- **Performance Metrics**: Response times, throughput, and resource usage
- **Security Monitoring**: Authentication events and security violations
- **Business Metrics**: Driver marketplace revenue and usage statistics
- **Operational Insights**: Logs, traces, and debugging information

## Alerting

CAM-OS includes Prometheus alert rules for monitoring and alerting on critical metrics. The alert rules are available in the `monitoring/prometheus/rules/alerts.yml` file.

### Alert Rules

- **CAM-OS Down**: Triggered when CAM-OS is unreachable
- **High Syscall Latency**: Triggered when syscall latency exceeds thresholds
- **Memory Context Errors**: Triggered when memory operations fail
- **Security Violations**: Triggered when authentication failures spike
- **Performance Degradation**: Triggered when performance metrics degrade

## Setup

### Docker Compose

1. Start the CAM-OS with monitoring enabled:
   ```bash
   docker-compose -f docker-compose.test.yml up -d
   ```

2. Access Prometheus at http://localhost:9090

3. Access Grafana at http://localhost:3000 (admin/admin)

4. Import the CAM-OS dashboard from `monitoring/grafana/dashboards/cam_overview.json`

### Kubernetes

1. Install the CAM-OS operator:
   ```bash
   kubectl apply -f deployment/kubernetes/operator/
   ```

2. Deploy monitoring stack:
   ```bash
   kubectl apply -f deployment/kubernetes/monitoring/
   ```

3. Access services through ingress or port-forwarding

## Distributed Tracing

CAM-OS supports distributed tracing through the `sys_emit_trace` syscall:

```bash
grpcurl -plaintext -d '{
  "verb": "emit_trace",
  "payload": "trace_id:abc123,span_id:def456,operation:syscall_execution"
}' localhost:50051 cam.SyscallService/Execute
```

### Trace Collection

Traces are collected and can be exported to:
- Jaeger
- Zipkin
- OpenTelemetry collectors

## Log Aggregation

CAM-OS produces structured logs that can be aggregated using:

1. **Loki**: For Grafana integration
2. **Elasticsearch**: For advanced search and analysis
3. **Splunk**: For enterprise log management

### Log Format

```json
{
  "timestamp": "2024-12-01T12:00:00Z",
  "level": "INFO",
  "component": "syscall_dispatcher",
  "syscall": "think",
  "caller_id": "agent-123",
  "latency_ms": 0.8,
  "success": true
}
```

## Health Checks

CAM-OS provides multiple health check endpoints:

### Basic Health Check
```bash
grpcurl -plaintext -d '{"caller_id": "health-check"}' \
  localhost:50051 cam.SyscallService/HealthCheck
```

### Detailed Health Check
```bash
grpcurl -plaintext -d '{"caller_id": "health-check", "detailed": true}' \
  localhost:50051 cam.SyscallService/HealthCheck
```

### Component Health
- **Redis Backend**: Connection and latency checks
- **TPM Security**: Hardware security module status
- **Driver Runtime**: Loaded drivers and their health
- **Scheduler**: Queue size and performance metrics

## Custom Metrics

Applications can emit custom metrics using the `sys_emit_metric` syscall:

```bash
grpcurl -plaintext -d '{
  "verb": "emit_metric",
  "payload": "metric_name:custom_counter,value:1,labels:app=myapp,env=prod"
}' localhost:50051 cam.SyscallService/Execute
```

## Troubleshooting

### Common Issues

1. **High Latency**: Check scheduler queue size and Redis performance
2. **Memory Leaks**: Monitor context storage growth and cleanup
3. **Security Violations**: Review authentication and authorization logs
4. **Performance Degradation**: Analyze syscall distribution and bottlenecks

### Debug Mode

Enable debug logging:
```bash
export CAM_LOG_LEVEL=debug
./cam-kernel
```

### Profiling

Enable CPU and memory profiling:
```bash
export CAM_PROFILING_ENABLED=true
./cam-kernel
```

Access profiling data at http://localhost:8080/debug/pprof/

## Integration

### Prometheus Configuration

Add CAM-OS to your Prometheus configuration:

```yaml
scrape_configs:
  - job_name: 'cam-os'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
    scrape_interval: 5s
```

### Grafana Dashboard

Import the CAM-OS dashboard:
1. Open Grafana
2. Go to "+" → "Import"
3. Upload `monitoring/grafana/dashboards/cam_overview.json`
4. Configure data source as Prometheus

### Alertmanager

Configure Alertmanager for CAM-OS alerts:

```yaml
route:
  group_by: ['alertname']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'cam-os-alerts'

receivers:
- name: 'cam-os-alerts'
  slack_configs:
  - api_url: 'YOUR_SLACK_WEBHOOK_URL'
    channel: '#cam-os-alerts'
    title: 'CAM-OS Alert'
    text: '{{ range .Alerts }}{{ .Annotations.summary }}{{ end }}'
```

## Best Practices

1. **Monitor Key Metrics**: Focus on syscall latency, error rates, and resource usage
2. **Set Appropriate Thresholds**: Balance between noise and missed issues
3. **Use Structured Logging**: Enable JSON logging for better parsing
4. **Regular Health Checks**: Implement automated health monitoring
5. **Capacity Planning**: Monitor growth trends and plan for scaling

## Support

For observability questions:
- [Monitoring Documentation](../monitoring/README.md)
- [GitHub Issues](https://github.com/Dru-Edwards/CAM-OS/issues)
- [Community Discord](https://discord.gg/cam-os)
