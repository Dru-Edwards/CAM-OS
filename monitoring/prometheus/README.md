# CAM-OS Prometheus Configuration

This directory contains Prometheus configuration files and alert rules for monitoring CAM-OS.

## Files

- `prometheus.yml`: Main Prometheus configuration file
- `rules/alerts.yml`: Alert rules for CAM-OS monitoring

## Setup

1. Start Prometheus with the provided configuration:
   ```bash
   prometheus --config.file=prometheus.yml
   ```

2. The configuration will scrape metrics from:
   - CAM-OS kernel metrics endpoint (port 8080)
   - Node exporter (port 9100)
   - Redis exporter (port 9121)

## Metrics

CAM-OS exposes the following key metrics:

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

## Alerts

The alert rules include:

- **CAM-OS Down**: Triggered when CAM-OS is unreachable
- **High Syscall Latency**: Triggered when syscall latency exceeds thresholds
- **Memory Context Errors**: Triggered when memory operations fail
- **Security Violations**: Triggered when authentication failures spike
- **Performance Degradation**: Triggered when performance metrics degrade

## Integration

To integrate with existing monitoring:

1. Add the CAM-OS job to your existing Prometheus configuration
2. Import the alert rules into your Alertmanager
3. Configure notification channels for CAM-OS alerts
4. Set up dashboards using the provided Grafana configuration
