# CAM Protocol Prometheus Configuration

This directory contains Prometheus configuration files and alert rules for monitoring the CAM Protocol.

## Directory Structure

- **[rules/](./rules/)**: Contains Prometheus alert rules
  - **[alerts.yml](./rules/alerts.yml)**: Alert rules for latency, errors, resource utilization, and more

## Alert Rules

The `alerts.yml` file defines the following alert rules:

- **HighLatency**: Triggers when 95th percentile latency exceeds 2 seconds
- **HighErrorRate**: Triggers when error rate exceeds 5%
- **HighCPUUsage**: Triggers when CPU usage exceeds 80%
- **HighMemoryUsage**: Triggers when memory usage exceeds 80%
- **ServiceDown**: Triggers when a service is down for more than 1 minute
- **HighRejectionRate**: Triggers when routing rejection rate exceeds 10%
- **HighCostRate**: Triggers when API costs exceed $100/hour
- **HighConnectionCount**: Triggers when connection count exceeds 1000

## How to Use

1. Start the monitoring stack using the Docker Compose file in the [examples/quickstart](../../examples/quickstart) directory.

2. Access Prometheus at http://localhost:9090.

3. View active alerts in the "Alerts" tab.

## Customizing Alert Rules

To customize the alert rules:

1. Modify the `rules/alerts.yml` file
2. Adjust thresholds, durations, or add new rules as needed
3. Restart Prometheus for the changes to take effect

## Adding New Rules

To add new alert rules:

1. Edit the `rules/alerts.yml` file
2. Follow the Prometheus alert rule syntax
3. Restart Prometheus for the changes to take effect
