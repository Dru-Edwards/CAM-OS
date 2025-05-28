# CAM Protocol Grafana Dashboards

This directory contains Grafana dashboards and configurations for monitoring the CAM Protocol.

## Dashboards

The `dashboards` directory contains JSON definitions for the following Grafana dashboards:

- **[cam_overview.json](./dashboards/cam_overview.json)**: A comprehensive overview dashboard for monitoring the CAM Protocol's performance, resource utilization, and business metrics.

## How to Use

1. Start the monitoring stack using the Docker Compose file in the [examples/quickstart](../../examples/quickstart) directory.

2. Access Grafana at http://localhost:3001 (default credentials: admin/admin).

3. The dashboards should be automatically provisioned. If not, you can import them manually:
   - In Grafana, click on the "+" icon in the sidebar
   - Select "Import"
   - Upload the JSON file or paste its contents
   - Click "Import"

## Dashboard Features

The CAM Protocol Overview dashboard includes:

- Request rate and latency metrics
- Error rate monitoring
- Resource utilization (CPU, memory)
- Routing decisions and performance
- Cost tracking
- Agent collaboration metrics

## Customizing Dashboards

You can customize these dashboards to suit your specific needs:

1. Make a copy of the dashboard in Grafana
2. Modify the panels, variables, and queries as needed
3. Save your custom dashboard

## Adding New Dashboards

To add a new dashboard:

1. Create the dashboard in Grafana
2. Export it as JSON
3. Add it to the `dashboards` directory
4. Update the provisioning configuration if necessary
