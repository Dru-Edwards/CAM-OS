# CAM Protocol Quickstart

This quickstart example provides a complete environment for testing and exploring the CAM Protocol with minimal setup.

## What's Included

- **CAM Protocol Core Service**: The main arbitration and routing service
- **Toy LLM Service**: A simple mock LLM service for demonstration purposes
- **Redis**: For caching and message brokering
- **PostgreSQL**: For persistent storage
- **Prometheus**: For metrics collection
- **Grafana**: For visualization and monitoring

## Getting Started

### Prerequisites

- Docker and Docker Compose installed on your system
- 4GB+ of available RAM
- 10GB+ of available disk space

### Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/cam-protocol/complete-arbitration-mesh.git
   cd complete-arbitration-mesh/examples/quickstart
   ```

2. Start the environment:
   ```bash
   docker-compose up -d
   ```

3. Verify all services are running:
   ```bash
   docker-compose ps
   ```

4. Test the CAM Protocol API:
   ```bash
   curl -X POST http://localhost:8080/mesh/chat \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer demo-key-for-quickstart" \
     -d '{"message": "Hello, CAM Protocol!"}'
   ```

## Accessing the Services

- **CAM Protocol API**: http://localhost:8080
- **Toy LLM Service**: http://localhost:3000
- **Grafana Dashboard**: http://localhost:3001 (admin/admin)
- **Prometheus**: http://localhost:9090

## Exploring the Dashboard

1. Open Grafana at http://localhost:3001
2. Log in with username `admin` and password `admin`
3. Navigate to the "CAM Protocol Overview" dashboard
4. Generate some traffic using the test command above to see metrics in action

## Next Steps

Once you're familiar with the basic setup, you can:

1. Integrate real LLM providers by updating the environment variables
2. Customize the routing policies in the CAM Protocol configuration
3. Explore the advanced features like agent collaboration and cost optimization

## Cleanup

To stop and remove all containers, networks, and volumes:

```bash
docker-compose down -v
```

## Troubleshooting

If you encounter any issues:

1. Check container logs: `docker-compose logs cam-core`
2. Ensure all services are healthy: `docker-compose ps`
3. Restart a specific service: `docker-compose restart cam-core`
4. Rebuild and restart everything: `docker-compose down && docker-compose up -d --build`
