# CAM-OS Quickstart

This quickstart example provides a complete environment for testing and exploring CAM-OS with minimal setup.

## What's Included

- **CAM-OS Kernel**: The main cognitive operating system kernel
- **Redis Backend**: For distributed context storage
- **Toy LLM Service**: Example AI service for testing
- **Monitoring Stack**: Prometheus and Grafana for observability

## Prerequisites

- Docker and Docker Compose
- 4GB+ available RAM
- Available ports: 50051, 6379, 8080, 3000, 9090

## Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/Dru-Edwards/CAM-OS.git
   cd CAM-OS/examples/quickstart
   ```

2. Start the environment:
   ```bash
   docker-compose up -d
   ```

3. Wait for services to be ready (about 30 seconds)

4. Test the CAM-OS API:
   ```bash
   curl -X POST http://localhost:50051/api/v1/syscall \
   -H "Content-Type: application/json" \
   -d '{"verb": "think", "payload": "Hello, CAM-OS!"}'
   ```

## Access Points

- **CAM-OS Kernel gRPC**: localhost:50051
- **Redis Backend**: localhost:6379
- **Toy LLM Service**: http://localhost:8080
- **Prometheus**: http://localhost:9090
- **Grafana**: http://localhost:3000 (admin/admin)

## Monitoring

1. Open Grafana at http://localhost:3000
2. Login with admin/admin
3. Navigate to the "CAM-OS Overview" dashboard
4. Explore the cognitive syscall metrics

## Testing Cognitive Syscalls

### Think Syscall
```bash
grpcurl -plaintext -d '{"verb":"think", "payload":"solve problem"}' \
  localhost:50051 cam.SyscallService/Execute
```

### Context Operations
```bash
# Write context
grpcurl -plaintext -d '{"verb":"context_write", "payload":"namespace:test,key:data,value:example"}' \
  localhost:50051 cam.SyscallService/Execute

# Read context
grpcurl -plaintext -d '{"verb":"context_read", "payload":"namespace:test,key:data"}' \
  localhost:50051 cam.SyscallService/Execute
```

### Agent Operations
```bash
# Register agent
grpcurl -plaintext -d '{"verb":"register_agent", "payload":"agent_id:test-agent,capabilities:reasoning"}' \
  localhost:50051 cam.SyscallService/Execute

# Agent communication
grpcurl -plaintext -d '{"verb":"communicate", "payload":"from:agent-1,to:agent-2,message:hello"}' \
  localhost:50051 cam.SyscallService/Execute
```

## Customization

1. Modify the toy LLM service in `toy-llm/index.js`
2. Customize the routing policies in the CAM-OS configuration
3. Add your own AI services to the docker-compose.yml

## Cleanup

```bash
docker-compose down -v
```

## Next Steps

- Explore the [API Reference](../../docs/api-reference.md)
- Learn about [Driver Development](../../docs/drivers/)
- Deploy to production with [Kubernetes](../../deployment/kubernetes/)

## Support

For questions or issues:
- [GitHub Issues](https://github.com/Dru-Edwards/CAM-OS/issues)
- [Documentation](https://docs.cam-os.dev)
- [Community Discord](https://discord.gg/cam-os)
