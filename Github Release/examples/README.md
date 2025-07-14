# CAM-OS Kernel Examples

This directory contains examples and demonstrations of the CAM-OS kernel in action.

## Available Examples

- **[Quickstart](./quickstart/)**: A complete Docker Compose setup for quickly getting started with CAM-OS kernel
- **[Toy LLM](./toy-llm/)**: A simple mock LLM service for demonstration purposes (legacy)
- **[Drivers](./drivers/)**: Examples of gRPC drivers for the CAM-OS kernel
- **[Syscalls](./syscalls/)**: Examples of using the cognitive syscalls
- **[Deployment](./deployment/)**: Production deployment examples

## Quickstart Example

For the fastest way to get started with CAM-OS kernel, see the [Quickstart](./quickstart/) directory, which includes a complete Docker Compose setup with:

- CAM-OS Kernel Core Service
- Driver Runtime
- Redis and PostgreSQL
- Prometheus and Grafana for monitoring

```bash
# Navigate to the quickstart directory
cd examples/quickstart

# Start the environment
docker-compose up -d

# Test the kernel with syscalls (requires grpcurl)
grpcurl -plaintext -d '{}' localhost:8080 syscall.SyscallService/HealthCheck
grpcurl -plaintext -d '{"task_id": "test-001", "options": {"provider": "demo"}}' localhost:8080 syscall.SyscallService/Arbitrate
```

## Syscall Examples

### Health Check
```bash
grpcurl -plaintext -d '{}' localhost:8080 syscall.SyscallService/HealthCheck
```

### Task Arbitration
```bash
grpcurl -plaintext -d '{
  "task_id": "task-001",
  "options": {
    "provider": "openai",
    "priority": "high"
  }
}' localhost:8080 syscall.SyscallService/Arbitrate
```

### Context Operations
```bash
# Write to context
grpcurl -plaintext -d '{
  "namespace": "user-123",
  "key": "session-data",
  "value": "eyJzZXNzaW9uX2lkIjoidGVzdCJ9"
}' localhost:8080 syscall.SyscallService/ContextWrite

# Read from context
grpcurl -plaintext -d '{
  "namespace": "user-123",
  "key": "session-data"
}' localhost:8080 syscall.SyscallService/ContextRead
```
