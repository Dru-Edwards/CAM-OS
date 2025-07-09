# CAM-OS Docker Test Environment

This document provides instructions for testing CAM-OS using Docker containers.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/Dru-Edwards/CAM-OS.git
cd CAM-OS

# Run the complete test environment
./quick-start-docker.sh
```

## Manual Testing

### 1. Start the Environment

```bash
docker-compose -f docker-compose.test.yml up -d
```

### 2. Test Core Syscalls

#### Think Syscall
```bash
docker run --rm --network cam-os_cam-network fullstorydev/grpcurl:latest \
  -plaintext -d '{"verb":"think", "payload":"solve problem"}' \
  cam-kernel:50051 cam.SyscallService/Execute
```

#### Decide Syscall
```bash
docker run --rm --network cam-os_cam-network fullstorydev/grpcurl:latest \
  -plaintext -d '{"verb":"decide", "payload":"choose option A"}' \
  cam-kernel:50051 cam.SyscallService/Execute
```

### 3. Test Memory Context Operations

#### Context Write
```bash
docker run --rm --network cam-os_cam-network fullstorydev/grpcurl:latest \
  -plaintext -d '{"verb":"context_write", "payload":"namespace:test,key:data,value:example"}' \
  cam-kernel:50051 cam.SyscallService/Execute
```

#### Context Read
```bash
docker run --rm --network cam-os_cam-network fullstorydev/grpcurl:latest \
  -plaintext -d '{"verb":"context_read", "payload":"namespace:test,key:data"}' \
  cam-kernel:50051 cam.SyscallService/Execute
```

### 4. Test Agent Operations

#### Register Agent
```bash
docker run --rm --network cam-os_cam-network fullstorydev/grpcurl:latest \
  -plaintext -d '{"verb":"register_agent", "payload":"agent_id:test-agent,capabilities:reasoning,thinking"}' \
  cam-kernel:50051 cam.SyscallService/Execute
```

#### Communicate
```bash
docker run --rm --network cam-os_cam-network fullstorydev/grpcurl:latest \
  -plaintext -d '{"verb":"communicate", "payload":"from:agent-1,to:agent-2,message:hello"}' \
  cam-kernel:50051 cam.SyscallService/Execute
```

### 5. Test Task Management

#### Commit Task
```bash
docker run --rm --network cam-os_cam-network fullstorydev/grpcurl:latest \
  -plaintext -d '{"verb":"commit_task", "payload":"task_id:task-123,description:process data"}' \
  cam-kernel:50051 cam.SyscallService/Execute
```

#### Rollback Task
```bash
docker run --rm --network cam-os_cam-network fullstorydev/grpcurl:latest \
  -plaintext -d '{"verb":"rollback_task", "payload":"task_id:task-123"}' \
  cam-kernel:50051 cam.SyscallService/Execute
```

### 6. Test Observability

#### Observe
```bash
docker run --rm --network cam-os_cam-network fullstorydev/grpcurl:latest \
  -plaintext -d '{"verb":"observe", "payload":"component:scheduler,metrics:queue_size,latency"}' \
  cam-kernel:50051 cam.SyscallService/Execute
```

#### Explain Action
```bash
docker run --rm --network cam-os_cam-network fullstorydev/grpcurl:latest \
  -plaintext -d '{"verb":"explain_action", "payload":"action_id:action-456,detail_level:high"}' \
  cam-kernel:50051 cam.SyscallService/Execute
```

## Monitoring and Observability

### Access Grafana Dashboard
```bash
# Open in browser
open http://localhost:3000
# Default credentials: admin/admin
```

### View Prometheus Metrics
```bash
# Open in browser
open http://localhost:9090
```

### Check Redis Data
```bash
docker exec -it cam-os-redis redis-cli
```

## Performance Testing

### Load Testing
```bash
# Run automated load tests
./test-scripts/run-all-tests.sh

# Or run specific performance tests
docker run --rm --network cam-os_cam-network fullstorydev/grpcurl:latest \
  -plaintext -d '{"verb":"tune_system", "payload":"performance_mode:high,max_workers:200"}' \
  cam-kernel:50051 cam.SyscallService/Execute
```

### Stress Testing
```bash
# High-volume syscall testing
for i in {1..1000}; do
  docker run --rm --network cam-os_cam-network fullstorydev/grpcurl:latest \
    -plaintext -d '{"verb":"think", "payload":"stress test '$i'"}' \
    cam-kernel:50051 cam.SyscallService/Execute &
done
wait
```

## Troubleshooting

### Check Container Status
```bash
docker-compose -f docker-compose.test.yml ps
```

### View Logs
```bash
# CAM-OS kernel logs
docker logs cam-os-kernel

# Redis logs
docker logs cam-os-redis

# All logs
docker-compose -f docker-compose.test.yml logs -f
```

### Clean Up
```bash
# Stop all containers
docker-compose -f docker-compose.test.yml down

# Remove volumes
docker-compose -f docker-compose.test.yml down -v

# Clean up images
docker system prune -f
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CAM_PORT` | 50051 | gRPC server port |
| `CAM_REDIS_URL` | redis://redis:6379 | Redis connection URL |
| `CAM_LOG_LEVEL` | info | Log level (debug, info, warn, error) |
| `CAM_METRICS_PORT` | 8080 | Metrics server port |
| `CAM_HEALTH_PORT` | 8081 | Health check port |

## Testing Checklist

- [ ] All 15 cognitive syscalls respond successfully
- [ ] Memory context operations work correctly
- [ ] Agent registration and communication function
- [ ] Task management (commit/rollback) works
- [ ] Observability and monitoring are functional
- [ ] Performance targets are met (<1ms latency)
- [ ] Security features are operational
- [ ] Error handling works correctly
- [ ] Resource cleanup is proper
- [ ] Monitoring dashboards display data

## Advanced Testing

### Security Testing
```bash
# Test authentication
docker run --rm --network cam-os_cam-network fullstorydev/grpcurl:latest \
  -plaintext -H "Authorization: Bearer invalid-token" \
  -d '{"verb":"think", "payload":"test"}' \
  cam-kernel:50051 cam.SyscallService/Execute
```

### Federation Testing
```bash
# Test multi-cluster operations
docker run --rm --network cam-os_cam-network fullstorydev/grpcurl:latest \
  -plaintext -d '{"verb":"federate", "payload":"cluster:remote,operation:sync"}' \
  cam-kernel:50051 cam.SyscallService/Execute
```

### Driver Testing
```bash
# Test driver loading
docker run --rm --network cam-os_cam-network fullstorydev/grpcurl:latest \
  -plaintext -d '{"verb":"load_driver", "payload":"driver:test-driver,type:wasm"}' \
  cam-kernel:50051 cam.SyscallService/Execute
```

## Support

For issues with the Docker test environment:

1. Check the troubleshooting section above
2. Review container logs for error messages
3. Verify network connectivity between containers
4. Ensure all required ports are available
5. Check resource availability (CPU, memory, disk)

For additional support, please open an issue on the [CAM-OS GitHub repository](https://github.com/Dru-Edwards/CAM-OS/issues). 