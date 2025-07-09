# 🚀 CAM-OS Kernel Docker Test Environment

Since CAM-OS is a Go-based cognitive operating system kernel that runs on existing operating systems (not a bootable OS), this Docker environment provides the best way to quickly test and evaluate the kernel functionality.

## 📦 What's Included

This Docker test environment includes:

- **CAM-OS Kernel**: The main cognitive operating system kernel
- **Redis Backend**: For distributed context storage
- **Prometheus**: Metrics collection and monitoring
- **Grafana**: Visualization dashboard
- **Test Suite**: Comprehensive syscall testing
- **Monitoring**: Real-time performance metrics

## 🚀 Quick Start

### Prerequisites

- Docker (>= 20.0)
- Docker Compose (>= 2.0)
- 4GB+ available RAM
- Available ports: 8080, 6379, 9090, 3000

### One-Command Setup

```bash
# Make the script executable (Linux/macOS)
chmod +x quick-start-docker.sh

# Run the complete environment
./quick-start-docker.sh
```

### Windows Users

```powershell
# Create directories
mkdir logs, test-data, test-results, monitoring -Force

# Run Docker Compose manually
docker-compose -f docker-compose.test.yml build
docker-compose -f docker-compose.test.yml up -d
```

## 🔧 Manual Testing

### Test Individual Syscalls

```bash
# Health Check
docker run --rm --network cam-protocol_cam-network fullstorydev/grpcurl:latest \
  -plaintext -d '{"caller_id": "test", "detailed": true}' \
  cam-kernel:8080 cam.syscall.SyscallService/HealthCheck

# Context Write
docker run --rm --network cam-protocol_cam-network fullstorydev/grpcurl:latest \
  -plaintext -d '{
    "namespace": "demo",
    "key": "test-key",
    "data": "SGVsbG8gQ0FNLU9TIQ==",
    "caller_id": "demo-user"
  }' cam-kernel:8080 cam.syscall.SyscallService/ContextWrite

# Context Read
docker run --rm --network cam-protocol_cam-network fullstorydev/grpcurl:latest \
  -plaintext -d '{
    "namespace": "demo",
    "key": "test-key",
    "caller_id": "demo-user"
  }' cam-kernel:8080 cam.syscall.SyscallService/ContextRead

# Task Arbitration
docker run --rm --network cam-protocol_cam-network fullstorydev/grpcurl:latest \
  -plaintext -d '{
    "task": {
      "id": "demo-task",
      "description": "Demo arbitration task",
      "type": "TASK_TYPE_ARBITRATION",
      "priority": 100
    },
    "caller_id": "demo-user"
  }' cam-kernel:8080 cam.syscall.SyscallService/Arbitrate
```

### Run Full Test Suite

```bash
# Run comprehensive test suite
docker-compose -f docker-compose.test.yml --profile testing run --rm test-client

# View test results
ls -la test-results/
cat test-results/test_results_*.log
```

## 📊 Monitoring & Dashboards

### Access Points

- **CAM-OS Kernel gRPC**: `localhost:8080`
- **Redis Backend**: `localhost:6379`
- **Prometheus Metrics**: http://localhost:9090
- **Grafana Dashboard**: http://localhost:3000
  - Username: `admin`
  - Password: `camadmin`

### Key Metrics to Monitor

1. **Syscall Latency**: Should be <1ms for health checks
2. **Throughput**: Target >10,000 ops/sec
3. **Memory Usage**: Context storage efficiency
4. **Error Rates**: Failed syscall percentage
5. **Redis Performance**: Backend storage health

### Grafana Queries

```promql
# Average syscall latency
rate(cam_syscall_latency_seconds_sum[5m]) / rate(cam_syscall_latency_seconds_count[5m])

# Syscall success rate
rate(cam_syscall_total{success="true"}[5m]) / rate(cam_syscall_total[5m])

# Memory usage by namespace
cam_namespace_total_size

# Active connections
cam_active_connections
```

## 🧪 Advanced Testing

### Performance Testing

```bash
# Stress test (100 concurrent requests)
for i in {1..100}; do
  docker run --rm --network cam-protocol_cam-network fullstorydev/grpcurl:latest \
    -plaintext -d '{"caller_id": "stress-test-'$i'"}' \
    cam-kernel:8080 cam.syscall.SyscallService/HealthCheck &
done
wait
```

### Load Testing with Different Workloads

```bash
# Context-heavy workload
docker-compose -f docker-compose.test.yml --profile testing run --rm \
  -e TEST_WORKLOAD=context test-client

# Arbitration-heavy workload  
docker-compose -f docker-compose.test.yml --profile testing run --rm \
  -e TEST_WORKLOAD=arbitration test-client

# Mixed workload
docker-compose -f docker-compose.test.yml --profile testing run --rm \
  -e TEST_WORKLOAD=mixed test-client
```

### Security Testing

```bash
# Test post-quantum security features
docker run --rm --network cam-protocol_cam-network fullstorydev/grpcurl:latest \
  -plaintext -d '{
    "data": "dGVzdCBkYXRhIGZvciBzaWduaW5n",
    "caller_id": "security-test",
    "key_id": "test-key"
  }' cam-kernel:8080 cam.syscall.SyscallService/TmpSign

# Test secure channel establishment
docker run --rm --network cam-protocol_cam-network fullstorydev/grpcurl:latest \
  -plaintext -d '{
    "peer_id": "test-peer",
    "caller_id": "security-test",
    "protocol": "kyber768"
  }' cam-kernel:8080 cam.syscall.SyscallService/EstablishSecureChannel
```

## 🐛 Troubleshooting

### Common Issues

1. **Port Conflicts**
   ```bash
   # Change ports in docker-compose.test.yml
   ports:
     - "18080:8080"  # Changed from 8080
   ```

2. **Memory Issues**
   ```bash
   # Reduce resource limits
   deploy:
     resources:
       limits:
         memory: 512M
   ```

3. **Build Failures**
   ```bash
   # Clean rebuild
   docker-compose -f docker-compose.test.yml down --volumes
   docker system prune -f
   docker-compose -f docker-compose.test.yml build --no-cache
   ```

### View Logs

```bash
# Kernel logs
docker-compose -f docker-compose.test.yml logs -f cam-kernel

# Redis logs
docker-compose -f docker-compose.test.yml logs redis

# All service logs
docker-compose -f docker-compose.test.yml logs
```

### Debug Mode

```bash
# Run with debug logging
docker-compose -f docker-compose.test.yml up -d \
  -e CAM_LOG_LEVEL=debug cam-kernel

# Interactive debugging
docker-compose -f docker-compose.test.yml exec cam-kernel /bin/sh
```

## 🔧 Configuration

### Environment Variables

- `CAM_REDIS_ADDR`: Redis connection string (default: `redis:6379`)
- `CAM_LOG_LEVEL`: Logging level (debug, info, warn, error)
- `CAM_METRICS_ENABLED`: Enable metrics collection (true/false)
- `CAM_POST_QUANTUM`: Enable post-quantum cryptography (true/false)
- `CAM_TLS_ENABLED`: Enable TLS (true/false, disabled for testing)

### Custom Configuration

```bash
# Mount custom configuration
docker-compose -f docker-compose.test.yml run \
  -v ./my-config.toml:/home/camuser/config/custom.toml \
  cam-kernel ./cam-kernel --config config/custom.toml
```

## 🚀 Scaling & Production

### Horizontal Scaling

```bash
# Scale kernel instances
docker-compose -f docker-compose.test.yml up -d --scale cam-kernel=3

# Load balancer (add to docker-compose.test.yml)
nginx:
  image: nginx:alpine
  ports:
    - "80:80"
  volumes:
    - ./nginx.conf:/etc/nginx/nginx.conf
```

### Production Considerations

1. **Use persistent volumes for Redis**
2. **Enable TLS for production**
3. **Configure proper monitoring**
4. **Set up log aggregation**
5. **Implement backup strategies**

## 📖 What This Tests

This environment validates:

✅ **15 Cognitive Syscalls**: All enhanced syscalls from the fork expansion  
✅ **Post-Quantum Security**: Kyber768 + Dilithium3 framework  
✅ **Memory Management**: Redis-backed context storage with versioning  
✅ **Performance**: <1ms syscall latency targets  
✅ **Observability**: Comprehensive metrics and tracing  
✅ **Explainability**: Decision audit trails  
✅ **Scalability**: Multi-instance deployment  

## 🎯 Next Steps

After testing, you can:

1. **Deploy to Kubernetes** using the Helm charts in `/deployment/helm/`
2. **Integrate with your applications** using the gRPC interface
3. **Extend with custom drivers** following the driver framework
4. **Scale for production** with the deployment templates

---

**🚀 This Docker environment provides a complete, production-like testing experience for the CAM-OS cognitive operating system kernel!** 