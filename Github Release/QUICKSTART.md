# CAM-OS v1.1.0 Quick Start Guide

Get CAM-OS up and running in **less than 5 minutes**.

## 🚀 30-Second Start

```bash
# One-liner installation
curl -sSL https://install.cam-os.dev | bash

# Start CAM-OS
cam-os start

# Test the system
cam-os health
```

## 📋 Prerequisites

- **OS**: Linux (Ubuntu 20.04+, CentOS 8+, Alpine 3.15+)
- **Memory**: 512MB+ RAM
- **Storage**: 1GB+ available space
- **Network**: Internet connection for initial setup

## 🐳 Docker Quick Start (Recommended)

### Step 1: Download and Start
```bash
# Download the latest release
curl -sSL https://github.com/Dru-Edwards/CAM-OS/releases/download/v1.1.0/cam-os-docker.tar.gz | tar -xz
cd cam-os-v1.1.0

# Start all services
docker-compose up -d
```

### Step 2: Verify Installation
```bash
# Check service status
docker-compose ps

# Expected output:
# Name                State    Ports
# cam-os-kernel       Up       0.0.0.0:8080->8080/tcp
# cam-os-redis        Up       6379/tcp
# cam-os-prometheus   Up       9090/tcp
# cam-os-grafana      Up       3000/tcp
```

### Step 3: Test the System
```bash
# Health check
curl http://localhost:8080/health

# Expected response:
# {"status":"healthy","uptime":"30s","version":"v1.1.0"}
```

## 🔧 Native Installation

### Step 1: Download Binary
```bash
# Download for your platform
wget https://github.com/Dru-Edwards/CAM-OS/releases/download/v1.1.0/cam-os-linux-amd64.tar.gz

# Extract
tar -xzf cam-os-linux-amd64.tar.gz
cd cam-os-v1.1.0
```

### Step 2: Install
```bash
# Install system-wide
sudo ./install.sh

# Start service
sudo systemctl start cam-os
sudo systemctl enable cam-os
```

### Step 3: Verify
```bash
# Check status
sudo systemctl status cam-os

# Test API
curl http://localhost:8080/health
```

## 🎯 First API Call

### Using curl
```bash
# Get JWT token (development mode)
TOKEN=$(curl -s -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"demo","password":"demo"}' | jq -r '.token')

# Make your first syscall
curl -X POST http://localhost:8080/api/v1/arbitrate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "task_type": "hello_world",
    "priority": "MEDIUM",
    "payload": "SGVsbG8gQ0FNLU9T", 
    "context_id": "quickstart"
  }'
```

### Expected Response
```json
{
  "execution_id": "exec_123456",
  "assigned_worker": "worker_cpu_01",
  "estimated_completion": {
    "duration_ms": 50,
    "confidence": 0.98
  },
  "reason": {
    "algorithm": "triple_helix",
    "factors": ["low_load", "cpu_available", "cache_warm"]
  }
}
```

## 🧪 Interactive Demo

### Step 1: Start Demo Mode
```bash
# Start interactive demo
cam-os demo

# Or with Docker
docker run -it --rm cam-os:v1.1.0 demo
```

### Step 2: Try Key Features
The demo will guide you through:
- **Cognitive Syscalls** - All 15 syscalls with examples
- **Memory Management** - Store and retrieve context
- **Security Features** - JWT auth, encryption, TPM
- **Performance** - Real-time latency measurements
- **Federation** - Multi-node clustering

## 📊 Performance Validation

### Latency Test
```bash
# Test syscall latency
for i in {1..100}; do
  curl -s -w "%{time_total}\n" -o /dev/null \
    -X POST http://localhost:8080/api/v1/health \
    -H "Authorization: Bearer $TOKEN"
done | awk '{sum+=$1} END {print "Average:", sum/NR*1000 "ms"}'
```

### Throughput Test
```bash
# Install Apache Bench
sudo apt-get install apache2-utils

# Test throughput
ab -n 1000 -c 10 \
  -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/health
```

### Expected Results
- **Latency**: <1ms (99th percentile)
- **Throughput**: >10,000 requests/second
- **Memory**: <100MB usage

## 🔍 Monitoring Dashboard

### Access Grafana
```bash
# Open in browser
open http://localhost:3000

# Login credentials
# Username: admin
# Password: admin
```

### Key Metrics to Monitor
- **Syscall Latency** - Response times per syscall
- **Throughput** - Operations per second
- **Memory Usage** - Context storage utilization
- **Error Rate** - Failed operations percentage

## 🛠️ Development Setup

### Go Development
```bash
# Install Go client
go get github.com/Dru-Edwards/CAM-OS/client/go

# Example usage
cat > main.go << 'EOF'
package main

import (
    "context"
    "fmt"
    "log"
    camOS "github.com/Dru-Edwards/CAM-OS/client/go"
)

func main() {
    client := camOS.NewClient("localhost:8080")
    
    // Authenticate
    token, err := client.Login("demo", "demo")
    if err != nil {
        log.Fatal(err)
    }
    client.SetToken(token)
    
    // Make syscall
    resp, err := client.Health(context.Background())
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Status: %s\n", resp.Status)
    fmt.Printf("Uptime: %s\n", resp.Uptime)
    fmt.Printf("Version: %s\n", resp.Version)
}
EOF

go run main.go
```

### Python Development
```bash
# Install Python client
pip install cam-os-client

# Example usage
cat > example.py << 'EOF'
import cam_os_client

# Create client
client = cam_os_client.Client("localhost:8080")

# Authenticate
token = client.login("demo", "demo")
client.set_token(token)

# Make syscall
health = client.health()
print(f"Status: {health.status}")
print(f"Uptime: {health.uptime}")
print(f"Version: {health.version}")
EOF

python example.py
```

## 🔒 Security Quick Setup

### Generate TLS Certificates
```bash
# Generate development certificates
openssl req -x509 -newkey rsa:4096 \
  -keyout server.key -out server.crt \
  -days 365 -nodes \
  -subj "/CN=localhost"

# Update configuration
sudo cp server.crt /etc/cam-os/tls/
sudo cp server.key /etc/cam-os/tls/
```

### Enable Authentication
```bash
# Generate JWT secret
openssl rand -hex 32 > /etc/cam-os/jwt-secret

# Set environment variable
echo 'JWT_SIGNING_KEY_FILE=/etc/cam-os/jwt-secret' | sudo tee -a /etc/cam-os/environment

# Restart service
sudo systemctl restart cam-os
```

## 🌐 Multi-Node Cluster

### Quick Cluster Setup
```bash
# Download cluster configuration
curl -sSL https://github.com/Dru-Edwards/CAM-OS/releases/download/v1.1.0/cam-os-cluster.tar.gz | tar -xz
cd cam-os-cluster

# Start 3-node cluster
./start-cluster.sh --nodes 3

# Verify cluster
./check-cluster.sh
```

### Test Federation
```bash
# Test cross-node communication
cam-os federate --operation sync --cluster-id test-cluster

# Check peer status
cam-os federate --operation query-peers
```

## 📚 Common Use Cases

### 1. LLM Inference
```bash
# Route LLM task
curl -X POST http://localhost:8080/api/v1/arbitrate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "task_type": "llm_inference",
    "priority": "HIGH",
    "payload": "V2hhdCBpcyBDQU0tT1M=",
    "metadata": {
      "model": "gpt-4",
      "max_tokens": "1000"
    }
  }'
```

### 2. Data Processing
```bash
# Process data batch
curl -X POST http://localhost:8080/api/v1/arbitrate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "task_type": "data_processing",
    "priority": "MEDIUM",
    "payload": "base64_encoded_data",
    "metadata": {
      "batch_size": "1000",
      "format": "json"
    }
  }'
```

### 3. Real-time Analytics
```bash
# Stream analytics
curl -X POST http://localhost:8080/api/v1/arbitrate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "task_type": "real_time_analytics",
    "priority": "HIGH",
    "payload": "c3RyZWFtX2RhdGE=",
    "metadata": {
      "window_size": "1m",
      "aggregation": "sum"
    }
  }'
```

## 🧹 Cleanup

### Stop Services
```bash
# Docker deployment
docker-compose down

# Native installation
sudo systemctl stop cam-os
sudo systemctl disable cam-os
```

### Remove Installation
```bash
# Complete removal
sudo ./uninstall.sh

# Or manual cleanup
sudo rm -rf /etc/cam-os
sudo rm -rf /var/lib/cam-os
sudo rm -rf /var/log/cam-os
```

## ❓ Troubleshooting

### Common Issues

#### Service Won't Start
```bash
# Check logs
sudo journalctl -u cam-os -f

# Check permissions
sudo chown -R cam-os:cam-os /var/lib/cam-os
```

#### API Returns 401 Unauthorized
```bash
# Check token validity
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/auth/validate

# Refresh token
TOKEN=$(curl -s -X POST http://localhost:8080/auth/refresh \
  -H "Authorization: Bearer $TOKEN" | jq -r '.token')
```

#### Performance Issues
```bash
# Check system resources
top -p $(pgrep cam-os)

# Check configuration
cam-os config --validate
```

## 📖 Next Steps

1. **[Complete Installation Guide](INSTALLATION.md)** - Production deployment
2. **[API Reference](API_REFERENCE.md)** - Full API documentation
3. **[Architecture Guide](ARCHITECTURE.md)** - System design
4. **[Examples](examples/)** - Working code examples
5. **[Community](https://community.cam-os.dev)** - Join the community

## 🆘 Getting Help

- **Documentation**: https://docs.cam-os.dev
- **Community Forum**: https://community.cam-os.dev
- **GitHub Issues**: https://github.com/Dru-Edwards/CAM-OS/issues
- **Slack**: https://cam-os.slack.com
- **Email**: support@edwards-tech.com

---

**CAM-OS v1.1.0 Quick Start Guide** | Get Started in 5 Minutes | December 2024 