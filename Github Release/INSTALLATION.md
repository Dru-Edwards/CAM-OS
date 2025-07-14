# CAM-OS v1.1.0 Installation Guide

This guide provides step-by-step instructions for installing CAM-OS v1.1.0 across different environments.

## 🚀 Quick Start

### Prerequisites
- Linux operating system (Ubuntu 20.04+ recommended)
- Docker and Docker Compose (for containerized deployment)
- Go 1.21+ (for source installation)
- 2+ CPU cores, 512MB+ RAM, 1GB+ storage

### 30-Second Installation
```bash
curl -sSL https://install.cam-os.dev | bash
```

## 📦 Installation Methods

### 1. Docker Deployment (Recommended)

#### Single Node
```bash
# Download release
curl -sSL https://github.com/Dru-Edwards/CAM-OS/releases/download/v1.1.0/cam-os-docker.tar.gz | tar -xz
cd cam-os-v1.1.0

# Start services
docker-compose up -d

# Verify installation
make validate-deployment
```

#### Multi-Node Cluster
```bash
# Download cluster configuration
curl -sSL https://github.com/Dru-Edwards/CAM-OS/releases/download/v1.1.0/cam-os-cluster.tar.gz | tar -xz
cd cam-os-cluster

# Configure cluster
./configure-cluster.sh --nodes 3 --domain cam-os.local

# Deploy cluster
docker-compose -f docker-compose.cluster.yml up -d
```

### 2. Kubernetes Deployment

#### Using Operator (Recommended)
```bash
# Install operator
kubectl apply -f https://github.com/Dru-Edwards/CAM-OS/releases/download/v1.1.0/cam-os-operator.yaml

# Wait for operator to be ready
kubectl wait --for=condition=available --timeout=300s deployment/cam-os-operator -n cam-os-system

# Create CAM-OS instance
kubectl apply -f https://github.com/Dru-Edwards/CAM-OS/releases/download/v1.1.0/cam-os-instance.yaml
```

#### Manual Deployment
```bash
# Download Kubernetes manifests
curl -sSL https://github.com/Dru-Edwards/CAM-OS/releases/download/v1.1.0/cam-os-k8s.tar.gz | tar -xz
cd cam-os-k8s

# Deploy components
kubectl apply -f namespace.yaml
kubectl apply -f rbac.yaml
kubectl apply -f configmap.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
kubectl apply -f ingress.yaml
```

### 3. Native Linux Installation

#### Binary Installation
```bash
# Download binary
wget https://github.com/Dru-Edwards/CAM-OS/releases/download/v1.1.0/cam-os-linux-amd64.tar.gz
tar -xzf cam-os-linux-amd64.tar.gz
cd cam-os-v1.1.0

# Install system-wide
sudo ./install.sh

# Start service
sudo systemctl start cam-os
sudo systemctl enable cam-os

# Verify installation
cam-os version
cam-os health
```

#### Source Installation
```bash
# Prerequisites
sudo apt-get update
sudo apt-get install -y build-essential git golang-1.21 protobuf-compiler

# Clone and build
git clone https://github.com/Dru-Edwards/CAM-OS.git
cd CAM-OS
make build

# Install
sudo make install

# Configure
sudo cp config/default.yaml /etc/cam-os/config.yaml
sudo systemctl start cam-os
sudo systemctl enable cam-os
```

## ⚙️ Configuration

### Basic Configuration
```yaml
# /etc/cam-os/config.yaml
server:
  port: 8080
  host: "0.0.0.0"
  timeout: 30s

security:
  jwt:
    expiration: 1h
  tls:
    enabled: true
    cert_file: "/etc/certs/server.crt"
    key_file: "/etc/certs/server.key"

memory:
  backend: "redis"
  redis:
    host: "localhost"
    port: 6379
    db: 0
```

### Advanced Configuration
```yaml
# Production configuration
performance:
  max_cpu_cores: 8
  max_memory: "2GB"
  syscall_targets:
    latency_p99: "1ms"
    throughput: 20000

federation:
  enabled: true
  cluster_id: "prod-cluster"
  crdt:
    sync_interval: 50ms
    max_peers: 20

observability:
  metrics:
    enabled: true
    port: 9090
  tracing:
    enabled: true
    endpoint: "http://jaeger:14268/api/traces"
```

## 🔒 Security Setup

### TLS Certificates
```bash
# Generate self-signed certificates (development only)
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes

# Or use Let's Encrypt (production)
certbot certonly --standalone -d cam-os.yourdomain.com
```

### JWT Configuration
```bash
# Generate JWT signing key
openssl rand -hex 32 > jwt-secret.key

# Set environment variable
export JWT_SIGNING_KEY=$(cat jwt-secret.key)
```

### TPM Setup (Optional)
```bash
# Install TPM tools
sudo apt-get install -y tpm2-tools

# Initialize TPM
sudo tpm2_startup -c
sudo tpm2_clear

# Generate TPM key
sudo tpm2_createprimary -C e -g sha256 -G rsa -c primary.ctx
sudo tpm2_create -C primary.ctx -g sha256 -G rsa -r key.priv -u key.pub
```

## 🌐 Network Configuration

### Firewall Rules
```bash
# Allow CAM-OS ports
sudo ufw allow 8080/tcp  # Main API
sudo ufw allow 8081/tcp  # gRPC drivers
sudo ufw allow 9090/tcp  # Metrics
sudo ufw allow 6379/tcp  # Redis
```

### Load Balancer Configuration
```nginx
# nginx.conf
upstream cam-os {
    server cam-os-1:8080;
    server cam-os-2:8080;
    server cam-os-3:8080;
}

server {
    listen 80;
    server_name cam-os.yourdomain.com;
    
    location / {
        proxy_pass http://cam-os;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## 📊 Monitoring Setup

### Prometheus
```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'cam-os'
    static_configs:
      - targets: ['localhost:9090']
```

### Grafana
```bash
# Install Grafana
docker run -d -p 3000:3000 grafana/grafana

# Import CAM-OS dashboard
curl -X POST http://admin:admin@localhost:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @grafana-dashboard.json
```

## 🧪 Validation

### Health Checks
```bash
# Basic health check
curl http://localhost:8080/health

# Detailed system status
curl http://localhost:8080/status

# Performance metrics
curl http://localhost:9090/metrics
```

### Performance Testing
```bash
# Run performance tests
make test-performance

# Expected results:
# - Latency: <1ms (99th percentile)
# - Throughput: >10,000 ops/sec
# - Memory: <100MB
```

### Security Validation
```bash
# Test TLS connection
openssl s_client -connect localhost:8080 -tls1_3

# Test JWT authentication
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/v1/status

# Test TPM validation
cam-os tpm-validate --cert-chain /path/to/cert-chain.pem
```

## 🔧 Troubleshooting

### Common Issues

#### Port Already in Use
```bash
# Find process using port
sudo netstat -tulpn | grep :8080
sudo kill -9 <pid>
```

#### Permission Denied
```bash
# Fix permissions
sudo chown -R cam-os:cam-os /var/lib/cam-os
sudo chmod 755 /var/lib/cam-os
```

#### Memory Issues
```bash
# Increase memory limits
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### Log Analysis
```bash
# View logs
sudo journalctl -u cam-os -f

# Debug mode
sudo systemctl edit cam-os
# Add: Environment=CAM_OS_DEBUG=true
```

## 📱 Client Installation

### Go Client
```bash
go get github.com/Dru-Edwards/CAM-OS/client/go
```

### Python Client
```bash
pip install cam-os-client
```

### JavaScript Client
```bash
npm install @cam-os/client
```

## 🚀 Production Deployment

### High Availability Setup
```bash
# 3-node cluster with load balancing
./deploy-ha.sh --nodes 3 --domain prod.cam-os.com
```

### Backup Configuration
```bash
# Automated backup
./setup-backup.sh --schedule "0 2 * * *" --retention 30
```

### Monitoring Alerts
```bash
# Setup alerting
./setup-alerts.sh --email alerts@yourdomain.com --slack webhook-url
```

## 🔄 Updates

### Automatic Updates
```bash
# Enable auto-updates
sudo systemctl enable cam-os-updater
```

### Manual Updates
```bash
# Update to latest version
sudo cam-os update --version latest
sudo systemctl restart cam-os
```

## 📚 Next Steps

1. **Complete the [Quick Start Guide](QUICKSTART.md)**
2. **Review the [API Reference](API_REFERENCE.md)**
3. **Explore [Examples](examples/)**
4. **Join the [Community](https://community.cam-os.dev)**

## 🆘 Support

- **Documentation**: https://docs.cam-os.dev
- **Community**: https://community.cam-os.dev
- **Issues**: https://github.com/Dru-Edwards/CAM-OS/issues
- **Email**: support@edwards-tech.com

---

**CAM-OS v1.1.0 Installation Guide** | Production Ready | December 2024 