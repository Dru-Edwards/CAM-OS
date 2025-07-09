#!/bin/bash

# CAM-OS Kernel Quick Start Docker Environment
# This script builds and runs the complete CAM-OS testing environment

set -e

echo "🚀 CAM-OS Kernel Quick Start"
echo "============================"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Create required directories
echo "📁 Creating required directories..."
mkdir -p logs test-data test-results monitoring/{grafana/provisioning,prometheus}

# Create monitoring configuration
echo "📊 Creating monitoring configuration..."
cat > monitoring/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'cam-kernel'
    static_configs:
      - targets: ['cam-kernel:8080']
    metrics_path: '/metrics'
    scrape_interval: 5s

  - job_name: 'redis'
    static_configs:
      - targets: ['redis:6379']
EOF

# Create test configuration directory
echo "🔧 Creating test configuration..."
mkdir -p docker-test-config
cat > docker-test-config/test.toml << 'EOF'
# CAM-OS Kernel Test Configuration
[kernel]
name = "cam-os-kernel-test"
version = "1.1.0"
description = "CAM-OS Kernel Test Environment"

[security]
post_quantum = true
tls_enabled = false  # Disabled for testing
tpm_required = false  # Disabled for testing

[memory]
context_backend = "redis"
max_namespaces = 100
max_context_size = "10MB"
compression_enabled = true

[performance]
syscall_latency_target = "1ms"
arbitration_latency_target = "100ms"
context_latency_target = "10ms"
EOF

# Build and start the environment
echo "🏗️  Building CAM-OS Kernel Docker images..."
docker-compose -f docker-compose.test.yml build

echo "🚀 Starting CAM-OS Kernel test environment..."
docker-compose -f docker-compose.test.yml up -d redis prometheus grafana

echo "⏳ Waiting for services to be ready..."
sleep 10

echo "🚀 Starting CAM-OS Kernel..."
docker-compose -f docker-compose.test.yml up -d cam-kernel

echo "⏳ Waiting for kernel to initialize..."
sleep 15

# Check if kernel is healthy
echo "🔍 Checking kernel health..."
if docker-compose -f docker-compose.test.yml exec -T cam-kernel wget -q --tries=1 --spider http://localhost:8080/health; then
    echo "✅ CAM-OS Kernel is healthy and ready!"
else
    echo "⚠️  Kernel may still be starting up. Continuing..."
fi

# Run tests
echo "🧪 Running test suite..."
docker-compose -f docker-compose.test.yml --profile testing run --rm test-client

# Show access information
echo ""
echo "🎉 CAM-OS Kernel Environment is Running!"
echo "========================================"
echo ""
echo "📍 Access Points:"
echo "  • CAM-OS Kernel gRPC: localhost:8080"
echo "  • Redis Backend: localhost:6379"
echo "  • Prometheus Metrics: http://localhost:9090"
echo "  • Grafana Dashboard: http://localhost:3000 (admin/camadmin)"
echo ""
echo "📋 Available Commands:"
echo "  • View logs: docker-compose -f docker-compose.test.yml logs cam-kernel"
echo "  • Run tests: docker-compose -f docker-compose.test.yml --profile testing run --rm test-client"
echo "  • Scale kernel: docker-compose -f docker-compose.test.yml up -d --scale cam-kernel=3"
echo "  • Stop environment: docker-compose -f docker-compose.test.yml down"
echo ""
echo "🔧 Test gRPC calls manually:"
echo "  docker run --rm --network cam-protocol_cam-network fullstorydev/grpcurl:latest \\"
echo "    -plaintext -d '{\"caller_id\": \"manual-test\", \"detailed\": true}' \\"
echo "    cam-kernel:8080 cam.syscall.SyscallService/HealthCheck"
echo ""
echo "📊 View test results:"
echo "  ls -la test-results/"
echo ""

# Offer to show live logs
read -p "📺 Would you like to view live kernel logs? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "📺 Showing live logs (Ctrl+C to exit)..."
    docker-compose -f docker-compose.test.yml logs -f cam-kernel
fi 