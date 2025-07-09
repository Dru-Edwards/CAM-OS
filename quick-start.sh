#!/bin/bash
# CAM-OS Kernel Quick Start Script
# This script helps you quickly set up and run the CAM-OS kernel for demonstration purposes

set -e

# Colors for better readability
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}   CAM-OS Kernel - Quick Start Demo Script   ${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed. Please install Docker first.${NC}"
    echo "Visit https://docs.docker.com/get-docker/ for installation instructions."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}Error: Docker Compose is not installed. Please install Docker Compose first.${NC}"
    echo "Visit https://docs.docker.com/compose/install/ for installation instructions."
    exit 1
fi

# Check if grpcurl is available (for testing)
if ! command -v grpcurl &> /dev/null; then
    echo -e "${YELLOW}Note: grpcurl is not installed. You can install it to test the kernel.${NC}"
    echo "Visit https://github.com/fullstorydev/grpcurl for installation instructions."
fi

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo -e "${YELLOW}Creating .env file with demo settings...${NC}"
    cat > .env << EOL
# CAM-OS Kernel Demo Environment
# For production use, replace these with your actual settings

# Kernel Configuration
CAM_LOG_LEVEL=info
CAM_GRPC_PORT=8080
CAM_METRICS_PORT=9090
CAM_DEVELOPMENT=true

# Redis Configuration
CAM_REDIS_URL=redis://redis:6379

# Database Configuration
CAM_POSTGRES_URL=postgres://cam_user:cam_password@postgres:5432/cam_db

# Security Configuration (Demo Mode)
CAM_SECURITY_ENABLED=false
CAM_TPM_ENABLED=false
CAM_POST_QUANTUM_ENABLED=false
EOL
    echo -e "${GREEN}Created .env file with demo settings.${NC}"
fi

# Create necessary directories
mkdir -p drivers
mkdir -p monitoring/prometheus
mkdir -p monitoring/grafana/provisioning/datasources
mkdir -p monitoring/grafana/provisioning/dashboards
mkdir -p monitoring/grafana/dashboards

# Create basic prometheus config for kernel metrics
if [ ! -f monitoring/prometheus/prometheus.yml ]; then
    echo -e "${YELLOW}Creating Prometheus configuration for kernel metrics...${NC}"
    cat > monitoring/prometheus/prometheus.yml << EOL
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'cam-kernel'
    static_configs:
      - targets: ['cam-kernel:9090']
    metrics_path: '/metrics'

  - job_name: 'driver-runtime'
    static_configs:
      - targets: ['driver-runtime:8081']
    metrics_path: '/metrics'

  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
EOL
    echo -e "${GREEN}Created Prometheus configuration.${NC}"
fi

# Create Grafana datasource config
if [ ! -f monitoring/grafana/provisioning/datasources/datasource.yml ]; then
    echo -e "${YELLOW}Creating Grafana datasource configuration...${NC}"
    cat > monitoring/grafana/provisioning/datasources/datasource.yml << EOL
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    orgId: 1
    url: http://prometheus:9090
    isDefault: true
    version: 1
    editable: false
EOL
    echo -e "${GREEN}Created Grafana datasource configuration.${NC}"
fi

# Create Grafana dashboard provisioning config
if [ ! -f monitoring/grafana/provisioning/dashboards/dashboards.yml ]; then
    echo -e "${YELLOW}Creating Grafana dashboard provisioning configuration...${NC}"
    cat > monitoring/grafana/provisioning/dashboards/dashboards.yml << EOL
apiVersion: 1

providers:
  - name: 'CAM-OS Kernel'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    allowUiUpdates: true
    options:
      path: /var/lib/grafana/dashboards
      foldersFromFilesStructure: true
EOL
    echo -e "${GREEN}Created Grafana dashboard provisioning configuration.${NC}"
fi

# Create basic CAM-OS kernel manifest if it doesn't exist
if [ ! -f MANIFEST.toml ]; then
    echo -e "${YELLOW}Creating basic kernel manifest...${NC}"
    cp MANIFEST.toml MANIFEST.toml.backup 2>/dev/null || true
    echo -e "${GREEN}Using existing kernel manifest.${NC}"
fi

echo -e "${YELLOW}Starting CAM-OS kernel services...${NC}"
docker-compose up -d

echo ""
echo -e "${GREEN}=== CAM-OS Kernel Demo is now running! ===${NC}"
echo ""
echo -e "Access the following services:"
echo -e "  - ${BLUE}CAM-OS Kernel gRPC API:${NC} localhost:8080"
echo -e "  - ${BLUE}Kernel Metrics:${NC} http://localhost:9090"
echo -e "  - ${BLUE}Driver Runtime:${NC} http://localhost:8081"
echo -e "  - ${BLUE}Grafana Dashboard:${NC} http://localhost:3000 (admin/admin)"
echo -e "  - ${BLUE}Prometheus:${NC} http://localhost:9091"
echo -e "  - ${BLUE}Redis:${NC} localhost:6379"
echo -e "  - ${BLUE}PostgreSQL:${NC} localhost:5432"
echo ""
echo -e "Try test syscalls (requires grpcurl):"
echo -e "${YELLOW}# Health check syscall"
echo -e "grpcurl -plaintext -d '{}' localhost:8080 syscall.SyscallService/HealthCheck"
echo ""
echo -e "# Arbitration syscall"
echo -e "grpcurl -plaintext -d '{\"task_id\": \"test-001\", \"options\": {\"provider\": \"demo\"}}' \\
  localhost:8080 syscall.SyscallService/Arbitrate${NC}"
echo ""
echo -e "View kernel logs:"
echo -e "${YELLOW}docker logs cam-kernel -f${NC}"
echo ""
echo -e "To stop the demo:"
echo -e "${YELLOW}docker-compose down${NC}"
echo ""
echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}   Thank you for trying CAM-OS Kernel!     ${NC}"
echo -e "${BLUE}============================================${NC}"
