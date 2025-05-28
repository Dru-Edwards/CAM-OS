#!/bin/bash
# CAM Protocol Quick Start Script
# This script helps you quickly set up and run the CAM Protocol for demonstration purposes

set -e

# Colors for better readability
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}   CAM Protocol - Quick Start Demo Script   ${NC}"
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

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo -e "${YELLOW}Creating .env file with demo settings...${NC}"
    cat > .env << EOL
# CAM Protocol Demo Environment
# For production use, replace these with your actual API keys

# API Keys (demo mode uses mock services)
OPENAI_API_KEY=demo-key-replace-me
ANTHROPIC_API_KEY=demo-key-replace-me

# Service Configuration
NODE_ENV=development
LOG_LEVEL=info
PORT=8080

# Database Configuration
DB_HOST=postgres
DB_PORT=5432
DB_USER=cam_user
DB_PASSWORD=cam_password
DB_NAME=cam_db

# Redis Configuration
REDIS_HOST=redis
REDIS_PORT=6379
EOL
    echo -e "${GREEN}Created .env file with demo settings.${NC}"
fi

# Create necessary directories
mkdir -p config
mkdir -p monitoring/prometheus
mkdir -p monitoring/grafana/provisioning/datasources
mkdir -p monitoring/grafana/provisioning/dashboards
mkdir -p monitoring/grafana/dashboards

# Create basic prometheus config if it doesn't exist
if [ ! -f monitoring/prometheus/prometheus.yml ]; then
    echo -e "${YELLOW}Creating basic Prometheus configuration...${NC}"
    cat > monitoring/prometheus/prometheus.yml << EOL
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'cam-core'
    static_configs:
      - targets: ['cam-core:8080']
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
  - name: 'CAM Protocol'
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

echo -e "${YELLOW}Starting CAM Protocol services...${NC}"
docker-compose up -d

echo ""
echo -e "${GREEN}=== CAM Protocol Demo is now running! ===${NC}"
echo ""
echo -e "Access the following services:"
echo -e "  - ${BLUE}CAM Protocol API:${NC} http://localhost:8080"
echo -e "  - ${BLUE}Mock OpenAI API:${NC} http://localhost:8081"
echo -e "  - ${BLUE}Mock Anthropic API:${NC} http://localhost:8082"
echo -e "  - ${BLUE}Grafana Dashboard:${NC} http://localhost:3000 (admin/admin)"
echo -e "  - ${BLUE}Prometheus:${NC} http://localhost:9090"
echo ""
echo -e "Try a test request:"
echo -e "${YELLOW}curl -X POST http://localhost:8080/mesh/chat \\
  -H \"Content-Type: application/json\" \\
  -d '{\"message\": \"Hello world\", \"options\": {\"routing\": \"auto\"}}'${NC}"
echo ""
echo -e "To stop the demo:"
echo -e "${YELLOW}docker-compose down${NC}"
echo ""
echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}   Thank you for trying the CAM Protocol!   ${NC}"
echo -e "${BLUE}============================================${NC}"
