#!/bin/bash

# CAM-OS Docker Quick Start Script
# This script sets up a complete CAM-OS testing environment using Docker

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
}

# Function to check if Docker is installed and running
check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        print_error "Docker is not running. Please start Docker first."
        exit 1
    fi
    
    print_status "Docker is installed and running"
}

# Function to check if Docker Compose is available
check_docker_compose() {
    if docker compose version &> /dev/null; then
        COMPOSE_CMD="docker compose"
    elif docker-compose --version &> /dev/null; then
        COMPOSE_CMD="docker-compose"
    else
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    print_status "Docker Compose is available"
}

# Function to check system requirements
check_requirements() {
    print_header "Checking System Requirements"
    
    # Check available memory
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        available_memory=$(free -m | awk 'NR==2{printf "%.0f", $7}')
        if [ "$available_memory" -lt 4000 ]; then
            print_warning "Available memory is ${available_memory}MB. Recommended: 4GB+"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        available_memory=$(vm_stat | grep "Pages free" | awk '{print $3}' | sed 's/\.//')
        available_memory=$((available_memory * 4096 / 1024 / 1024))
        if [ "$available_memory" -lt 4000 ]; then
            print_warning "Available memory is ${available_memory}MB. Recommended: 4GB+"
        fi
    fi
    
    # Check available disk space
    available_disk=$(df -h . | awk 'NR==2 {print $4}' | sed 's/G//')
    if [ "${available_disk%.*}" -lt 10 ]; then
        print_warning "Available disk space is ${available_disk}GB. Recommended: 10GB+"
    fi
    
    check_docker
    check_docker_compose
}

# Function to create necessary directories
create_directories() {
    print_header "Creating Directories"
    
    directories=(
        "logs"
        "test-data"
        "test-results"
        "monitoring"
        "redis-data"
    )
    
    for dir in "${directories[@]}"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            print_status "Created directory: $dir"
        else
            print_status "Directory already exists: $dir"
        fi
    done
}

# Function to pull Docker images
pull_images() {
    print_header "Pulling Docker Images"
    
    images=(
        "redis:7-alpine"
        "prom/prometheus:latest"
        "grafana/grafana:latest"
        "fullstorydev/grpcurl:latest"
    )
    
    for image in "${images[@]}"; do
        print_status "Pulling $image..."
        docker pull "$image"
    done
}

# Function to build CAM-OS kernel image
build_kernel() {
    print_header "Building CAM-OS Kernel"
    
    if [ -f "Dockerfile.test" ]; then
        print_status "Building CAM-OS kernel image..."
        docker build -f Dockerfile.test -t cam-os-kernel:latest .
        print_status "CAM-OS kernel image built successfully"
    else
        print_error "Dockerfile.test not found. Please ensure you're in the CAM-OS project directory."
        exit 1
    fi
}

# Function to start the environment
start_environment() {
    print_header "Starting CAM-OS Environment"
    
    if [ -f "docker-compose.test.yml" ]; then
        print_status "Starting services with Docker Compose..."
        $COMPOSE_CMD -f docker-compose.test.yml up -d
        
        # Wait for services to be ready
        print_status "Waiting for services to be ready..."
        sleep 10
        
        # Check if services are running
        if $COMPOSE_CMD -f docker-compose.test.yml ps | grep -q "Up"; then
            print_status "Services started successfully"
        else
            print_error "Some services failed to start. Check logs with: $COMPOSE_CMD -f docker-compose.test.yml logs"
            exit 1
        fi
    else
        print_error "docker-compose.test.yml not found. Please ensure you're in the CAM-OS project directory."
        exit 1
    fi
}

# Function to run basic tests
run_tests() {
    print_header "Running Basic Tests"
    
    # Wait for CAM-OS kernel to be ready
    print_status "Waiting for CAM-OS kernel to be ready..."
    sleep 5
    
    # Test health check
    print_status "Testing health check..."
    if docker run --rm --network cam-os_cam-network fullstorydev/grpcurl:latest \
        -plaintext -d '{"caller_id": "quickstart-test"}' \
        cam-kernel:50051 cam.SyscallService/HealthCheck > /dev/null 2>&1; then
        print_status "✅ Health check passed"
    else
        print_error "❌ Health check failed"
    fi
    
    # Test think syscall
    print_status "Testing think syscall..."
    if docker run --rm --network cam-os_cam-network fullstorydev/grpcurl:latest \
        -plaintext -d '{"verb":"think", "payload":"hello world"}' \
        cam-kernel:50051 cam.SyscallService/Execute > /dev/null 2>&1; then
        print_status "✅ Think syscall test passed"
    else
        print_error "❌ Think syscall test failed"
    fi
    
    # Test context operations
    print_status "Testing context operations..."
    if docker run --rm --network cam-os_cam-network fullstorydev/grpcurl:latest \
        -plaintext -d '{"verb":"context_write", "payload":"namespace:test,key:quickstart,value:success"}' \
        cam-kernel:50051 cam.SyscallService/Execute > /dev/null 2>&1; then
        print_status "✅ Context write test passed"
    else
        print_error "❌ Context write test failed"
    fi
}

# Function to display access information
show_access_info() {
    print_header "Access Information"
    
    echo -e "${GREEN}CAM-OS Environment is Ready!${NC}"
    echo ""
    echo "🚀 Services:"
    echo "  - CAM-OS Kernel gRPC: localhost:50051"
    echo "  - Redis Backend: localhost:6379"
    echo "  - Prometheus: http://localhost:9090"
    echo "  - Grafana: http://localhost:3000 (admin/admin)"
    echo ""
    echo "🧪 Test Commands:"
    echo "  # Health check"
    echo "  docker run --rm --network cam-os_cam-network fullstorydev/grpcurl:latest \\"
    echo "    -plaintext -d '{\"caller_id\": \"test\"}' \\"
    echo "    cam-kernel:50051 cam.SyscallService/HealthCheck"
    echo ""
    echo "  # Think syscall"
    echo "  docker run --rm --network cam-os_cam-network fullstorydev/grpcurl:latest \\"
    echo "    -plaintext -d '{\"verb\":\"think\", \"payload\":\"solve problem\"}' \\"
    echo "    cam-kernel:50051 cam.SyscallService/Execute"
    echo ""
    echo "📊 Monitoring:"
    echo "  - View metrics: http://localhost:9090"
    echo "  - View dashboards: http://localhost:3000"
    echo "  - Check logs: $COMPOSE_CMD -f docker-compose.test.yml logs -f"
    echo ""
    echo "🛑 To stop:"
    echo "  $COMPOSE_CMD -f docker-compose.test.yml down"
    echo ""
    echo "📚 Documentation:"
    echo "  - Full testing guide: README-DOCKER-TEST.md"
    echo "  - API documentation: docs/api-reference.md"
    echo ""
}

# Function to cleanup on exit
cleanup() {
    if [ "$1" != "0" ]; then
        print_error "Script failed. Cleaning up..."
        if [ -n "$COMPOSE_CMD" ]; then
            $COMPOSE_CMD -f docker-compose.test.yml down 2>/dev/null || true
        fi
    fi
}

# Main execution
main() {
    print_header "CAM-OS Docker Quick Start"
    
    # Set up cleanup trap
    trap 'cleanup $?' EXIT
    
    # Check if help is requested
    if [[ "$1" == "--help" || "$1" == "-h" ]]; then
        echo "CAM-OS Docker Quick Start Script"
        echo ""
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  -h, --help     Show this help message"
        echo "  --no-pull      Skip pulling Docker images"
        echo "  --no-test      Skip running basic tests"
        echo "  --build-only   Only build images, don't start services"
        echo ""
        echo "This script will:"
        echo "  1. Check system requirements"
        echo "  2. Create necessary directories"
        echo "  3. Pull required Docker images"
        echo "  4. Build CAM-OS kernel image"
        echo "  5. Start the complete environment"
        echo "  6. Run basic functionality tests"
        echo ""
        exit 0
    fi
    
    # Parse command line arguments
    SKIP_PULL=false
    SKIP_TEST=false
    BUILD_ONLY=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --no-pull)
                SKIP_PULL=true
                shift
                ;;
            --no-test)
                SKIP_TEST=true
                shift
                ;;
            --build-only)
                BUILD_ONLY=true
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Execute steps
    check_requirements
    create_directories
    
    if [ "$SKIP_PULL" != true ]; then
        pull_images
    fi
    
    build_kernel
    
    if [ "$BUILD_ONLY" != true ]; then
        start_environment
        
        if [ "$SKIP_TEST" != true ]; then
            run_tests
        fi
        
        show_access_info
    else
        print_status "Build complete. Use '$COMPOSE_CMD -f docker-compose.test.yml up -d' to start services."
    fi
}

# Run main function with all arguments
main "$@" 