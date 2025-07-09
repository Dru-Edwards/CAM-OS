#!/bin/bash
set -e

# Docker entrypoint script for CAM-OS Kernel

# Default values
DEFAULT_PORT=50051
DEFAULT_REDIS_URL="redis://localhost:6379"
DEFAULT_LOG_LEVEL="info"
DEFAULT_METRICS_PORT=8080
DEFAULT_HEALTH_PORT=8081

# Environment variables with defaults
export CAM_PORT=${CAM_PORT:-$DEFAULT_PORT}
export CAM_REDIS_URL=${CAM_REDIS_URL:-$DEFAULT_REDIS_URL}
export CAM_LOG_LEVEL=${CAM_LOG_LEVEL:-$DEFAULT_LOG_LEVEL}
export CAM_METRICS_PORT=${CAM_METRICS_PORT:-$DEFAULT_METRICS_PORT}
export CAM_HEALTH_PORT=${CAM_HEALTH_PORT:-$DEFAULT_HEALTH_PORT}

# Function to log messages
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to check if Redis is available
check_redis() {
    log "Checking Redis connection..."
    if command -v redis-cli >/dev/null 2>&1; then
        if redis-cli -u "$CAM_REDIS_URL" ping >/dev/null 2>&1; then
            log "Redis connection successful"
            return 0
        else
            log "Redis connection failed"
            return 1
        fi
    else
        log "redis-cli not available, skipping Redis check"
        return 0
    fi
}

# Function to wait for Redis
wait_for_redis() {
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if check_redis; then
            return 0
        fi
        
        log "Waiting for Redis... (attempt $attempt/$max_attempts)"
        sleep 2
        attempt=$((attempt + 1))
    done
    
    log "Failed to connect to Redis after $max_attempts attempts"
    return 1
}

# Function to validate environment
validate_environment() {
    log "Validating environment..."
    
    # Check required environment variables
    if [ -z "$CAM_PORT" ]; then
        log "ERROR: CAM_PORT is not set"
        exit 1
    fi
    
    if [ -z "$CAM_REDIS_URL" ]; then
        log "ERROR: CAM_REDIS_URL is not set"
        exit 1
    fi
    
    # Validate port numbers
    if ! [[ "$CAM_PORT" =~ ^[0-9]+$ ]] || [ "$CAM_PORT" -lt 1 ] || [ "$CAM_PORT" -gt 65535 ]; then
        log "ERROR: Invalid CAM_PORT: $CAM_PORT"
        exit 1
    fi
    
    if ! [[ "$CAM_METRICS_PORT" =~ ^[0-9]+$ ]] || [ "$CAM_METRICS_PORT" -lt 1 ] || [ "$CAM_METRICS_PORT" -gt 65535 ]; then
        log "ERROR: Invalid CAM_METRICS_PORT: $CAM_METRICS_PORT"
        exit 1
    fi
    
    if ! [[ "$CAM_HEALTH_PORT" =~ ^[0-9]+$ ]] || [ "$CAM_HEALTH_PORT" -lt 1 ] || [ "$CAM_HEALTH_PORT" -gt 65535 ]; then
        log "ERROR: Invalid CAM_HEALTH_PORT: $CAM_HEALTH_PORT"
        exit 1
    fi
    
    log "Environment validation successful"
}

# Function to initialize CAM-OS
initialize_cam_os() {
    log "Initializing CAM-OS Kernel..."
    
    # Create necessary directories
    mkdir -p /var/log/cam-os
    mkdir -p /var/lib/cam-os
    mkdir -p /tmp/cam-os
    
    # Set permissions
    chmod 755 /var/log/cam-os
    chmod 755 /var/lib/cam-os
    chmod 755 /tmp/cam-os
    
    # Initialize configuration if not present
    if [ ! -f /etc/cam-os/config.yaml ]; then
        log "Creating default configuration..."
        mkdir -p /etc/cam-os
        cat > /etc/cam-os/config.yaml << EOF
server:
  port: $CAM_PORT
  metrics_port: $CAM_METRICS_PORT
  health_port: $CAM_HEALTH_PORT
  
redis:
  url: $CAM_REDIS_URL
  
logging:
  level: $CAM_LOG_LEVEL
  
security:
  tls_enabled: false
  
performance:
  max_workers: 100
  timeout_ms: 1000
EOF
    fi
    
    log "CAM-OS initialization complete"
}

# Function to start CAM-OS
start_cam_os() {
    log "Starting CAM-OS Kernel..."
    
    # Start the CAM-OS kernel
    exec /usr/local/bin/cam-kernel "$@"
}

# Main execution
main() {
    log "Starting CAM-OS Docker container..."
    
    # Parse command line arguments
    case "$1" in
        "help"|"--help"|"-h")
            cat << EOF
CAM-OS Docker Container

Usage: docker run [OPTIONS] cam-os/kernel [COMMAND]

Commands:
  start     Start the CAM-OS kernel (default)
  help      Show this help message
  version   Show version information
  test      Run connectivity tests

Environment Variables:
  CAM_PORT            gRPC server port (default: 50051)
  CAM_REDIS_URL       Redis connection URL (default: redis://localhost:6379)
  CAM_LOG_LEVEL       Log level (default: info)
  CAM_METRICS_PORT    Metrics server port (default: 8080)
  CAM_HEALTH_PORT     Health check port (default: 8081)

Examples:
  docker run -p 50051:50051 cam-os/kernel
  docker run -e CAM_LOG_LEVEL=debug cam-os/kernel
  docker run cam-os/kernel test
EOF
            exit 0
            ;;
        "version"|"--version"|"-v")
            echo "CAM-OS Kernel v1.1.0"
            exit 0
            ;;
        "test")
            log "Running connectivity tests..."
            check_redis
            log "All tests passed"
            exit 0
            ;;
        "start"|"")
            # Default behavior - start the kernel
            ;;
        *)
            log "Unknown command: $1"
            log "Use 'help' for usage information"
            exit 1
            ;;
    esac
    
    # Validate environment
    validate_environment
    
    # Wait for Redis if needed
    if [ "$CAM_REDIS_URL" != "redis://localhost:6379" ]; then
        wait_for_redis
    fi
    
    # Initialize CAM-OS
    initialize_cam_os
    
    # Start CAM-OS
    start_cam_os "$@"
}

# Run main function
main "$@"
