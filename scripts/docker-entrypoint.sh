#!/bin/bash
set -euo pipefail

# Docker entrypoint script for CAM Protocol
# This script handles initialization and graceful shutdown

# Function to handle signals
shutdown() {
    echo "Received shutdown signal, gracefully shutting down..."
    kill -TERM "$child" 2>/dev/null
    wait "$child"
    echo "Shutdown complete"
    exit 0
}

# Trap signals
trap shutdown SIGTERM SIGINT

# Set default values
export NODE_ENV=${NODE_ENV:-production}
export PORT=${PORT:-8080}
export CAM_LOG_LEVEL=${CAM_LOG_LEVEL:-info}

# Health check function
health_check() {
    if curl -f "http://localhost:${PORT}/health" > /dev/null 2>&1; then
        echo "Health check passed"
        return 0
    else
        echo "Health check failed"
        return 1
    fi
}

# Wait for dependencies
wait_for_dependencies() {
    echo "Waiting for dependencies..."
    
    # Wait for Redis
    if [ -n "${CAM_REDIS_URL:-}" ]; then
        echo "Waiting for Redis..."
        redis_host=$(echo "$CAM_REDIS_URL" | sed 's/redis:\/\///' | cut -d':' -f1)
        redis_port=$(echo "$CAM_REDIS_URL" | sed 's/redis:\/\///' | cut -d':' -f2 | cut -d'/' -f1)
        until nc -z "$redis_host" "$redis_port"; do
            echo "Redis is unavailable - sleeping"
            sleep 2
        done
        echo "Redis is up"
    fi
    
    # Wait for PostgreSQL
    if [ -n "${CAM_DATABASE_URL:-}" ]; then
        echo "Waiting for PostgreSQL..."
        db_host=$(echo "$CAM_DATABASE_URL" | sed 's/postgresql:\/\/.*@//' | cut -d':' -f1)
        db_port=$(echo "$CAM_DATABASE_URL" | sed 's/postgresql:\/\/.*@//' | cut -d':' -f2 | cut -d'/' -f1)
        until nc -z "$db_host" "$db_port"; do
            echo "PostgreSQL is unavailable - sleeping"
            sleep 2
        done
        echo "PostgreSQL is up"
    fi
}

# Initialize the application
initialize() {
    echo "Initializing CAM Protocol..."
    
    # Create necessary directories
    mkdir -p /app/logs
    
    # Set permissions
    chown -R cam:nodejs /app/logs
    
    # Run database migrations if needed
    if [ "${NODE_ENV}" = "production" ] && [ -n "${CAM_DATABASE_URL:-}" ]; then
        echo "Running database migrations..."
        node dist/scripts/migrate.js
    fi
    
    echo "Initialization complete"
}

# Main execution
main() {
    echo "Starting CAM Protocol Docker container..."
    echo "Node.js version: $(node --version)"
    echo "Environment: ${NODE_ENV}"
    echo "Port: ${PORT}"
    echo "Log level: ${CAM_LOG_LEVEL}"
    
    # Wait for dependencies
    wait_for_dependencies
    
    # Initialize application
    initialize
    
    # Start the application
    echo "Starting application..."
    "$@" &
    child=$!
    
    # Wait for the application to start
    sleep 5
    
    # Perform initial health check
    if health_check; then
        echo "Application started successfully"
    else
        echo "Application failed to start properly"
        exit 1
    fi
    
    # Wait for the child process
    wait "$child"
}

# Execute main function with all arguments
main "$@"
