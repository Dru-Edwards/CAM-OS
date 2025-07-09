# Multi-stage Docker build for CAM-OS Kernel
# Build stage
FROM golang:1.21-alpine AS builder

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY proto/ ./proto/

# Build the kernel
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o cam-kernel ./cmd/cam-kernel

# Production stage
FROM alpine:3.18 AS production

# Set environment variables
ENV CAM_LOG_LEVEL=info
ENV CAM_GRPC_PORT=8080
ENV CAM_METRICS_PORT=9090

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata

# Create app directory and user
WORKDIR /app
RUN addgroup -g 1001 -S camkernel
RUN adduser -S camkernel -u 1001

# Copy kernel binary from builder stage
COPY --from=builder --chown=camkernel:camkernel /app/cam-kernel ./

# Copy configuration files
COPY --chown=camkernel:camkernel MANIFEST.toml ./
COPY --chown=camkernel:camkernel scripts/docker-entrypoint.sh ./

# Make entrypoint executable
RUN chmod +x docker-entrypoint.sh

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ./cam-kernel --health-check

# Expose ports
EXPOSE 8080 9090

# Switch to non-root user
USER camkernel

# Set entrypoint
ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["./cam-kernel"]
