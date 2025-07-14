# Proto Builder Docker Image
# Ensures consistent protobuf generation across environments
# Required by H-7: Proto drift guard

FROM golang:1.21-alpine AS builder

# Install protobuf compiler and dependencies
RUN apk add --no-cache \
    protobuf \
    protobuf-dev \
    git \
    make

# Install Go protobuf tools at specific versions for consistency
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.31.0 && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.3.0

# Set working directory
WORKDIR /workspace

# Create a lightweight final image
FROM alpine:3.18

# Install only runtime dependencies
RUN apk add --no-cache \
    protobuf \
    git \
    make

# Copy Go binaries from builder
COPY --from=builder /go/bin/protoc-gen-go /usr/local/bin/
COPY --from=builder /go/bin/protoc-gen-go-grpc /usr/local/bin/

# Set working directory
WORKDIR /workspace

# Default command to show usage
CMD ["sh", "-c", "echo 'Proto Builder v1.0' && echo 'Usage: docker run --rm -v \$(pwd):/workspace proto-builder make proto'"] 