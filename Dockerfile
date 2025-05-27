# Multi-stage Docker build for CAM Protocol
# Build stage
FROM node:18-alpine AS builder

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy source code
COPY src/ ./src/

# Build the application
RUN npm run build

# Production stage
FROM node:18-alpine AS production

# Set environment variables
ENV NODE_ENV=production
ENV PORT=8080
ENV CAM_LOG_LEVEL=info

# Create app directory and user
WORKDIR /app
RUN addgroup -g 1001 -S nodejs
RUN adduser -S cam -u 1001

# Copy package files
COPY package*.json ./

# Install only production dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy built application from builder stage
COPY --from=builder --chown=cam:nodejs /app/dist ./dist

# Copy configuration files
COPY --chown=cam:nodejs config/ ./config/
COPY --chown=cam:nodejs scripts/docker-entrypoint.sh ./

# Make entrypoint executable
RUN chmod +x docker-entrypoint.sh

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node dist/scripts/health-check.js

# Expose port
EXPOSE 8080

# Switch to non-root user
USER cam

# Set entrypoint
ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["node", "dist/index.js"]
