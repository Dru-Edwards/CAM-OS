# SPDX-License-Identifier: Apache-2.0
FROM node:18-alpine

WORKDIR /app

# Create package.json
RUN echo '{ \
  "name": "toy-llm", \
  "version": "1.0.0", \
  "description": "A simple toy LLM service for CAM Protocol quickstart", \
  "main": "index.js", \
  "scripts": { \
    "start": "node index.js" \
  }, \
  "dependencies": { \
    "express": "^4.18.2" \
  }, \
  "license": "Apache-2.0" \
}' > package.json

# Install dependencies
RUN npm install

# Copy application code
COPY . .

# Expose the port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:3000/health || exit 1

# Run the application
CMD ["npm", "start"]
