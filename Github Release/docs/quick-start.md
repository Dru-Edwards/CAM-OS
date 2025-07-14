# Quick Start Guide

Get up and running with Complete Arbitration Mesh in minutes.

> **Version:** This guide applies to **CAM Protocol v2.0.0**, released May 28, 2025. See [ROADMAP.md](../ROADMAP.md) for upcoming features.

## Prerequisites

- Node.js 18+ or Python 3.9+
- Docker (optional, for containerized deployment)
- Access to at least one AI provider (OpenAI, Anthropic, etc.)

## Installation

### Node.js/TypeScript

```bash
npm install complete-arbitration-mesh
```

### Python

```bash
pip install complete-arbitration-mesh
```

### Docker

```bash
docker pull cam/complete-arbitration-mesh:latest
```

## Basic Setup

### 1. Configuration

Create a configuration file:

```yaml
# cam-config.yaml
providers:
  openai:
    apiKey: "${OPENAI_API_KEY}"
    baseUrl: "https://api.openai.com/v1"
    models:
      - "gpt-4"
      - "gpt-3.5-turbo"
  
  anthropic:
    apiKey: "${ANTHROPIC_API_KEY}"
    baseUrl: "https://api.anthropic.com"
    models:
      - "claude-3-opus"
      - "claude-3-sonnet"

routing:
  defaultProvider: "openai"
  fallbackEnabled: true
  costOptimization: true

authentication:
  type: "jwt"
  secret: "${JWT_SECRET}"
  expiresIn: "24h"

collaboration:
  enabled: true
  agentRegistry: "local"
  maxAgentsPerTask: 5
```

### 2. Environment Variables

```bash
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
export JWT_SECRET="your-secret-key"
```

### 3. Basic Usage

#### TypeScript/JavaScript

```typescript
import { CompleteArbitrationMesh } from 'complete-arbitration-mesh';

const cam = new CompleteArbitrationMesh({
  configPath: './cam-config.yaml'
});

await cam.initialize();

// CAM Classic - Route a request
const response = await cam.route({
  prompt: "Explain quantum computing",
  model: "gpt-4",
  maxTokens: 1000
});

console.log(response.content);

// IACP - Start collaboration
const collaboration = await cam.startCollaboration({
  task: "Analyze market trends and create investment strategy",
  requiredCapabilities: ["data-analysis", "financial-modeling"],
  maxAgents: 3
});

const result = await collaboration.execute();
console.log(result);
```

#### Python

```python
from complete_arbitration_mesh import CompleteArbitrationMesh

cam = CompleteArbitrationMesh(config_path='./cam-config.yaml')
await cam.initialize()

# CAM Classic - Route a request
response = await cam.route({
    'prompt': 'Explain quantum computing',
    'model': 'gpt-4',
    'max_tokens': 1000
})

print(response['content'])

# IACP - Start collaboration
collaboration = await cam.start_collaboration({
    'task': 'Analyze market trends and create investment strategy',
    'required_capabilities': ['data-analysis', 'financial-modeling'],
    'max_agents': 3
})

result = await collaboration.execute()
print(result)
```

## First Request Test

Test your setup with a simple request:

```bash
curl -X POST http://localhost:3000/api/v1/route \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "prompt": "Hello, world!",
    "model": "gpt-3.5-turbo",
    "maxTokens": 50
  }'
```

Expected response:
```json
{
  "success": true,
  "content": "Hello! How can I assist you today?",
  "metadata": {
    "provider": "openai",
    "model": "gpt-3.5-turbo",
    "tokens": 8,
    "cost": 0.00001,
    "latency": 234
  }
}
```

## Next Steps

1. **Explore Examples**: Check `/examples` directory for advanced use cases
2. **Configure Providers**: Add more AI providers in configuration
3. **Set Up Monitoring**: Enable metrics and logging
4. **Deploy**: Follow [Deployment Guide](./deployment.md) for production
5. **Collaboration**: Set up agents for IACP functionality

## Common Issues

### Authentication Errors
- Verify JWT_SECRET is set
- Check token expiration
- Ensure proper Bearer token format

### Provider Errors
- Validate API keys
- Check provider quotas
- Verify network connectivity

### Configuration Issues
- Validate YAML syntax
- Check file permissions
- Verify environment variables

## Getting Help

- **Documentation**: See other guides in `/docs`
- **Examples**: Check `/examples` directory
- **Support**: Create GitHub issue
- **Community**: Join Discord server
