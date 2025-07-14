# Quick Start Guide

This guide will help you get started with the Complete Arbitration Mesh (CAM) Protocol quickly and efficiently.

## Installation

### NPM Installation

```bash
# Install the Complete Arbitration Mesh
npm install @cam-protocol/complete-arbitration-mesh
```

### Docker Installation

```bash
# Pull the Docker image
docker pull cam-protocol/complete-arbitration-mesh:latest

# Run the container
docker run -p 8080:8080 cam-protocol/complete-arbitration-mesh:latest
```

## Configuration

Create a configuration file (`.env` or `config.json`) with your API keys:

```
CAM_API_KEY=your_api_key
OPENAI_API_KEY=your_openai_key
ANTHROPIC_API_KEY=your_anthropic_key
COHERE_API_KEY=your_cohere_key
```

## Basic Usage

### Intelligent Routing

```typescript
import { CompleteArbitrationMesh } from '@cam-protocol/complete-arbitration-mesh';

// Initialize CAM
const cam = new CompleteArbitrationMesh({
  apiKey: process.env.CAM_API_KEY,
  environment: 'production'
});

// Route a request to the optimal provider
const response = await cam.routeRequest({
  prompt: "Explain quantum computing in simple terms",
  maxTokens: 150,
  requirements: {
    cost: "optimize",     // Prioritize cost savings
    performance: "balanced" // Balance between speed and quality
  }
});

console.log(`Provider used: ${response.provider}`);
console.log(`Response: ${response.content}`);
console.log(`Cost: $${response.cost}`);
```

### Multi-Agent Collaboration

```typescript
// Initialize a collaboration session
const collaboration = await cam.initiateCollaboration({
  task: "Analyze financial data and create visualizations",
  requirements: ["data-analysis", "visualization", "financial-expertise"],
  decomposition: "auto" // Automatically decompose the task
});

// Get the collaboration result
const result = await collaboration.getResult();

console.log(`Collaboration ID: ${collaboration.id}`);
console.log(`Participating agents: ${result.participatingAgents.join(', ')}`);
console.log(`Result: ${result.content}`);
```

## Advanced Features

### Custom Routing Policies

```typescript
// Define a custom routing policy
const customPolicy = {
  name: "enterprise-policy",
  rules: [
    {
      condition: { taskType: "sensitive-data" },
      action: { useProvider: "secure-provider", enforceEncryption: true }
    },
    {
      condition: { costSensitivity: "high" },
      action: { useProvider: "budget-provider", maxCost: 0.01 }
    }
  ]
};

// Register the policy
await cam.registerPolicy(customPolicy);

// Use the policy in a request
const response = await cam.routeRequest({
  prompt: "Analyze this financial data",
  policy: "enterprise-policy"
});
```

### Monitoring and Analytics

```typescript
// Get usage statistics
const usageStats = await cam.getUsageStatistics({
  startDate: "2025-05-01",
  endDate: "2025-05-27"
});

console.log(`Total requests: ${usageStats.totalRequests}`);
console.log(`Total cost: $${usageStats.totalCost}`);
console.log(`Cost savings: $${usageStats.costSavings}`);
```

## Running Benchmarks

To see the value of CAM Protocol in action, run our benchmarks:

```bash
# Run the cost optimization benchmark
npm run benchmark:cost

# Run the multi-agent collaboration benchmark
npm run benchmark:collaboration

# Run the full value demonstration
npm run demo:value
```

## Next Steps

- Explore the [API Reference](../api/README.md) for detailed documentation
- Learn about the [Architecture](../architecture/README.md) of CAM Protocol
- Review [Deployment Readiness](../DEPLOYMENT_READINESS.md) for production deployment
- Check out our [Compliance Documentation](../legal/COMPLIANCE_CHECKLIST.md)

## Support

If you need help, reach out to us:

- **Community Support**: [GitHub Discussions](https://github.com/cam-protocol/complete-arbitration-mesh/discussions)
- **Professional Support**: support@cam-protocol.com
- **Enterprise Support**: enterprise-support@cam-protocol.com
