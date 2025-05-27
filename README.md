# Complete Arbitration Mesh (CAM)

<div align="center">
  <img src="https://raw.githubusercontent.com/cam-protocol/assets/main/logo.png" alt="Complete Arbitration Mesh Logo" width="200"/>
  
  [![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE-CORE)
  [![Enterprise License: Commons Clause](https://img.shields.io/badge/License-Commons%20Clause-orange.svg)](LICENSE-ENTERPRISE)
  [![Version](https://img.shields.io/badge/Version-2.0.0-brightgreen.svg)](RELEASE_NOTES.md)
  
  **Intelligent Orchestration and Collaboration for Modern AI Ecosystems**
</div>

## 🌟 Overview

The Complete Arbitration Mesh (CAM) is a comprehensive platform that combines intelligent orchestration with advanced inter-agent collaboration capabilities. CAM serves as both the central nervous system for your AI integrations and the coordination layer for complex multi-agent collaborations.

### 🔍 Problem We Solve

Organizations face evolving challenges in the AI space:
- **Managing multiple AI providers** and their varying capabilities
- **Orchestrating collaboration** between specialized AI agents
- **Optimizing costs** while maintaining performance
- **Enforcing governance policies** across AI usage
- **Ensuring reliability** through intelligent failover
- **Maintaining compliance** with regulatory requirements
- **Scaling agent ecosystems** for complex tasks

## 🚀 Key Features

### Core Orchestration (CAM Classic)
- **FastPath Routing System** - Route requests to optimal AI providers 
- **Advanced Arbitration Engine** - Make decisions based on comprehensive criteria
- **Secure Authentication** - Protect access to your CAM instance
- **Comprehensive Monitoring** - Track detailed performance metrics
- **Policy Enforcement** - Apply governance rules consistently

### Inter-Agent Collaboration (IACP)
- **Agent Discovery** - Find and leverage specialized agents
- **Task Decomposition** - Break complex tasks into manageable components
- **Role-Based Collaboration** - Assign specialized roles to agents
- **Secure Inter-Agent Messaging** - Enable protected agent communication
- **Collaboration Marketplace** - Access specialized agent capabilities

## 📚 Quick Start

```bash
# Install the Complete Arbitration Mesh
npm install @cam-protocol/complete-arbitration-mesh

# Or using Docker
docker run -p 8080:8080 cam-protocol/complete-arbitration-mesh:latest
```

### Basic Usage

```typescript
import { CompleteArbitrationMesh } from '@cam-protocol/complete-arbitration-mesh';

const cam = new CompleteArbitrationMesh({
  apiKey: process.env.CAM_API_KEY,
  endpoint: 'https://api.complete-cam.com'
});

// Intelligent routing (original CAM functionality)
const routingResult = await cam.routeRequest({
  prompt: "Analyze this dataset",
  requirements: { cost: "optimize", performance: "balanced" }
});

// Agent collaboration (new IACP functionality)
const collaboration = await cam.initiateCollaboration({
  task: "Complex data analysis and visualization",
  requirements: ["data-analyst", "visualization-expert"],
  decomposition: "auto"
});
```

## 🏗️ Architecture

The Complete Arbitration Mesh integrates two powerful systems:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      Complete Arbitration Mesh                          │
├─────────────────────────────┬───────────────────────────────────────────┤
│      Routing System         │      Inter-Agent Collaboration            │
│       (CAM Core)            │            Protocol (IACP)                │
├─────────────────────────────┼───────────────────────────────────────────┤
│ • FastPath Routing          │ • Agent Discovery                         │
│ • Provider Selection        │ • Task Decomposition                      │
│ • Policy Enforcement        │ • Role-Based Collaboration                │
│ • Cost Optimization         │ • Secure Messaging                        │
└─────────────────────────────┴───────────────────────────────────────────┘
                                  │
┌─────────────────────────────────┴───────────────────────────────────────┐
│                         Shared Infrastructure                           │
├─────────────────────────────────────────────────────────────────────────┤
│ • Authentication & Authorization  • Provider Connectors                 │
│ • State Management               • Metrics & Telemetry                  │
│ • Configuration                  • Security Layer                       │
└─────────────────────────────────────────────────────────────────────────┘
```

## 📖 Documentation

- [Quick Start Guide](docs/guides/quick-start.md)
- [API Reference](docs/api/README.md)
- [Architecture Overview](docs/architecture/README.md)
- [Deployment Guide](docs/deployment/README.md)
- [Migration from CAM Classic](docs/guides/migration.md)

## 🔧 Development

```bash
# Clone the repository
git clone https://github.com/cam-protocol/complete-arbitration-mesh.git
cd complete-arbitration-mesh

# Install dependencies
npm install

# Start development server
npm run dev

# Run tests
npm test

# Build for production
npm run build
```

## 🛡️ Security

The Complete Arbitration Mesh takes security seriously:

- **Enterprise Authentication** - SAML, LDAP, OAuth 2.0
- **Zero-Trust Architecture** - Every request is authenticated and authorized
- **End-to-End Encryption** - All communications are encrypted
- **Audit Logging** - Comprehensive audit trails for compliance
- **FIPS Compliance** - Available in Enterprise tier

## 📋 Subscription Tiers

| Feature | Community | Professional | Enterprise |
|---------|:---------:|:------------:|:----------:|
| **AI Model Arbitration** | ✅ | ✅ | ✅ |
| **Agent Collaboration** | Basic | Advanced | Comprehensive |
| **Policy Management** | Limited | Standard | Advanced |
| **Support** | Community | Business Hours | 24/7 Premium |
| **Price** | Free | $299/mo | $4,999/mo |

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## 📄 License

- **Community Edition**: Apache 2.0 License
- **Professional/Enterprise**: Commons Clause License

## 🆘 Support

- **Community**: [GitHub Discussions](https://github.com/cam-protocol/complete-arbitration-mesh/discussions)
- **Professional**: Email support (business hours)
- **Enterprise**: 24/7 premium support

## 🗺️ Roadmap

See our [public roadmap](https://github.com/cam-protocol/complete-arbitration-mesh/projects/1) for upcoming features and improvements.

---

**Complete Arbitration Mesh** - Intelligent orchestration and collaboration for the AI-powered future.
