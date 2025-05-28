# Complete Arbitration Mesh (CAM)

<div align="center">
  <img src="docs/assets/cam1.png" alt="Complete Arbitration Mesh Logo" width="200"/>
  <h3>Complete Arbitration Mesh (CAM) Protocol</h3>
  
  [![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
  [![Version](https://img.shields.io/badge/Version-2.0.0-brightgreen.svg)](docs/RELEASE_NOTES.md)
  [![Compliance](https://img.shields.io/badge/Compliance-GDPR%20|%20CCPA-green.svg)](docs/legal/COMPLIANCE_CHECKLIST.md)
  [![Build Status](https://img.shields.io/github/workflow/status/Complete-Arbitration-Mesh/CAM-PROTOCOL/Continuous%20Integration?branch=main)](https://github.com/Complete-Arbitration-Mesh/CAM-PROTOCOL/actions/workflows/ci.yml)
  [![Coverage](https://img.shields.io/badge/coverage-94%25-brightgreen.svg)](./badges/coverage-statements.svg)
  [![SBOM](https://img.shields.io/badge/SBOM-CycloneDX-orange)](https://github.com/Complete-Arbitration-Mesh/CAM-PROTOCOL/actions/workflows/ci.yml)
  
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

### Complete Environment with Docker Compose

For a full-featured environment including CAM Protocol, a toy LLM, and monitoring:

```bash
# Clone the repository
git clone https://github.com/Complete-Arbitration-Mesh/CAM-PROTOCOL.git

# Start the quickstart environment
cd CAM-PROTOCOL/examples/quickstart
docker-compose up -d

# Test it with a simple request
curl localhost:8080/mesh/chat -d '{"message":"Hello CAM!"}' -H "Content-Type: application/json" -H "Authorization: Bearer demo-key-for-quickstart"
```

See [examples/quickstart](examples/quickstart) for more details.

### Try it in 30 Seconds

```bash
# Run our interactive demo to see CAM in action
npx @cam-protocol/demo

# Or try our value demonstration script
npm run demo:value
```

### SDK Examples

CAM Protocol provides SDKs for multiple languages. Here are examples in TypeScript, Python, and Go:

#### TypeScript/JavaScript ([SDK Documentation](sdk/js/README.md))

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

#### Python ([SDK Documentation](sdk/python/README.md))

```python
from cam_protocol import CompleteArbitrationMesh

# Initialize the CAM client
cam = CompleteArbitrationMesh(
    api_key=os.environ.get("CAM_API_KEY"),
    endpoint="https://api.complete-cam.com"
)

# Intelligent routing
routing_result = cam.route_request(
    prompt="Analyze this dataset",
    requirements={"cost": "optimize", "performance": "balanced"}
)

# Agent collaboration
collaboration = cam.initiate_collaboration(
    task="Complex data analysis and visualization",
    requirements=["data-analyst", "visualization-expert"],
    decomposition="auto"
)
```

#### Go ([SDK Documentation](sdk/go/README.md))

```go
package main

import (
	"os"
	"github.com/complete-arbitration-mesh/cam-protocol-go"
)

func main() {
	// Initialize the CAM client
	cam, err := camprotocol.NewClient(
		camprotocol.WithAPIKey(os.Getenv("CAM_API_KEY")),
		camprotocol.WithEndpoint("https://api.complete-cam.com"),
	)
	if err != nil {
		panic(err)
	}

	// Intelligent routing
	routingResult, err := cam.RouteRequest(camprotocol.RouteRequest{
		Prompt: "Analyze this dataset",
		Requirements: map[string]string{
			"cost":        "optimize",
			"performance": "balanced",
		},
	})

	// Agent collaboration
	collaboration, err := cam.InitiateCollaboration(camprotocol.CollaborationRequest{
		Task:         "Complex data analysis and visualization",
		Requirements: []string{"data-analyst", "visualization-expert"},
		Decomposition: "auto",
	})
}
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

For a complete overview of all documentation, see our [Documentation Index](docs/index.md).

### Guides
- [Quick Start Guide](docs/guides/quick-start.md)
- [Deployment Readiness](docs/DEPLOYMENT_READINESS.md)
- [Proof of Value](docs/PROOF_OF_VALUE.md)

### Technical Documentation
- [API Reference](docs/api/README.md)
- [Architecture Overview](docs/architecture/README.md)

### Legal & Compliance
- [Compliance Checklist](docs/legal/COMPLIANCE_CHECKLIST.md)
- [Privacy Policy](docs/legal/PRIVACY_POLICY.md)
- [Terms of Service](docs/legal/TERMS_OF_SERVICE.md)
- [GDPR Compliance](docs/legal/GDPR_COMPLIANCE.md)
- [CCPA Compliance](docs/legal/CCPA_COMPLIANCE.md)
- [Security Policy](docs/legal/SECURITY_POLICY.md)
- [Security Pre-Launch Checklist](docs/security/SECURITY_CHECKLIST.md)
- [Data Processing Agreement](docs/legal/DATA_PROCESSING_AGREEMENT.md)

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

# Run benchmarks
npm run benchmark:cost
npm run benchmark:collaboration

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

| Feature | Community | Growth | Professional | Enterprise |
|---------|:---------:|:------:|:------------:|:----------:|
| **AI Model Arbitration** | ✅ | ✅ | ✅ | ✅ |
| **Agent Collaboration** | Basic | Standard | Advanced | Comprehensive |
| **Policy Management** | Limited | Standard | Advanced | Enterprise-grade |
| **Support** | Community | Email | Business Hours | 24/7 Premium |
| **SLA** | None | 99.9% | 99.95% | 99.99% |
| **Price** | Free | [Contact Us](mailto:edwardstechpros@outlook.com) | [Contact Us](mailto:edwardstechpros@outlook.com) | [Contact Us](mailto:edwardstechpros@outlook.com) |

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## 📄 License

CAM Protocol is available under a dual-licensing model:

- **Community Edition**: [Apache 2.0 License](LICENSE)
- **Professional/Enterprise**: [Apache 2.0 with Commons Clause](LICENSE-ENTERPRISE)

See our detailed [licensing documentation](LICENSES.md) for more information.

## 🆘 Support

- **Community**: [GitHub Discussions](https://github.com/orgs/Complete-Arbitration-Mesh/discussions)
- **Professional**: Email support (business hours)
- **Enterprise**: 24/7 premium support

## 🗺️ Roadmap

See our [public roadmap](https://github.com/cam-protocol/complete-arbitration-mesh/projects/1) for upcoming features and improvements.

## 📊 Value Demonstration

We've created comprehensive benchmarks and demonstrations to show the value of CAM Protocol:

### Cost Optimization

On average, organizations using CAM Protocol see **30-40% reduction in AI API costs** while maintaining quality.

```bash
# Run the cost optimization benchmark
npm run benchmark:cost
```

### Enhanced Capabilities

Multi-agent collaboration through CAM Protocol provides **35-50% improvement in task completion quality**.

```bash
# Run the multi-agent collaboration benchmark
npm run benchmark:collaboration
```

### Reliability & Governance

CAM Protocol provides **99.99% availability** through intelligent failover and ensures **100% policy compliance** across all AI usage.

```bash
# Run the full value demonstration
npm run demo:value
```

See our [Proof of Value](docs/PROOF_OF_VALUE.md) document for comprehensive benchmarking results and case studies.

## 🔒 Legal & Compliance

The CAM Protocol is designed with security and compliance at its core:

- **[Privacy Policy](docs/legal/PRIVACY_POLICY.md)** - How we handle user data
- **[Terms of Service](docs/legal/TERMS_OF_SERVICE.md)** - Rules for using our service
- **[GDPR Compliance](docs/legal/GDPR_COMPLIANCE.md)** - EU data protection compliance
- **[CCPA Compliance](docs/legal/CCPA_COMPLIANCE.md)** - California privacy compliance
- **[Security Policy](docs/legal/SECURITY_POLICY.md)** - Our security practices
- **[Data Processing Agreement](docs/legal/DATA_PROCESSING_AGREEMENT.md)** - For processing customer data
- **[Acceptable Use Policy](docs/legal/ACCEPTABLE_USE_POLICY.md)** - Guidelines for acceptable use
- **[Service Level Agreement](docs/legal/SERVICE_LEVEL_AGREEMENT.md)** - Our uptime and performance guarantees

---

**Complete Arbitration Mesh** - Intelligent orchestration and collaboration for the AI-powered future.
