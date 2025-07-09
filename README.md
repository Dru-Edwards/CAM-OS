# CAM-OS Kernel 🧠

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![CI](https://github.com/Dru-Edwards/CAM-OS/actions/workflows/ci.yml/badge.svg)](https://github.com/Dru-Edwards/CAM-OS/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat&logo=docker)](docker-compose.test.yml)
[![Security](https://img.shields.io/badge/Security-Post--Quantum-green)](docs/security/)

**CAM-OS** (Cognitive Arbitration Mesh Operating System) is a next-generation, AI-native cognitive operating system kernel designed for autonomous agent coordination, intelligent resource arbitration, and explainable AI governance.

Detailed protobuf specification lives in [`proto/syscall.proto`](proto/syscall.proto) ([view raw ↗](https://raw.githubusercontent.com/Dru-Edwards/CAM-OS/main/proto/syscall.proto)).

## 🚀 Features

### 🧠 Cognitive Syscalls (15 Total)
- **Core Operations**: `think`, `decide`, `learn`, `remember`, `forget`
- **Agent Coordination**: `communicate`, `collaborate`, `arbitrate`, `register_agent`
- **Task Management**: `commit_task`, `rollback_task`, `query_policy`
- **Observability**: `observe`, `explain_action`, `tune_system`

### 🔒 Post-Quantum Security
- **Kyber768** key exchange
- **Dilithium3** digital signatures
- **TPM 2.0** integration
- **CAM Trust Envelope** architecture

### 🎯 Triple-Helix Scheduler
- **5D Priority Queue**: Urgency, Importance, Efficiency, Energy, Trust
- **Dynamic Load Balancing**
- **Energy-Aware Scheduling**

### 🧮 Memory Context Orchestration
- **Redis-Backed Storage**
- **Versioned Context Management**
- **Encrypted Namespaces**
- **Schema Validation**

### 📊 Explainability Engine
- **Decision Audit Trails**
- **Real-time Explanations**
- **Governance Compliance**
- **Trust Scoring**

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                 CAM-OS Kernel                       │
├─────────────────┬───────────────┬───────────────────┤
│   Syscall API   │   Security    │   Explainability │
│   (15 verbs)    │   Manager     │   Engine          │
├─────────────────┼───────────────┼───────────────────┤
│   Arbitration   │   Memory      │   Triple-Helix    │
│   Engine        │   Context     │   Scheduler       │
├─────────────────┴───────────────┴───────────────────┤
│              Driver Runtime (gRPC + WASM)           │
├─────────────────────────────────────────────────────┤
│          Redis Backend │ Monitoring Stack           │
└─────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

| Method | Command | Description |
|--------|---------|-------------|
| **Docker (Recommended)** | `docker-compose -f docker-compose.test.yml up` | Complete test environment |
| **Local Development** | `./scripts/dev-up.sh` | Local build with Redis |
| **Production** | `helm install cam-os deployment/helm/cam-chart/` | Kubernetes deployment |

### Option 1: Docker Test Environment (Recommended)
```bash
# Clone the repository
git clone https://github.com/Dru-Edwards/CAM-OS.git
cd CAM-OS

# Run complete test environment
./quick-start-docker.sh
```

### Option 2: Local Development
```bash
# Prerequisites: Go 1.21+, Redis, protoc

# Install dependencies
go mod download

# Generate protobuf code
protoc --go_out=. --go-grpc_out=. proto/syscall.proto

# Build kernel
go build -o cam-kernel cmd/cam-kernel/main.go

# Start Redis and run kernel
redis-server --daemonize yes && ./cam-kernel
```

## 🧪 Testing & Quality Gates

The Docker test environment provides comprehensive testing:

```bash
# Run all cognitive syscall tests
./test-scripts/run-all-tests.sh

# Individual syscall testing
grpcurl -plaintext -d '{"verb":"think", "payload":"solve problem"}' \
  localhost:50051 cam.SyscallService/Execute

# Run benchmarks
make bench

# Fuzz testing (requires libFuzzer)
make fuzz
# Note: macOS users may need: brew install llvm && export CC=clang
```

### Test Coverage
- ✅ All 15 cognitive syscalls
- ✅ Post-quantum security protocols
- ✅ Memory context management
- ✅ Performance targets (<1ms latency)
- ✅ Explainability and audit trails

## 📊 Performance Targets

| Metric | Target | Status |
|--------|--------|--------|
| Syscall Latency | <1ms | ✅ Achieved |
| Throughput | >10K ops/sec | ✅ Achieved |
| Memory Efficiency | <100MB baseline | ✅ Achieved |
| Security Overhead | <5% performance impact | ✅ Achieved |

## 🛡️ Security

CAM-OS implements enterprise-grade security:

- **Post-Quantum Cryptography**: Future-proof against quantum computers
- **Zero-Trust Architecture**: All operations require verification
- **Hardware Security**: TPM 2.0 integration for root of trust
- **Process Isolation**: Sandboxed driver execution

See [Security Documentation](docs/security/) for details.

## 📚 Documentation

- [**Architecture Guide**](docs/architecture/README.md) - System design and components
- [**API Reference**](docs/api/README.md) - Complete syscall documentation
- [**Deployment Guide**](docs/deployment/DEPLOYMENT_GUIDE.md) - Production deployment
- [**Security Policy**](docs/legal/SECURITY_POLICY.md) - Security practices
- [**Quick Start**](docs/guides/quick-start.md) - Getting started guide

## 🔧 Development

### Dev Workflow
```bash
# Development build
make build-dev

# Production build
make build-prod

# Run tests
make test

# Start development environment (includes Redis)
./scripts/dev-up.sh

# Generate docs
make docs
```

### Contributing
1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## 🌍 Deployment

CAM-OS supports multiple deployment options:

- **Docker**: `docker-compose up`
- **Kubernetes**: Helm charts included
- **Cloud**: AWS, Azure, GCP templates
- **Bare Metal**: Systemd services

See [deployment/](deployment/) for platform-specific guides.

## 📈 Monitoring

Built-in observability with:

- **Prometheus**: Metrics collection
- **Grafana**: Performance dashboards
- **Jaeger**: Distributed tracing
- **Loki/Splunk compatible audit logs**: Compliance tracking

## 🛣️ Roadmap

| Version | Features | Target |
|---------|----------|--------|
| **v2.1** | Enhanced WASM driver runtime | Q3 2025 |
| **v2.2** | Multi-cluster federation | Q4 2025 |
| **v2.3** | Advanced ML model integration | Q1 2026 |
| **v3.0** | Quantum-safe key distribution | Q2 2026 |

See [ROADMAP.md](ROADMAP.md) for detailed timeline.

## 📄 License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.

### Enterprise License
Enterprise features available under commercial license. Contact us for pricing.

## 🤝 Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/Dru-Edwards/CAM-OS/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Dru-Edwards/CAM-OS/discussions)
- **Enterprise Support**: Contact [enterprise@cam-os.dev](mailto:enterprise@cam-os.dev)

## 🙏 Acknowledgments

- Built with ❤️ for the AI community
- Inspired by cognitive science and neuroscience research
- Thanks to all contributors and the open-source community

---

**CAM-OS**: The future of cognitive computing is here. 🧠✨
