# Contributing to CAM-OS Kernel 🧠

Thank you for your interest in contributing to CAM-OS! This document provides guidelines and information for contributors.

## 🎯 Project Vision

CAM-OS is building the world's first cognitive operating system kernel - infrastructure designed specifically for AI-native workloads, autonomous agent coordination, and explainable AI governance. We're creating the substrate that will power the next generation of intelligent systems.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contribution Workflow](#contribution-workflow)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Documentation Guidelines](#documentation-guidelines)
- [Security Considerations](#security-considerations)
- [Performance Requirements](#performance-requirements)
- [Review Process](#review-process)
- [Release Process](#release-process)
- [Community](#community)

## 📜 Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## 🚀 Getting Started

### Prerequisites

Before contributing, ensure you have:

- **Go 1.21+** - [Installation Guide](https://golang.org/doc/install)
- **Protocol Buffers Compiler** - [Installation Guide](https://grpc.io/docs/protoc-installation/)
- **Docker & Docker Compose** - [Installation Guide](https://docs.docker.com/get-docker/)
- **Redis 6.0+** - For local development
- **Make** - Build automation
- **Git** - Version control

### Initial Setup

1. **Fork the Repository**
   ```bash
   # Fork on GitHub, then clone your fork
   git clone https://github.com/your-username/cam-os-kernel.git
   cd cam-os-kernel
   ```

2. **Set Up Upstream Remote**
   ```bash
   git remote add upstream https://github.com/cam-os/kernel.git
   git fetch upstream
   ```

3. **Initialize Development Environment**
   ```bash
   # Install development tools and dependencies
   make init
   
   # Verify setup
   make check
   ```

4. **Start Development Environment**
   ```bash
   # Start Redis and monitoring stack
   make dev
   
   # Build and run kernel
   make run-dev
   ```

## 🛠️ Development Setup

### Environment Configuration

1. **Copy Configuration Template**
   ```bash
   cp MANIFEST.toml MANIFEST.toml.local
   ```

2. **Configure for Development**
   ```toml
   [kernel]
   log_level = "debug"
   development_mode = true
   
   [redis]
   url = "redis://localhost:6379"
   
   [security]
   skip_tpm_check = true  # For development only
   ```

3. **Set Environment Variables**
   ```bash
   export CAM_ENV=development
   export CAM_LOG_LEVEL=debug
   export REDIS_URL=redis://localhost:6379
   ```

### IDE Configuration

#### Visual Studio Code

```json
{
  "go.toolsManagement.checkForUpdates": "local",
  "go.useLanguageServer": true,
  "go.lintTool": "golangci-lint",
  "go.formatTool": "goimports",
  "go.testFlags": ["-v", "-race"],
  "go.buildFlags": ["-race"]
}
```

#### GoLand/IntelliJ

- Enable Go modules integration
- Configure golangci-lint as external tool
- Set up run configurations for kernel and tests

## 🔄 Contribution Workflow

### 1. Issue First

- **For Bugs**: Create a detailed bug report with reproduction steps
- **For Features**: Open a feature request with use cases and requirements
- **For Enhancements**: Discuss the improvement with maintainers first

### 2. Branch Strategy

```bash
# Create feature branch
git checkout -b feature/your-feature-name

# Create bugfix branch
git checkout -b bugfix/issue-number-description

# Create hotfix branch (for urgent production fixes)
git checkout -b hotfix/critical-issue-description
```

### 3. Development Process

1. **Write Tests First** (TDD encouraged)
   ```bash
   # Write failing tests
   make test
   
   # Implement feature
   # ...
   
   # Verify tests pass
   make test
   ```

2. **Follow Coding Standards**
   ```bash
   # Format code
   make fmt
   
   # Run linters
   make lint
   
   # Run security scan
   make security-scan
   ```

3. **Update Documentation**
   - Update relevant documentation
   - Add API documentation for new syscalls
   - Update configuration examples

4. **Test Thoroughly**
   ```bash
   # Run all tests
   make test-all
   
   # Run Docker tests
   make docker-test
   
   # Run performance tests
   make perf-test
   ```

### 4. Commit Guidelines

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```bash
# Format
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]

# Examples
feat(syscall): add sys_rollback_task syscall
fix(security): resolve TPM initialization race condition
docs(api): update syscall documentation
perf(scheduler): optimize 5D priority calculation
test(integration): add Redis failover tests
```

**Types:**
- `feat`: New features
- `fix`: Bug fixes
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Test additions/modifications
- `chore`: Maintenance tasks

### 5. Pull Request Process

1. **Rebase on Latest Main**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Create Pull Request**
   - Use descriptive title following conventional commits
   - Fill out PR template completely
   - Link related issues
   - Add reviewers

3. **PR Requirements**
   - [ ] All tests pass
   - [ ] Code coverage maintained/improved
   - [ ] Documentation updated
   - [ ] Performance benchmarks included (if applicable)
   - [ ] Security considerations addressed

## 📝 Coding Standards

### Go Style Guide

Follow [Effective Go](https://golang.org/doc/effective_go.html) and [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments).

#### Key Principles

1. **Clarity over Cleverness**
   ```go
   // Good
   func processTask(task *Task) error {
       if task == nil {
           return ErrInvalidTask
       }
       return task.Execute()
   }
   
   // Avoid
   func processTask(task *Task) error {
       return map[bool]error{true: task.Execute(), false: ErrInvalidTask}[task != nil]
   }
   ```

2. **Error Handling**
   ```go
   // Always handle errors explicitly
   result, err := doSomething()
   if err != nil {
       return fmt.Errorf("failed to do something: %w", err)
   }
   ```

3. **Context Usage**
   ```go
   // Always accept context as first parameter
   func (s *Service) ProcessWithTimeout(ctx context.Context, task *Task) error {
       ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
       defer cancel()
       // ...
   }
   ```

#### Package Organization

```
internal/
├── arbitration/     # Arbitration engine
├── explainability/ # Explainability engine
├── memory/          # Context management
├── policy/          # Policy engine
├── scheduler/       # Triple-helix scheduler
├── security/        # Security framework
└── syscall/         # Syscall dispatcher
```

#### Naming Conventions

- **Packages**: lowercase, single word preferred
- **Functions**: camelCase, descriptive verbs
- **Interfaces**: noun or adjective + "er" suffix
- **Constants**: CamelCase or SCREAMING_SNAKE_CASE
- **Variables**: camelCase, descriptive nouns

#### Comments

```go
// Package comment describes the package purpose
package arbitration

// Public function requires comment
// ProcessTask executes a cognitive task using the arbitration engine.
// It returns the task result or an error if processing fails.
func ProcessTask(ctx context.Context, task *Task) (*Result, error) {
    // Implementation comments for complex logic
    // ...
}
```

### Protocol Buffers

- Use consistent field numbering (no gaps)
- Include comprehensive field documentation
- Version services appropriately
- Use semantic field names

```protobuf
syntax = "proto3";

package cam;

// SyscallRequest represents a cognitive syscall invocation
message SyscallRequest {
  // Unique identifier for the syscall invocation
  string call_id = 1;
  
  // The cognitive verb to execute
  string verb = 2;
  
  // JSON-encoded payload for the syscall
  string payload = 3;
  
  // Context information for the syscall
  SyscallContext context = 4;
}
```

## 🧪 Testing Guidelines

### Test Categories

1. **Unit Tests** (`*_test.go`)
   - Test individual functions/methods
   - Mock external dependencies
   - Focus on business logic

2. **Integration Tests** (`tests/integration/`)
   - Test component interactions
   - Use real Redis instance
   - Test syscall flows

3. **End-to-End Tests** (`tests/e2e/`)
   - Test complete user workflows
   - Use Docker environment
   - Validate performance targets

4. **Performance Tests** (`tests/performance/`)
   - Benchmark critical paths
   - Validate latency requirements
   - Monitor resource usage

### Testing Best Practices

```go
func TestSyscallDispatcher_Execute(t *testing.T) {
    tests := []struct {
        name    string
        verb    string
        payload string
        want    *SyscallResponse
        wantErr bool
    }{
        {
            name: "valid think syscall",
            verb: "think",
            payload: `{"query": "solve problem"}`,
            want: &SyscallResponse{
                Status: StatusSuccess,
                // ...
            },
            wantErr: false,
        },
        // More test cases...
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            d := NewSyscallDispatcher()
            got, err := d.Execute(context.Background(), tt.verb, tt.payload)
            
            if (err != nil) != tt.wantErr {
                t.Errorf("Execute() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            
            if !reflect.DeepEqual(got, tt.want) {
                t.Errorf("Execute() = %v, want %v", got, tt.want)
            }
        })
    }
}
```

### Performance Testing

```go
func BenchmarkSyscallDispatcher_Execute(b *testing.B) {
    d := NewSyscallDispatcher()
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := d.Execute(context.Background(), "think", `{"query":"test"}`)
        if err != nil {
            b.Fatal(err)
        }
    }
}
```

## 📚 Documentation Guidelines

### API Documentation

- Document all public functions and types
- Include usage examples
- Specify error conditions
- Document performance characteristics

### Architecture Documentation

- Update architecture diagrams for structural changes
- Document design decisions and trade-offs
- Include deployment considerations
- Provide troubleshooting guides

### Configuration Documentation

- Document all configuration options
- Provide secure defaults
- Include environment-specific examples
- Document validation rules

## 🔒 Security Considerations

### Security Review Checklist

- [ ] Input validation for all user data
- [ ] Authentication/authorization checks
- [ ] Secure defaults in configuration
- [ ] No hardcoded secrets or credentials
- [ ] Proper error handling (no information disclosure)
- [ ] Rate limiting and resource bounds
- [ ] Cryptographic best practices

### Sensitive Data Handling

```go
// Use structured logging for security events
logger.Info("authentication_attempt",
    zap.String("user_id", userID),
    zap.String("source_ip", request.RemoteAddr),
    zap.Bool("success", success),
)

// Never log sensitive data
// BAD: logger.Info("password", password)
// GOOD: logger.Info("password_length", len(password))
```

### Post-Quantum Cryptography

- Use approved algorithms (Kyber768, Dilithium3)
- Implement crypto-agility
- Regular key rotation
- Secure key storage

## ⚡ Performance Requirements

### Latency Targets

- **Syscall Processing**: <1ms (99th percentile)
- **Context Operations**: <10ms (average)
- **Arbitration Decisions**: <100ms (average)

### Throughput Targets

- **Syscalls**: >10,000 ops/sec
- **Context Updates**: >1,000 ops/sec
- **Concurrent Connections**: >1,000

### Memory Efficiency

- **Base Memory**: <100MB
- **Per-Connection Overhead**: <1MB
- **Context Storage**: Compressed and efficient

### Performance Testing

```go
func TestPerformanceTargets(t *testing.T) {
    if testing.Short() {
        t.Skip("skipping performance test in short mode")
    }
    
    // Test syscall latency
    start := time.Now()
    for i := 0; i < 1000; i++ {
        _, err := dispatcher.Execute(ctx, "think", payload)
        require.NoError(t, err)
    }
    
    avgLatency := time.Since(start) / 1000
    require.Less(t, avgLatency, time.Millisecond, "Average latency exceeds 1ms")
}
```

## 👀 Review Process

### Review Criteria

1. **Functionality**
   - Meets requirements
   - Handles edge cases
   - Proper error handling

2. **Code Quality**
   - Follows style guide
   - Well-structured and readable
   - Appropriate abstractions

3. **Testing**
   - Adequate test coverage
   - Tests are meaningful
   - Performance tests included

4. **Documentation**
   - Code is well-documented
   - API docs updated
   - User-facing docs updated

5. **Security**
   - No security vulnerabilities
   - Follows security best practices
   - Proper input validation

### Review Timeline

- **Initial Review**: Within 2 business days
- **Follow-up Reviews**: Within 1 business day
- **Approval**: Requires 2 approvals from maintainers
- **Merge**: After all checks pass and approvals received

## 🚢 Release Process

### Version Strategy

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes to APIs or protocols
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes and security updates

### Release Schedule

- **Patch Releases**: As needed for critical fixes
- **Minor Releases**: Monthly feature releases
- **Major Releases**: Quarterly architectural updates

### Release Checklist

- [ ] All tests pass
- [ ] Performance benchmarks meet targets
- [ ] Security scan passes
- [ ] Documentation updated
- [ ] Changelog updated
- [ ] Version bumped appropriately
- [ ] Release notes prepared

## 🤝 Community

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and ideas
- **Discord**: Real-time chat and collaboration
- **Mailing List**: Important announcements

### Maintainers

- **Core Team**: Architecture and strategic decisions
- **Module Maintainers**: Specific component expertise
- **Community Contributors**: Regular contributors with write access

### Recognition

We recognize contributions in several ways:

- **Contributor Wall**: Recognition in README
- **Release Notes**: Contributor acknowledgments
- **Conference Talks**: Speaking opportunities
- **Mentorship**: Guidance for new contributors

### Getting Help

- **Documentation**: Check docs first
- **GitHub Discussions**: Ask questions
- **Discord**: Real-time help
- **Office Hours**: Weekly maintainer availability

## 🎓 Learning Resources

### Understanding CAM-OS

- [Architecture Overview](docs/architecture/README.md)
- [Cognitive Syscalls Guide](docs/api/README.md)
- [Security Framework](docs/security/README.md)
- [Performance Optimization](docs/performance/README.md)

### Go Resources

- [A Tour of Go](https://tour.golang.org/)
- [Effective Go](https://golang.org/doc/effective_go.html)
- [Go by Example](https://gobyexample.com/)

### gRPC and Protocol Buffers

- [gRPC Documentation](https://grpc.io/docs/)
- [Protocol Buffers Guide](https://developers.google.com/protocol-buffers)

### Distributed Systems

- [Designing Data-Intensive Applications](https://dataintensive.net/)
- [Distributed Systems Concepts](https://www.coursera.org/learn/distributed-systems-concepts)

---

Thank you for contributing to CAM-OS! Together, we're building the future of cognitive computing. 🧠✨

*For questions about contributing, please reach out through our community channels or open a GitHub Discussion.*
