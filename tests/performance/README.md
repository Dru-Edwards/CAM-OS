# CAM Performance Testing Framework

This directory contains a comprehensive performance testing and benchmarking framework for the Complete Arbitration Mesh (CAM) system. The framework provides load testing, stress testing, benchmark analysis, and performance validation capabilities.

## Overview

The performance testing framework consists of:

1. **Load Testing Suite** - Simulates realistic user loads and measures system performance
2. **Benchmark Framework** - Compares CAM performance against baseline metrics and competitors
3. **Stress Testing** - Validates system behavior under extreme conditions
4. **Performance Profiling** - Detailed analysis of system resource utilization
5. **Scalability Testing** - Validates horizontal and vertical scaling capabilities
6. **Endurance Testing** - Long-running tests to identify memory leaks and degradation

## Quick Start

### Prerequisites

```bash
# Install Node.js dependencies
npm install

# Install performance testing tools
npm install -g k6 artillery clinic

# Install Python dependencies for analysis
pip install -r requirements.txt
```

### Running Load Tests

```bash
# Basic load test
npm run test:load:basic

# Stress test
npm run test:load:stress

# Full benchmark suite
npm run test:benchmark:full

# Custom load test
./scripts/run-load-test.sh --scenario=arbitration --users=100 --duration=300
```

## Directory Structure

```
performance/
├── README.md                    # This file
├── requirements.txt             # Python dependencies
├── package.json                 # Node.js test dependencies
├── config/                      # Test configurations
│   ├── load-test-configs.yaml   # Load test scenarios
│   ├── benchmark-configs.yaml   # Benchmark definitions
│   └── stress-test-configs.yaml # Stress test parameters
├── scripts/                     # Test execution scripts
│   ├── run-load-test.sh         # Load test runner
│   ├── run-benchmark.sh         # Benchmark runner
│   ├── run-stress-test.sh       # Stress test runner
│   └── generate-report.sh       # Report generation
├── k6/                          # K6 load testing scripts
│   ├── load-tests/              # Load test scenarios
│   ├── stress-tests/            # Stress test scenarios
│   └── utils/                   # Common K6 utilities
├── artillery/                   # Artillery test configurations
│   ├── scenarios/               # Artillery test scenarios
│   └── plugins/                 # Custom Artillery plugins
├── benchmarks/                  # Benchmark test suites
│   ├── arbitration-performance/ # Arbitration engine benchmarks
│   ├── agent-collaboration/     # Multi-agent collaboration benchmarks
│   ├── provider-comparison/     # Provider performance comparison
│   └── cost-optimization/       # Cost efficiency benchmarks
├── profiling/                   # Performance profiling tools
│   ├── memory-analysis/         # Memory usage analysis
│   ├── cpu-profiling/          # CPU performance profiling
│   └── network-analysis/        # Network I/O analysis
├── utils/                       # Utility libraries
│   ├── metrics-collector.js     # Performance metrics collection
│   ├── report-generator.js      # Test report generation
│   ├── data-analyzer.py         # Statistical analysis tools
│   └── visualization.py         # Performance data visualization
├── fixtures/                    # Test data and scenarios
│   ├── test-data/              # Sample test data
│   ├── scenarios/              # Test scenario definitions
│   └── baselines/              # Performance baselines
└── results/                     # Test results (gitignored)
    ├── load-tests/             # Load test results
    ├── benchmarks/             # Benchmark results
    ├── stress-tests/           # Stress test results
    └── reports/                # Generated reports
```

## Test Scenarios

### Load Testing Scenarios

1. **Basic Load Test**
   - 50 concurrent users
   - 5-minute duration
   - Standard arbitration requests

2. **Heavy Load Test**
   - 200 concurrent users
   - 15-minute duration
   - Mixed request types

3. **Peak Load Test**
   - 500 concurrent users
   - 30-minute duration
   - Enterprise feature usage

4. **Spike Test**
   - Sudden traffic spikes
   - Variable user load
   - Resilience validation

### Benchmark Categories

1. **Arbitration Performance**
   - Decision latency
   - Provider selection accuracy
   - Cost optimization effectiveness

2. **Agent Collaboration**
   - Multi-agent coordination efficiency
   - Communication overhead
   - Task completion rates

3. **Provider Integration**
   - API response times
   - Error handling efficiency
   - Failover performance

4. **Cost Optimization**
   - Token usage efficiency
   - Cost reduction metrics
   - ROI calculations

### Stress Testing Scenarios

1. **High Concurrency**
   - 1000+ concurrent users
   - Resource exhaustion testing
   - Graceful degradation validation

2. **Memory Stress**
   - Large payload processing
   - Memory leak detection
   - Garbage collection impact

3. **Network Stress**
   - High latency simulation
   - Network partition testing
   - Connection pool exhaustion

## Performance Metrics

### Primary Metrics

- **Latency**: P50, P95, P99 response times
- **Throughput**: Requests per second (RPS)
- **Error Rate**: Percentage of failed requests
- **Availability**: System uptime percentage

### System Metrics

- **CPU Utilization**: Average and peak CPU usage
- **Memory Usage**: Heap and non-heap memory consumption
- **Network I/O**: Bytes in/out per second
- **Disk I/O**: Read/write operations per second

### CAM-Specific Metrics

- **Arbitration Decision Time**: Time to select optimal provider
- **Provider Switch Rate**: Frequency of provider changes
- **Cost Optimization Rate**: Percentage cost reduction achieved
- **Consensus Time**: Multi-agent consensus duration

## Benchmark Standards

### Performance Targets

| Tier | Max Latency (P95) | Min Throughput | Max Error Rate |
|------|------------------|----------------|----------------|
| Community | 200ms | 100 RPS | 0.1% |
| Professional | 100ms | 500 RPS | 0.05% |
| Enterprise | 50ms | 2000 RPS | 0.01% |

### Comparison Baselines

- **Direct Provider Access**: Raw API performance
- **Basic Load Balancer**: Simple round-robin distribution
- **Competitive Solutions**: Industry standard alternatives

## Running Tests

### Load Testing

```bash
# Run specific load test scenario
npm run test:load -- --scenario=basic

# Run with custom parameters
npm run test:load -- --scenario=custom --users=100 --duration=600

# Run all load test scenarios
npm run test:load:all
```

### Benchmarking

```bash
# Run arbitration performance benchmark
npm run test:benchmark -- --category=arbitration

# Run cost optimization benchmark
npm run test:benchmark -- --category=cost-optimization

# Run full benchmark suite
npm run test:benchmark:full
```

### Stress Testing

```bash
# Run memory stress test
npm run test:stress -- --type=memory

# Run concurrency stress test
npm run test:stress -- --type=concurrency

# Run all stress tests
npm run test:stress:all
```

## Result Analysis

### Automated Analysis

The framework provides automated analysis tools:

- **Statistical Analysis**: Mean, median, percentiles, standard deviation
- **Trend Analysis**: Performance trends over time
- **Regression Detection**: Automatic performance regression alerts
- **Comparison Reports**: Side-by-side performance comparisons

### Visualization

Performance data is visualized using:

- **Grafana Dashboards**: Real-time performance monitoring
- **Custom Charts**: Test result visualizations
- **Trend Graphs**: Historical performance trends
- **Heatmaps**: Load distribution analysis

### Reporting

Generated reports include:

- **Executive Summary**: High-level performance overview
- **Detailed Analysis**: In-depth technical analysis
- **Benchmark Comparison**: Performance vs. competitors
- **Recommendations**: Performance optimization suggestions

## Integration with CI/CD

### Automated Testing

```yaml
# GitHub Actions example
- name: Run Performance Tests
  run: |
    npm run test:load:basic
    npm run test:benchmark:quick
    
- name: Performance Regression Check
  run: |
    npm run test:regression-check
```

### Performance Gates

- **Latency Gate**: Fail if P95 latency exceeds threshold
- **Throughput Gate**: Fail if RPS drops below minimum
- **Error Rate Gate**: Fail if error rate exceeds maximum
- **Resource Gate**: Fail if resource usage exceeds limits

## Troubleshooting

### Common Issues

1. **High Latency**
   - Check network connectivity
   - Verify database performance
   - Review provider response times

2. **Low Throughput**
   - Increase connection pool size
   - Optimize database queries
   - Scale infrastructure resources

3. **Memory Leaks**
   - Use profiling tools
   - Check for unclosed connections
   - Review caching strategies

### Debug Tools

- **K6 Debug Mode**: Detailed execution logs
- **Artillery Debug**: Request/response debugging
- **Node.js Profiling**: Memory and CPU profiling
- **Distributed Tracing**: Request flow analysis

## Contributing

### Adding New Tests

1. Create test scenario configuration
2. Implement test script (K6 or Artillery)
3. Add analysis and reporting
4. Update documentation

### Benchmark Submissions

1. Follow benchmark methodology
2. Include reproducible test setup
3. Provide statistical analysis
4. Submit for peer review

## License

This performance testing framework is part of the Complete Arbitration Mesh project and is subject to the same license terms.
