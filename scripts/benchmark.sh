#!/bin/bash

# Complete Arbitration Mesh - Performance Benchmarking Script
# Comprehensive load testing with k6, Apache Bench, and custom metrics

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="$PROJECT_ROOT/benchmark-results/$TIMESTAMP"
LOG_FILE="$RESULTS_DIR/benchmark.log"

# Test configuration
TARGET_URL="${TARGET_URL:-http://localhost:3000}"
TEST_DURATION="${TEST_DURATION:-300s}"
RAMP_UP_DURATION="${RAMP_UP_DURATION:-30s}"
MAX_VUS="${MAX_VUS:-100}"
CONCURRENT_USERS="${CONCURRENT_USERS:-50}"
REQUESTS_PER_SECOND="${REQUESTS_PER_SECOND:-100}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$LOG_FILE"
}

info() { log "INFO" "$@"; }
warn() { log "WARN" "${YELLOW}$*${NC}"; }
error() { log "ERROR" "${RED}$*${NC}"; }
success() { log "SUCCESS" "${GREEN}$*${NC}"; }

# Setup function
setup() {
    info "Setting up benchmark environment..."
    
    # Create results directory
    mkdir -p "$RESULTS_DIR"
    mkdir -p "$RESULTS_DIR/reports"
    mkdir -p "$RESULTS_DIR/metrics"
    mkdir -p "$RESULTS_DIR/logs"
    
    # Check dependencies
    check_dependencies
    
    # Validate target
    validate_target
    
    # Generate test data
    generate_test_data
    
    success "Setup completed successfully"
}

# Check required dependencies
check_dependencies() {
    info "Checking dependencies..."
    
    local deps=("k6" "ab" "curl" "jq")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            error "Required dependency not found: $dep"
            exit 1
        fi
    done
    
    success "All dependencies are available"
}

# Validate target URL
validate_target() {
    info "Validating target URL: $TARGET_URL"
    
    if ! curl -sf "$TARGET_URL/health" > /dev/null; then
        error "Target URL is not responding: $TARGET_URL"
        exit 1
    fi
    
    success "Target URL is responding"
}

# Generate test data
generate_test_data() {
    info "Generating test data..."
    
    cat > "$RESULTS_DIR/test-cases.json" << 'EOF'
{
  "arbitrationCases": [
    {
      "id": "case-001",
      "type": "contract_dispute",
      "priority": "high",
      "evidence": [
        {"type": "document", "hash": "0x1234567890abcdef"},
        {"type": "witness", "id": "witness-001"}
      ],
      "parties": ["party-a", "party-b"],
      "deadline": "2024-12-31T23:59:59Z"
    },
    {
      "id": "case-002",
      "type": "payment_dispute",
      "priority": "medium",
      "evidence": [
        {"type": "transaction", "hash": "0xabcdef1234567890"}
      ],
      "parties": ["party-c", "party-d"],
      "deadline": "2024-12-30T23:59:59Z"
    }
  ],
  "consensusRequests": [
    {
      "id": "consensus-001",
      "type": "leader_election",
      "nodes": ["node-1", "node-2", "node-3"],
      "timeout": 30000
    },
    {
      "id": "consensus-002",
      "type": "state_agreement",
      "data": {"key": "value", "timestamp": "2024-01-01T00:00:00Z"},
      "quorum": 3
    }
  ]
}
EOF
    
    success "Test data generated"
}

# K6 Load Testing
run_k6_tests() {
    info "Running K6 load tests..."
    
    # Create K6 test script
    cat > "$RESULTS_DIR/k6-test.js" << EOF
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('error_rate');
const responseTime = new Trend('response_time');
const requestCount = new Counter('request_count');

// Test configuration
export const options = {
  stages: [
    { duration: '${RAMP_UP_DURATION}', target: ${MAX_VUS} },
    { duration: '${TEST_DURATION}', target: ${MAX_VUS} },
    { duration: '30s', target: 0 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'],
    http_req_failed: ['rate<0.1'],
    error_rate: ['rate<0.05'],
  },
};

// Test data
const testCases = JSON.parse(open('./test-cases.json'));

export default function () {
  // Health check
  let response = http.get('${TARGET_URL}/health');
  check(response, {
    'health check status is 200': (r) => r.status === 200,
  });
  requestCount.add(1);
  responseTime.add(response.timings.duration);
  errorRate.add(response.status !== 200);
  
  sleep(0.1);
  
  // Create arbitration case
  const arbitrationPayload = JSON.stringify(testCases.arbitrationCases[0]);
  response = http.post('${TARGET_URL}/api/arbitration/cases', arbitrationPayload, {
    headers: { 'Content-Type': 'application/json' },
  });
  check(response, {
    'create arbitration status is 201': (r) => r.status === 201,
    'response has case id': (r) => JSON.parse(r.body).id !== undefined,
  });
  requestCount.add(1);
  responseTime.add(response.timings.duration);
  errorRate.add(response.status !== 201);
  
  sleep(0.1);
  
  // List arbitration cases
  response = http.get('${TARGET_URL}/api/arbitration/cases');
  check(response, {
    'list cases status is 200': (r) => r.status === 200,
    'response is array': (r) => Array.isArray(JSON.parse(r.body)),
  });
  requestCount.add(1);
  responseTime.add(response.timings.duration);
  errorRate.add(response.status !== 200);
  
  sleep(0.1);
  
  // Consensus request
  const consensusPayload = JSON.stringify(testCases.consensusRequests[0]);
  response = http.post('${TARGET_URL}/api/consensus/request', consensusPayload, {
    headers: { 'Content-Type': 'application/json' },
  });
  check(response, {
    'consensus request status is 200 or 202': (r) => [200, 202].includes(r.status),
  });
  requestCount.add(1);
  responseTime.add(response.timings.duration);
  errorRate.add(![200, 202].includes(response.status));
  
  sleep(0.5);
}

export function handleSummary(data) {
  return {
    'k6-summary.json': JSON.stringify(data, null, 2),
    'k6-summary.html': htmlReport(data),
  };
}

function htmlReport(data) {
  return \`
<!DOCTYPE html>
<html>
<head>
  <title>K6 Load Test Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    .metric { margin: 10px 0; padding: 10px; border: 1px solid #ddd; }
    .passed { background-color: #d4edda; }
    .failed { background-color: #f8d7da; }
  </style>
</head>
<body>
  <h1>K6 Load Test Report</h1>
  <h2>Test Summary</h2>
  <div class="metric">
    <strong>Total Requests:</strong> \${data.metrics.http_reqs.count}
  </div>
  <div class="metric">
    <strong>Failed Requests:</strong> \${data.metrics.http_req_failed.count} (\${(data.metrics.http_req_failed.rate * 100).toFixed(2)}%)
  </div>
  <div class="metric">
    <strong>Average Response Time:</strong> \${data.metrics.http_req_duration.avg.toFixed(2)}ms
  </div>
  <div class="metric">
    <strong>95th Percentile:</strong> \${data.metrics.http_req_duration['p(95)'].toFixed(2)}ms
  </div>
  <div class="metric">
    <strong>Test Duration:</strong> \${data.state.testRunDurationMs}ms
  </div>
</body>
</html>
  \`;
}
EOF
    
    # Run K6 test
    cd "$RESULTS_DIR"
    k6 run --out json=k6-results.json k6-test.js
    
    success "K6 load tests completed"
}

# Apache Bench Testing
run_apache_bench() {
    info "Running Apache Bench tests..."
    
    # Test endpoints
    local endpoints=(
        "/health"
        "/ready"
        "/api/arbitration/cases"
        "/api/consensus/status"
        "/metrics"
    )
    
    for endpoint in "${endpoints[@]}"; do
        info "Testing endpoint: $endpoint"
        
        ab -n 1000 -c "$CONCURRENT_USERS" -g "$RESULTS_DIR/ab-${endpoint//\//_}.tsv" \
           -e "$RESULTS_DIR/ab-${endpoint//\//_}.csv" \
           "${TARGET_URL}${endpoint}" > "$RESULTS_DIR/ab-${endpoint//\//_}.txt" 2>&1
    done
    
    success "Apache Bench tests completed"
}

# Stress Testing
run_stress_tests() {
    info "Running stress tests..."
    
    # High load test
    info "Running high load test (2x normal capacity)..."
    local high_load_vus=$((MAX_VUS * 2))
    
    cat > "$RESULTS_DIR/stress-test.js" << EOF
import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '60s', target: ${high_load_vus} },
    { duration: '120s', target: ${high_load_vus} },
    { duration: '60s', target: 0 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<2000'],
    http_req_failed: ['rate<0.2'],
  },
};

export default function () {
  const response = http.get('${TARGET_URL}/health');
  check(response, {
    'status is 200': (r) => r.status === 200,
  });
  sleep(0.1);
}
EOF
    
    cd "$RESULTS_DIR"
    k6 run --out json=stress-results.json stress-test.js
    
    success "Stress tests completed"
}

# Spike Testing
run_spike_tests() {
    info "Running spike tests..."
    
    cat > "$RESULTS_DIR/spike-test.js" << EOF
import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '30s', target: 10 },
    { duration: '10s', target: ${MAX_VUS} },
    { duration: '30s', target: 10 },
    { duration: '10s', target: $((MAX_VUS * 3)) },
    { duration: '30s', target: 10 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<1000'],
    http_req_failed: ['rate<0.15'],
  },
};

export default function () {
  const response = http.get('${TARGET_URL}/health');
  check(response, {
    'status is 200': (r) => r.status === 200,
  });
  sleep(0.1);
}
EOF
    
    cd "$RESULTS_DIR"
    k6 run --out json=spike-results.json spike-test.js
    
    success "Spike tests completed"
}

# Database Performance Testing
run_database_tests() {
    info "Running database performance tests..."
    
    cat > "$RESULTS_DIR/db-test.js" << EOF
import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  vus: 20,
  duration: '120s',
  thresholds: {
    http_req_duration: ['p(95)<1000'],
    http_req_failed: ['rate<0.1'],
  },
};

export default function () {
  // Create multiple arbitration cases to test database writes
  for (let i = 0; i < 5; i++) {
    const payload = JSON.stringify({
      type: 'performance_test',
      priority: 'low',
      evidence: [{ type: 'synthetic', data: \`test-data-\${i}\` }],
      parties: [\`party-\${i}-a\`, \`party-\${i}-b\`],
    });
    
    const response = http.post('${TARGET_URL}/api/arbitration/cases', payload, {
      headers: { 'Content-Type': 'application/json' },
    });
    
    check(response, {
      'create case status is 201': (r) => r.status === 201,
    });
    
    sleep(0.1);
  }
  
  // Query cases to test database reads
  const response = http.get('${TARGET_URL}/api/arbitration/cases?limit=100');
  check(response, {
    'list cases status is 200': (r) => r.status === 200,
  });
  
  sleep(1);
}
EOF
    
    cd "$RESULTS_DIR"
    k6 run --out json=db-results.json db-test.js
    
    success "Database performance tests completed"
}

# Memory and Resource Testing
run_resource_tests() {
    info "Running resource utilization tests..."
    
    # Monitor system resources during testing
    (
        echo "timestamp,cpu_percent,memory_mb,disk_io,network_io" > "$RESULTS_DIR/resource-usage.csv"
        while true; do
            local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
            local cpu=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//')
            local memory=$(free -m | awk 'NR==2{printf "%.1f", $3}')
            local disk_io=$(iostat -d 1 1 | tail -n +4 | awk '{sum+=$4} END {print sum}')
            local network_io=$(cat /proc/net/dev | grep eth0 | awk '{print $2+$10}')
            
            echo "$timestamp,$cpu,$memory,$disk_io,$network_io" >> "$RESULTS_DIR/resource-usage.csv"
            sleep 5
        done
    ) &
    local monitor_pid=$!
    
    # Run intensive test
    cat > "$RESULTS_DIR/resource-test.js" << EOF
import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  vus: ${MAX_VUS},
  duration: '300s',
};

export default function () {
  // Simulate heavy workload
  const largePayload = JSON.stringify({
    type: 'resource_test',
    data: 'x'.repeat(10000), // 10KB payload
    timestamp: new Date().toISOString(),
  });
  
  const response = http.post('${TARGET_URL}/api/arbitration/cases', largePayload, {
    headers: { 'Content-Type': 'application/json' },
  });
  
  check(response, {
    'status is 201 or 400': (r) => [201, 400].includes(r.status),
  });
  
  sleep(0.5);
}
EOF
    
    cd "$RESULTS_DIR"
    k6 run --out json=resource-results.json resource-test.js
    
    # Stop resource monitoring
    kill $monitor_pid 2>/dev/null || true
    
    success "Resource utilization tests completed"
}

# Generate comprehensive report
generate_report() {
    info "Generating performance report..."
    
    cat > "$RESULTS_DIR/performance-report.html" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CAM Performance Test Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
        h1, h2, h3 {
            color: #333;
            border-bottom: 2px solid #4CAF50;
            padding-bottom: 10px;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .metric-card {
            background: #f9f9f9;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #4CAF50;
        }
        .metric-value {
            font-size: 2em;
            font-weight: bold;
            color: #2196F3;
        }
        .metric-label {
            color: #666;
            font-size: 0.9em;
        }
        .status-good { color: #4CAF50; }
        .status-warning { color: #FF9800; }
        .status-error { color: #F44336; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }
        th {
            background-color: #4CAF50;
            color: white;
        }
        tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        .chart-container {
            margin: 20px 0;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Complete Arbitration Mesh - Performance Test Report</h1>
        
        <div class="summary">
            <div class="metric-card">
                <div class="metric-value" id="total-requests">Loading...</div>
                <div class="metric-label">Total Requests</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" id="avg-response-time">Loading...</div>
                <div class="metric-label">Avg Response Time (ms)</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" id="error-rate">Loading...</div>
                <div class="metric-label">Error Rate (%)</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" id="throughput">Loading...</div>
                <div class="metric-label">Throughput (req/s)</div>
            </div>
        </div>
        
        <h2>Test Configuration</h2>
        <table>
            <tr><th>Parameter</th><th>Value</th></tr>
            <tr><td>Target URL</td><td>TARGET_URL_PLACEHOLDER</td></tr>
            <tr><td>Test Duration</td><td>TEST_DURATION_PLACEHOLDER</td></tr>
            <tr><td>Max Virtual Users</td><td>MAX_VUS_PLACEHOLDER</td></tr>
            <tr><td>Ramp-up Duration</td><td>RAMP_UP_DURATION_PLACEHOLDER</td></tr>
        </table>
        
        <h2>Test Results Summary</h2>
        <div id="test-results">
            <h3>Load Test Results</h3>
            <div id="load-test-results">Loading...</div>
            
            <h3>Stress Test Results</h3>
            <div id="stress-test-results">Loading...</div>
            
            <h3>Spike Test Results</h3>
            <div id="spike-test-results">Loading...</div>
        </div>
        
        <h2>Performance Metrics</h2>
        <table id="metrics-table">
            <thead>
                <tr>
                    <th>Metric</th>
                    <th>Value</th>
                    <th>Threshold</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>95th Percentile Response Time</td>
                    <td id="p95-response-time">Loading...</td>
                    <td>&lt; 500ms</td>
                    <td id="p95-status">Loading...</td>
                </tr>
                <tr>
                    <td>Error Rate</td>
                    <td id="error-rate-detail">Loading...</td>
                    <td>&lt; 1%</td>
                    <td id="error-rate-status">Loading...</td>
                </tr>
                <tr>
                    <td>Memory Usage</td>
                    <td id="memory-usage">Loading...</td>
                    <td>&lt; 2GB</td>
                    <td id="memory-status">Loading...</td>
                </tr>
            </tbody>
        </table>
        
        <h2>Recommendations</h2>
        <div id="recommendations">
            <ul>
                <li>Monitor response times under high load</li>
                <li>Consider horizontal scaling if error rates exceed 1%</li>
                <li>Optimize database queries for better performance</li>
                <li>Implement caching for frequently accessed data</li>
                <li>Set up alerting for performance degradation</li>
            </ul>
        </div>
        
        <h2>Raw Data</h2>
        <p>Detailed test results and raw data files are available in the benchmark results directory.</p>
        
        <div style="margin-top: 40px; text-align: center; color: #666;">
            <p>Report generated on: <span id="report-timestamp"></span></p>
        </div>
    </div>
    
    <script>
        // Set report timestamp
        document.getElementById('report-timestamp').textContent = new Date().toLocaleString();
        
        // Replace placeholders
        document.body.innerHTML = document.body.innerHTML
            .replace(/TARGET_URL_PLACEHOLDER/g, 'TARGET_URL_VALUE')
            .replace(/TEST_DURATION_PLACEHOLDER/g, 'TEST_DURATION_VALUE')
            .replace(/MAX_VUS_PLACEHOLDER/g, 'MAX_VUS_VALUE')
            .replace(/RAMP_UP_DURATION_PLACEHOLDER/g, 'RAMP_UP_DURATION_VALUE');
    </script>
</body>
</html>
EOF
    
    # Replace placeholders with actual values
    sed -i "s/TARGET_URL_VALUE/$TARGET_URL/g" "$RESULTS_DIR/performance-report.html"
    sed -i "s/TEST_DURATION_VALUE/$TEST_DURATION/g" "$RESULTS_DIR/performance-report.html"
    sed -i "s/MAX_VUS_VALUE/$MAX_VUS/g" "$RESULTS_DIR/performance-report.html"
    sed -i "s/RAMP_UP_DURATION_VALUE/$RAMP_UP_DURATION/g" "$RESULTS_DIR/performance-report.html"
    
    success "Performance report generated: $RESULTS_DIR/performance-report.html"
}

# Cleanup function
cleanup() {
    info "Cleaning up temporary files..."
    
    # Kill any remaining background processes
    jobs -p | xargs -r kill 2>/dev/null || true
    
    # Compress results
    cd "$(dirname "$RESULTS_DIR")"
    tar -czf "benchmark-results-$TIMESTAMP.tar.gz" "$(basename "$RESULTS_DIR")"
    
    success "Cleanup completed"
}

# Main execution
main() {
    info "Starting Complete Arbitration Mesh performance benchmarking..."
    info "Results will be saved to: $RESULTS_DIR"
    
    # Setup
    setup
    
    # Run tests
    run_k6_tests
    run_apache_bench
    run_stress_tests
    run_spike_tests
    run_database_tests
    run_resource_tests
    
    # Generate report
    generate_report
    
    # Cleanup
    cleanup
    
    success "Performance benchmarking completed successfully!"
    info "Results available at: $RESULTS_DIR"
    info "Open the performance report: file://$RESULTS_DIR/performance-report.html"
}

# Handle script termination
trap cleanup EXIT

# Run main function
main "$@"
