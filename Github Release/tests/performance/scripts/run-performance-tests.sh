#!/bin/bash
# CAM Performance Test Runner - Cross-platform bash version
# Simplified version of the PowerShell script for Linux/macOS compatibility

set -e

# Default configuration
TEST_TYPE="load"
ENVIRONMENT="dev"
DURATION=10
CONCURRENT=10
BASE_URL="http://localhost:3000"
API_TOKEN=""
REPORT_FORMAT="both"
BASELINE=""
SKIP_SYSTEM_CHECK=false
ENABLE_PROFILING=false

# Script directory and paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$PROJECT_ROOT/results"
LOGS_DIR="$PROJECT_ROOT/logs"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create required directories
mkdir -p "$RESULTS_DIR" "$LOGS_DIR"

# Logging function
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local log_file="$LOGS_DIR/performance-tests-$TIMESTAMP.log"
    
    case "$level" in
        "INFO") echo -e "${BLUE}[$timestamp] [INFO]${NC} $message" ;;
        "WARN") echo -e "${YELLOW}[$timestamp] [WARN]${NC} $message" ;;
        "ERROR") echo -e "${RED}[$timestamp] [ERROR]${NC} $message" ;;
        "SUCCESS") echo -e "${GREEN}[$timestamp] [SUCCESS]${NC} $message" ;;
    esac
    
    echo "[$timestamp] [$level] $message" >> "$log_file"
}

# Help function
show_help() {
    cat << EOF
CAM Performance Test Runner

Usage: $0 [OPTIONS]

Options:
    -t, --test-type TYPE        Type of test: load, stress, benchmark, all (default: load)
    -e, --environment ENV       Environment: dev, staging, prod (default: dev)
    -d, --duration MINUTES      Test duration in minutes (default: 10)
    -c, --concurrent USERS      Number of concurrent users (default: 10)
    -u, --base-url URL          CAM system base URL (default: http://localhost:3000)
    -a, --api-token TOKEN       API token for authentication
    -r, --report-format FORMAT  Report format: json, html, both (default: both)
    -b, --baseline FILE         Baseline results file for comparison
    -s, --skip-system-check     Skip system requirements check
    -p, --enable-profiling      Enable performance profiling
    -h, --help                  Show this help message

Examples:
    $0 -t load -e staging -d 15 -c 50
    $0 -t benchmark -u https://api.cam-system.com -a \$CAM_API_TOKEN
EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--test-type)
            TEST_TYPE="$2"
            shift 2
            ;;
        -e|--environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        -d|--duration)
            DURATION="$2"
            shift 2
            ;;
        -c|--concurrent)
            CONCURRENT="$2"
            shift 2
            ;;
        -u|--base-url)
            BASE_URL="$2"
            shift 2
            ;;
        -a|--api-token)
            API_TOKEN="$2"
            shift 2
            ;;
        -r|--report-format)
            REPORT_FORMAT="$2"
            shift 2
            ;;
        -b|--baseline)
            BASELINE="$2"
            shift 2
            ;;
        -s|--skip-system-check)
            SKIP_SYSTEM_CHECK=true
            shift
            ;;
        -p|--enable-profiling)
            ENABLE_PROFILING=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# System requirements check
check_system_requirements() {
    log "INFO" "Checking system requirements..."
    
    local missing=()
    
    # Check required tools
    for tool in k6 node python npm; do
        if command -v "$tool" &> /dev/null; then
            local version=$($tool --version 2>/dev/null || echo "unknown")
            log "SUCCESS" "✓ $tool is installed: $version"
        else
            missing+=("$tool")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        log "ERROR" "Missing required tools: ${missing[*]}"
        log "ERROR" "Please install missing tools and try again."
        return 1
    fi
    
    # Install Node.js dependencies
    if [ -f "$PROJECT_ROOT/package.json" ]; then
        log "INFO" "Installing Node.js dependencies..."
        cd "$PROJECT_ROOT"
        if npm install &> /dev/null; then
            log "SUCCESS" "✓ Node.js dependencies installed successfully"
        else
            log "WARN" "Failed to install Node.js dependencies"
        fi
    fi
    
    # Install Python dependencies
    if [ -f "$PROJECT_ROOT/requirements.txt" ]; then
        log "INFO" "Installing Python dependencies..."
        if python -m pip install -r "$PROJECT_ROOT/requirements.txt" &> /dev/null; then
            log "SUCCESS" "✓ Python dependencies installed successfully"
        else
            log "WARN" "Failed to install Python dependencies"
        fi
    fi
    
    return 0
}

# CAM system health check
check_cam_health() {
    local url="$1"
    local token="$2"
    
    log "INFO" "Checking CAM system health at $url..."
    
    local curl_cmd="curl -s -f --max-time 10"
    if [ -n "$token" ]; then
        curl_cmd="$curl_cmd -H \"Authorization: Bearer $token\""
    fi
    curl_cmd="$curl_cmd \"$url/api/v1/status\""
    
    if response=$(eval "$curl_cmd" 2>/dev/null); then
        if echo "$response" | grep -q '"status":"healthy"'; then
            log "SUCCESS" "✓ CAM system is healthy"
            return 0
        else
            log "WARN" "CAM system status: $(echo "$response" | grep -o '"status":"[^"]*"' || echo 'unknown')"
            return 1
        fi
    else
        log "ERROR" "CAM system health check failed"
        return 1
    fi
}

# Run K6 load tests
run_load_tests() {
    local url="$1"
    local token="$2"
    local duration="$3"
    local concurrent="$4"
    
    log "INFO" "Running K6 load tests..."
    
    local k6_script="$PROJECT_ROOT/k6/load-tests/cam-load-test.js"
    local results_file="$RESULTS_DIR/load-test-results-$TIMESTAMP.json"
    
    export CAM_BASE_URL="$url"
    export CAM_API_TOKEN="$token"
    export CAM_DURATION="$duration"
    export CAM_CONCURRENT_USERS="$concurrent"
    
    if [ -f "$k6_script" ]; then
        log "INFO" "Executing K6 load test..."
        if k6 run --out "json=$results_file" "$k6_script"; then
            log "SUCCESS" "✓ Load tests completed successfully"
            echo "$results_file"
        else
            log "ERROR" "Load tests failed"
            return 1
        fi
    else
        log "ERROR" "K6 script not found: $k6_script"
        return 1
    fi
}

# Run K6 stress tests
run_stress_tests() {
    local url="$1"
    local token="$2"
    local duration="$3"
    
    log "INFO" "Running K6 stress tests..."
    
    local k6_script="$PROJECT_ROOT/k6/stress-tests/cam-stress-test.js"
    local results_file="$RESULTS_DIR/stress-test-results-$TIMESTAMP.json"
    
    export CAM_BASE_URL="$url"
    export CAM_API_TOKEN="$token"
    export CAM_STRESS_DURATION="$duration"
    
    if [ -f "$k6_script" ]; then
        log "INFO" "Executing K6 stress test..."
        if k6 run --out "json=$results_file" "$k6_script"; then
            log "SUCCESS" "✓ Stress tests completed successfully"
            echo "$results_file"
        else
            log "ERROR" "Stress tests failed"
            return 1
        fi
    else
        log "ERROR" "K6 script not found: $k6_script"
        return 1
    fi
}

# Run benchmarks
run_benchmarks() {
    local url="$1"
    local token="$2"
    
    log "INFO" "Running performance benchmarks..."
    
    local benchmark_scripts=(
        "arbitration-performance.js"
        "agent-collaboration.js"
        "cost-optimization.js"
    )
    
    local results=()
    
    export CAM_BASE_URL="$url"
    export CAM_API_TOKEN="$token"
    
    for script in "${benchmark_scripts[@]}"; do
        local script_path="$PROJECT_ROOT/k6/benchmarks/$script"
        local results_file="$RESULTS_DIR/benchmark-${script%.js}-$TIMESTAMP.json"
        
        if [ -f "$script_path" ]; then
            log "INFO" "Running benchmark: $script"
            if k6 run --out "json=$results_file" "$script_path"; then
                log "SUCCESS" "✓ Benchmark $script completed successfully"
                results+=("$results_file")
            else
                log "WARN" "Benchmark $script failed"
            fi
        else
            log "WARN" "Benchmark script not found: $script_path"
        fi
    done
    
    printf '%s\n' "${results[@]}"
}

# Generate performance analysis
run_analysis() {
    local results_files=("$@")
    
    if [ ${#results_files[@]} -eq 0 ]; then
        log "WARN" "No results files provided for analysis"
        return
    fi
    
    log "INFO" "Generating performance analysis..."
    
    local analyzer_script="$PROJECT_ROOT/analysis/performance-analyzer.py"
    local output_dir="$RESULTS_DIR/analysis-$TIMESTAMP"
    
    if [ -f "$analyzer_script" ]; then
        for results_file in "${results_files[@]}"; do
            if [ -f "$results_file" ]; then
                local args=(
                    "--results" "$results_file"
                    "--output-dir" "$output_dir"
                    "--report" "$output_dir/analysis-report.json"
                )
                
                if [ -n "$BASELINE" ] && [ -f "$BASELINE" ]; then
                    args+=("--baseline" "$BASELINE")
                fi
                
                log "INFO" "Analyzing: $(basename "$results_file")"
                if python "$analyzer_script" "${args[@]}"; then
                    log "SUCCESS" "✓ Analysis completed for $(basename "$results_file")"
                else
                    log "WARN" "Analysis failed for $(basename "$results_file")"
                fi
            fi
        done
    else
        log "WARN" "Performance analyzer script not found: $analyzer_script"
    fi
}

# Main execution
main() {
    log "INFO" "=== CAM Performance Test Runner Started ==="
    log "INFO" "Test Type: $TEST_TYPE | Environment: $ENVIRONMENT | Duration: $DURATION min | Concurrent: $CONCURRENT"
    
    # System requirements check
    if [ "$SKIP_SYSTEM_CHECK" != "true" ]; then
        if ! check_system_requirements; then
            log "ERROR" "System requirements check failed. Exiting."
            exit 1
        fi
    fi
    
    # CAM system health check
    if ! check_cam_health "$BASE_URL" "$API_TOKEN"; then
        log "ERROR" "CAM system health check failed. Please verify the system is running."
        if [ "$ENVIRONMENT" != "dev" ]; then
            exit 1
        else
            log "WARN" "Continuing in development mode..."
        fi
    fi
    
    local all_results=()
    
    # Execute tests based on type
    case "$TEST_TYPE" in
        "load")
            log "INFO" "Executing load tests..."
            if result=$(run_load_tests "$BASE_URL" "$API_TOKEN" "$DURATION" "$CONCURRENT"); then
                all_results+=("$result")
            fi
            ;;
        "stress")
            log "INFO" "Executing stress tests..."
            if result=$(run_stress_tests "$BASE_URL" "$API_TOKEN" "$DURATION"); then
                all_results+=("$result")
            fi
            ;;
        "benchmark")
            log "INFO" "Executing benchmarks..."
            readarray -t results < <(run_benchmarks "$BASE_URL" "$API_TOKEN")
            all_results+=("${results[@]}")
            ;;
        "all")
            log "INFO" "Executing comprehensive test suite..."
            
            # Load tests
            if result=$(run_load_tests "$BASE_URL" "$API_TOKEN" "$DURATION" "$CONCURRENT"); then
                all_results+=("$result")
            fi
            
            # Stress tests
            if result=$(run_stress_tests "$BASE_URL" "$API_TOKEN" "$DURATION"); then
                all_results+=("$result")
            fi
            
            # Benchmarks
            readarray -t results < <(run_benchmarks "$BASE_URL" "$API_TOKEN")
            all_results+=("${results[@]}")
            ;;
        *)
            log "ERROR" "Unknown test type: $TEST_TYPE"
            exit 1
            ;;
    esac
    
    # Generate analysis and reports
    if [ ${#all_results[@]} -gt 0 ]; then
        log "INFO" "Generating performance analysis and reports..."
        run_analysis "${all_results[@]}"
        
        # Summary
        log "SUCCESS" "=== Performance Test Summary ==="
        log "INFO" "Total test suites executed: ${#all_results[@]}"
        log "INFO" "Results directory: $RESULTS_DIR"
        log "INFO" "Logs directory: $LOGS_DIR"
        
        log "SUCCESS" "✓ Performance testing completed successfully!"
        exit 0
    else
        log "ERROR" "No test results generated. Check logs for errors."
        exit 1
    fi
}

# Execute main function
main "$@"
