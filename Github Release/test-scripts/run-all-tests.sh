#!/bin/bash

# CAM-OS Kernel Test Suite
# This script tests all 15 cognitive syscalls and kernel functionality

set -e

echo "🚀 CAM-OS Kernel Test Suite Starting..."
echo "=================================="

# Configuration
CAM_KERNEL_ADDR=${CAM_KERNEL_ADDR:-"localhost:8080"}
RESULTS_DIR=${RESULTS_DIR:-"/app/results"}
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Create results directory
mkdir -p "$RESULTS_DIR"
TEST_LOG="$RESULTS_DIR/test_results_$TIMESTAMP.log"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$TEST_LOG"
}

# Test result tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Test function wrapper
run_test() {
    local test_name="$1"
    local test_command="$2"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    log "🧪 Running test: $test_name"
    
    if eval "$test_command" >> "$TEST_LOG" 2>&1; then
        log "✅ PASSED: $test_name"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    else
        log "❌ FAILED: $test_name"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
}

# Wait for kernel to be ready
wait_for_kernel() {
    log "⏳ Waiting for CAM-OS Kernel to be ready..."
    local retries=30
    while [ $retries -gt 0 ]; do
        if grpcurl -plaintext "$CAM_KERNEL_ADDR" grpc.health.v1.Health/Check > /dev/null 2>&1; then
            log "✅ Kernel is ready!"
            return 0
        fi
        sleep 2
        retries=$((retries - 1))
    done
    log "❌ Kernel failed to start within timeout"
    exit 1
}

# Test 1: Health Check Syscall
test_health_check() {
    grpcurl -plaintext -d '{"caller_id": "test-client", "detailed": true}' \
        "$CAM_KERNEL_ADDR" cam.syscall.SyscallService/HealthCheck
}

# Test 2: Context Write Syscall
test_context_write() {
    grpcurl -plaintext -d '{
        "namespace": "test-ns",
        "key": "test-key",
        "data": "SGVsbG8gQ0FNLU9TIQ==",
        "caller_id": "test-client",
        "metadata": {"test": "true", "timestamp": "'$(date -u +%s)'"}
    }' "$CAM_KERNEL_ADDR" cam.syscall.SyscallService/ContextWrite
}

# Test 3: Context Read Syscall
test_context_read() {
    grpcurl -plaintext -d '{
        "namespace": "test-ns",
        "key": "test-key",
        "caller_id": "test-client",
        "version": 0
    }' "$CAM_KERNEL_ADDR" cam.syscall.SyscallService/ContextRead
}

# Test 4: Arbitration Syscall
test_arbitration() {
    grpcurl -plaintext -d '{
        "task": {
            "id": "test-task-001",
            "description": "Test arbitration task",
            "requirements": ["cpu", "memory"],
            "metadata": {"priority": "high"},
            "priority": 100,
            "deadline": '$(date -d "+1 hour" +%s)',
            "type": "TASK_TYPE_ARBITRATION",
            "agent_id": "test-agent"
        },
        "policy_id": "default",
        "caller_id": "test-client"
    }' "$CAM_KERNEL_ADDR" cam.syscall.SyscallService/Arbitrate
}

# Test 5: Task Commit Syscall
test_task_commit() {
    grpcurl -plaintext -d '{
        "task": {
            "id": "test-task-002",
            "description": "Test commit task",
            "requirements": ["storage"],
            "priority": 50,
            "deadline": '$(date -d "+2 hours" +%s)',
            "type": "TASK_TYPE_COLLABORATION",
            "agent_id": "test-agent"
        },
        "agent_id": "test-agent",
        "caller_id": "test-client",
        "allow_rollback": true
    }' "$CAM_KERNEL_ADDR" cam.syscall.SyscallService/CommitTask
}

# Test 6: Policy Query Syscall
test_policy_query() {
    grpcurl -plaintext -d '{
        "policy_id": "access-control",
        "query": "allow user test-client to read namespace test-ns",
        "caller_id": "test-client",
        "context": {"user": "test-client", "resource": "test-ns"}
    }' "$CAM_KERNEL_ADDR" cam.syscall.SyscallService/QueryPolicy
}

# Test 7: Context Snapshot Syscall
test_context_snapshot() {
    grpcurl -plaintext -d '{
        "namespace": "test-ns",
        "caller_id": "test-client",
        "description": "Test snapshot for validation",
        "options": {
            "include_metadata": true,
            "compression_algorithm": "lz4"
        }
    }' "$CAM_KERNEL_ADDR" cam.syscall.SyscallService/ContextSnapshot
}

# Test 8: Agent Registration Syscall (Fork Expansion)
test_agent_register() {
    grpcurl -plaintext -d '{
        "agent_id": "test-agent-001",
        "agent_name": "Test Agent",
        "capabilities": ["data-processing", "analysis"],
        "metadata": {"version": "1.0.0", "type": "test"},
        "caller_id": "test-client",
        "spec": {
            "version": "1.0.0",
            "supported_task_types": ["TASK_TYPE_ANALYSIS"],
            "security_profile": {
                "required_permissions": ["read", "write"],
                "isolation_level": "process"
            }
        }
    }' "$CAM_KERNEL_ADDR" cam.syscall.SyscallService/AgentRegister
}

# Test 9: System Tuning Syscall (Fork Expansion)
test_system_tuning() {
    grpcurl -plaintext -d '{
        "caller_id": "test-client",
        "parameters": {"memory_gc_target": "75", "compression_enabled": "true"},
        "dry_run": true,
        "tuning_profile": "balanced"
    }' "$CAM_KERNEL_ADDR" cam.syscall.SyscallService/SystemTuning
}

# Test 10: Emit Metric Syscall
test_emit_metric() {
    grpcurl -plaintext -d '{
        "name": "test_metric",
        "value": 42.0,
        "type": "gauge",
        "labels": {"component": "test-client", "test": "true"},
        "timestamp": '$(date +%s000000000)',
        "caller_id": "test-client"
    }' "$CAM_KERNEL_ADDR" cam.syscall.SyscallService/EmitMetric
}

# Test 11: Emit Trace Syscall
test_emit_trace() {
    grpcurl -plaintext -d '{
        "trace_id": "test-trace-001",
        "span_id": "test-span-001",
        "operation_name": "test_operation",
        "start_time": '$(date +%s000000000)',
        "end_time": '$(($(date +%s) + 1))000000000',
        "tags": {"test": "true", "component": "test-client"},
        "caller_id": "test-client"
    }' "$CAM_KERNEL_ADDR" cam.syscall.SyscallService/EmitTrace
}

# Test 12: Explain Action Syscall
test_explain_action() {
    grpcurl -plaintext -d '{
        "trace_id": "test-trace-001",
        "caller_id": "test-client",
        "include_reasoning": true,
        "format": "EXPLANATION_FORMAT_NATURAL_LANGUAGE",
        "depth": "EXPLANATION_DEPTH_DETAILED"
    }' "$CAM_KERNEL_ADDR" cam.syscall.SyscallService/ExplainAction
}

# Performance Tests
test_performance() {
    log "🏃 Running performance tests..."
    
    # Test syscall latency
    local start_time=$(date +%s%N)
    test_health_check > /dev/null 2>&1
    local end_time=$(date +%s%N)
    local latency=$(( (end_time - start_time) / 1000000 )) # Convert to milliseconds
    
    log "📊 Health check latency: ${latency}ms"
    
    # Test should be under 10ms for health check
    if [ $latency -lt 10 ]; then
        log "✅ Performance test PASSED: latency under 10ms"
        return 0
    else
        log "❌ Performance test FAILED: latency ${latency}ms exceeds 10ms threshold"
        return 1
    fi
}

# Stress Test
test_stress() {
    log "💪 Running stress test..."
    
    local success_count=0
    local total_requests=100
    
    for i in $(seq 1 $total_requests); do
        if test_health_check > /dev/null 2>&1; then
            success_count=$((success_count + 1))
        fi
        if [ $((i % 20)) -eq 0 ]; then
            log "   Progress: $i/$total_requests requests completed"
        fi
    done
    
    local success_rate=$((success_count * 100 / total_requests))
    log "📊 Stress test results: $success_count/$total_requests successful (${success_rate}%)"
    
    if [ $success_rate -ge 95 ]; then
        log "✅ Stress test PASSED: ${success_rate}% success rate"
        return 0
    else
        log "❌ Stress test FAILED: ${success_rate}% success rate below 95% threshold"
        return 1
    fi
}

# Main test execution
main() {
    log "🚀 Starting CAM-OS Kernel Test Suite"
    log "Target: $CAM_KERNEL_ADDR"
    log "Results: $TEST_LOG"
    
    # Wait for kernel readiness
    wait_for_kernel
    
    # Core syscall tests
    log ""
    log "📋 Running Core Syscall Tests..."
    run_test "Health Check" "test_health_check"
    run_test "Context Write" "test_context_write"
    run_test "Context Read" "test_context_read"
    run_test "Context Snapshot" "test_context_snapshot"
    run_test "Task Arbitration" "test_arbitration"
    run_test "Task Commit" "test_task_commit"
    run_test "Policy Query" "test_policy_query"
    run_test "Explain Action" "test_explain_action"
    
    # Fork expansion syscall tests
    log ""
    log "🔀 Running Fork Expansion Syscall Tests..."
    run_test "Agent Registration" "test_agent_register"
    run_test "System Tuning" "test_system_tuning"
    
    # Observability syscall tests
    log ""
    log "👁️ Running Observability Syscall Tests..."
    run_test "Emit Metric" "test_emit_metric"
    run_test "Emit Trace" "test_emit_trace"
    
    # Performance and stress tests
    log ""
    log "⚡ Running Performance & Stress Tests..."
    run_test "Performance Test" "test_performance"
    run_test "Stress Test" "test_stress"
    
    # Generate test report
    log ""
    log "📊 TEST RESULTS SUMMARY"
    log "======================"
    log "Total Tests: $TOTAL_TESTS"
    log "Passed: $PASSED_TESTS"
    log "Failed: $FAILED_TESTS"
    log "Success Rate: $(( PASSED_TESTS * 100 / TOTAL_TESTS ))%"
    
    # Create JSON report
    cat > "$RESULTS_DIR/test_summary_$TIMESTAMP.json" << EOF
{
    "timestamp": "$TIMESTAMP",
    "kernel_address": "$CAM_KERNEL_ADDR",
    "total_tests": $TOTAL_TESTS,
    "passed_tests": $PASSED_TESTS,
    "failed_tests": $FAILED_TESTS,
    "success_rate": $(( PASSED_TESTS * 100 / TOTAL_TESTS )),
    "log_file": "$TEST_LOG"
}
EOF
    
    if [ $FAILED_TESTS -eq 0 ]; then
        log "🎉 All tests passed! CAM-OS Kernel is functioning correctly."
        exit 0
    else
        log "⚠️  Some tests failed. Check the log for details."
        exit 1
    fi
}

# Run main function
main "$@" 