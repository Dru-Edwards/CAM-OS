package integration

import (
	"context"
	"testing"
	"time"

	pb "github.com/cam-os/kernel/proto/generated"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestTimeoutExceeded verifies that syscalls properly timeout after SyscallTimeout (500ms)
// This is the integration test required by H-2
func TestTimeoutExceeded(t *testing.T) {
	// Skip test if no integration test server is available
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Connect to test server
	client, conn, err := setupTestClient()
	if err != nil {
		t.Fatalf("Failed to setup test client: %v", err)
	}
	defer conn.Close()

	testCases := []struct {
		name            string
		operation       func(context.Context) error
		expectedTimeout time.Duration
	}{
		{
			name: "Arbitrate timeout",
			operation: func(ctx context.Context) error {
				_, err := client.Arbitrate(ctx, &pb.ArbitrateRequest{
					Task: &pb.Task{
						Id:          "timeout-test",
						Description: "Test timeout behavior",
						Type:        pb.TaskType_TASK_TYPE_ARBITRATION,
					},
					CallerId: "timeout-test-client",
				})
				return err
			},
			expectedTimeout: 500 * time.Millisecond,
		},
		{
			name: "ContextRead timeout",
			operation: func(ctx context.Context) error {
				_, err := client.ContextRead(ctx, &pb.ContextReadRequest{
					Namespace: "test-timeout",
					Key:       "timeout-key",
					CallerId:  "timeout-test-client",
				})
				return err
			},
			expectedTimeout: 500 * time.Millisecond,
		},
		{
			name: "QueryPolicy timeout",
			operation: func(ctx context.Context) error {
				_, err := client.QueryPolicy(ctx, &pb.QueryPolicyRequest{
					PolicyId: "timeout-policy",
					Query:    "allow",
					CallerId: "timeout-test-client",
				})
				return err
			},
			expectedTimeout: 500 * time.Millisecond,
		},
		{
			name: "EmitTrace timeout (observability fast-path)",
			operation: func(ctx context.Context) error {
				_, err := client.EmitTrace(ctx, &pb.EmitTraceRequest{
					TraceId:   "timeout-trace",
					Operation: "timeout-test-op",
					CallerId:  "timeout-test-client",
				})
				return err
			},
			expectedTimeout: 500 * time.Millisecond,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create context with timeout slightly longer than expected timeout
			// This ensures we test the server-side timeout, not client timeout
			ctx, cancel := context.WithTimeout(context.Background(), tc.expectedTimeout+200*time.Millisecond)
			defer cancel()

			// Record start time
			start := time.Now()

			// Call the operation (this should timeout server-side)
			err := tc.operation(ctx)

			// Record duration
			duration := time.Since(start)

			// Verify error occurred
			if err == nil {
				t.Errorf("Expected timeout error, got success")
				return
			}

			// Extract gRPC status
			st, ok := status.FromError(err)
			if !ok {
				t.Errorf("Expected gRPC status error, got: %v", err)
				return
			}

			// Verify DEADLINE_EXCEEDED status code
			if st.Code() != codes.DeadlineExceeded {
				t.Errorf("Expected DEADLINE_EXCEEDED (%v), got %v: %s",
					codes.DeadlineExceeded, st.Code(), st.Message())
				return
			}

			// Verify timeout happened approximately at expected time
			// Allow for some variance due to system scheduling
			minTimeout := tc.expectedTimeout - 50*time.Millisecond
			maxTimeout := tc.expectedTimeout + 100*time.Millisecond

			if duration < minTimeout || duration > maxTimeout {
				t.Errorf("Timeout duration %v not within expected range [%v, %v]",
					duration, minTimeout, maxTimeout)
			}

			t.Logf("Operation %s timed out after %v (expected ~%v)",
				tc.name, duration, tc.expectedTimeout)
		})
	}
}

// TestSyscallTimeoutConfiguration verifies that SyscallTimeout is properly configured
func TestSyscallTimeoutConfiguration(t *testing.T) {
	// This test verifies the configuration is loaded correctly
	// The actual timeout behavior is tested in TestTimeoutExceeded

	config, err := loadTestConfig()
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}

	// Verify SyscallTimeout is set to 500ms as required by H-2
	expectedTimeout := 500 * time.Millisecond
	if config.SyscallTimeout != expectedTimeout {
		t.Errorf("SyscallTimeout is %v, expected %v",
			config.SyscallTimeout, expectedTimeout)
	}

	t.Logf("SyscallTimeout correctly configured as %v", config.SyscallTimeout)
}

// TestContextTimeoutHandling verifies that all handlers properly handle context timeout
func TestContextTimeoutHandling(t *testing.T) {
	// Connect to test server
	client, conn, err := setupTestClient()
	if err != nil {
		t.Fatalf("Failed to setup test client: %v", err)
	}
	defer conn.Close()

	// Test with a very short timeout to force timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// Sleep to ensure timeout occurs
	time.Sleep(10 * time.Millisecond)

	// Try an operation that should fail with timeout
	_, err = client.HealthCheck(ctx, &pb.HealthCheckRequest{
		CallerId: "timeout-test",
	})

	// Should get context deadline exceeded
	if err == nil {
		t.Error("Expected timeout error, got success")
		return
	}

	// Check that it's the right kind of error
	st, ok := status.FromError(err)
	if !ok {
		t.Errorf("Expected gRPC status error, got: %v", err)
		return
	}

	// Should be either DeadlineExceeded or Canceled (both indicate timeout)
	if st.Code() != codes.DeadlineExceeded && st.Code() != codes.Canceled {
		t.Errorf("Expected DEADLINE_EXCEEDED or CANCELED, got %v: %s",
			st.Code(), st.Message())
	}
}
