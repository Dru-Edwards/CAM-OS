package integration

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cam-os/kernel/internal/server"
	pb "github.com/cam-os/kernel/proto/generated"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// TestAuthChainNegativeCases tests negative scenarios for H-4 auth chain
func TestAuthChainNegativeCases(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Set up environment for secretless JWT
	originalJWTKey := os.Getenv("JWT_SIGNING_KEY")
	testJWTKey := "test-secret-key-for-h4-testing-32-chars"
	os.Setenv("JWT_SIGNING_KEY", testJWTKey)
	defer func() {
		if originalJWTKey != "" {
			os.Setenv("JWT_SIGNING_KEY", originalJWTKey)
		} else {
			os.Unsetenv("JWT_SIGNING_KEY")
		}
	}()

	client, conn, err := setupTestClient()
	if err != nil {
		t.Fatalf("Failed to setup test client: %v", err)
	}
	defer conn.Close()

	t.Run("Invalid JWT - malformed token", func(t *testing.T) {
		// Create context with invalid JWT
		md := metadata.Pairs("authorization", "Bearer invalid-malformed-token")
		ctx := metadata.NewOutgoingContext(context.Background(), md)

		// Try to call protected endpoint
		_, err := client.HealthCheck(ctx, &pb.HealthCheckRequest{
			CallerId: "test-invalid-jwt",
		})

		// Should get Unauthenticated error
		assertGRPCError(t, err, codes.Unauthenticated, "JWT verification")
	})

	t.Run("Invalid JWT - wrong signing key", func(t *testing.T) {
		// Create JWT with wrong signing key
		wrongKey := []byte("wrong-signing-key-different-from-env")
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, &jwt.RegisteredClaims{
			Subject:   "test-user",
			Issuer:    "test-issuer",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		})

		tokenString, err := token.SignedString(wrongKey)
		if err != nil {
			t.Fatalf("Failed to sign token: %v", err)
		}

		md := metadata.Pairs("authorization", "Bearer "+tokenString)
		ctx := metadata.NewOutgoingContext(context.Background(), md)

		_, err = client.HealthCheck(ctx, &pb.HealthCheckRequest{
			CallerId: "test-wrong-key",
		})

		assertGRPCError(t, err, codes.Unauthenticated, "JWT verification")
	})

	t.Run("Invalid JWT - expired token", func(t *testing.T) {
		// Create expired JWT
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, &jwt.RegisteredClaims{
			Subject:   "test-user",
			Issuer:    "test-issuer",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)), // Expired 1 hour ago
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		})

		tokenString, err := token.SignedString([]byte(testJWTKey))
		if err != nil {
			t.Fatalf("Failed to sign token: %v", err)
		}

		md := metadata.Pairs("authorization", "Bearer "+tokenString)
		ctx := metadata.NewOutgoingContext(context.Background(), md)

		_, err = client.HealthCheck(ctx, &pb.HealthCheckRequest{
			CallerId: "test-expired-jwt",
		})

		assertGRPCError(t, err, codes.Unauthenticated, "JWT verification")
	})

	t.Run("Missing JWT token", func(t *testing.T) {
		// Call without authorization header
		ctx := context.Background()

		_, err := client.HealthCheck(ctx, &pb.HealthCheckRequest{
			CallerId: "test-missing-jwt",
		})

		assertGRPCError(t, err, codes.Unauthenticated, "JWT verification")
	})
}

// TestOPADenyScenarios tests OPA policy denial cases (H-4 requirement)
func TestOPADenyScenarios(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Set up JWT key
	testJWTKey := "test-secret-key-for-h4-testing-32-chars"
	os.Setenv("JWT_SIGNING_KEY", testJWTKey)
	defer os.Unsetenv("JWT_SIGNING_KEY")

	client, conn, err := setupTestClient()
	if err != nil {
		t.Fatalf("Failed to setup test client: %v", err)
	}
	defer conn.Close()

	t.Run("OPA policy denies access", func(t *testing.T) {
		// Create valid JWT for user that should be denied by policy
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, &jwt.RegisteredClaims{
			Subject:   "blocked-user", // This user should be blocked by OPA policy
			Issuer:    "test-issuer",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		})

		tokenString, err := token.SignedString([]byte(testJWTKey))
		if err != nil {
			t.Fatalf("Failed to sign token: %v", err)
		}

		md := metadata.Pairs("authorization", "Bearer "+tokenString)
		ctx := metadata.NewOutgoingContext(context.Background(), md)

		// Try to call protected endpoint
		_, err = client.QueryPolicy(ctx, &pb.QueryPolicyRequest{
			PolicyId: "sensitive-policy",
			Query:    "allow",
			CallerId: "blocked-user",
		})

		// Should get PermissionDenied error
		assertGRPCError(t, err, codes.PermissionDenied, "authorization failed")
	})

	t.Run("OPA policy blocks sensitive operations", func(t *testing.T) {
		// Create valid JWT for regular user trying to access admin operation
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, &jwt.RegisteredClaims{
			Subject:   "regular-user",
			Issuer:    "test-issuer",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		})

		tokenString, err := token.SignedString([]byte(testJWTKey))
		if err != nil {
			t.Fatalf("Failed to sign token: %v", err)
		}

		md := metadata.Pairs("authorization", "Bearer "+tokenString)
		ctx := metadata.NewOutgoingContext(context.Background(), md)

		// Try to perform admin operation
		_, err = client.SystemTuning(ctx, &pb.SystemTuningRequest{
			TuningProfile: "performance",
			Parameters:    map[string]string{"admin_setting": "true"},
			CallerId:      "regular-user",
		})

		assertGRPCError(t, err, codes.PermissionDenied, "authorization failed")
	})
}

// TestRateLimitExceeded tests rate limiting scenarios (H-4 requirement)
func TestRateLimitExceeded(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Set up JWT key
	testJWTKey := "test-secret-key-for-h4-testing-32-chars"
	os.Setenv("JWT_SIGNING_KEY", testJWTKey)
	defer os.Unsetenv("JWT_SIGNING_KEY")

	client, conn, err := setupTestClient()
	if err != nil {
		t.Fatalf("Failed to setup test client: %v", err)
	}
	defer conn.Close()

	// Create valid JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &jwt.RegisteredClaims{
		Subject:   "rate-limit-test-user",
		Issuer:    "test-issuer",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	})

	tokenString, err := token.SignedString([]byte(testJWTKey))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	md := metadata.Pairs("authorization", "Bearer "+tokenString)
	ctx := metadata.NewOutgoingContext(context.Background(), md)

	t.Run("Per-method rate limit exceeded (100 QPS)", func(t *testing.T) {
		// Make rapid successive calls to exceed per-method rate limit
		// H-4 specifies 100 QPS per client per method
		successCount := 0
		rateLimitedCount := 0

		// Make 150 requests rapidly to exceed the 100 QPS limit
		for i := 0; i < 150; i++ {
			_, err := client.HealthCheck(ctx, &pb.HealthCheckRequest{
				CallerId: fmt.Sprintf("rate-test-%d", i),
			})

			if err != nil {
				st, ok := status.FromError(err)
				if ok && st.Code() == codes.ResourceExhausted {
					rateLimitedCount++
				}
			} else {
				successCount++
			}

			// Small delay to avoid overwhelming the server
			time.Sleep(1 * time.Millisecond)
		}

		// We should have some successful requests and some rate-limited ones
		if rateLimitedCount == 0 {
			t.Error("Expected some requests to be rate-limited, but none were")
		}

		if successCount == 0 {
			t.Error("Expected some requests to succeed, but none did")
		}

		t.Logf("Rate limit test: %d successful, %d rate-limited out of 150 requests",
			successCount, rateLimitedCount)
	})

	t.Run("Different methods have separate rate limits", func(t *testing.T) {
		// Test that different methods have separate rate limit buckets
		// This verifies the per-method aspect of H-4

		// Make calls to HealthCheck
		_, err1 := client.HealthCheck(ctx, &pb.HealthCheckRequest{
			CallerId: "method-separation-test",
		})

		// Make calls to different method (should have separate rate limit)
		_, err2 := client.QueryPolicy(ctx, &pb.QueryPolicyRequest{
			PolicyId: "test-policy",
			Query:    "allow",
			CallerId: "method-separation-test",
		})

		// Both should succeed if rate limits are separate
		if err1 != nil {
			t.Errorf("HealthCheck failed: %v", err1)
		}

		if err2 != nil {
			// This might fail due to OPA deny, but shouldn't be rate limit
			st, ok := status.FromError(err2)
			if ok && st.Code() == codes.ResourceExhausted {
				t.Error("QueryPolicy was rate-limited, suggesting rate limits are not per-method")
			}
		}
	})
}

// TestSecretlessJWTConfiguration tests that JWT key must come from env-var (H-4)
func TestSecretlessJWTConfiguration(t *testing.T) {
	t.Run("Auth interceptor fails without JWT_SIGNING_KEY env var", func(t *testing.T) {
		// Save original value
		originalJWTKey := os.Getenv("JWT_SIGNING_KEY")

		// Unset the environment variable
		os.Unsetenv("JWT_SIGNING_KEY")

		// Try to create auth interceptor - should fail
		config := server.DefaultAuthConfig()
		_, err := server.NewAuthInterceptor(config)

		// Restore original value
		if originalJWTKey != "" {
			os.Setenv("JWT_SIGNING_KEY", originalJWTKey)
		}

		// Should get error about missing env var
		if err == nil {
			t.Error("Expected error when JWT_SIGNING_KEY env var is missing, got nil")
		}

		expectedMsg := "JWT_SIGNING_KEY environment variable is required"
		if !strings.Contains(err.Error(), expectedMsg) {
			t.Errorf("Expected error to contain '%s', got: %v", expectedMsg, err)
		}
	})
}

// Helper function to assert gRPC error codes and messages
func assertGRPCError(t *testing.T, err error, expectedCode codes.Code, expectedMsgContains string) {
	t.Helper()

	if err == nil {
		t.Errorf("Expected error with code %v, got nil", expectedCode)
		return
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Errorf("Expected gRPC status error, got: %v", err)
		return
	}

	if st.Code() != expectedCode {
		t.Errorf("Expected error code %v, got %v: %s", expectedCode, st.Code(), st.Message())
		return
	}

	if expectedMsgContains != "" && !strings.Contains(st.Message(), expectedMsgContains) {
		t.Errorf("Expected error message to contain '%s', got: %s", expectedMsgContains, st.Message())
	}
}
