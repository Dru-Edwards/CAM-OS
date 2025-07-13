package security

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestSecurityInterceptor(t *testing.T) {
	// Create test configuration
	config := &InterceptorConfig{
		RequireMTLS:       false, // Disable mTLS for testing
		JWTEnabled:        true,
		JWTIssuer:         "test-issuer",
		JWTAudience:       "test-audience",
		OPAEnabled:        false, // Disable OPA for testing
		RateLimitEnabled:  true,
		RequestsPerSecond: 100,
		BurstSize:         10,
		AuditEnabled:      true,
	}

	// Generate test JWT secret
	jwtSecret := make([]byte, 32)
	rand.Read(jwtSecret)

	// Create interceptor
	interceptor, err := NewSecurityInterceptor(config, jwtSecret, nil)
	if err != nil {
		t.Fatalf("Failed to create interceptor: %v", err)
	}

	// Test JWT validation
	t.Run("ValidJWT", func(t *testing.T) {
		// Create valid JWT token
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, &jwt.RegisteredClaims{
			Subject:   "test-user",
			Issuer:    config.JWTIssuer,
			Audience:  []string{config.JWTAudience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		})

		tokenString, err := token.SignedString(jwtSecret)
		if err != nil {
			t.Fatalf("Failed to sign token: %v", err)
		}

		// Create context with JWT token
		md := metadata.Pairs("authorization", "Bearer "+tokenString)
		ctx := metadata.NewIncomingContext(context.Background(), md)

		// Test interceptor
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/TestMethod"}
		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			return "success", nil
		}

		resp, err := interceptor.UnaryInterceptor(ctx, nil, info, handler)
		if err != nil {
			t.Errorf("Expected success, got error: %v", err)
		}

		if resp != "success" {
			t.Errorf("Expected 'success', got %v", resp)
		}
	})

	t.Run("InvalidJWT", func(t *testing.T) {
		// Create context with invalid JWT token
		md := metadata.Pairs("authorization", "Bearer invalid-token")
		ctx := metadata.NewIncomingContext(context.Background(), md)

		// Test interceptor
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/TestMethod"}
		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			return "success", nil
		}

		_, err := interceptor.UnaryInterceptor(ctx, nil, info, handler)
		if err == nil {
			t.Error("Expected error for invalid JWT, got nil")
		}

		if status.Code(err) != codes.Unauthenticated {
			t.Errorf("Expected Unauthenticated error, got %v", status.Code(err))
		}
	})

	t.Run("MissingJWT", func(t *testing.T) {
		// Create context without JWT token
		ctx := context.Background()

		// Test interceptor
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/TestMethod"}
		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			return "success", nil
		}

		_, err := interceptor.UnaryInterceptor(ctx, nil, info, handler)
		if err == nil {
			t.Error("Expected error for missing JWT, got nil")
		}

		if status.Code(err) != codes.Unauthenticated {
			t.Errorf("Expected Unauthenticated error, got %v", status.Code(err))
		}
	})
}

func TestTokenBucketRateLimiter(t *testing.T) {
	// Create rate limiter
	limiter := NewTokenBucketRateLimiter(10, 5, true)

	t.Run("GlobalRateLimit", func(t *testing.T) {
		// Test global rate limiting
		allowed := 0
		for i := 0; i < 20; i++ {
			if limiter.AllowGlobal() {
				allowed++
			}
		}

		// Should allow burst size initially
		if allowed < 5 {
			t.Errorf("Expected at least 5 requests allowed, got %d", allowed)
		}

		if allowed > 15 {
			t.Errorf("Expected at most 15 requests allowed, got %d", allowed)
		}
	})

	t.Run("UserRateLimit", func(t *testing.T) {
		// Test per-user rate limiting
		allowed := 0
		for i := 0; i < 10; i++ {
			if limiter.AllowUser("user1") {
				allowed++
			}
		}

		// Should allow at least 1 request per user
		if allowed < 1 {
			t.Errorf("Expected at least 1 request allowed for user, got %d", allowed)
		}
	})

	t.Run("MultipleUsers", func(t *testing.T) {
		// Test multiple users with a fresh limiter
		freshLimiter := NewTokenBucketRateLimiter(100, 10, true)

		user1Allowed := 0
		user2Allowed := 0

		for i := 0; i < 5; i++ {
			if freshLimiter.AllowUser("user1") {
				user1Allowed++
			}
			if freshLimiter.AllowUser("user2") {
				user2Allowed++
			}
		}

		// Both users should be allowed at least 1 request
		if user1Allowed == 0 {
			t.Errorf("Expected user1 to be allowed at least 1 request, got %d", user1Allowed)
		}
		if user2Allowed == 0 {
			t.Errorf("Expected user2 to be allowed at least 1 request, got %d", user2Allowed)
		}
	})
}

func TestOPAClient(t *testing.T) {
	// This test would require a running OPA instance
	// For now, we'll just test the client creation

	client, err := NewOPAClient("http://localhost:8181", 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to create OPA client: %v", err)
	}

	if client == nil {
		t.Error("Expected OPA client, got nil")
	}

	if client.endpoint != "http://localhost:8181" {
		t.Errorf("Expected endpoint 'http://localhost:8181', got %s", client.endpoint)
	}

	if client.timeout != 100*time.Millisecond {
		t.Errorf("Expected timeout 100ms, got %v", client.timeout)
	}
}

func TestInterceptorConfig(t *testing.T) {
	config := DefaultInterceptorConfig()

	// Test default values
	if !config.RequireMTLS {
		t.Error("Expected RequireMTLS to be true by default")
	}

	if !config.JWTEnabled {
		t.Error("Expected JWTEnabled to be true by default")
	}

	if !config.OPAEnabled {
		t.Error("Expected OPAEnabled to be true by default")
	}

	if !config.RateLimitEnabled {
		t.Error("Expected RateLimitEnabled to be true by default")
	}

	if config.RequestsPerSecond != 1000 {
		t.Errorf("Expected RequestsPerSecond to be 1000, got %d", config.RequestsPerSecond)
	}

	if config.BurstSize != 100 {
		t.Errorf("Expected BurstSize to be 100, got %d", config.BurstSize)
	}
}
