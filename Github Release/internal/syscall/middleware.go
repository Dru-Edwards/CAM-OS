package syscall

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log"
	"os"
	"time"

	"github.com/cam-os/kernel/internal/security"
	"google.golang.org/grpc"
)

// MiddlewareConfig holds configuration for syscall middleware
type MiddlewareConfig struct {
	// Security interceptor configuration
	SecurityInterceptor *security.InterceptorConfig

	// JWT configuration
	JWTSigningKey []byte

	// Audit configuration
	AuditEnabled bool
	AuditLogger  *log.Logger

	// Performance configuration
	EnableMetrics bool
	MetricsLogger *log.Logger
}

// DefaultMiddlewareConfig returns a secure default middleware configuration
func DefaultMiddlewareConfig() *MiddlewareConfig {
	// Generate a random JWT signing key (in production, this should be loaded from secure storage)
	signingKey := make([]byte, 32)
	rand.Read(signingKey)

	return &MiddlewareConfig{
		SecurityInterceptor: security.DefaultInterceptorConfig(),
		JWTSigningKey:       signingKey,
		AuditEnabled:        true,
		AuditLogger:         log.New(os.Stdout, "[AUDIT] ", log.LstdFlags|log.Lmicroseconds),
		EnableMetrics:       true,
		MetricsLogger:       log.New(os.Stdout, "[METRICS] ", log.LstdFlags),
	}
}

// SetupSecurityMiddleware sets up the security interceptor chain for gRPC server
func SetupSecurityMiddleware(config *MiddlewareConfig) (grpc.UnaryServerInterceptor, error) {
	if config == nil {
		config = DefaultMiddlewareConfig()
	}

	// Create audit logger function
	auditLogger := func(format string, args ...interface{}) {
		if config.AuditEnabled && config.AuditLogger != nil {
			config.AuditLogger.Printf(format, args...)
		}
	}

	// Create security interceptor
	securityInterceptor, err := security.NewSecurityInterceptor(
		config.SecurityInterceptor,
		config.JWTSigningKey,
		auditLogger,
	)
	if err != nil {
		return nil, err
	}

	// Create combined interceptor chain
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Security chain: mTLS → JWT → OPA → token-bucket
		return securityInterceptor.UnaryInterceptor(ctx, req, info, func(ctx context.Context, req interface{}) (interface{}, error) {
			// Add performance metrics
			if config.EnableMetrics {
				start := time.Now()
				resp, err := handler(ctx, req)
				latency := time.Since(start)

				if config.MetricsLogger != nil {
					config.MetricsLogger.Printf("method=%s latency=%v success=%v",
						info.FullMethod, latency, err == nil)
				}

				return resp, err
			}

			return handler(ctx, req)
		})
	}, nil
}

// LoadSecurityConfig loads security configuration from environment or config file
func LoadSecurityConfig() (*MiddlewareConfig, error) {
	config := DefaultMiddlewareConfig()

	// Override with environment variables if present
	if jwtKey := os.Getenv("CAM_OS_JWT_SIGNING_KEY"); jwtKey != "" {
		key, err := hex.DecodeString(jwtKey)
		if err != nil {
			return nil, err
		}
		config.JWTSigningKey = key
	}

	// Configure security interceptor based on environment
	if os.Getenv("CAM_OS_DISABLE_MTLS") == "true" {
		config.SecurityInterceptor.RequireMTLS = false
	}

	if os.Getenv("CAM_OS_DISABLE_JWT") == "true" {
		config.SecurityInterceptor.JWTEnabled = false
	}

	if os.Getenv("CAM_OS_DISABLE_OPA") == "true" {
		config.SecurityInterceptor.OPAEnabled = false
	}

	if os.Getenv("CAM_OS_DISABLE_RATE_LIMIT") == "true" {
		config.SecurityInterceptor.RateLimitEnabled = false
	}

	// Override OPA endpoint if specified
	if opaEndpoint := os.Getenv("CAM_OS_OPA_ENDPOINT"); opaEndpoint != "" {
		config.SecurityInterceptor.OPAEndpoint = opaEndpoint
	}

	return config, nil
}

// ValidationMiddleware provides additional validation for syscall requests
func ValidationMiddleware(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	// Add request validation here if needed
	// This runs after the security interceptor chain

	return handler(ctx, req)
}

// RecoveryMiddleware provides panic recovery for syscall handlers
func RecoveryMiddleware(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Panic recovered in %s: %v", info.FullMethod, r)
		}
	}()

	return handler(ctx, req)
}

// ChainInterceptors chains multiple unary interceptors together
func ChainInterceptors(interceptors ...grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Build the chain from right to left
		for i := len(interceptors) - 1; i >= 0; i-- {
			interceptor := interceptors[i]
			h := handler
			handler = func(ctx context.Context, req interface{}) (interface{}, error) {
				return interceptor(ctx, req, info, h)
			}
		}

		return handler(ctx, req)
	}
}

// CreateSecureMiddlewareChain creates a complete secure middleware chain
func CreateSecureMiddlewareChain(config *MiddlewareConfig) (grpc.UnaryServerInterceptor, error) {
	// Setup security interceptor
	securityInterceptor, err := SetupSecurityMiddleware(config)
	if err != nil {
		return nil, err
	}

	// Create the complete chain: Recovery → Security → Validation
	return ChainInterceptors(
		RecoveryMiddleware,
		securityInterceptor,
		ValidationMiddleware,
	), nil
}
