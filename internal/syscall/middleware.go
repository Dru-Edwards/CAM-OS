package syscall

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// AuthMiddleware handles authentication and authorization
type AuthMiddleware struct {
	requireMTLS    bool
	trustedCAs     []string
	jwtValidator   JWTValidator
	policyEngine   PolicyEngine
}

// RateLimiter implements token bucket rate limiting per client
type RateLimiter struct {
	buckets    map[string]*TokenBucket
	mu         sync.RWMutex
	maxRate    int
	burstSize  int
	cleanupTTL time.Duration
}

// TokenBucket represents a token bucket for rate limiting
type TokenBucket struct {
	tokens    int
	maxTokens int
	lastRefill time.Time
	refillRate time.Duration
}

// JWTValidator interface for JWT token validation
type JWTValidator interface {
	ValidateToken(ctx context.Context, token string) (*Claims, error)
}

// PolicyEngine interface for authorization decisions
type PolicyEngine interface {
	Authorize(ctx context.Context, subject string, action string, resource string) (bool, error)
}

// Claims represents JWT claims
type Claims struct {
	Subject     string            `json:"sub"`
	Issuer      string            `json:"iss"`
	Audience    string            `json:"aud"`
	ExpiresAt   int64             `json:"exp"`
	IssuedAt    int64             `json:"iat"`
	Permissions []string          `json:"permissions"`
	Metadata    map[string]string `json:"metadata"`
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(requireMTLS bool, trustedCAs []string, jwtValidator JWTValidator, policyEngine PolicyEngine) *AuthMiddleware {
	return &AuthMiddleware{
		requireMTLS:  requireMTLS,
		trustedCAs:   trustedCAs,
		jwtValidator: jwtValidator,
		policyEngine: policyEngine,
	}
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(maxRate, burstSize int) *RateLimiter {
	return &RateLimiter{
		buckets:    make(map[string]*TokenBucket),
		maxRate:    maxRate,
		burstSize:  burstSize,
		cleanupTTL: 10 * time.Minute,
	}
}

// UnaryInterceptor returns a gRPC unary interceptor for auth and rate limiting
func (am *AuthMiddleware) UnaryInterceptor(rateLimiter *RateLimiter) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Step 1: Extract client identity
		clientID, err := am.extractClientIdentity(ctx)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "failed to extract client identity")
		}

		// Step 2: Rate limiting check
		if !rateLimiter.Allow(clientID) {
			return nil, status.Error(codes.ResourceExhausted, "rate limit exceeded")
		}

		// Step 3: mTLS validation (if required)
		if am.requireMTLS {
			if err := am.validateMTLS(ctx); err != nil {
				return nil, status.Error(codes.Unauthenticated, "mTLS validation failed")
			}
		}

		// Step 4: JWT validation
		claims, err := am.validateJWT(ctx)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "JWT validation failed")
		}

		// Step 5: Authorization check
		if err := am.authorize(ctx, claims, info.FullMethod); err != nil {
			return nil, status.Error(codes.PermissionDenied, "authorization failed")
		}

		// Step 6: Add claims to context
		ctx = context.WithValue(ctx, "claims", claims)
		ctx = context.WithValue(ctx, "client_id", clientID)

		// Call the handler
		return handler(ctx, req)
	}
}

// extractClientIdentity extracts client identity from the context
func (am *AuthMiddleware) extractClientIdentity(ctx context.Context) (string, error) {
	// Try to get from peer info (mTLS certificate)
	if peer, ok := peer.FromContext(ctx); ok {
		if tlsInfo, ok := peer.AuthInfo.(credentials.TLSInfo); ok {
			if len(tlsInfo.State.PeerCertificates) > 0 {
				cert := tlsInfo.State.PeerCertificates[0]
				return cert.Subject.CommonName, nil
			}
		}
	}

	// Try to get from metadata (API key or client ID)
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if clientIDs := md.Get("client-id"); len(clientIDs) > 0 {
			return clientIDs[0], nil
		}
	}

	return "", fmt.Errorf("no client identity found")
}

// validateMTLS validates mutual TLS connection
func (am *AuthMiddleware) validateMTLS(ctx context.Context) error {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return fmt.Errorf("no peer info")
	}

	tlsInfo, ok := peer.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return fmt.Errorf("no TLS info")
	}

	// Check if client certificate is present
	if len(tlsInfo.State.PeerCertificates) == 0 {
		return fmt.Errorf("no client certificate")
	}

	// Validate certificate chain
	cert := tlsInfo.State.PeerCertificates[0]
	
	// Check certificate validity
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return fmt.Errorf("certificate expired or not yet valid")
	}

	// Additional certificate validation logic can be added here
	// e.g., checking against trusted CAs, CRL, OCSP, etc.

	return nil
}

// validateJWT validates JWT token from metadata
func (am *AuthMiddleware) validateJWT(ctx context.Context) (*Claims, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("no metadata")
	}

	authHeaders := md.Get("authorization")
	if len(authHeaders) == 0 {
		return nil, fmt.Errorf("no authorization header")
	}

	token := authHeaders[0]
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}

	return am.jwtValidator.ValidateToken(ctx, token)
}

// authorize checks if the client is authorized to perform the action
func (am *AuthMiddleware) authorize(ctx context.Context, claims *Claims, method string) error {
	// Extract action and resource from method
	action, resource := parseGRPCMethod(method)
	
	// Check authorization
	allowed, err := am.policyEngine.Authorize(ctx, claims.Subject, action, resource)
	if err != nil {
		return fmt.Errorf("authorization check failed: %w", err)
	}

	if !allowed {
		return fmt.Errorf("access denied for %s on %s", action, resource)
	}

	return nil
}

// Allow checks if a client is allowed to make a request (rate limiting)
func (rl *RateLimiter) Allow(clientID string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	bucket, exists := rl.buckets[clientID]
	if !exists {
		bucket = &TokenBucket{
			tokens:     rl.burstSize,
			maxTokens:  rl.burstSize,
			lastRefill: time.Now(),
			refillRate: time.Second / time.Duration(rl.maxRate),
		}
		rl.buckets[clientID] = bucket
	}

	// Refill tokens
	now := time.Now()
	tokensToAdd := int(now.Sub(bucket.lastRefill) / bucket.refillRate)
	if tokensToAdd > 0 {
		bucket.tokens = min(bucket.maxTokens, bucket.tokens+tokensToAdd)
		bucket.lastRefill = now
	}

	// Check if request is allowed
	if bucket.tokens > 0 {
		bucket.tokens--
		return true
	}

	return false
}

// Cleanup removes old token buckets to prevent memory leaks
func (rl *RateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Now().Add(-rl.cleanupTTL)
	for clientID, bucket := range rl.buckets {
		if bucket.lastRefill.Before(cutoff) {
			delete(rl.buckets, clientID)
		}
	}
}

// StartCleanupRoutine starts a background goroutine to clean up old buckets
func (rl *RateLimiter) StartCleanupRoutine() {
	go func() {
		ticker := time.NewTicker(rl.cleanupTTL)
		defer ticker.Stop()

		for range ticker.C {
			rl.Cleanup()
		}
	}()
}

// parseGRPCMethod extracts action and resource from gRPC method name
func parseGRPCMethod(method string) (action, resource string) {
	// Example: "/cam.SyscallService/Arbitrate" -> action: "arbitrate", resource: "tasks"
	
	// Extract method name from full path
	if len(method) > 0 && method[0] == '/' {
		parts := strings.Split(method[1:], "/")
		if len(parts) == 2 {
			methodName := strings.ToLower(parts[1])
			
			// Map methods to actions and resources
			methodMap := map[string][2]string{
				"arbitrate":              {"arbitrate", "tasks"},
				"committask":             {"commit", "tasks"},
				"taskrollback":           {"rollback", "tasks"},
				"agentregister":          {"register", "agents"},
				"querypolicy":            {"query", "policies"},
				"policyupdate":           {"update", "policies"},
				"contextread":            {"read", "context"},
				"contextwrite":           {"write", "context"},
				"contextsnapshot":        {"snapshot", "context"},
				"contextrestore":         {"restore", "context"},
				"tmpsign":                {"sign", "security"},
				"verifymanifest":         {"verify", "security"},
				"establishsecurechannel": {"establish", "security"},
				"explainaction":          {"explain", "observability"},
				"emittrace":              {"emit", "observability"},
				"emitmetric":             {"emit", "observability"},
				"systemtuning":           {"tune", "system"},
				"healthcheck":            {"check", "health"},
			}
			
			if mapping, exists := methodMap[methodName]; exists {
				return mapping[0], mapping[1]
			}
		}
	}
	
	return "unknown", "unknown"
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GetClientID extracts client ID from context (utility function)
func GetClientID(ctx context.Context) string {
	if clientID, ok := ctx.Value("client_id").(string); ok {
		return clientID
	}
	return "unknown"
}

// GetClaims extracts JWT claims from context (utility function)  
func GetClaims(ctx context.Context) *Claims {
	if claims, ok := ctx.Value("claims").(*Claims); ok {
		return claims
	}
	return nil
} 