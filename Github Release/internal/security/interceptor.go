package security

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// SecurityInterceptor implements the mTLS → JWT → OPA → token-bucket authentication chain
type SecurityInterceptor struct {
	config      *InterceptorConfig
	jwtSecret   []byte
	opaClient   *OPAClient
	rateLimiter *TokenBucketRateLimiter
	trustedCAs  *x509.CertPool
	mutex       sync.RWMutex
	auditLogger func(string, ...interface{})
}

// InterceptorConfig holds configuration for the security interceptor
type InterceptorConfig struct {
	// mTLS configuration
	RequireMTLS        bool
	TrustedCACerts     []string
	ClientCertRequired bool

	// JWT configuration
	JWTEnabled    bool
	JWTSigningKey string
	JWTExpiry     time.Duration
	JWTIssuer     string
	JWTAudience   string

	// OPA configuration
	OPAEnabled    bool
	OPAEndpoint   string
	OPAPolicyPath string
	OPATimeout    time.Duration

	// Rate limiting configuration
	RateLimitEnabled  bool
	RequestsPerSecond int
	BurstSize         int
	RateLimitByUser   bool
	RateLimitGlobal   bool

	// Audit configuration
	AuditEnabled      bool
	AuditFailuresOnly bool
}

// DefaultInterceptorConfig returns a secure default configuration
func DefaultInterceptorConfig() *InterceptorConfig {
	return &InterceptorConfig{
		RequireMTLS:        true,
		ClientCertRequired: true,
		JWTEnabled:         true,
		JWTExpiry:          time.Hour,
		JWTIssuer:          "cam-os",
		JWTAudience:        "cam-os-api",
		OPAEnabled:         true,
		OPAEndpoint:        "http://localhost:8181",
		OPAPolicyPath:      "/v1/data/cam/allow",
		OPATimeout:         200 * time.Millisecond,
		RateLimitEnabled:   true,
		RequestsPerSecond:  1000,
		BurstSize:          100,
		RateLimitByUser:    true,
		RateLimitGlobal:    true,
		AuditEnabled:       true,
		AuditFailuresOnly:  false,
	}
}

// NewSecurityInterceptor creates a new security interceptor with the authentication chain
func NewSecurityInterceptor(config *InterceptorConfig, jwtSecret []byte, auditLogger func(string, ...interface{})) (*SecurityInterceptor, error) {
	if config == nil {
		config = DefaultInterceptorConfig()
	}

	if auditLogger == nil {
		auditLogger = func(format string, args ...interface{}) {
			fmt.Printf("[AUDIT] "+format+"\n", args...)
		}
	}

	// Initialize trusted CA pool
	trustedCAs := x509.NewCertPool()
	for _, certPEM := range config.TrustedCACerts {
		if ok := trustedCAs.AppendCertsFromPEM([]byte(certPEM)); !ok {
			return nil, fmt.Errorf("failed to parse trusted CA certificate")
		}
	}

	// Initialize OPA client
	opaClient, err := NewOPAClient(config.OPAEndpoint, config.OPATimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to create OPA client: %v", err)
	}

	// Initialize rate limiter
	rateLimiter := NewTokenBucketRateLimiter(config.RequestsPerSecond, config.BurstSize, config.RateLimitByUser)

	return &SecurityInterceptor{
		config:      config,
		jwtSecret:   jwtSecret,
		opaClient:   opaClient,
		rateLimiter: rateLimiter,
		trustedCAs:  trustedCAs,
		auditLogger: auditLogger,
	}, nil
}

// UnaryInterceptor implements the gRPC unary interceptor for the authentication chain
func (s *SecurityInterceptor) UnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	startTime := time.Now()

	// Extract client information for audit
	clientInfo := s.extractClientInfo(ctx)

	// Step 1: mTLS verification
	if s.config.RequireMTLS {
		if err := s.verifyMTLS(ctx); err != nil {
			s.auditLogger("mTLS verification failed for %s: %v", info.FullMethod, err)
			return nil, status.Errorf(codes.Unauthenticated, "mTLS verification failed: %v", err)
		}
	}

	// Step 2: JWT verification
	var userID string
	if s.config.JWTEnabled {
		claims, err := s.verifyJWT(ctx)
		if err != nil {
			s.auditLogger("JWT verification failed for %s: %v", info.FullMethod, err)
			return nil, status.Errorf(codes.Unauthenticated, "JWT verification failed: %v", err)
		}
		userID = claims.Subject
	}

	// Step 3: OPA authorization
	if s.config.OPAEnabled {
		if err := s.authorizeWithOPA(ctx, userID, info.FullMethod, req); err != nil {
			s.auditLogger("OPA authorization failed for user %s on %s: %v", userID, info.FullMethod, err)
			return nil, status.Errorf(codes.PermissionDenied, "authorization failed: %v", err)
		}
	}

	// Step 4: Rate limiting (token bucket)
	if s.config.RateLimitEnabled {
		if err := s.checkRateLimit(ctx, userID); err != nil {
			s.auditLogger("Rate limit exceeded for user %s on %s", userID, info.FullMethod)
			return nil, status.Errorf(codes.ResourceExhausted, "rate limit exceeded: %v", err)
		}
	}

	// Call the handler
	resp, err := handler(ctx, req)

	// Audit log
	latency := time.Since(startTime)
	if err != nil {
		s.auditLogger("Request failed - method: %s, user: %s, client: %s, latency: %v, error: %v",
			info.FullMethod, userID, clientInfo, latency, err)
	} else if !s.config.AuditFailuresOnly {
		s.auditLogger("Request succeeded - method: %s, user: %s, client: %s, latency: %v",
			info.FullMethod, userID, clientInfo, latency)
	}

	return resp, err
}

// verifyMTLS verifies the mTLS certificate chain
func (s *SecurityInterceptor) verifyMTLS(ctx context.Context) error {
	// Get peer info from context
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return fmt.Errorf("no peer information available")
	}

	// Check if connection is TLS
	tlsInfo, ok := peer.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return fmt.Errorf("connection is not TLS")
	}

	// Verify peer certificates
	if len(tlsInfo.State.PeerCertificates) == 0 {
		return fmt.Errorf("no client certificate provided")
	}

	// Verify certificate chain
	clientCert := tlsInfo.State.PeerCertificates[0]
	_, err := clientCert.Verify(x509.VerifyOptions{
		Roots:       s.trustedCAs,
		CurrentTime: time.Now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})

	if err != nil {
		return fmt.Errorf("certificate verification failed: %v", err)
	}

	return nil
}

// verifyJWT verifies and parses the JWT token
func (s *SecurityInterceptor) verifyJWT(ctx context.Context) (*jwt.RegisteredClaims, error) {
	// Extract JWT from metadata
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("no metadata available")
	}

	authHeaders := md.Get("authorization")
	if len(authHeaders) == 0 {
		return nil, fmt.Errorf("no authorization header")
	}

	authHeader := authHeaders[0]
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, fmt.Errorf("invalid authorization header format")
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// Parse and verify JWT
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.jwtSecret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("token parsing failed: %v", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Verify standard claims
	if claims.Issuer != s.config.JWTIssuer {
		return nil, fmt.Errorf("invalid issuer")
	}

	if claims.Audience != nil && len(claims.Audience) > 0 && claims.Audience[0] != s.config.JWTAudience {
		return nil, fmt.Errorf("invalid audience")
	}

	return claims, nil
}

// authorizeWithOPA checks authorization using Open Policy Agent
func (s *SecurityInterceptor) authorizeWithOPA(ctx context.Context, userID, method string, req interface{}) error {
	// Prepare OPA input
	input := map[string]interface{}{
		"user":    userID,
		"method":  method,
		"request": req,
		"time":    time.Now().Unix(),
	}

	// Query OPA
	allowed, err := s.opaClient.Authorize(ctx, input)
	if err != nil {
		return fmt.Errorf("OPA query failed: %v", err)
	}

	if !allowed {
		return fmt.Errorf("access denied by policy")
	}

	return nil
}

// checkRateLimit checks if the request is within rate limits
func (s *SecurityInterceptor) checkRateLimit(ctx context.Context, userID string) error {
	if s.config.RateLimitGlobal {
		if !s.rateLimiter.AllowGlobal() {
			return fmt.Errorf("global rate limit exceeded")
		}
	}

	if s.config.RateLimitByUser && userID != "" {
		if !s.rateLimiter.AllowUser(userID) {
			return fmt.Errorf("user rate limit exceeded")
		}
	}

	return nil
}

// extractClientInfo extracts client information for audit logging
func (s *SecurityInterceptor) extractClientInfo(ctx context.Context) string {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return "unknown"
	}

	if tlsInfo, ok := peer.AuthInfo.(credentials.TLSInfo); ok {
		if len(tlsInfo.State.PeerCertificates) > 0 {
			cert := tlsInfo.State.PeerCertificates[0]
			return fmt.Sprintf("%s (%s)", cert.Subject.CommonName, peer.Addr.String())
		}
	}

	return peer.Addr.String()
}

// OPAClient handles communication with Open Policy Agent
type OPAClient struct {
	endpoint string
	timeout  time.Duration
	client   *http.Client
}

// NewOPAClient creates a new OPA client
func NewOPAClient(endpoint string, timeout time.Duration) (*OPAClient, error) {
	return &OPAClient{
		endpoint: endpoint,
		timeout:  timeout,
		client: &http.Client{
			Timeout: timeout,
		},
	}, nil
}

// Authorize queries OPA for authorization decision
func (c *OPAClient) Authorize(ctx context.Context, input map[string]interface{}) (bool, error) {
	// Prepare request
	reqBody := map[string]interface{}{
		"input": input,
	}

	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		return false, fmt.Errorf("failed to marshal request: %v", err)
	}

	// Make HTTP request to OPA
	url := fmt.Sprintf("%s/v1/data/cam/allow", c.endpoint)
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(reqJSON)))
	if err != nil {
		return false, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("OPA returned status %d", resp.StatusCode)
	}

	// Parse response
	var result struct {
		Result bool `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, fmt.Errorf("failed to decode response: %v", err)
	}

	return result.Result, nil
}

// TokenBucketRateLimiter implements rate limiting using token bucket algorithm
type TokenBucketRateLimiter struct {
	globalLimiter *rate.Limiter
	userLimiters  map[string]*rate.Limiter
	mutex         sync.RWMutex
	perUserRate   rate.Limit
	perUserBurst  int
}

// NewTokenBucketRateLimiter creates a new token bucket rate limiter
func NewTokenBucketRateLimiter(requestsPerSecond, burstSize int, enablePerUser bool) *TokenBucketRateLimiter {
	limiter := &TokenBucketRateLimiter{
		globalLimiter: rate.NewLimiter(rate.Limit(requestsPerSecond), burstSize),
		userLimiters:  make(map[string]*rate.Limiter),
		perUserRate:   rate.Limit(requestsPerSecond / 10), // 10% of global rate per user
		perUserBurst:  burstSize / 10,                     // 10% of global burst per user
	}

	if limiter.perUserBurst < 1 {
		limiter.perUserBurst = 1
	}

	return limiter
}

// AllowGlobal checks if the global rate limit allows the request
func (l *TokenBucketRateLimiter) AllowGlobal() bool {
	return l.globalLimiter.Allow()
}

// AllowUser checks if the user's rate limit allows the request
func (l *TokenBucketRateLimiter) AllowUser(userID string) bool {
	l.mutex.RLock()
	limiter, exists := l.userLimiters[userID]
	l.mutex.RUnlock()

	if !exists {
		// Create new limiter for user
		l.mutex.Lock()
		limiter, exists = l.userLimiters[userID]
		if !exists {
			limiter = rate.NewLimiter(l.perUserRate, l.perUserBurst)
			l.userLimiters[userID] = limiter
		}
		l.mutex.Unlock()
	}

	return limiter.Allow()
}

// GetStats returns rate limiting statistics
func (l *TokenBucketRateLimiter) GetStats() map[string]interface{} {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	return map[string]interface{}{
		"global_tokens":  l.globalLimiter.Tokens(),
		"active_users":   len(l.userLimiters),
		"per_user_rate":  float64(l.perUserRate),
		"per_user_burst": l.perUserBurst,
	}
}
