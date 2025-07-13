package server

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
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

// AuthInterceptor implements the mTLS → JWT → OPA → token-bucket auth chain (H-4)
type AuthInterceptor struct {
	jwtSigningKey   []byte
	opaClient       *OPAClient
	rateLimiter     *PerMethodRateLimiter
	trustedCAs      *x509.CertPool
	enableMTLS      bool
	enableJWT       bool
	enableOPA       bool
	enableRateLimit bool
	auditLogger     func(string, ...interface{})
}

// AuthConfig holds configuration for the auth interceptor
type AuthConfig struct {
	EnableMTLS      bool
	EnableJWT       bool
	EnableOPA       bool
	EnableRateLimit bool
	TrustedCACerts  []string
	OPAEndpoint     string
	OPATimeout      time.Duration
	GlobalQPS       int // 1000 QPS global as per H-4
	PerMethodQPS    int // 100 QPS per client per method as per H-4
}

// DefaultAuthConfig returns secure defaults for auth configuration
func DefaultAuthConfig() *AuthConfig {
	return &AuthConfig{
		EnableMTLS:      true,
		EnableJWT:       true,
		EnableOPA:       true,
		EnableRateLimit: true,
		OPAEndpoint:     "http://localhost:8181",
		OPATimeout:      200 * time.Millisecond,
		GlobalQPS:       1000, // H-4 requirement: 1k QPS global
		PerMethodQPS:    100,  // H-4 requirement: 100 QPS/client/method
	}
}

// NewAuthInterceptor creates a new auth interceptor (H-4 implementation)
func NewAuthInterceptor(config *AuthConfig) (*AuthInterceptor, error) {
	if config == nil {
		config = DefaultAuthConfig()
	}

	// **H-4 Secretless requirement**: JWT signing key MUST come from env-var
	jwtSigningKey := os.Getenv("JWT_SIGNING_KEY")
	if jwtSigningKey == "" {
		return nil, fmt.Errorf("JWT_SIGNING_KEY environment variable is required (H-4 secretless requirement)")
	}

	// Initialize trusted CA pool for mTLS
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

	// Initialize per-method rate limiter (H-4 requirement)
	rateLimiter := NewPerMethodRateLimiter(config.GlobalQPS, config.PerMethodQPS)

	auditLogger := func(format string, args ...interface{}) {
		fmt.Printf("[AUTH_AUDIT] "+format+"\n", args...)
	}

	return &AuthInterceptor{
		jwtSigningKey:   []byte(jwtSigningKey),
		opaClient:       opaClient,
		rateLimiter:     rateLimiter,
		trustedCAs:      trustedCAs,
		enableMTLS:      config.EnableMTLS,
		enableJWT:       config.EnableJWT,
		enableOPA:       config.EnableOPA,
		enableRateLimit: config.EnableRateLimit,
		auditLogger:     auditLogger,
	}, nil
}

// UnaryInterceptor implements the complete auth chain (H-4)
func (a *AuthInterceptor) UnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	startTime := time.Now()

	// Extract client info for audit
	clientInfo := a.extractClientInfo(ctx)
	userID := ""

	// Step 1: mTLS verification
	if a.enableMTLS {
		if err := a.verifyMTLS(ctx); err != nil {
			a.auditLogger("mTLS verification failed for %s: %v", info.FullMethod, err)
			return nil, status.Errorf(codes.Unauthenticated, "mTLS verification failed")
		}
	}

	// Step 2: JWT verification (H-4: secretless)
	if a.enableJWT {
		claims, err := a.verifyJWT(ctx)
		if err != nil {
			a.auditLogger("JWT verification failed for %s: %v", info.FullMethod, err)
			return nil, status.Errorf(codes.Unauthenticated, "JWT verification failed")
		}
		userID = claims.Subject
	}

	// Step 3: OPA authorization
	if a.enableOPA {
		if err := a.authorizeWithOPA(ctx, userID, info.FullMethod, req); err != nil {
			a.auditLogger("OPA authorization failed for user %s on %s: %v", userID, info.FullMethod, err)
			return nil, status.Errorf(codes.PermissionDenied, "authorization failed")
		}
	}

	// Step 4: Per-method token bucket rate limiting (H-4 requirement)
	if a.enableRateLimit {
		if err := a.checkPerMethodRateLimit(userID, info.FullMethod); err != nil {
			a.auditLogger("Rate limit exceeded for user %s on %s", userID, info.FullMethod)
			return nil, status.Errorf(codes.ResourceExhausted, "rate limit exceeded")
		}
	}

	// Call the handler
	resp, err := handler(ctx, req)

	// Audit log
	latency := time.Since(startTime)
	if err != nil {
		a.auditLogger("Request failed - method: %s, user: %s, client: %s, latency: %v, error: %v",
			info.FullMethod, userID, clientInfo, latency, err)
	} else {
		a.auditLogger("Request succeeded - method: %s, user: %s, client: %s, latency: %v",
			info.FullMethod, userID, clientInfo, latency)
	}

	return resp, err
}

// verifyMTLS verifies mTLS certificate chain
func (a *AuthInterceptor) verifyMTLS(ctx context.Context) error {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return fmt.Errorf("no peer information available")
	}

	tlsInfo, ok := peer.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return fmt.Errorf("connection is not TLS")
	}

	if len(tlsInfo.State.PeerCertificates) == 0 {
		return fmt.Errorf("no client certificate provided")
	}

	// Verify certificate chain
	clientCert := tlsInfo.State.PeerCertificates[0]
	_, err := clientCert.Verify(x509.VerifyOptions{
		Roots:       a.trustedCAs,
		CurrentTime: time.Now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})

	if err != nil {
		return fmt.Errorf("certificate verification failed: %v", err)
	}

	return nil
}

// verifyJWT verifies JWT token (H-4: uses secretless key from env-var)
func (a *AuthInterceptor) verifyJWT(ctx context.Context) (*jwt.RegisteredClaims, error) {
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

	// Parse and verify JWT using secretless key
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return a.jwtSigningKey, nil
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

	return claims, nil
}

// authorizeWithOPA checks authorization using Open Policy Agent
func (a *AuthInterceptor) authorizeWithOPA(ctx context.Context, userID, method string, req interface{}) error {
	input := map[string]interface{}{
		"user":    userID,
		"method":  method,
		"request": req,
		"time":    time.Now().Unix(),
	}

	allowed, err := a.opaClient.Authorize(ctx, input)
	if err != nil {
		return fmt.Errorf("OPA query failed: %v", err)
	}

	if !allowed {
		return fmt.Errorf("access denied by policy")
	}

	return nil
}

// checkPerMethodRateLimit checks per-method rate limits (H-4 requirement)
func (a *AuthInterceptor) checkPerMethodRateLimit(userID, method string) error {
	// Check global rate limit (1k QPS)
	if !a.rateLimiter.AllowGlobal() {
		return fmt.Errorf("global rate limit exceeded")
	}

	// Check per-user per-method rate limit (100 QPS)
	if userID != "" {
		if !a.rateLimiter.AllowUserMethod(userID, method) {
			return fmt.Errorf("per-method rate limit exceeded for user %s on %s", userID, method)
		}
	}

	return nil
}

// extractClientInfo extracts client information for audit logging
func (a *AuthInterceptor) extractClientInfo(ctx context.Context) string {
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

// PerMethodRateLimiter implements per-method rate limiting (H-4 requirement)
type PerMethodRateLimiter struct {
	globalLimiter      *rate.Limiter
	userMethodLimiters map[string]*rate.Limiter
	mutex              sync.RWMutex
	perMethodRate      rate.Limit
	perMethodBurst     int
}

// NewPerMethodRateLimiter creates a new per-method rate limiter
func NewPerMethodRateLimiter(globalQPS, perMethodQPS int) *PerMethodRateLimiter {
	return &PerMethodRateLimiter{
		globalLimiter:      rate.NewLimiter(rate.Limit(globalQPS), globalQPS/10),
		userMethodLimiters: make(map[string]*rate.Limiter),
		perMethodRate:      rate.Limit(perMethodQPS),
		perMethodBurst:     perMethodQPS / 10,
	}
}

// AllowGlobal checks global rate limit (1k QPS)
func (l *PerMethodRateLimiter) AllowGlobal() bool {
	return l.globalLimiter.Allow()
}

// AllowUserMethod checks per-user per-method rate limit (100 QPS)
func (l *PerMethodRateLimiter) AllowUserMethod(userID, method string) bool {
	key := fmt.Sprintf("%s:%s", userID, method)

	l.mutex.RLock()
	limiter, exists := l.userMethodLimiters[key]
	l.mutex.RUnlock()

	if !exists {
		l.mutex.Lock()
		limiter, exists = l.userMethodLimiters[key]
		if !exists {
			limiter = rate.NewLimiter(l.perMethodRate, l.perMethodBurst)
			l.userMethodLimiters[key] = limiter
		}
		l.mutex.Unlock()
	}

	return limiter.Allow()
}

// GetStats returns rate limiting statistics
func (l *PerMethodRateLimiter) GetStats() map[string]interface{} {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	return map[string]interface{}{
		"global_tokens":       l.globalLimiter.Tokens(),
		"active_user_methods": len(l.userMethodLimiters),
		"per_method_rate":     float64(l.perMethodRate),
		"per_method_burst":    l.perMethodBurst,
	}
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
	reqBody := map[string]interface{}{
		"input": input,
	}

	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		return false, fmt.Errorf("failed to marshal request: %v", err)
	}

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

	var result struct {
		Result bool `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, fmt.Errorf("failed to decode response: %v", err)
	}

	return result.Result, nil
}
