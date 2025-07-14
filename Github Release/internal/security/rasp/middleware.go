package rasp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// RASPMiddleware provides RASP integration for HTTP requests
type RASPMiddleware struct {
	engine *RASPEngine
	config *MiddlewareConfig
}

// MiddlewareConfig holds middleware configuration
type MiddlewareConfig struct {
	Enabled          bool
	SkipPaths        []string
	TrustedProxies   []string
	BlockingEnabled  bool
	AlertingEnabled  bool
	LoggingEnabled   bool
	MetricsEnabled   bool
	ResponseHeaders  map[string]string
	CustomErrorPage  string
	RateLimitHeaders bool
}

// NewRASPMiddleware creates a new RASP middleware
func NewRASPMiddleware(engine *RASPEngine, config *MiddlewareConfig) *RASPMiddleware {
	return &RASPMiddleware{
		engine: engine,
		config: config,
	}
}

// HTTPHandler returns an HTTP middleware handler
func (m *RASPMiddleware) HTTPHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.config.Enabled || m.shouldSkipPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()

		// Create request context
		reqCtx := m.createRequestContext(r)

		// Analyze request
		assessment, err := m.engine.AnalyzeRequest(reqCtx)
		if err != nil {
			// Log error and continue
			if m.config.LoggingEnabled {
				fmt.Printf("RASP analysis error: %v\n", err)
			}
			next.ServeHTTP(w, r)
			return
		}

		// Calculate analysis latency
		assessment.Latency = time.Since(start)

		// Handle threats
		if !assessment.Safe {
			m.handleThreats(w, r, assessment)
			return
		}

		// Add security headers
		m.addSecurityHeaders(w)

		// Add rate limit headers if enabled
		if m.config.RateLimitHeaders {
			m.addRateLimitHeaders(w, reqCtx.ClientIP)
		}

		// Continue with request
		next.ServeHTTP(w, r)
	})
}

// GRPCInterceptor returns a gRPC interceptor for RASP
func (m *RASPMiddleware) GRPCInterceptor() func(ctx context.Context, req interface{}, info interface{}, handler func(context.Context, interface{}) (interface{}, error)) (interface{}, error) {
	return func(ctx context.Context, req interface{}, info interface{}, handler func(context.Context, interface{}) (interface{}, error)) (interface{}, error) {
		if !m.config.Enabled {
			return handler(ctx, req)
		}

		start := time.Now()

		// Create request context for gRPC
		reqCtx := m.createGRPCRequestContext(ctx, req, info)

		// Analyze request
		assessment, err := m.engine.AnalyzeRequest(reqCtx)
		if err != nil {
			if m.config.LoggingEnabled {
				fmt.Printf("RASP gRPC analysis error: %v\n", err)
			}
			return handler(ctx, req)
		}

		assessment.Latency = time.Since(start)

		// Handle threats
		if !assessment.Safe {
			return nil, m.createGRPCError(assessment)
		}

		// Continue with request
		return handler(ctx, req)
	}
}

// SyscallInterceptor provides RASP protection for syscall handlers
func (m *RASPMiddleware) SyscallInterceptor() func(ctx context.Context, req interface{}, handler func(context.Context, interface{}) (interface{}, error)) (interface{}, error) {
	return func(ctx context.Context, req interface{}, handler func(context.Context, interface{}) (interface{}, error)) (interface{}, error) {
		if !m.config.Enabled {
			return handler(ctx, req)
		}

		start := time.Now()

		// Create request context for syscall
		reqCtx := m.createSyscallRequestContext(ctx, req)

		// Analyze request
		assessment, err := m.engine.AnalyzeRequest(reqCtx)
		if err != nil {
			if m.config.LoggingEnabled {
				fmt.Printf("RASP syscall analysis error: %v\n", err)
			}
			return handler(ctx, req)
		}

		assessment.Latency = time.Since(start)

		// Handle threats for syscalls
		if !assessment.Safe {
			return nil, m.createSyscallError(assessment)
		}

		// Continue with syscall
		return handler(ctx, req)
	}
}

// createRequestContext creates a request context from HTTP request
func (m *RASPMiddleware) createRequestContext(r *http.Request) *RequestContext {
	// Extract client IP
	clientIP := m.getClientIP(r)

	// Extract user ID from context or session
	userID := m.getUserID(r)

	// Read request body
	body := m.readRequestBody(r)

	// Extract parameters
	params := make(map[string]string)
	for key, values := range r.URL.Query() {
		if len(values) > 0 {
			params[key] = values[0]
		}
	}

	// Extract cookies
	cookies := make(map[string]string)
	for _, cookie := range r.Cookies() {
		cookies[cookie.Name] = cookie.Value
	}

	// Extract headers
	headers := make(map[string]string)
	for key, values := range r.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	return &RequestContext{
		ID:         fmt.Sprintf("req_%d", time.Now().UnixNano()),
		Endpoint:   r.URL.Path,
		Method:     r.Method,
		Headers:    headers,
		Body:       body,
		ClientIP:   clientIP,
		UserAgent:  r.UserAgent(),
		UserID:     userID,
		Timestamp:  time.Now(),
		Parameters: params,
		Cookies:    cookies,
	}
}

// createGRPCRequestContext creates a request context from gRPC request
func (m *RASPMiddleware) createGRPCRequestContext(ctx context.Context, req interface{}, info interface{}) *RequestContext {
	// Extract client IP from gRPC context
	clientIP := m.getGRPCClientIP(ctx)

	// Extract user ID from gRPC context
	userID := m.getGRPCUserID(ctx)

	// Serialize request for analysis
	body, _ := json.Marshal(req)

	// Extract method name
	method := fmt.Sprintf("%v", info)

	return &RequestContext{
		ID:         fmt.Sprintf("grpc_%d", time.Now().UnixNano()),
		Endpoint:   method,
		Method:     "gRPC",
		Headers:    make(map[string]string),
		Body:       string(body),
		ClientIP:   clientIP,
		UserAgent:  "gRPC-Client",
		UserID:     userID,
		Timestamp:  time.Now(),
		Parameters: make(map[string]string),
		Cookies:    make(map[string]string),
	}
}

// createSyscallRequestContext creates a request context from syscall request
func (m *RASPMiddleware) createSyscallRequestContext(ctx context.Context, req interface{}) *RequestContext {
	// Extract client information from context
	clientIP := m.getSyscallClientIP(ctx)
	userID := m.getSyscallUserID(ctx)

	// Serialize request for analysis
	body, _ := json.Marshal(req)

	// Determine syscall type
	syscallType := fmt.Sprintf("%T", req)

	return &RequestContext{
		ID:         fmt.Sprintf("syscall_%d", time.Now().UnixNano()),
		Endpoint:   syscallType,
		Method:     "SYSCALL",
		Headers:    make(map[string]string),
		Body:       string(body),
		ClientIP:   clientIP,
		UserAgent:  "CAM-Syscall",
		UserID:     userID,
		Timestamp:  time.Now(),
		Parameters: make(map[string]string),
		Cookies:    make(map[string]string),
	}
}

// handleThreats handles detected threats
func (m *RASPMiddleware) handleThreats(w http.ResponseWriter, r *http.Request, assessment *ThreatAssessment) {
	// Determine response based on threat level
	highestLevel := ThreatLevelInfo
	for _, threat := range assessment.Threats {
		if threat.Level > highestLevel {
			highestLevel = threat.Level
		}
	}

	// Log threats
	if m.config.LoggingEnabled {
		m.logThreats(assessment)
	}

	// Send alerts
	if m.config.AlertingEnabled {
		m.sendThreatAlert(assessment)
	}

	// Block request if blocking is enabled
	if m.config.BlockingEnabled {
		m.blockRequest(w, r, assessment, highestLevel)
	}
}

// blockRequest blocks the request based on threat level
func (m *RASPMiddleware) blockRequest(w http.ResponseWriter, r *http.Request, assessment *ThreatAssessment, level ThreatLevel) {
	// Set security headers
	m.addSecurityHeaders(w)

	// Set appropriate status code
	var statusCode int
	var message string

	switch level {
	case ThreatLevelCritical:
		statusCode = http.StatusForbidden
		message = "Request blocked due to critical security threat"
	case ThreatLevelHigh:
		statusCode = http.StatusForbidden
		message = "Request blocked due to high security threat"
	case ThreatLevelMedium:
		statusCode = http.StatusTooManyRequests
		message = "Request blocked due to suspicious activity"
	default:
		statusCode = http.StatusBadRequest
		message = "Request blocked due to security policy"
	}

	// Use custom error page if configured
	if m.config.CustomErrorPage != "" {
		http.ServeFile(w, r, m.config.CustomErrorPage)
		return
	}

	// Send JSON error response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	errorResponse := map[string]interface{}{
		"error": map[string]interface{}{
			"code":       statusCode,
			"message":    message,
			"timestamp":  time.Now().Unix(),
			"request_id": assessment.RequestID,
		},
	}

	json.NewEncoder(w).Encode(errorResponse)
}

// createGRPCError creates a gRPC error for threats
func (m *RASPMiddleware) createGRPCError(assessment *ThreatAssessment) error {
	// Determine error based on threat level
	highestLevel := ThreatLevelInfo
	for _, threat := range assessment.Threats {
		if threat.Level > highestLevel {
			highestLevel = threat.Level
		}
	}

	switch highestLevel {
	case ThreatLevelCritical:
		return fmt.Errorf("PERMISSION_DENIED: Critical security threat detected")
	case ThreatLevelHigh:
		return fmt.Errorf("PERMISSION_DENIED: High security threat detected")
	case ThreatLevelMedium:
		return fmt.Errorf("RESOURCE_EXHAUSTED: Suspicious activity detected")
	default:
		return fmt.Errorf("INVALID_ARGUMENT: Security policy violation")
	}
}

// createSyscallError creates a syscall error for threats
func (m *RASPMiddleware) createSyscallError(assessment *ThreatAssessment) error {
	// Determine error based on threat level
	highestLevel := ThreatLevelInfo
	for _, threat := range assessment.Threats {
		if threat.Level > highestLevel {
			highestLevel = threat.Level
		}
	}

	switch highestLevel {
	case ThreatLevelCritical:
		return fmt.Errorf("syscall blocked: critical security threat detected (ID: %s)", assessment.RequestID)
	case ThreatLevelHigh:
		return fmt.Errorf("syscall blocked: high security threat detected (ID: %s)", assessment.RequestID)
	case ThreatLevelMedium:
		return fmt.Errorf("syscall rejected: suspicious activity detected (ID: %s)", assessment.RequestID)
	default:
		return fmt.Errorf("syscall rejected: security policy violation (ID: %s)", assessment.RequestID)
	}
}

// Helper methods

func (m *RASPMiddleware) shouldSkipPath(path string) bool {
	for _, skipPath := range m.config.SkipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

func (m *RASPMiddleware) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return strings.TrimSpace(xri)
	}

	// Use remote address
	ip := r.RemoteAddr
	if strings.Contains(ip, ":") {
		ip = strings.Split(ip, ":")[0]
	}
	return ip
}

func (m *RASPMiddleware) getUserID(r *http.Request) string {
	// Try to extract user ID from various sources

	// Check Authorization header
	auth := r.Header.Get("Authorization")
	if auth != "" && strings.HasPrefix(auth, "Bearer ") {
		// In a real implementation, decode JWT token
		return "user_from_token"
	}

	// Check session cookie
	if cookie, err := r.Cookie("session_id"); err == nil {
		return fmt.Sprintf("user_session_%s", cookie.Value)
	}

	// Check X-User-ID header
	if userID := r.Header.Get("X-User-ID"); userID != "" {
		return userID
	}

	return "anonymous"
}

func (m *RASPMiddleware) readRequestBody(r *http.Request) string {
	// In a real implementation, would read and restore body
	// For now, return empty string to avoid consuming body
	return ""
}

func (m *RASPMiddleware) getGRPCClientIP(ctx context.Context) string {
	// Extract client IP from gRPC context
	// In a real implementation, would use gRPC metadata
	return "127.0.0.1"
}

func (m *RASPMiddleware) getGRPCUserID(ctx context.Context) string {
	// Extract user ID from gRPC context
	// In a real implementation, would use gRPC metadata
	return "grpc_user"
}

func (m *RASPMiddleware) getSyscallClientIP(ctx context.Context) string {
	// Extract client IP from syscall context
	if ip, ok := ctx.Value("client_ip").(string); ok {
		return ip
	}
	return "127.0.0.1"
}

func (m *RASPMiddleware) getSyscallUserID(ctx context.Context) string {
	// Extract user ID from syscall context
	if userID, ok := ctx.Value("user_id").(string); ok {
		return userID
	}
	return "syscall_user"
}

func (m *RASPMiddleware) addSecurityHeaders(w http.ResponseWriter) {
	// Add standard security headers
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	w.Header().Set("Content-Security-Policy", "default-src 'self'")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

	// Add custom headers
	for key, value := range m.config.ResponseHeaders {
		w.Header().Set(key, value)
	}
}

func (m *RASPMiddleware) addRateLimitHeaders(w http.ResponseWriter, clientIP string) {
	// Add rate limit headers based on current limits
	// In a real implementation, would query actual rate limit state
	w.Header().Set("X-RateLimit-Limit", "1000")
	w.Header().Set("X-RateLimit-Remaining", "999")
	w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(time.Hour).Unix()))
}

func (m *RASPMiddleware) logThreats(assessment *ThreatAssessment) {
	for _, threat := range assessment.Threats {
		fmt.Printf("[RASP] Threat detected: ID=%s, Type=%s, Level=%d, Source=%s, Target=%s, Confidence=%.2f\n",
			threat.ID, threat.Type, threat.Level, threat.Source, threat.Target, threat.Confidence)
	}
}

func (m *RASPMiddleware) sendThreatAlert(assessment *ThreatAssessment) {
	// In a real implementation, would send alerts to security team
	// via email, Slack, PagerDuty, etc.
	fmt.Printf("[RASP] SECURITY ALERT: %d threats detected in request %s\n",
		len(assessment.Threats), assessment.RequestID)
}

// GetMetrics returns current RASP metrics
func (m *RASPMiddleware) GetMetrics() *RASPMetrics {
	return m.engine.metrics
}

// GetThreatHistory returns recent threat history
func (m *RASPMiddleware) GetThreatHistory(limit int) []Threat {
	m.engine.threatsMutex.RLock()
	defer m.engine.threatsMutex.RUnlock()

	threats := make([]Threat, 0)
	start := len(m.engine.threats) - limit
	if start < 0 {
		start = 0
	}

	for i := start; i < len(m.engine.threats); i++ {
		threats = append(threats, m.engine.threats[i])
	}

	return threats
}

// UpdateRules updates RASP detection rules
func (m *RASPMiddleware) UpdateRules(rules []*Rule) error {
	m.engine.rulesMutex.Lock()
	defer m.engine.rulesMutex.Unlock()

	for _, rule := range rules {
		rule.UpdatedAt = time.Now()
		m.engine.rules[rule.ID] = rule
	}

	return nil
}

// GetActiveRules returns currently active rules
func (m *RASPMiddleware) GetActiveRules() []*Rule {
	return m.engine.getRules()
}
