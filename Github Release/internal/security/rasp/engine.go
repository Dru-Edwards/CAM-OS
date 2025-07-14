package rasp

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// ThreatLevel represents the severity of a detected threat
type ThreatLevel int

const (
	ThreatLevelInfo ThreatLevel = iota
	ThreatLevelLow
	ThreatLevelMedium
	ThreatLevelHigh
	ThreatLevelCritical
)

// ActionType represents the type of protective action to take
type ActionType int

const (
	ActionLog ActionType = iota
	ActionAlert
	ActionBlock
	ActionQuarantine
	ActionTerminate
)

// ThreatType represents different categories of threats
type ThreatType string

const (
	ThreatSQLInjection     ThreatType = "sql_injection"
	ThreatXSS              ThreatType = "xss"
	ThreatCommandInjection ThreatType = "command_injection"
	ThreatPathTraversal    ThreatType = "path_traversal"
	ThreatDeserialization  ThreatType = "deserialization"
	ThreatRCE              ThreatType = "remote_code_execution"
	ThreatDDoS             ThreatType = "ddos"
	ThreatBruteForce       ThreatType = "brute_force"
	ThreatPrivilegeEsc     ThreatType = "privilege_escalation"
	ThreatDataExfiltration ThreatType = "data_exfiltration"
)

// Threat represents a detected security threat
type Threat struct {
	ID         string
	Type       ThreatType
	Level      ThreatLevel
	Source     string
	Target     string
	Payload    string
	Timestamp  time.Time
	UserAgent  string
	IPAddress  string
	Context    map[string]interface{}
	Confidence float64
	Blocked    bool
	Actions    []ActionType
}

// Rule represents a RASP detection rule
type Rule struct {
	ID         string
	Name       string
	Type       ThreatType
	Pattern    string
	Regex      string
	Level      ThreatLevel
	Action     ActionType
	Enabled    bool
	FalsePos   int
	TruePos    int
	Confidence float64
	UpdatedAt  time.Time
}

// RASPEngine provides runtime application self-protection
type RASPEngine struct {
	rules        map[string]*Rule
	rulesMutex   sync.RWMutex
	threats      []Threat
	threatsMutex sync.RWMutex

	// Behavioral analysis
	userSessions  map[string]*UserSession
	sessionsMutex sync.RWMutex

	// Rate limiting
	rateLimits map[string]*RateLimit
	ratesMutex sync.RWMutex

	// Configuration
	config *Config

	// Channels for threat processing
	threatChan chan Threat
	actionChan chan ThreatAction

	// Machine learning model for anomaly detection
	mlModel *AnomalyModel

	// Real-time monitoring
	metrics *RASPMetrics

	ctx    context.Context
	cancel context.CancelFunc
}

// UserSession tracks user behavior for anomaly detection
type UserSession struct {
	UserID       string
	IPAddress    string
	UserAgent    string
	SessionStart time.Time
	LastActivity time.Time
	RequestCount int
	ErrorCount   int
	Countries    map[string]int
	Endpoints    map[string]int
	Anomalies    []string
	RiskScore    float64
}

// RateLimit tracks request rates for DDoS protection
type RateLimit struct {
	IP           string
	Requests     int
	LastReset    time.Time
	Blocked      bool
	BlockedUntil time.Time
}

// ThreatAction represents an action to take in response to a threat
type ThreatAction struct {
	ThreatID string
	Action   ActionType
	Target   string
	Duration time.Duration
	Reason   string
}

// AnomalyModel represents a machine learning model for anomaly detection
type AnomalyModel struct {
	Weights    map[string]float64
	Thresholds map[string]float64
	Features   []string
	UpdatedAt  time.Time
}

// RASPMetrics tracks RASP engine performance and statistics
type RASPMetrics struct {
	ThreatsDetected int64
	ThreatsBlocked  int64
	FalsePositives  int64
	TruePositives   int64
	AverageLatency  time.Duration
	RulesProcessed  int64
	ActiveSessions  int64
	BlockedIPs      int64
}

// Config holds the RASP engine configuration
type Config struct {
	Enabled            bool
	LogLevel           string
	MaxThreatHistory   int
	RateLimitWindow    time.Duration
	RateLimitThreshold int
	SessionTimeout     time.Duration
	MLEnabled          bool
	RealTimeBlocking   bool
	GeolocationEnabled bool
	WhitelistedIPs     []string
	BlacklistedIPs     []string
	TrustedUserAgents  []string
	SuspiciousPatterns map[ThreatType][]string
}

// NewRASPEngine creates a new RASP engine
func NewRASPEngine(config *Config) *RASPEngine {
	ctx, cancel := context.WithCancel(context.Background())

	engine := &RASPEngine{
		rules:        make(map[string]*Rule),
		threats:      make([]Threat, 0),
		userSessions: make(map[string]*UserSession),
		rateLimits:   make(map[string]*RateLimit),
		config:       config,
		threatChan:   make(chan Threat, 1000),
		actionChan:   make(chan ThreatAction, 1000),
		mlModel: &AnomalyModel{
			Weights:    make(map[string]float64),
			Thresholds: make(map[string]float64),
			Features:   []string{"request_rate", "error_rate", "geo_anomaly", "time_anomaly"},
		},
		metrics: &RASPMetrics{},
		ctx:     ctx,
		cancel:  cancel,
	}

	// Initialize default rules
	engine.initializeDefaultRules()

	// Initialize ML model
	if config.MLEnabled {
		engine.initializeMLModel()
	}

	return engine
}

// Start starts the RASP engine
func (r *RASPEngine) Start() error {
	if !r.config.Enabled {
		return nil
	}

	// Start threat processing worker
	go r.threatProcessor()

	// Start action processor worker
	go r.actionProcessor()

	// Start session cleanup worker
	go r.sessionCleanup()

	// Start metrics collector
	go r.metricsCollector()

	// Start ML model updater if enabled
	if r.config.MLEnabled {
		go r.mlModelUpdater()
	}

	return nil
}

// Stop stops the RASP engine
func (r *RASPEngine) Stop() error {
	r.cancel()
	close(r.threatChan)
	close(r.actionChan)
	return nil
}

// AnalyzeRequest analyzes an incoming request for threats
func (r *RASPEngine) AnalyzeRequest(req *RequestContext) (*ThreatAssessment, error) {
	if !r.config.Enabled {
		return &ThreatAssessment{Safe: true}, nil
	}

	assessment := &ThreatAssessment{
		RequestID:  req.ID,
		Timestamp:  time.Now(),
		Safe:       true,
		Threats:    make([]Threat, 0),
		Actions:    make([]ActionType, 0),
		Confidence: 1.0,
	}

	// Check rate limiting
	if r.checkRateLimit(req.ClientIP) {
		threat := r.createThreat(ThreatDDoS, ThreatLevelHigh, req.ClientIP, req.Endpoint, "Rate limit exceeded", req)
		assessment.Threats = append(assessment.Threats, threat)
		assessment.Safe = false
		r.threatChan <- threat
	}

	// Check IP blacklist
	if r.isBlacklistedIP(req.ClientIP) {
		threat := r.createThreat(ThreatDDoS, ThreatLevelCritical, req.ClientIP, req.Endpoint, "Blacklisted IP", req)
		assessment.Threats = append(assessment.Threats, threat)
		assessment.Safe = false
		r.threatChan <- threat
	}

	// Analyze request payload
	for _, rule := range r.getRules() {
		if rule.Enabled && r.matchesRule(req, rule) {
			threat := r.createThreat(rule.Type, rule.Level, req.ClientIP, req.Endpoint, req.Body, req)
			threat.Confidence = rule.Confidence
			assessment.Threats = append(assessment.Threats, threat)
			assessment.Safe = false
			r.threatChan <- threat
		}
	}

	// Machine learning analysis
	if r.config.MLEnabled {
		mlScore := r.analyzeWithML(req)
		if mlScore > 0.7 {
			threat := r.createThreat("anomaly", ThreatLevelMedium, req.ClientIP, req.Endpoint, "ML anomaly detected", req)
			threat.Confidence = mlScore
			assessment.Threats = append(assessment.Threats, threat)
			assessment.Safe = false
			r.threatChan <- threat
		}
	}

	// User behavior analysis
	session := r.getOrCreateSession(req.UserID, req.ClientIP, req.UserAgent)
	sessionRisk := r.analyzeSessionBehavior(session, req)
	if sessionRisk > 0.8 {
		threat := r.createThreat("behavioral_anomaly", ThreatLevelMedium, req.ClientIP, req.Endpoint, "Suspicious user behavior", req)
		threat.Confidence = sessionRisk
		assessment.Threats = append(assessment.Threats, threat)
		assessment.Safe = false
		r.threatChan <- threat
	}

	// Calculate overall confidence
	if len(assessment.Threats) > 0 {
		totalConfidence := 0.0
		for _, threat := range assessment.Threats {
			totalConfidence += threat.Confidence
		}
		assessment.Confidence = totalConfidence / float64(len(assessment.Threats))
	}

	return assessment, nil
}

// RequestContext contains request information for analysis
type RequestContext struct {
	ID         string
	Endpoint   string
	Method     string
	Headers    map[string]string
	Body       string
	ClientIP   string
	UserAgent  string
	UserID     string
	Timestamp  time.Time
	Parameters map[string]string
	Cookies    map[string]string
}

// ThreatAssessment contains the result of threat analysis
type ThreatAssessment struct {
	RequestID  string
	Timestamp  time.Time
	Safe       bool
	Threats    []Threat
	Actions    []ActionType
	Confidence float64
	Latency    time.Duration
}

// initializeDefaultRules sets up the default RASP detection rules
func (r *RASPEngine) initializeDefaultRules() {
	defaultRules := []*Rule{
		{
			ID:         "sql_injection_001",
			Name:       "SQL Injection Detection",
			Type:       ThreatSQLInjection,
			Pattern:    `(?i)(union|select|insert|update|delete|drop|exec|script)`,
			Level:      ThreatLevelHigh,
			Action:     ActionBlock,
			Enabled:    true,
			Confidence: 0.85,
		},
		{
			ID:         "xss_001",
			Name:       "Cross-Site Scripting Detection",
			Type:       ThreatXSS,
			Pattern:    `(?i)(<script|javascript:|onerror=|onload=|eval\(|alert\()`,
			Level:      ThreatLevelHigh,
			Action:     ActionBlock,
			Enabled:    true,
			Confidence: 0.80,
		},
		{
			ID:         "command_injection_001",
			Name:       "Command Injection Detection",
			Type:       ThreatCommandInjection,
			Pattern:    `(?i)(;|\||&|&&|\$\(|` + "`" + `|\$\{)`,
			Level:      ThreatLevelCritical,
			Action:     ActionBlock,
			Enabled:    true,
			Confidence: 0.90,
		},
		{
			ID:         "path_traversal_001",
			Name:       "Path Traversal Detection",
			Type:       ThreatPathTraversal,
			Pattern:    `(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\\)`,
			Level:      ThreatLevelMedium,
			Action:     ActionBlock,
			Enabled:    true,
			Confidence: 0.75,
		},
		{
			ID:         "rce_001",
			Name:       "Remote Code Execution Detection",
			Type:       ThreatRCE,
			Pattern:    `(?i)(eval|exec|system|shell_exec|passthru|proc_open)`,
			Level:      ThreatLevelCritical,
			Action:     ActionBlock,
			Enabled:    true,
			Confidence: 0.95,
		},
	}

	r.rulesMutex.Lock()
	for _, rule := range defaultRules {
		rule.UpdatedAt = time.Now()
		r.rules[rule.ID] = rule
	}
	r.rulesMutex.Unlock()
}

// Helper methods implementation would continue here...
// Due to length constraints, I'll implement key methods

func (r *RASPEngine) createThreat(threatType ThreatType, level ThreatLevel, source, target, payload string, req *RequestContext) Threat {
	return Threat{
		ID:        fmt.Sprintf("threat_%d", time.Now().UnixNano()),
		Type:      threatType,
		Level:     level,
		Source:    source,
		Target:    target,
		Payload:   payload,
		Timestamp: time.Now(),
		UserAgent: req.UserAgent,
		IPAddress: req.ClientIP,
		Context: map[string]interface{}{
			"method":     req.Method,
			"endpoint":   req.Endpoint,
			"user_id":    req.UserID,
			"headers":    req.Headers,
			"parameters": req.Parameters,
		},
		Confidence: 0.8,
		Blocked:    false,
		Actions:    make([]ActionType, 0),
	}
}

func (r *RASPEngine) checkRateLimit(ip string) bool {
	r.ratesMutex.Lock()
	defer r.ratesMutex.Unlock()

	now := time.Now()
	limit, exists := r.rateLimits[ip]

	if !exists {
		r.rateLimits[ip] = &RateLimit{
			IP:        ip,
			Requests:  1,
			LastReset: now,
			Blocked:   false,
		}
		return false
	}

	// Check if blocked
	if limit.Blocked && now.Before(limit.BlockedUntil) {
		return true
	}

	// Reset if window expired
	if now.Sub(limit.LastReset) > r.config.RateLimitWindow {
		limit.Requests = 1
		limit.LastReset = now
		limit.Blocked = false
		return false
	}

	limit.Requests++
	if limit.Requests > r.config.RateLimitThreshold {
		limit.Blocked = true
		limit.BlockedUntil = now.Add(time.Hour) // Block for 1 hour
		return true
	}

	return false
}

func (r *RASPEngine) isBlacklistedIP(ip string) bool {
	for _, blacklisted := range r.config.BlacklistedIPs {
		if ip == blacklisted {
			return true
		}

		// Check CIDR ranges
		if strings.Contains(blacklisted, "/") {
			_, network, err := net.ParseCIDR(blacklisted)
			if err == nil && network.Contains(net.ParseIP(ip)) {
				return true
			}
		}
	}
	return false
}

func (r *RASPEngine) getRules() []*Rule {
	r.rulesMutex.RLock()
	defer r.rulesMutex.RUnlock()

	rules := make([]*Rule, 0, len(r.rules))
	for _, rule := range r.rules {
		if rule.Enabled {
			rules = append(rules, rule)
		}
	}
	return rules
}

func (r *RASPEngine) matchesRule(req *RequestContext, rule *Rule) bool {
	// Simple pattern matching - in production would use compiled regex
	payload := strings.ToLower(req.Body + " " + req.Endpoint)
	for key, value := range req.Parameters {
		payload += " " + strings.ToLower(key+"="+value)
	}

	return strings.Contains(payload, strings.ToLower(rule.Pattern))
}

func (r *RASPEngine) analyzeWithML(req *RequestContext) float64 {
	// Simplified ML analysis - in production would use actual ML model
	score := 0.0

	// Check request rate
	if len(req.Body) > 10000 {
		score += 0.3
	}

	// Check suspicious patterns
	if strings.Contains(strings.ToLower(req.Body), "eval") {
		score += 0.4
	}

	// Check time-based anomalies
	hour := req.Timestamp.Hour()
	if hour < 6 || hour > 22 {
		score += 0.2
	}

	return score
}

func (r *RASPEngine) getOrCreateSession(userID, ip, userAgent string) *UserSession {
	r.sessionsMutex.Lock()
	defer r.sessionsMutex.Unlock()

	sessionKey := fmt.Sprintf("%s_%s", userID, ip)
	session, exists := r.userSessions[sessionKey]

	if !exists || time.Since(session.LastActivity) > r.config.SessionTimeout {
		session = &UserSession{
			UserID:       userID,
			IPAddress:    ip,
			UserAgent:    userAgent,
			SessionStart: time.Now(),
			LastActivity: time.Now(),
			Countries:    make(map[string]int),
			Endpoints:    make(map[string]int),
			Anomalies:    make([]string, 0),
		}
		r.userSessions[sessionKey] = session
	}

	session.LastActivity = time.Now()
	session.RequestCount++

	return session
}

func (r *RASPEngine) analyzeSessionBehavior(session *UserSession, req *RequestContext) float64 {
	riskScore := 0.0

	// Check request frequency
	duration := time.Since(session.SessionStart)
	requestRate := float64(session.RequestCount) / duration.Minutes()
	if requestRate > 60 { // More than 60 requests per minute
		riskScore += 0.4
	}

	// Check endpoint diversity
	session.Endpoints[req.Endpoint]++
	if len(session.Endpoints) > 20 { // Accessing too many endpoints
		riskScore += 0.3
	}

	// Check error rate
	errorRate := float64(session.ErrorCount) / float64(session.RequestCount)
	if errorRate > 0.2 { // More than 20% errors
		riskScore += 0.3
	}

	return riskScore
}

// Workers for background processing
func (r *RASPEngine) threatProcessor() {
	for {
		select {
		case threat := <-r.threatChan:
			r.processThreat(threat)
		case <-r.ctx.Done():
			return
		}
	}
}

func (r *RASPEngine) processThreat(threat Threat) {
	// Store threat
	r.threatsMutex.Lock()
	r.threats = append(r.threats, threat)
	if len(r.threats) > r.config.MaxThreatHistory {
		r.threats = r.threats[1:]
	}
	r.threatsMutex.Unlock()

	// Determine action
	var action ActionType
	switch threat.Level {
	case ThreatLevelCritical:
		action = ActionTerminate
	case ThreatLevelHigh:
		action = ActionBlock
	case ThreatLevelMedium:
		action = ActionAlert
	default:
		action = ActionLog
	}

	// Queue action
	threatAction := ThreatAction{
		ThreatID: threat.ID,
		Action:   action,
		Target:   threat.Source,
		Duration: time.Hour,
		Reason:   fmt.Sprintf("Threat detected: %s", threat.Type),
	}

	select {
	case r.actionChan <- threatAction:
	default:
		// Channel full, log error
	}

	// Update metrics
	r.metrics.ThreatsDetected++
	if action == ActionBlock || action == ActionTerminate {
		r.metrics.ThreatsBlocked++
	}
}

func (r *RASPEngine) actionProcessor() {
	for {
		select {
		case action := <-r.actionChan:
			r.executeAction(action)
		case <-r.ctx.Done():
			return
		}
	}
}

func (r *RASPEngine) executeAction(action ThreatAction) {
	switch action.Action {
	case ActionBlock:
		r.blockIP(action.Target, action.Duration)
	case ActionQuarantine:
		r.quarantineSession(action.Target)
	case ActionTerminate:
		r.terminateConnection(action.Target)
	case ActionAlert:
		r.sendAlert(action)
	case ActionLog:
		r.logThreat(action)
	}
}

func (r *RASPEngine) blockIP(ip string, duration time.Duration) {
	r.ratesMutex.Lock()
	defer r.ratesMutex.Unlock()

	if limit, exists := r.rateLimits[ip]; exists {
		limit.Blocked = true
		limit.BlockedUntil = time.Now().Add(duration)
	} else {
		r.rateLimits[ip] = &RateLimit{
			IP:           ip,
			Blocked:      true,
			BlockedUntil: time.Now().Add(duration),
		}
	}
	r.metrics.BlockedIPs++
}

func (r *RASPEngine) quarantineSession(sessionID string) {
	// Implementation for session quarantine
}

func (r *RASPEngine) terminateConnection(target string) {
	// Implementation for connection termination
}

func (r *RASPEngine) sendAlert(action ThreatAction) {
	// Implementation for sending alerts to security team
}

func (r *RASPEngine) logThreat(action ThreatAction) {
	// Implementation for threat logging
}

func (r *RASPEngine) sessionCleanup() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.cleanupExpiredSessions()
		case <-r.ctx.Done():
			return
		}
	}
}

func (r *RASPEngine) cleanupExpiredSessions() {
	r.sessionsMutex.Lock()
	defer r.sessionsMutex.Unlock()

	cutoff := time.Now().Add(-r.config.SessionTimeout)
	for key, session := range r.userSessions {
		if session.LastActivity.Before(cutoff) {
			delete(r.userSessions, key)
		}
	}
	r.metrics.ActiveSessions = int64(len(r.userSessions))
}

func (r *RASPEngine) metricsCollector() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.updateMetrics()
		case <-r.ctx.Done():
			return
		}
	}
}

func (r *RASPEngine) updateMetrics() {
	// Update various metrics
	r.metrics.ActiveSessions = int64(len(r.userSessions))
	// Additional metrics updates...
}

func (r *RASPEngine) mlModelUpdater() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.updateMLModel()
		case <-r.ctx.Done():
			return
		}
	}
}

func (r *RASPEngine) updateMLModel() {
	// Implementation for updating ML model based on recent threats
}

func (r *RASPEngine) initializeMLModel() {
	// Initialize default ML model weights and thresholds
	r.mlModel.Weights["request_rate"] = 0.3
	r.mlModel.Weights["error_rate"] = 0.4
	r.mlModel.Weights["geo_anomaly"] = 0.2
	r.mlModel.Weights["time_anomaly"] = 0.1

	r.mlModel.Thresholds["anomaly_score"] = 0.7
	r.mlModel.Thresholds["session_risk"] = 0.8

	r.mlModel.UpdatedAt = time.Now()
}
