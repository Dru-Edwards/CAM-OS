package zerotrust

import (
	"context"
	"fmt"
	"net"
	"time"
)

// CAMZeroTrustIntegration provides integration with CAM-OS security infrastructure
type CAMZeroTrustIntegration struct {
	ztEngine   *ZeroTrustEngine
	config     *IntegrationConfig
	middleware *ZeroTrustMiddleware
}

// IntegrationConfig holds integration configuration
type IntegrationConfig struct {
	Enabled                bool
	AutoRegisterEntities   bool
	EnforceNetworkPolicy   bool
	RequireAuthentication  bool
	ContinuousMonitoring   bool
	RiskBasedAccess        bool
	MicroSegmentation      bool
	PolicyEnforcement      bool
	AuditAllRequests       bool
	BlockHighRiskRequests  bool
	MaxRiskThreshold       float64
	SessionTimeoutOverride time.Duration
	DefaultZoneAssignment  SecurityZone
	TrustLevelMapping      map[string]TrustLevel
}

// ZeroTrustMiddleware provides middleware for zero-trust enforcement
type ZeroTrustMiddleware struct {
	integration *CAMZeroTrustIntegration
}

// RequestContext represents a request context for zero-trust evaluation
type RequestContext struct {
	UserID      string
	DeviceID    string
	IPAddress   string
	UserAgent   string
	Endpoint    string
	Method      string
	Headers     map[string]string
	Body        string
	Timestamp   time.Time
	SessionID   string
	ClientCert  []byte
	Geolocation *GeolocationData
	Risk        float64
}

// NewCAMZeroTrustIntegration creates a new CAM zero-trust integration
func NewCAMZeroTrustIntegration(config *IntegrationConfig) *CAMZeroTrustIntegration {
	// Create zero-trust engine config
	ztConfig := &Config{
		Enabled:                true,
		DefaultTrustLevel:      TrustLevelLow,
		DefaultSecurityZone:    config.DefaultZoneAssignment,
		SessionTimeout:         config.SessionTimeoutOverride,
		RiskThreshold:          config.MaxRiskThreshold,
		ContinuousAuth:         config.ContinuousMonitoring,
		DeviceVerification:     true,
		GeolocationEnabled:     true,
		BehaviorAnalysis:       true,
		NetworkSegmentation:    config.MicroSegmentation,
		EncryptionRequired:     true,
		CertificateValidation:  true,
		AuditLogging:           config.AuditAllRequests,
		MaxSessions:            10000,
		MaxEntities:            50000,
		PolicyUpdateInterval:   time.Hour,
		RiskUpdateInterval:     15 * time.Minute,
	}
	
	// Create zero-trust engine
	ztEngine := NewZeroTrustEngine(ztConfig)
	
	integration := &CAMZeroTrustIntegration{
		ztEngine: ztEngine,
		config:   config,
	}
	
	// Create middleware
	integration.middleware = &ZeroTrustMiddleware{
		integration: integration,
	}
	
	return integration
}

// Start starts the zero-trust integration
func (c *CAMZeroTrustIntegration) Start() error {
	if !c.config.Enabled {
		return nil
	}
	
	return c.ztEngine.Start()
}

// Stop stops the zero-trust integration
func (c *CAMZeroTrustIntegration) Stop() error {
	return c.ztEngine.Stop()
}

// RegisterCAMEntity registers a CAM entity with the zero-trust system
func (c *CAMZeroTrustIntegration) RegisterCAMEntity(entityID, entityType, userID, ipAddress string) error {
	// Map entity type
	var ztEntityType EntityType
	switch entityType {
	case "user":
		ztEntityType = EntityTypeUser
	case "device":
		ztEntityType = EntityTypeDevice
	case "service":
		ztEntityType = EntityTypeService
	case "agent":
		ztEntityType = EntityTypeAgent
	default:
		ztEntityType = EntityTypeDevice
	}
	
	// Determine initial trust level
	trustLevel := c.config.TrustLevelMapping[entityType]
	if trustLevel == 0 {
		trustLevel = TrustLevelLow
	}
	
	// Determine security zone based on IP
	securityZone := c.determineSecurityZone(ipAddress)
	
	// Create entity
	entity := &Entity{
		ID:           entityID,
		Type:         ztEntityType,
		Name:         entityID,
		IPAddress:    ipAddress,
		UserID:       userID,
		TrustLevel:   trustLevel,
		SecurityZone: securityZone,
		Attributes:   make(map[string]string),
		Policies:     make([]string, 0),
		Verified:     false,
		Compromised:  false,
	}
	
	// Add CAM-specific attributes
	entity.Attributes["cam_entity_type"] = entityType
	entity.Attributes["cam_user_id"] = userID
	entity.Attributes["registration_source"] = "cam_os"
	
	return c.ztEngine.RegisterEntity(entity)
}

// EvaluateCAMAccess evaluates a CAM access request
func (c *CAMZeroTrustIntegration) EvaluateCAMAccess(ctx *RequestContext) (*AccessEvaluationResult, error) {
	// Auto-register entity if enabled
	if c.config.AutoRegisterEntities {
		entityID := c.generateEntityID(ctx.UserID, ctx.DeviceID, ctx.IPAddress)
		c.RegisterCAMEntity(entityID, "user", ctx.UserID, ctx.IPAddress)
	}
	
	// Create access request
	accessRequest := &AccessRequest{
		ID:          c.generateRequestID(),
		RequestorID: c.generateEntityID(ctx.UserID, ctx.DeviceID, ctx.IPAddress),
		ResourceID:  ctx.Endpoint,
		Action:      ctx.Method,
		Timestamp:   ctx.Timestamp,
		Context: map[string]interface{}{
			"user_id":    ctx.UserID,
			"device_id":  ctx.DeviceID,
			"session_id": ctx.SessionID,
			"headers":    ctx.Headers,
			"body":       ctx.Body,
		},
		IPAddress:   ctx.IPAddress,
		UserAgent:   ctx.UserAgent,
		ClientCert:  ctx.ClientCert,
		Geolocation: ctx.Geolocation,
		Risk:        ctx.Risk,
	}
	
	// Evaluate access
	decision, err := c.ztEngine.EvaluateAccess(accessRequest)
	if err != nil {
		return nil, fmt.Errorf("zero-trust access evaluation failed: %v", err)
	}
	
	// Convert to CAM result
	result := &AccessEvaluationResult{
		RequestID:         accessRequest.ID,
		Allowed:           decision.Decision == PolicyActionAllow,
		Requires2FA:       decision.Decision == PolicyActionChallenge,
		RequiresApproval:  decision.Decision == PolicyActionChallenge && decision.RiskScore > 0.8,
		BlockReason:       decision.Reason,
		RiskScore:         decision.RiskScore,
		TrustLevel:        decision.TrustLevel,
		SecurityZone:      decision.SecurityZone,
		ValidUntil:        decision.ValidUntil,
		RequiredActions:   decision.RequiredAuth,
		PolicyConditions:  decision.Conditions,
		Timestamp:         decision.Timestamp,
		ProcessingLatency: decision.Latency,
	}
	
	// Apply CAM-specific logic
	if c.config.BlockHighRiskRequests && decision.RiskScore > c.config.MaxRiskThreshold {
		result.Allowed = false
		result.BlockReason = fmt.Sprintf("High risk score: %.2f exceeds threshold: %.2f", decision.RiskScore, c.config.MaxRiskThreshold)
	}
	
	return result, nil
}

// AccessEvaluationResult represents the result of access evaluation
type AccessEvaluationResult struct {
	RequestID         string
	Allowed           bool
	Requires2FA       bool
	RequiresApproval  bool
	BlockReason       string
	RiskScore         float64
	TrustLevel        TrustLevel
	SecurityZone      SecurityZone
	ValidUntil        time.Time
	RequiredActions   []string
	PolicyConditions  []string
	Timestamp         time.Time
	ProcessingLatency time.Duration
}

// VerifyNetworkAccess verifies network access based on zero-trust policies
func (c *CAMZeroTrustIntegration) VerifyNetworkAccess(sourceIP, destIP string, port int) (*NetworkAccessResult, error) {
	decision, err := c.ztEngine.VerifyNetworkSegmentation(sourceIP, destIP, port)
	if err != nil {
		return nil, fmt.Errorf("network segmentation verification failed: %v", err)
	}
	
	result := &NetworkAccessResult{
		Allowed:         decision.Allowed,
		Reason:          decision.Reason,
		SourceZone:      decision.SourceZone,
		DestinationZone: decision.DestinationZone,
		Port:            decision.Port,
		RequiredAuth:    decision.RequiredAuth,
		Encryption:      decision.Encryption,
		Timestamp:       decision.Timestamp,
	}
	
	return result, nil
}

// NetworkAccessResult represents the result of network access verification
type NetworkAccessResult struct {
	Allowed         bool
	Reason          string
	SourceZone      SecurityZone
	DestinationZone SecurityZone
	Port            int
	RequiredAuth    bool
	Encryption      bool
	Timestamp       time.Time
}

// CreateCAMSession creates a new CAM session with zero-trust validation
func (c *CAMZeroTrustIntegration) CreateCAMSession(userID, deviceID, ipAddress string, authData map[string]interface{}) (*CAMSession, error) {
	entityID := c.generateEntityID(userID, deviceID, ipAddress)
	
	// Create zero-trust session
	session, err := c.ztEngine.CreateSession(entityID, authData)
	if err != nil {
		return nil, fmt.Errorf("zero-trust session creation failed: %v", err)
	}
	
	// Convert to CAM session
	camSession := &CAMSession{
		ID:            session.ID,
		UserID:        userID,
		DeviceID:      deviceID,
		EntityID:      entityID,
		IPAddress:     session.IPAddress,
		UserAgent:     session.UserAgent,
		CreatedAt:     session.CreatedAt,
		LastActivity:  session.LastActivity,
		ExpiresAt:     session.ExpiresAt,
		TrustLevel:    session.TrustLevel,
		RiskScore:     session.RiskScore,
		Verified:      session.Verified,
		Compromised:   session.Compromised,
		Attributes:    session.Attributes,
		Actions:       session.Actions,
	}
	
	return camSession, nil
}

// CAMSession represents a CAM session with zero-trust attributes
type CAMSession struct {
	ID            string
	UserID        string
	DeviceID      string
	EntityID      string
	IPAddress     string
	UserAgent     string
	CreatedAt     time.Time
	LastActivity  time.Time
	ExpiresAt     time.Time
	TrustLevel    TrustLevel
	RiskScore     float64
	Verified      bool
	Compromised   bool
	Attributes    map[string]string
	Actions       []string
}

// GetSecurityMetrics returns comprehensive security metrics
func (c *CAMZeroTrustIntegration) GetSecurityMetrics() *SecurityMetrics {
	ztMetrics := c.ztEngine.GetMetrics()
	
	return &SecurityMetrics{
		ZeroTrustMetrics: &ZeroTrustMetrics{
			AccessRequests:      ztMetrics.AccessRequests,
			AccessDenied:        ztMetrics.AccessDenied,
			AccessAllowed:       ztMetrics.AccessAllowed,
			AccessChallenged:    ztMetrics.AccessChallenged,
			EntitiesRegistered:  ztMetrics.EntitiesRegistered,
			ActiveSessions:      ztMetrics.ActiveSessions,
			PoliciesEvaluated:   ztMetrics.PoliciesEvaluated,
			RiskAssessments:     ztMetrics.RiskAssessments,
			AnomaliesDetected:   ztMetrics.AnomaliesDetected,
			SecurityViolations:  ztMetrics.SecurityViolations,
			AuditEvents:         ztMetrics.AuditEvents,
			AverageRiskScore:    ztMetrics.AverageRiskScore,
			ZoneViolations:      ztMetrics.ZoneViolations,
			CryptoOperations:    ztMetrics.CryptoOperations,
		},
		NetworkSegmentation: &NetworkSegmentationMetrics{
			ZoneTransitions:     ztMetrics.ZoneViolations,
			BlockedConnections:  ztMetrics.AccessDenied,
			AllowedConnections:  ztMetrics.AccessAllowed,
			PolicyViolations:    ztMetrics.SecurityViolations,
		},
		RiskAssessment: &RiskAssessmentMetrics{
			HighRiskRequests:   c.countHighRiskRequests(ztMetrics),
			MediumRiskRequests: c.countMediumRiskRequests(ztMetrics),
			LowRiskRequests:    c.countLowRiskRequests(ztMetrics),
			AverageRiskScore:   ztMetrics.AverageRiskScore,
			RiskTrends:         c.getRiskTrends(),
		},
	}
}

// SecurityMetrics represents comprehensive security metrics
type SecurityMetrics struct {
	ZeroTrustMetrics    *ZeroTrustMetrics
	NetworkSegmentation *NetworkSegmentationMetrics
	RiskAssessment      *RiskAssessmentMetrics
}

// ZeroTrustMetrics represents zero-trust specific metrics
type ZeroTrustMetrics struct {
	AccessRequests      int64
	AccessDenied        int64
	AccessAllowed       int64
	AccessChallenged    int64
	EntitiesRegistered  int64
	ActiveSessions      int64
	PoliciesEvaluated   int64
	RiskAssessments     int64
	AnomaliesDetected   int64
	SecurityViolations  int64
	AuditEvents         int64
	AverageRiskScore    float64
	ZoneViolations      int64
	CryptoOperations    int64
}

// NetworkSegmentationMetrics represents network segmentation metrics
type NetworkSegmentationMetrics struct {
	ZoneTransitions     int64
	BlockedConnections  int64
	AllowedConnections  int64
	PolicyViolations    int64
}

// RiskAssessmentMetrics represents risk assessment metrics
type RiskAssessmentMetrics struct {
	HighRiskRequests   int64
	MediumRiskRequests int64
	LowRiskRequests    int64
	AverageRiskScore   float64
	RiskTrends         []RiskTrend
}

// RiskTrend represents risk trend data
type RiskTrend struct {
	Timestamp   time.Time
	RiskScore   float64
	RequestType string
}

// GetAuditTrail returns audit trail for zero-trust events
func (c *CAMZeroTrustIntegration) GetAuditTrail(limit int) []CAMAuditEvent {
	events := c.ztEngine.GetAuditEvents(limit)
	
	camEvents := make([]CAMAuditEvent, 0, len(events))
	for _, event := range events {
		camEvent := CAMAuditEvent{
			ID:          event.ID,
			Timestamp:   event.Timestamp,
			EventType:   event.EventType,
			EntityID:    event.EntityID,
			UserID:      c.extractUserID(event.Context),
			Action:      event.Action,
			Resource:    event.Resource,
			Result:      event.Result,
			RiskScore:   event.RiskScore,
			Context:     event.Context,
			IPAddress:   c.extractIPAddress(event.Context),
			UserAgent:   c.extractUserAgent(event.Context),
			Geolocation: c.extractGeolocation(event.Context),
		}
		camEvents = append(camEvents, camEvent)
	}
	
	return camEvents
}

// CAMAuditEvent represents a CAM audit event
type CAMAuditEvent struct {
	ID          string
	Timestamp   time.Time
	EventType   string
	EntityID    string
	UserID      string
	Action      string
	Resource    string
	Result      string
	RiskScore   float64
	Context     map[string]interface{}
	IPAddress   string
	UserAgent   string
	Geolocation *GeolocationData
}

// Helper methods

func (c *CAMZeroTrustIntegration) determineSecurityZone(ipAddress string) SecurityZone {
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return ZonePublic
	}
	
	// Check for private IP ranges
	if ip.IsPrivate() {
		// More specific zone determination based on IP ranges
		if ip.IsLoopback() {
			return ZoneSecure
		}
		
		// Check specific private ranges
		if ip.To4() != nil {
			// 10.10.x.x is secure zone
			if ip.To4()[0] == 10 && ip.To4()[1] == 10 {
				return ZoneSecure
			}
			// 192.168.x.x is private zone
			if ip.To4()[0] == 192 && ip.To4()[1] == 168 {
				return ZonePrivate
			}
		}
		
		return ZonePrivate
	}
	
	return ZonePublic
}

func (c *CAMZeroTrustIntegration) generateEntityID(userID, deviceID, ipAddress string) string {
	if userID != "" && deviceID != "" {
		return fmt.Sprintf("user:%s:device:%s", userID, deviceID)
	}
	if userID != "" {
		return fmt.Sprintf("user:%s:ip:%s", userID, ipAddress)
	}
	if deviceID != "" {
		return fmt.Sprintf("device:%s:ip:%s", deviceID, ipAddress)
	}
	return fmt.Sprintf("ip:%s", ipAddress)
}

func (c *CAMZeroTrustIntegration) generateRequestID() string {
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}

func (c *CAMZeroTrustIntegration) countHighRiskRequests(metrics *Metrics) int64 {
	// Simplified implementation - in production would track actual risk levels
	return int64(float64(metrics.AccessRequests) * 0.1)
}

func (c *CAMZeroTrustIntegration) countMediumRiskRequests(metrics *Metrics) int64 {
	return int64(float64(metrics.AccessRequests) * 0.2)
}

func (c *CAMZeroTrustIntegration) countLowRiskRequests(metrics *Metrics) int64 {
	return int64(float64(metrics.AccessRequests) * 0.7)
}

func (c *CAMZeroTrustIntegration) getRiskTrends() []RiskTrend {
	// Simplified implementation - in production would track actual trends
	return []RiskTrend{
		{
			Timestamp:   time.Now().Add(-time.Hour),
			RiskScore:   0.3,
			RequestType: "normal",
		},
		{
			Timestamp:   time.Now().Add(-30 * time.Minute),
			RiskScore:   0.5,
			RequestType: "elevated",
		},
		{
			Timestamp:   time.Now(),
			RiskScore:   0.4,
			RequestType: "normal",
		},
	}
}

func (c *CAMZeroTrustIntegration) extractUserID(context map[string]interface{}) string {
	if userID, ok := context["user_id"].(string); ok {
		return userID
	}
	return ""
}

func (c *CAMZeroTrustIntegration) extractIPAddress(context map[string]interface{}) string {
	if ip, ok := context["ip_address"].(string); ok {
		return ip
	}
	return ""
}

func (c *CAMZeroTrustIntegration) extractUserAgent(context map[string]interface{}) string {
	if ua, ok := context["user_agent"].(string); ok {
		return ua
	}
	return ""
}

func (c *CAMZeroTrustIntegration) extractGeolocation(context map[string]interface{}) *GeolocationData {
	if geo, ok := context["geolocation"].(*GeolocationData); ok {
		return geo
	}
	return nil
}

// Middleware methods

func (m *ZeroTrustMiddleware) EvaluateRequest(ctx *RequestContext) (*AccessEvaluationResult, error) {
	return m.integration.EvaluateCAMAccess(ctx)
}

func (m *ZeroTrustMiddleware) VerifyNetworkConnection(sourceIP, destIP string, port int) (*NetworkAccessResult, error) {
	return m.integration.VerifyNetworkAccess(sourceIP, destIP, port)
}

func (m *ZeroTrustMiddleware) CreateSession(userID, deviceID, ipAddress string, authData map[string]interface{}) (*CAMSession, error) {
	return m.integration.CreateCAMSession(userID, deviceID, ipAddress, authData)
}

func (m *ZeroTrustMiddleware) GetMiddleware() *ZeroTrustMiddleware {
	return m
} 