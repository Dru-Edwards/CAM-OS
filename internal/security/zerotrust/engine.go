package zerotrust

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// TrustLevel represents the trust level assigned to entities
type TrustLevel int

const (
	TrustLevelNone TrustLevel = iota
	TrustLevelMinimal
	TrustLevelLow
	TrustLevelMedium
	TrustLevelHigh
	TrustLevelUltimate
)

// PolicyAction represents the action to take based on policy evaluation
type PolicyAction int

const (
	PolicyActionDeny PolicyAction = iota
	PolicyActionAllow
	PolicyActionChallenge
	PolicyActionAudit
	PolicyActionTempAllow
)

// SecurityZone represents a network security zone
type SecurityZone string

const (
	ZonePublic     SecurityZone = "public"
	ZonePrivate    SecurityZone = "private"
	ZoneSecure     SecurityZone = "secure"
	ZoneRestricted SecurityZone = "restricted"
	ZoneIsolated   SecurityZone = "isolated"
)

// Entity represents a network entity (user, device, service)
type Entity struct {
	ID                string
	Type              EntityType
	Name              string
	IPAddress         string
	MACAddress        string
	DeviceFingerprint string
	UserID            string
	CreatedAt         time.Time
	LastSeen          time.Time
	TrustLevel        TrustLevel
	SecurityZone      SecurityZone
	Attributes        map[string]string
	Certificates      [][]byte
	Policies          []string
	RiskScore         float64
	Verified          bool
	Compromised       bool
}

// EntityType represents the type of entity
type EntityType string

const (
	EntityTypeUser    EntityType = "user"
	EntityTypeDevice  EntityType = "device"
	EntityTypeService EntityType = "service"
	EntityTypeAgent   EntityType = "agent"
)

// AccessRequest represents a request for access to resources
type AccessRequest struct {
	ID          string
	RequestorID string
	ResourceID  string
	Action      string
	Timestamp   time.Time
	Context     map[string]interface{}
	IPAddress   string
	UserAgent   string
	ClientCert  []byte
	TokenClaims map[string]interface{}
	Risk        float64
	Geolocation *GeolocationData
}

// GeolocationData represents geographical information
type GeolocationData struct {
	Country    string
	Region     string
	City       string
	Latitude   float64
	Longitude  float64
	ISP        string
	Timezone   string
	Suspicious bool
}

// Policy represents a zero-trust security policy
type Policy struct {
	ID          string
	Name        string
	Description string
	Zone        SecurityZone
	Subjects    []string // Entity IDs or patterns
	Resources   []string // Resource IDs or patterns
	Actions     []string // Allowed actions
	Conditions  []Condition
	Effect      PolicyAction
	Priority    int
	Enabled     bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Condition represents a policy condition
type Condition struct {
	Type     ConditionType
	Operator string
	Value    interface{}
}

// ConditionType represents the type of condition
type ConditionType string

const (
	ConditionTypeTime     ConditionType = "time"
	ConditionTypeLocation ConditionType = "location"
	ConditionTypeRisk     ConditionType = "risk"
	ConditionTypeTrust    ConditionType = "trust"
	ConditionTypeNetwork  ConditionType = "network"
	ConditionTypeDevice   ConditionType = "device"
	ConditionTypeUser     ConditionType = "user"
	ConditionTypeBehavior ConditionType = "behavior"
)

// ZeroTrustEngine provides zero-trust security enforcement
type ZeroTrustEngine struct {
	entities      map[string]*Entity
	entitiesMutex sync.RWMutex

	policies      map[string]*Policy
	policiesMutex sync.RWMutex

	sessions      map[string]*Session
	sessionsMutex sync.RWMutex

	networkZones map[string]*NetworkZone
	zonesMutex   sync.RWMutex

	riskEngine   *RiskEngine
	cryptoEngine *CryptoEngine
	auditLogger  *AuditLogger

	config  *Config
	metrics *Metrics

	ctx    context.Context
	cancel context.CancelFunc
}

// Session represents an authenticated session
type Session struct {
	ID           string
	EntityID     string
	CreatedAt    time.Time
	LastActivity time.Time
	ExpiresAt    time.Time
	IPAddress    string
	UserAgent    string
	TrustLevel   TrustLevel
	Attributes   map[string]string
	Verified     bool
	Compromised  bool
	Actions      []string
	RiskScore    float64
}

// NetworkZone represents a network security zone
type NetworkZone struct {
	ID           string
	Name         string
	SecurityZone SecurityZone
	IPRanges     []string
	AllowedPorts []int
	RequiredAuth bool
	Encryption   bool
	Monitoring   bool
	Isolation    bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// RiskEngine provides risk assessment capabilities
type RiskEngine struct {
	behaviorModels map[string]*BehaviorModel
	riskFactors    map[string]float64
	thresholds     map[string]float64
	mutex          sync.RWMutex
}

// BehaviorModel represents a behavioral analysis model
type BehaviorModel struct {
	EntityID      string
	NormalPattern map[string]float64
	Anomalies     []Anomaly
	UpdatedAt     time.Time
}

// Anomaly represents a behavioral anomaly
type Anomaly struct {
	Type        string
	Severity    float64
	Timestamp   time.Time
	Description string
	Context     map[string]interface{}
}

// CryptoEngine provides cryptographic operations
type CryptoEngine struct {
	keyCache      map[string][]byte
	cacheMutex    sync.RWMutex
	keyRotation   time.Duration
	encryptionAlg string
	signingAlg    string
}

// AuditLogger provides audit logging capabilities
type AuditLogger struct {
	events    []AuditEvent
	mutex     sync.RWMutex
	maxEvents int
	retention time.Duration
}

// AuditEvent represents an audit event
type AuditEvent struct {
	ID        string
	Timestamp time.Time
	EventType string
	EntityID  string
	Action    string
	Resource  string
	Result    string
	Context   map[string]interface{}
	RiskScore float64
}

// Config holds the zero-trust engine configuration
type Config struct {
	Enabled               bool
	DefaultTrustLevel     TrustLevel
	DefaultSecurityZone   SecurityZone
	SessionTimeout        time.Duration
	RiskThreshold         float64
	ContinuousAuth        bool
	DeviceVerification    bool
	GeolocationEnabled    bool
	BehaviorAnalysis      bool
	NetworkSegmentation   bool
	EncryptionRequired    bool
	CertificateValidation bool
	AuditLogging          bool
	MaxSessions           int
	MaxEntities           int
	PolicyUpdateInterval  time.Duration
	RiskUpdateInterval    time.Duration
}

// Metrics tracks zero-trust engine metrics
type Metrics struct {
	AccessRequests     int64
	AccessDenied       int64
	AccessAllowed      int64
	AccessChallenged   int64
	EntitiesRegistered int64
	ActiveSessions     int64
	PoliciesEvaluated  int64
	RiskAssessments    int64
	AnomaliesDetected  int64
	SecurityViolations int64
	AuditEvents        int64
	AverageRiskScore   float64
	ZoneViolations     int64
	CryptoOperations   int64
}

// NewZeroTrustEngine creates a new zero-trust security engine
func NewZeroTrustEngine(config *Config) *ZeroTrustEngine {
	ctx, cancel := context.WithCancel(context.Background())

	engine := &ZeroTrustEngine{
		entities:     make(map[string]*Entity),
		policies:     make(map[string]*Policy),
		sessions:     make(map[string]*Session),
		networkZones: make(map[string]*NetworkZone),
		riskEngine: &RiskEngine{
			behaviorModels: make(map[string]*BehaviorModel),
			riskFactors:    make(map[string]float64),
			thresholds:     make(map[string]float64),
		},
		cryptoEngine: &CryptoEngine{
			keyCache:      make(map[string][]byte),
			keyRotation:   24 * time.Hour,
			encryptionAlg: "AES-256-GCM",
			signingAlg:    "ECDSA-P256",
		},
		auditLogger: &AuditLogger{
			events:    make([]AuditEvent, 0),
			maxEvents: 100000,
			retention: 90 * 24 * time.Hour,
		},
		config:  config,
		metrics: &Metrics{},
		ctx:     ctx,
		cancel:  cancel,
	}

	// Initialize default policies
	engine.initializeDefaultPolicies()

	// Initialize network zones
	engine.initializeDefaultZones()

	// Initialize risk factors
	engine.initializeRiskFactors()

	return engine
}

// Start starts the zero-trust engine
func (z *ZeroTrustEngine) Start() error {
	if !z.config.Enabled {
		return nil
	}

	// Start background workers
	go z.sessionManager()
	go z.riskAssessmentWorker()
	go z.policyUpdateWorker()
	go z.auditWorker()
	go z.metricsCollector()

	if z.config.BehaviorAnalysis {
		go z.behaviorAnalysisWorker()
	}

	if z.config.ContinuousAuth {
		go z.continuousAuthWorker()
	}

	return nil
}

// Stop stops the zero-trust engine
func (z *ZeroTrustEngine) Stop() error {
	z.cancel()
	return nil
}

// RegisterEntity registers a new entity in the zero-trust system
func (z *ZeroTrustEngine) RegisterEntity(entity *Entity) error {
	z.entitiesMutex.Lock()
	defer z.entitiesMutex.Unlock()

	// Validate entity
	if entity.ID == "" {
		return fmt.Errorf("entity ID is required")
	}

	// Set default values
	if entity.TrustLevel == 0 {
		entity.TrustLevel = z.config.DefaultTrustLevel
	}

	if entity.SecurityZone == "" {
		entity.SecurityZone = z.config.DefaultSecurityZone
	}

	if entity.Attributes == nil {
		entity.Attributes = make(map[string]string)
	}

	entity.CreatedAt = time.Now()
	entity.LastSeen = time.Now()

	// Perform initial risk assessment
	entity.RiskScore = z.assessEntityRisk(entity)

	// Store entity
	z.entities[entity.ID] = entity
	z.metrics.EntitiesRegistered++

	// Log registration
	z.auditLogger.LogEvent(AuditEvent{
		ID:        z.generateID(),
		Timestamp: time.Now(),
		EventType: "entity_registration",
		EntityID:  entity.ID,
		Action:    "register",
		Resource:  "entity",
		Result:    "success",
		Context: map[string]interface{}{
			"entity_type":   entity.Type,
			"trust_level":   entity.TrustLevel,
			"security_zone": entity.SecurityZone,
			"risk_score":    entity.RiskScore,
		},
		RiskScore: entity.RiskScore,
	})

	return nil
}

// EvaluateAccess evaluates an access request against zero-trust policies
func (z *ZeroTrustEngine) EvaluateAccess(request *AccessRequest) (*AccessDecision, error) {
	startTime := time.Now()

	// Get entity
	entity, exists := z.getEntity(request.RequestorID)
	if !exists {
		return &AccessDecision{
			RequestID: request.ID,
			Decision:  PolicyActionDeny,
			Reason:    "Entity not found",
			Timestamp: time.Now(),
		}, nil
	}

	// Update entity last seen
	z.updateEntityLastSeen(entity.ID)

	// Perform risk assessment
	risk := z.assessAccessRisk(request, entity)
	request.Risk = risk

	// Evaluate policies
	decision := z.evaluatePolicies(request, entity)

	// Enhance decision with risk assessment
	if risk > z.config.RiskThreshold {
		if decision.Decision == PolicyActionAllow {
			decision.Decision = PolicyActionChallenge
			decision.Reason = "High risk detected - additional verification required"
		}
	}

	// Log access attempt
	z.auditLogger.LogEvent(AuditEvent{
		ID:        z.generateID(),
		Timestamp: time.Now(),
		EventType: "access_evaluation",
		EntityID:  request.RequestorID,
		Action:    request.Action,
		Resource:  request.ResourceID,
		Result:    string(decision.Decision),
		Context: map[string]interface{}{
			"request_id":  request.ID,
			"risk_score":  risk,
			"ip_address":  request.IPAddress,
			"user_agent":  request.UserAgent,
			"geolocation": request.Geolocation,
		},
		RiskScore: risk,
	})

	// Update metrics
	z.metrics.AccessRequests++
	z.metrics.PoliciesEvaluated++
	z.metrics.RiskAssessments++

	switch decision.Decision {
	case PolicyActionAllow:
		z.metrics.AccessAllowed++
	case PolicyActionDeny:
		z.metrics.AccessDenied++
	case PolicyActionChallenge:
		z.metrics.AccessChallenged++
	}

	decision.Latency = time.Since(startTime)
	return decision, nil
}

// AccessDecision represents the result of access evaluation
type AccessDecision struct {
	RequestID    string
	Decision     PolicyAction
	Reason       string
	Timestamp    time.Time
	Latency      time.Duration
	RequiredAuth []string
	Conditions   []string
	ValidUntil   time.Time
	RiskScore    float64
	TrustLevel   TrustLevel
	SecurityZone SecurityZone
}

// CreateSession creates a new authenticated session
func (z *ZeroTrustEngine) CreateSession(entityID string, authData map[string]interface{}) (*Session, error) {
	z.sessionsMutex.Lock()
	defer z.sessionsMutex.Unlock()

	// Check session limit
	if len(z.sessions) >= z.config.MaxSessions {
		return nil, fmt.Errorf("maximum sessions reached")
	}

	// Get entity
	entity, exists := z.getEntity(entityID)
	if !exists {
		return nil, fmt.Errorf("entity not found")
	}

	// Create session
	session := &Session{
		ID:           z.generateID(),
		EntityID:     entityID,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		ExpiresAt:    time.Now().Add(z.config.SessionTimeout),
		IPAddress:    "",
		UserAgent:    "",
		TrustLevel:   entity.TrustLevel,
		Attributes:   make(map[string]string),
		Verified:     true,
		Compromised:  false,
		Actions:      make([]string, 0),
		RiskScore:    entity.RiskScore,
	}

	// Extract auth data
	if ip, ok := authData["ip_address"].(string); ok {
		session.IPAddress = ip
	}
	if ua, ok := authData["user_agent"].(string); ok {
		session.UserAgent = ua
	}

	// Store session
	z.sessions[session.ID] = session
	z.metrics.ActiveSessions++

	// Log session creation
	z.auditLogger.LogEvent(AuditEvent{
		ID:        z.generateID(),
		Timestamp: time.Now(),
		EventType: "session_created",
		EntityID:  entityID,
		Action:    "create_session",
		Resource:  "session",
		Result:    "success",
		Context: map[string]interface{}{
			"session_id":  session.ID,
			"ip_address":  session.IPAddress,
			"user_agent":  session.UserAgent,
			"trust_level": session.TrustLevel,
		},
		RiskScore: session.RiskScore,
	})

	return session, nil
}

// VerifyNetworkSegmentation verifies network segmentation policies
func (z *ZeroTrustEngine) VerifyNetworkSegmentation(sourceIP, destIP string, port int) (*SegmentationDecision, error) {
	if !z.config.NetworkSegmentation {
		return &SegmentationDecision{
			Allowed: true,
			Reason:  "Network segmentation disabled",
		}, nil
	}

	// Determine source and destination zones
	sourceZone := z.getNetworkZone(sourceIP)
	destZone := z.getNetworkZone(destIP)

	// Check zone-to-zone communication policies
	allowed := z.isZoneCommunicationAllowed(sourceZone, destZone, port)

	decision := &SegmentationDecision{
		Allowed:         allowed,
		SourceZone:      sourceZone.SecurityZone,
		DestinationZone: destZone.SecurityZone,
		Port:            port,
		Timestamp:       time.Now(),
	}

	if !allowed {
		decision.Reason = fmt.Sprintf("Communication from %s to %s on port %d not allowed", sourceZone.SecurityZone, destZone.SecurityZone, port)
		z.metrics.ZoneViolations++
	} else {
		decision.Reason = "Zone communication allowed"
	}

	// Log segmentation decision
	z.auditLogger.LogEvent(AuditEvent{
		ID:        z.generateID(),
		Timestamp: time.Now(),
		EventType: "network_segmentation",
		EntityID:  sourceIP,
		Action:    "network_access",
		Resource:  destIP,
		Result:    fmt.Sprintf("%t", allowed),
		Context: map[string]interface{}{
			"source_ip":   sourceIP,
			"dest_ip":     destIP,
			"port":        port,
			"source_zone": sourceZone.SecurityZone,
			"dest_zone":   destZone.SecurityZone,
		},
		RiskScore: 0.0,
	})

	return decision, nil
}

// SegmentationDecision represents the result of network segmentation evaluation
type SegmentationDecision struct {
	Allowed         bool
	Reason          string
	SourceZone      SecurityZone
	DestinationZone SecurityZone
	Port            int
	Timestamp       time.Time
	RequiredAuth    bool
	Encryption      bool
}

// Helper methods

func (z *ZeroTrustEngine) getEntity(id string) (*Entity, bool) {
	z.entitiesMutex.RLock()
	defer z.entitiesMutex.RUnlock()
	entity, exists := z.entities[id]
	return entity, exists
}

func (z *ZeroTrustEngine) updateEntityLastSeen(id string) {
	z.entitiesMutex.Lock()
	defer z.entitiesMutex.Unlock()
	if entity, exists := z.entities[id]; exists {
		entity.LastSeen = time.Now()
	}
}

func (z *ZeroTrustEngine) assessEntityRisk(entity *Entity) float64 {
	risk := 0.0

	// Base risk by entity type
	switch entity.Type {
	case EntityTypeUser:
		risk += 0.2
	case EntityTypeDevice:
		risk += 0.1
	case EntityTypeService:
		risk += 0.05
	case EntityTypeAgent:
		risk += 0.3
	}

	// Risk based on trust level
	risk += (1.0 - (float64(entity.TrustLevel) / 5.0)) * 0.5

	// Risk based on security zone
	switch entity.SecurityZone {
	case ZonePublic:
		risk += 0.4
	case ZonePrivate:
		risk += 0.2
	case ZoneSecure:
		risk += 0.1
	case ZoneRestricted:
		risk += 0.05
	case ZoneIsolated:
		risk += 0.0
	}

	// Cap risk at 1.0
	if risk > 1.0 {
		risk = 1.0
	}

	return risk
}

func (z *ZeroTrustEngine) assessAccessRisk(request *AccessRequest, entity *Entity) float64 {
	risk := entity.RiskScore

	// Risk based on action sensitivity
	sensitiveActions := map[string]float64{
		"delete": 0.3,
		"admin":  0.4,
		"root":   0.5,
		"sudo":   0.4,
		"exec":   0.3,
	}

	if actionRisk, exists := sensitiveActions[request.Action]; exists {
		risk += actionRisk
	}

	// Risk based on geolocation
	if request.Geolocation != nil && request.Geolocation.Suspicious {
		risk += 0.3
	}

	// Risk based on time
	hour := time.Now().Hour()
	if hour < 6 || hour > 22 {
		risk += 0.2
	}

	// Cap risk at 1.0
	if risk > 1.0 {
		risk = 1.0
	}

	return risk
}

func (z *ZeroTrustEngine) evaluatePolicies(request *AccessRequest, entity *Entity) *AccessDecision {
	z.policiesMutex.RLock()
	defer z.policiesMutex.RUnlock()

	decision := &AccessDecision{
		RequestID:    request.ID,
		Decision:     PolicyActionDeny,
		Reason:       "No matching policy found",
		Timestamp:    time.Now(),
		RiskScore:    request.Risk,
		TrustLevel:   entity.TrustLevel,
		SecurityZone: entity.SecurityZone,
	}

	// Evaluate policies in priority order
	policies := z.getSortedPolicies()

	for _, policy := range policies {
		if z.policyMatches(policy, request, entity) {
			decision.Decision = policy.Effect
			decision.Reason = fmt.Sprintf("Policy %s applied", policy.Name)

			// Set conditions
			decision.Conditions = make([]string, 0)
			for _, condition := range policy.Conditions {
				decision.Conditions = append(decision.Conditions, fmt.Sprintf("%s %s %v", condition.Type, condition.Operator, condition.Value))
			}

			// Set validity period
			decision.ValidUntil = time.Now().Add(time.Hour)

			break
		}
	}

	return decision
}

func (z *ZeroTrustEngine) policyMatches(policy *Policy, request *AccessRequest, entity *Entity) bool {
	if !policy.Enabled {
		return false
	}

	// Check zone
	if policy.Zone != "" && entity.SecurityZone != policy.Zone {
		return false
	}

	// Check subjects
	if len(policy.Subjects) > 0 {
		matched := false
		for _, subject := range policy.Subjects {
			if z.matchesPattern(entity.ID, subject) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check resources
	if len(policy.Resources) > 0 {
		matched := false
		for _, resource := range policy.Resources {
			if z.matchesPattern(request.ResourceID, resource) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check actions
	if len(policy.Actions) > 0 {
		matched := false
		for _, action := range policy.Actions {
			if z.matchesPattern(request.Action, action) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check conditions
	for _, condition := range policy.Conditions {
		if !z.evaluateCondition(condition, request, entity) {
			return false
		}
	}

	return true
}

func (z *ZeroTrustEngine) evaluateCondition(condition Condition, request *AccessRequest, entity *Entity) bool {
	switch condition.Type {
	case ConditionTypeTime:
		return z.evaluateTimeCondition(condition, request)
	case ConditionTypeLocation:
		return z.evaluateLocationCondition(condition, request)
	case ConditionTypeRisk:
		return z.evaluateRiskCondition(condition, request)
	case ConditionTypeTrust:
		return z.evaluateTrustCondition(condition, entity)
	case ConditionTypeNetwork:
		return z.evaluateNetworkCondition(condition, request)
	default:
		return false
	}
}

func (z *ZeroTrustEngine) evaluateTimeCondition(condition Condition, request *AccessRequest) bool {
	now := time.Now()
	switch condition.Operator {
	case "hour_between":
		if hours, ok := condition.Value.([]int); ok && len(hours) == 2 {
			hour := now.Hour()
			return hour >= hours[0] && hour <= hours[1]
		}
	case "weekday":
		if weekdays, ok := condition.Value.([]string); ok {
			weekday := now.Weekday().String()
			for _, wd := range weekdays {
				if wd == weekday {
					return true
				}
			}
		}
	}
	return false
}

func (z *ZeroTrustEngine) evaluateLocationCondition(condition Condition, request *AccessRequest) bool {
	if request.Geolocation == nil {
		return false
	}

	switch condition.Operator {
	case "country_in":
		if countries, ok := condition.Value.([]string); ok {
			for _, country := range countries {
				if country == request.Geolocation.Country {
					return true
				}
			}
		}
	case "country_not_in":
		if countries, ok := condition.Value.([]string); ok {
			for _, country := range countries {
				if country == request.Geolocation.Country {
					return false
				}
			}
			return true
		}
	}
	return false
}

func (z *ZeroTrustEngine) evaluateRiskCondition(condition Condition, request *AccessRequest) bool {
	switch condition.Operator {
	case "less_than":
		if threshold, ok := condition.Value.(float64); ok {
			return request.Risk < threshold
		}
	case "greater_than":
		if threshold, ok := condition.Value.(float64); ok {
			return request.Risk > threshold
		}
	}
	return false
}

func (z *ZeroTrustEngine) evaluateTrustCondition(condition Condition, entity *Entity) bool {
	switch condition.Operator {
	case "min_level":
		if level, ok := condition.Value.(int); ok {
			return int(entity.TrustLevel) >= level
		}
	case "max_level":
		if level, ok := condition.Value.(int); ok {
			return int(entity.TrustLevel) <= level
		}
	}
	return false
}

func (z *ZeroTrustEngine) evaluateNetworkCondition(condition Condition, request *AccessRequest) bool {
	switch condition.Operator {
	case "ip_in_range":
		if cidr, ok := condition.Value.(string); ok {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				return false
			}
			ip := net.ParseIP(request.IPAddress)
			return network.Contains(ip)
		}
	case "ip_not_in_range":
		if cidr, ok := condition.Value.(string); ok {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				return false
			}
			ip := net.ParseIP(request.IPAddress)
			return !network.Contains(ip)
		}
	}
	return false
}

func (z *ZeroTrustEngine) matchesPattern(value, pattern string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := pattern[:len(pattern)-1]
		return strings.HasPrefix(value, prefix)
	}
	if strings.HasPrefix(pattern, "*") {
		suffix := pattern[1:]
		return strings.HasSuffix(value, suffix)
	}
	return value == pattern
}

func (z *ZeroTrustEngine) getNetworkZone(ip string) *NetworkZone {
	z.zonesMutex.RLock()
	defer z.zonesMutex.RUnlock()

	for _, zone := range z.networkZones {
		for _, ipRange := range zone.IPRanges {
			if z.ipInRange(ip, ipRange) {
				return zone
			}
		}
	}

	// Return default public zone
	return &NetworkZone{
		ID:           "default",
		Name:         "Public",
		SecurityZone: ZonePublic,
		IPRanges:     []string{"0.0.0.0/0"},
	}
}

func (z *ZeroTrustEngine) ipInRange(ip, cidr string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	parsedIP := net.ParseIP(ip)
	return network.Contains(parsedIP)
}

func (z *ZeroTrustEngine) isZoneCommunicationAllowed(source, dest *NetworkZone, port int) bool {
	// Define zone communication matrix
	allowedCommunications := map[SecurityZone]map[SecurityZone]bool{
		ZonePublic: {
			ZonePublic:     true,
			ZonePrivate:    false,
			ZoneSecure:     false,
			ZoneRestricted: false,
			ZoneIsolated:   false,
		},
		ZonePrivate: {
			ZonePublic:     true,
			ZonePrivate:    true,
			ZoneSecure:     false,
			ZoneRestricted: false,
			ZoneIsolated:   false,
		},
		ZoneSecure: {
			ZonePublic:     true,
			ZonePrivate:    true,
			ZoneSecure:     true,
			ZoneRestricted: false,
			ZoneIsolated:   false,
		},
		ZoneRestricted: {
			ZonePublic:     false,
			ZonePrivate:    false,
			ZoneSecure:     true,
			ZoneRestricted: true,
			ZoneIsolated:   false,
		},
		ZoneIsolated: {
			ZonePublic:     false,
			ZonePrivate:    false,
			ZoneSecure:     false,
			ZoneRestricted: false,
			ZoneIsolated:   true,
		},
	}

	// Check basic zone communication
	if zoneMap, exists := allowedCommunications[source.SecurityZone]; exists {
		if allowed, exists := zoneMap[dest.SecurityZone]; exists && allowed {
			// Check port restrictions
			if len(dest.AllowedPorts) > 0 {
				for _, allowedPort := range dest.AllowedPorts {
					if port == allowedPort {
						return true
					}
				}
				return false
			}
			return true
		}
	}

	return false
}

func (z *ZeroTrustEngine) getSortedPolicies() []*Policy {
	policies := make([]*Policy, 0, len(z.policies))
	for _, policy := range z.policies {
		policies = append(policies, policy)
	}

	// Sort by priority (higher priority first)
	for i := 0; i < len(policies)-1; i++ {
		for j := i + 1; j < len(policies); j++ {
			if policies[i].Priority < policies[j].Priority {
				policies[i], policies[j] = policies[j], policies[i]
			}
		}
	}

	return policies
}

func (z *ZeroTrustEngine) generateID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// Background workers

func (z *ZeroTrustEngine) sessionManager() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			z.cleanupExpiredSessions()
		case <-z.ctx.Done():
			return
		}
	}
}

func (z *ZeroTrustEngine) cleanupExpiredSessions() {
	z.sessionsMutex.Lock()
	defer z.sessionsMutex.Unlock()

	now := time.Now()
	for id, session := range z.sessions {
		if now.After(session.ExpiresAt) {
			delete(z.sessions, id)
			z.metrics.ActiveSessions--
		}
	}
}

func (z *ZeroTrustEngine) riskAssessmentWorker() {
	ticker := time.NewTicker(z.config.RiskUpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			z.updateRiskAssessments()
		case <-z.ctx.Done():
			return
		}
	}
}

func (z *ZeroTrustEngine) updateRiskAssessments() {
	z.entitiesMutex.Lock()
	defer z.entitiesMutex.Unlock()

	for _, entity := range z.entities {
		oldRisk := entity.RiskScore
		entity.RiskScore = z.assessEntityRisk(entity)

		if entity.RiskScore > oldRisk+0.1 {
			z.auditLogger.LogEvent(AuditEvent{
				ID:        z.generateID(),
				Timestamp: time.Now(),
				EventType: "risk_increase",
				EntityID:  entity.ID,
				Action:    "risk_assessment",
				Resource:  "entity",
				Result:    "risk_increased",
				Context: map[string]interface{}{
					"old_risk": oldRisk,
					"new_risk": entity.RiskScore,
				},
				RiskScore: entity.RiskScore,
			})
		}
	}
}

func (z *ZeroTrustEngine) policyUpdateWorker() {
	ticker := time.NewTicker(z.config.PolicyUpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			z.updatePolicyEffectiveness()
		case <-z.ctx.Done():
			return
		}
	}
}

func (z *ZeroTrustEngine) updatePolicyEffectiveness() {
	// Update policy effectiveness based on audit logs
	// This is a simplified implementation
}

func (z *ZeroTrustEngine) behaviorAnalysisWorker() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			z.analyzeBehaviorPatterns()
		case <-z.ctx.Done():
			return
		}
	}
}

func (z *ZeroTrustEngine) analyzeBehaviorPatterns() {
	// Analyze behavior patterns and detect anomalies
	// This is a simplified implementation
}

func (z *ZeroTrustEngine) continuousAuthWorker() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			z.performContinuousAuth()
		case <-z.ctx.Done():
			return
		}
	}
}

func (z *ZeroTrustEngine) performContinuousAuth() {
	// Perform continuous authentication checks
	// This is a simplified implementation
}

func (z *ZeroTrustEngine) auditWorker() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			z.auditLogger.CleanupOldEvents()
		case <-z.ctx.Done():
			return
		}
	}
}

func (z *ZeroTrustEngine) metricsCollector() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			z.updateMetrics()
		case <-z.ctx.Done():
			return
		}
	}
}

func (z *ZeroTrustEngine) updateMetrics() {
	z.sessionsMutex.RLock()
	z.metrics.ActiveSessions = int64(len(z.sessions))
	z.sessionsMutex.RUnlock()

	z.entitiesMutex.RLock()
	z.metrics.EntitiesRegistered = int64(len(z.entities))
	z.entitiesMutex.RUnlock()

	z.auditLogger.mutex.RLock()
	z.metrics.AuditEvents = int64(len(z.auditLogger.events))
	z.auditLogger.mutex.RUnlock()
}

// Initialization methods

func (z *ZeroTrustEngine) initializeDefaultPolicies() {
	// Default deny-all policy
	z.policies["default_deny"] = &Policy{
		ID:          "default_deny",
		Name:        "Default Deny",
		Description: "Default deny all access",
		Zone:        "",
		Subjects:    []string{"*"},
		Resources:   []string{"*"},
		Actions:     []string{"*"},
		Conditions:  []Condition{},
		Effect:      PolicyActionDeny,
		Priority:    0,
		Enabled:     true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Allow secure zone internal communication
	z.policies["secure_zone_internal"] = &Policy{
		ID:          "secure_zone_internal",
		Name:        "Secure Zone Internal",
		Description: "Allow internal communication within secure zone",
		Zone:        ZoneSecure,
		Subjects:    []string{"*"},
		Resources:   []string{"*"},
		Actions:     []string{"read", "write"},
		Conditions: []Condition{
			{
				Type:     ConditionTypeTrust,
				Operator: "min_level",
				Value:    int(TrustLevelMedium),
			},
		},
		Effect:    PolicyActionAllow,
		Priority:  100,
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func (z *ZeroTrustEngine) initializeDefaultZones() {
	z.networkZones["public"] = &NetworkZone{
		ID:           "public",
		Name:         "Public Zone",
		SecurityZone: ZonePublic,
		IPRanges:     []string{"0.0.0.0/0"},
		AllowedPorts: []int{80, 443},
		RequiredAuth: false,
		Encryption:   false,
		Monitoring:   true,
		Isolation:    false,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	z.networkZones["private"] = &NetworkZone{
		ID:           "private",
		Name:         "Private Zone",
		SecurityZone: ZonePrivate,
		IPRanges:     []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
		AllowedPorts: []int{22, 80, 443, 3389},
		RequiredAuth: true,
		Encryption:   true,
		Monitoring:   true,
		Isolation:    false,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	z.networkZones["secure"] = &NetworkZone{
		ID:           "secure",
		Name:         "Secure Zone",
		SecurityZone: ZoneSecure,
		IPRanges:     []string{"10.10.0.0/16"},
		AllowedPorts: []int{443, 8443},
		RequiredAuth: true,
		Encryption:   true,
		Monitoring:   true,
		Isolation:    true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
}

func (z *ZeroTrustEngine) initializeRiskFactors() {
	z.riskEngine.riskFactors["failed_auth"] = 0.3
	z.riskEngine.riskFactors["suspicious_location"] = 0.4
	z.riskEngine.riskFactors["unusual_time"] = 0.2
	z.riskEngine.riskFactors["new_device"] = 0.3
	z.riskEngine.riskFactors["privilege_escalation"] = 0.5
	z.riskEngine.riskFactors["data_exfiltration"] = 0.6

	z.riskEngine.thresholds["low"] = 0.3
	z.riskEngine.thresholds["medium"] = 0.6
	z.riskEngine.thresholds["high"] = 0.8
	z.riskEngine.thresholds["critical"] = 0.9
}

// Public API methods

func (z *ZeroTrustEngine) GetMetrics() *Metrics {
	return z.metrics
}

func (z *ZeroTrustEngine) GetAuditEvents(limit int) []AuditEvent {
	return z.auditLogger.GetEvents(limit)
}

// AuditLogger methods

func (a *AuditLogger) LogEvent(event AuditEvent) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if event.ID == "" {
		bytes := make([]byte, 8)
		rand.Read(bytes)
		event.ID = hex.EncodeToString(bytes)
	}

	a.events = append(a.events, event)

	if len(a.events) > a.maxEvents {
		a.events = a.events[1:]
	}
}

func (a *AuditLogger) GetEvents(limit int) []AuditEvent {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	start := len(a.events) - limit
	if start < 0 {
		start = 0
	}

	events := make([]AuditEvent, 0)
	for i := start; i < len(a.events); i++ {
		events = append(events, a.events[i])
	}

	return events
}

func (a *AuditLogger) CleanupOldEvents() {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	cutoff := time.Now().Add(-a.retention)

	newEvents := make([]AuditEvent, 0)
	for _, event := range a.events {
		if event.Timestamp.After(cutoff) {
			newEvents = append(newEvents, event)
		}
	}

	a.events = newEvents
}
