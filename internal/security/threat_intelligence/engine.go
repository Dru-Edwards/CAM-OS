package threat_intelligence

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// ThreatIntelligenceEngine manages threat intelligence feeds and analysis
type ThreatIntelligenceEngine struct {
	// Core components
	feedManager     *FeedManager
	correlationEngine *CorrelationEngine
	analysisEngine    *AnalysisEngine
	iocDetector       *IOCDetector
	huntingEngine     *HuntingEngine
	
	// Data stores
	threatData      map[string]*ThreatIndicator
	campaigns       map[string]*ThreatCampaign
	actors          map[string]*ThreatActor
	signatures      map[string]*ThreatSignature
	rules           map[string]*DetectionRule
	
	// Synchronization
	mutex           sync.RWMutex
	feedMutex       sync.RWMutex
	analysisMutex   sync.RWMutex
	
	// Configuration
	config          *ThreatIntelConfig
	
	// Metrics
	totalIndicators  int64
	activeFeeds      int64
	correlations     int64
	detections       int64
	falsePositives   int64
	lastUpdate       time.Time
	
	// Context for shutdown
	ctx             context.Context
	cancel          context.CancelFunc
	
	// Event channels
	threatChannel   chan *ThreatEvent
	alertChannel    chan *ThreatAlert
	
	// Cache
	cache          *ThreatCache
	
	// External integrations
	externalFeeds   map[string]*ExternalFeed
	apiClients      map[string]*APIClient
}

// ThreatIntelConfig holds configuration for threat intelligence
type ThreatIntelConfig struct {
	// Feed configuration
	FeedUpdateInterval    time.Duration
	FeedTimeout          time.Duration
	MaxFeedSize          int64
	EnabledFeeds         []string
	
	// Analysis configuration
	AnalysisWorkers      int
	CorrelationWindow    time.Duration
	ConfidenceThreshold  float64
	MaxCorrelationDepth  int
	
	// Detection configuration
	DetectionSensitivity string
	AlertThreshold       float64
	AutoBlockThreshold   float64
	WhitelistEnabled     bool
	
	// Storage configuration
	RetentionPeriod      time.Duration
	MaxIndicators        int
	CacheSize            int
	
	// Performance settings
	BatchSize            int
	ProcessingInterval   time.Duration
	MaxConcurrentAnalysis int
	
	// Integration settings
	ExternalAPITimeout   time.Duration
	RateLimitPerSecond   int
	EnableCloudFeeds     bool
	EnableCommercialFeeds bool
}

// ThreatIndicator represents a threat intelligence indicator
type ThreatIndicator struct {
	ID               string
	Type             IndicatorType
	Value            string
	Source           string
	FirstSeen        time.Time
	LastSeen         time.Time
	Confidence       float64
	Severity         ThreatSeverity
	TLP              TLPLevel
	
	// Attribution
	Campaign         string
	Actor            string
	Malware          string
	AttackVector     string
	
	// Technical details
	Hash             string
	Domain           string
	URL              string
	IP               string
	Port             int
	Protocol         string
	UserAgent        string
	FileSize         int64
	FileType         string
	
	// Context
	Description      string
	Tags             []string
	MITRE            []string
	CVE              []string
	References       []string
	
	// Metadata
	Raw              string
	Processed        bool
	Verified         bool
	Active           bool
	Expired          bool
	
	// Scoring
	RiskScore        float64
	RelevanceScore   float64
	FreshnessFactor  float64
	
	// Relationships
	RelatedIndicators []string
	ChildIndicators   []string
	ParentIndicators  []string
}

// IndicatorType represents the type of threat indicator
type IndicatorType string

const (
	IndicatorTypeHash       IndicatorType = "hash"
	IndicatorTypeIP         IndicatorType = "ip"
	IndicatorTypeDomain     IndicatorType = "domain"
	IndicatorTypeURL        IndicatorType = "url"
	IndicatorTypeEmail      IndicatorType = "email"
	IndicatorTypeFile       IndicatorType = "file"
	IndicatorTypeRegistry   IndicatorType = "registry"
	IndicatorTypeMutex      IndicatorType = "mutex"
	IndicatorTypeYara       IndicatorType = "yara"
	IndicatorTypeSnort      IndicatorType = "snort"
	IndicatorTypeCertificate IndicatorType = "certificate"
	IndicatorTypeUserAgent  IndicatorType = "user_agent"
	IndicatorTypeSSL        IndicatorType = "ssl"
	IndicatorTypeX509       IndicatorType = "x509"
)

// ThreatSeverity represents the severity level of a threat
type ThreatSeverity string

const (
	SeverityInfo     ThreatSeverity = "info"
	SeverityLow      ThreatSeverity = "low"
	SeverityMedium   ThreatSeverity = "medium"
	SeverityHigh     ThreatSeverity = "high"
	SeverityCritical ThreatSeverity = "critical"
)

// TLPLevel represents Traffic Light Protocol classification
type TLPLevel string

const (
	TLPWhite  TLPLevel = "white"
	TLPGreen  TLPLevel = "green"
	TLPAmber  TLPLevel = "amber"
	TLPRed    TLPLevel = "red"
)

// ThreatCampaign represents a threat campaign
type ThreatCampaign struct {
	ID               string
	Name             string
	Description      string
	FirstSeen        time.Time
	LastSeen         time.Time
	Active           bool
	Confidence       float64
	
	// Attribution
	Actors           []string
	Malware          []string
	Tools            []string
	TTP              []string
	
	// Targeting
	Sectors          []string
	Regions          []string
	Countries        []string
	
	// Indicators
	Indicators       []string
	TotalIndicators  int
	UniqueIndicators int
	
	// Analysis
	Sophistication   string
	Motivation       string
	Objectives       []string
	
	// Metadata
	Sources          []string
	Tags             []string
	References       []string
	LastAnalyzed     time.Time
}

// ThreatActor represents a threat actor
type ThreatActor struct {
	ID               string
	Name             string
	Aliases          []string
	Description      string
	FirstSeen        time.Time
	LastSeen         time.Time
	Active           bool
	Confidence       float64
	
	// Attribution
	Country          string
	Motivation       string
	Sophistication   string
	Resources        string
	
	// Capabilities
	Tools            []string
	Malware          []string
	TTP              []string
	
	// Targeting
	Sectors          []string
	Regions          []string
	Countries        []string
	
	// Campaigns
	Campaigns        []string
	Operations       []string
	
	// Indicators
	Indicators       []string
	TotalIndicators  int
	
	// Metadata
	Sources          []string
	Tags             []string
	References       []string
	LastAnalyzed     time.Time
}

// ThreatSignature represents a detection signature
type ThreatSignature struct {
	ID               string
	Name             string
	Type             SignatureType
	Content          string
	Version          string
	Author           string
	CreatedAt        time.Time
	UpdatedAt        time.Time
	
	// Detection
	Confidence       float64
	Severity         ThreatSeverity
	FalsePositiveRate float64
	
	// Metadata
	Description      string
	References       []string
	Tags             []string
	MITRE            []string
	
	// Performance
	Matches          int64
	LastMatch        time.Time
	ProcessingTime   time.Duration
	
	// Status
	Active           bool
	Verified         bool
	Deprecated       bool
	
	// Relationships
	RelatedSignatures []string
	CoveredIndicators []string
}

// SignatureType represents the type of detection signature
type SignatureType string

const (
	SignatureTypeYara    SignatureType = "yara"
	SignatureTypeSnort   SignatureType = "snort"
	SignatureTypeSigma   SignatureType = "sigma"
	SignatureTypeCustom  SignatureType = "custom"
	SignatureTypeRegex   SignatureType = "regex"
	SignatureTypeHash    SignatureType = "hash"
	SignatureTypeBehavior SignatureType = "behavior"
)

// DetectionRule represents a detection rule
type DetectionRule struct {
	ID               string
	Name             string
	Description      string
	Severity         ThreatSeverity
	Confidence       float64
	Author           string
	CreatedAt        time.Time
	UpdatedAt        time.Time
	
	// Rule logic
	Conditions       []RuleCondition
	Actions          []RuleAction
	Threshold        int
	TimeWindow       time.Duration
	
	// Performance
	Matches          int64
	FalsePositives   int64
	LastMatch        time.Time
	ProcessingTime   time.Duration
	
	// Status
	Active           bool
	Verified         bool
	Tuned            bool
	
	// Metadata
	Tags             []string
	MITRE            []string
	References       []string
	
	// Relationships
	RelatedRules     []string
	CoveredThreat    []string
}

// RuleCondition represents a condition in a detection rule
type RuleCondition struct {
	Field            string
	Operator         string
	Value            interface{}
	CaseSensitive    bool
	Negated          bool
}

// RuleAction represents an action to take when a rule matches
type RuleAction struct {
	Type             string
	Parameters       map[string]interface{}
	Severity         ThreatSeverity
	Alert            bool
	Block            bool
	Log              bool
}

// ThreatEvent represents a threat intelligence event
type ThreatEvent struct {
	ID               string
	Type             EventType
	Timestamp        time.Time
	Source           string
	Indicator        *ThreatIndicator
	Campaign         *ThreatCampaign
	Actor            *ThreatActor
	Signature        *ThreatSignature
	
	// Context
	Description      string
	Severity         ThreatSeverity
	Confidence       float64
	RiskScore        float64
	
	// Metadata
	Tags             []string
	References       []string
	Raw              string
	Processed        bool
	
	// Relationships
	RelatedEvents    []string
	CorrelatedEvents []string
}

// EventType represents the type of threat event
type EventType string

const (
	EventTypeNewIndicator    EventType = "new_indicator"
	EventTypeUpdatedIndicator EventType = "updated_indicator"
	EventTypeNewCampaign     EventType = "new_campaign"
	EventTypeNewActor        EventType = "new_actor"
	EventTypeCorrelation     EventType = "correlation"
	EventTypeDetection       EventType = "detection"
	EventTypeAlert           EventType = "alert"
	EventTypeFalsePositive   EventType = "false_positive"
)

// ThreatAlert represents a threat intelligence alert
type ThreatAlert struct {
	ID               string
	Type             AlertType
	Timestamp        time.Time
	Source           string
	Title            string
	Description      string
	Severity         ThreatSeverity
	Confidence       float64
	RiskScore        float64
	
	// Indicators
	Indicators       []string
	PrimaryIndicator string
	
	// Attribution
	Campaign         string
	Actor            string
	Malware          string
	
	// Technical details
	AttackVector     string
	TTP              []string
	MITRE            []string
	
	// Response
	Recommended      []string
	Mitigations      []string
	Actions          []string
	
	// Status
	Status           AlertStatus
	Acknowledged     bool
	Resolved         bool
	FalsePositive    bool
	
	// Metadata
	Tags             []string
	References       []string
	LastUpdated      time.Time
	
	// Relationships
	RelatedAlerts    []string
	ChildAlerts      []string
	ParentAlert      string
}

// AlertType represents the type of threat alert
type AlertType string

const (
	AlertTypeIndicator   AlertType = "indicator"
	AlertTypeCampaign    AlertType = "campaign"
	AlertTypeActor       AlertType = "actor"
	AlertTypeSignature   AlertType = "signature"
	AlertTypeCorrelation AlertType = "correlation"
	AlertTypeAnomaly     AlertType = "anomaly"
	AlertTypeHunt        AlertType = "hunt"
)

// AlertStatus represents the status of an alert
type AlertStatus string

const (
	AlertStatusNew        AlertStatus = "new"
	AlertStatusInvestigating AlertStatus = "investigating"
	AlertStatusConfirmed  AlertStatus = "confirmed"
	AlertStatusFalsePositive AlertStatus = "false_positive"
	AlertStatusResolved   AlertStatus = "resolved"
	AlertStatusSuppressed AlertStatus = "suppressed"
)

// NewThreatIntelligenceEngine creates a new threat intelligence engine
func NewThreatIntelligenceEngine(config *ThreatIntelConfig) *ThreatIntelligenceEngine {
	if config == nil {
		config = &ThreatIntelConfig{
			FeedUpdateInterval:     15 * time.Minute,
			FeedTimeout:           30 * time.Second,
			MaxFeedSize:           100 * 1024 * 1024, // 100MB
			EnabledFeeds:          []string{"misp", "otx", "virustotal", "internal"},
			AnalysisWorkers:       4,
			CorrelationWindow:     24 * time.Hour,
			ConfidenceThreshold:   0.7,
			MaxCorrelationDepth:   5,
			DetectionSensitivity:  "medium",
			AlertThreshold:        0.8,
			AutoBlockThreshold:    0.9,
			WhitelistEnabled:      true,
			RetentionPeriod:       30 * 24 * time.Hour,
			MaxIndicators:         1000000,
			CacheSize:            10000,
			BatchSize:            1000,
			ProcessingInterval:    5 * time.Second,
			MaxConcurrentAnalysis: 10,
			ExternalAPITimeout:    30 * time.Second,
			RateLimitPerSecond:    10,
			EnableCloudFeeds:      true,
			EnableCommercialFeeds: false,
		}
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	engine := &ThreatIntelligenceEngine{
		config:           config,
		threatData:       make(map[string]*ThreatIndicator),
		campaigns:        make(map[string]*ThreatCampaign),
		actors:           make(map[string]*ThreatActor),
		signatures:       make(map[string]*ThreatSignature),
		rules:            make(map[string]*DetectionRule),
		ctx:              ctx,
		cancel:           cancel,
		threatChannel:    make(chan *ThreatEvent, 1000),
		alertChannel:     make(chan *ThreatAlert, 1000),
		externalFeeds:    make(map[string]*ExternalFeed),
		apiClients:       make(map[string]*APIClient),
	}
	
	// Initialize components
	engine.feedManager = NewFeedManager(config)
	engine.correlationEngine = NewCorrelationEngine(config)
	engine.analysisEngine = NewAnalysisEngine(config)
	engine.iocDetector = NewIOCDetector(config)
	engine.huntingEngine = NewHuntingEngine(config)
	engine.cache = NewThreatCache(config.CacheSize)
	
	return engine
}

// Start starts the threat intelligence engine
func (t *ThreatIntelligenceEngine) Start() error {
	// Start feed manager
	err := t.feedManager.Start(t.ctx)
	if err != nil {
		return fmt.Errorf("failed to start feed manager: %v", err)
	}
	
	// Start correlation engine
	err = t.correlationEngine.Start(t.ctx)
	if err != nil {
		return fmt.Errorf("failed to start correlation engine: %v", err)
	}
	
	// Start analysis engine
	err = t.analysisEngine.Start(t.ctx)
	if err != nil {
		return fmt.Errorf("failed to start analysis engine: %v", err)
	}
	
	// Start IoC detector
	err = t.iocDetector.Start(t.ctx)
	if err != nil {
		return fmt.Errorf("failed to start IoC detector: %v", err)
	}
	
	// Start hunting engine
	err = t.huntingEngine.Start(t.ctx)
	if err != nil {
		return fmt.Errorf("failed to start hunting engine: %v", err)
	}
	
	// Start background workers
	go t.processingWorker()
	go t.correlationWorker()
	go t.analysisWorker()
	go t.cleanupWorker()
	go t.eventProcessor()
	go t.alertProcessor()
	
	// Initialize external feeds
	t.initializeExternalFeeds()
	
	return nil
}

// Stop stops the threat intelligence engine
func (t *ThreatIntelligenceEngine) Stop() error {
	t.cancel()
	
	// Stop components
	t.feedManager.Stop()
	t.correlationEngine.Stop()
	t.analysisEngine.Stop()
	t.iocDetector.Stop()
	t.huntingEngine.Stop()
	
	// Close channels
	close(t.threatChannel)
	close(t.alertChannel)
	
	return nil
}

// IngestIndicator ingests a new threat indicator
func (t *ThreatIntelligenceEngine) IngestIndicator(indicator *ThreatIndicator) error {
	if indicator == nil {
		return fmt.Errorf("indicator is nil")
	}
	
	// Validate indicator
	err := t.validateIndicator(indicator)
	if err != nil {
		return fmt.Errorf("invalid indicator: %v", err)
	}
	
	// Generate ID if not provided
	if indicator.ID == "" {
		indicator.ID = t.generateIndicatorID(indicator)
	}
	
	// Enrich indicator
	err = t.enrichIndicator(indicator)
	if err != nil {
		return fmt.Errorf("failed to enrich indicator: %v", err)
	}
	
	// Store indicator
	t.mutex.Lock()
	t.threatData[indicator.ID] = indicator
	t.totalIndicators++
	t.lastUpdate = time.Now()
	t.mutex.Unlock()
	
	// Cache indicator
	t.cache.Set(indicator.ID, indicator)
	
	// Send event
	event := &ThreatEvent{
		ID:        t.generateEventID(),
		Type:      EventTypeNewIndicator,
		Timestamp: time.Now(),
		Source:    "engine",
		Indicator: indicator,
		Severity:  indicator.Severity,
		Confidence: indicator.Confidence,
		RiskScore: indicator.RiskScore,
	}
	
	select {
	case t.threatChannel <- event:
	default:
		// Channel full, drop event
	}
	
	return nil
}

// QueryIndicators queries threat indicators
func (t *ThreatIntelligenceEngine) QueryIndicators(query *ThreatQuery) ([]*ThreatIndicator, error) {
	if query == nil {
		return nil, fmt.Errorf("query is nil")
	}
	
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	
	var results []*ThreatIndicator
	
	// Filter indicators based on query
	for _, indicator := range t.threatData {
		if t.matchesQuery(indicator, query) {
			results = append(results, indicator)
		}
	}
	
	// Sort results
	sort.Slice(results, func(i, j int) bool {
		return results[i].RiskScore > results[j].RiskScore
	})
	
	// Apply limit
	if query.Limit > 0 && len(results) > query.Limit {
		results = results[:query.Limit]
	}
	
	return results, nil
}

// ThreatQuery represents a query for threat indicators
type ThreatQuery struct {
	Type            IndicatorType
	Value           string
	Source          string
	Severity        ThreatSeverity
	MinConfidence   float64
	MinRiskScore    float64
	Tags            []string
	Campaign        string
	Actor           string
	StartTime       time.Time
	EndTime         time.Time
	Active          *bool
	Expired         *bool
	Limit           int
	Offset          int
}

// LookupIndicator looks up a specific indicator
func (t *ThreatIntelligenceEngine) LookupIndicator(value string, indicatorType IndicatorType) (*ThreatIndicator, error) {
	// Try cache first
	key := fmt.Sprintf("%s:%s", indicatorType, value)
	if cached := t.cache.Get(key); cached != nil {
		if indicator, ok := cached.(*ThreatIndicator); ok {
			return indicator, nil
		}
	}
	
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	
	// Search through indicators
	for _, indicator := range t.threatData {
		if indicator.Type == indicatorType && indicator.Value == value {
			// Cache result
			t.cache.Set(key, indicator)
			return indicator, nil
		}
	}
	
	return nil, fmt.Errorf("indicator not found")
}

// AnalyzeIndicator performs comprehensive analysis of an indicator
func (t *ThreatIntelligenceEngine) AnalyzeIndicator(indicator *ThreatIndicator) (*ThreatAnalysis, error) {
	if indicator == nil {
		return nil, fmt.Errorf("indicator is nil")
	}
	
	analysis := &ThreatAnalysis{
		IndicatorID:     indicator.ID,
		Timestamp:       time.Now(),
		RiskScore:       indicator.RiskScore,
		Confidence:      indicator.Confidence,
		Severity:        indicator.Severity,
		ThreatTypes:     make([]string, 0),
		AttackVectors:   make([]string, 0),
		Mitigations:     make([]string, 0),
		Relationships:   make([]string, 0),
		Sources:         make([]string, 0),
		Enrichments:     make(map[string]interface{}),
	}
	
	// Perform analysis
	err := t.analysisEngine.AnalyzeIndicator(indicator, analysis)
	if err != nil {
		return nil, fmt.Errorf("analysis failed: %v", err)
	}
	
	// Find correlations
	correlations, err := t.correlationEngine.FindCorrelations(indicator)
	if err != nil {
		return nil, fmt.Errorf("correlation failed: %v", err)
	}
	
	analysis.Correlations = correlations
	
	// Add to relationships
	for _, correlation := range correlations {
		analysis.Relationships = append(analysis.Relationships, correlation.RelatedIndicator)
	}
	
	return analysis, nil
}

// ThreatAnalysis represents the analysis result for a threat indicator
type ThreatAnalysis struct {
	IndicatorID     string
	Timestamp       time.Time
	RiskScore       float64
	Confidence      float64
	Severity        ThreatSeverity
	ThreatTypes     []string
	AttackVectors   []string
	Mitigations     []string
	Relationships   []string
	Sources         []string
	Correlations    []*ThreatCorrelation
	Enrichments     map[string]interface{}
	Recommendations []string
	Timeline        []ThreatTimelineEvent
}

// ThreatCorrelation represents a correlation between threat indicators
type ThreatCorrelation struct {
	RelatedIndicator string
	CorrelationType  string
	Confidence       float64
	Evidence         []string
	Timestamp        time.Time
}

// ThreatTimelineEvent represents an event in the threat timeline
type ThreatTimelineEvent struct {
	Timestamp   time.Time
	Type        string
	Description string
	Source      string
	Indicator   string
}

// DetectThreats detects threats using the provided data
func (t *ThreatIntelligenceEngine) DetectThreats(data *DetectionData) ([]*ThreatDetection, error) {
	if data == nil {
		return nil, fmt.Errorf("detection data is nil")
	}
	
	var detections []*ThreatDetection
	
	// IoC detection
	iocDetections, err := t.iocDetector.DetectIOCs(data)
	if err != nil {
		return nil, fmt.Errorf("IoC detection failed: %v", err)
	}
	
	detections = append(detections, iocDetections...)
	
	// Signature-based detection
	sigDetections, err := t.detectSignatures(data)
	if err != nil {
		return nil, fmt.Errorf("signature detection failed: %v", err)
	}
	
	detections = append(detections, sigDetections...)
	
	// Rule-based detection
	ruleDetections, err := t.detectRules(data)
	if err != nil {
		return nil, fmt.Errorf("rule detection failed: %v", err)
	}
	
	detections = append(detections, ruleDetections...)
	
	// Update metrics
	t.detections += int64(len(detections))
	
	return detections, nil
}

// DetectionData represents data for threat detection
type DetectionData struct {
	Type        string
	Source      string
	Timestamp   time.Time
	Data        map[string]interface{}
	NetworkData *NetworkData
	FileData    *FileData
	ProcessData *ProcessData
	EventData   *EventData
}

// NetworkData represents network-related data
type NetworkData struct {
	SourceIP      string
	DestinationIP string
	SourcePort    int
	DestinationPort int
	Protocol      string
	Domain        string
	URL           string
	UserAgent     string
	Headers       map[string]string
	Payload       []byte
}

// FileData represents file-related data
type FileData struct {
	Path        string
	Name        string
	Size        int64
	Hash        string
	MD5         string
	SHA1        string
	SHA256      string
	Type        string
	Signature   string
	Metadata    map[string]string
}

// ProcessData represents process-related data
type ProcessData struct {
	PID         int
	PPID        int
	Name        string
	Path        string
	CommandLine string
	User        string
	StartTime   time.Time
	EndTime     time.Time
	ExitCode    int
	Modules     []string
	Connections []string
}

// EventData represents event-related data
type EventData struct {
	ID          string
	Type        string
	Category    string
	Action      string
	Outcome     string
	User        string
	Host        string
	Timestamp   time.Time
	Details     map[string]interface{}
}

// ThreatDetection represents a threat detection result
type ThreatDetection struct {
	ID              string
	Type            string
	Timestamp       time.Time
	Source          string
	Indicator       *ThreatIndicator
	Signature       *ThreatSignature
	Rule            *DetectionRule
	Confidence      float64
	Severity        ThreatSeverity
	RiskScore       float64
	Description     string
	Evidence        []string
	Mitigations     []string
	Actions         []string
	FalsePositive   bool
	Acknowledged    bool
	Suppressed      bool
	Context         map[string]interface{}
}

// Implementation methods

func (t *ThreatIntelligenceEngine) validateIndicator(indicator *ThreatIndicator) error {
	if indicator.Type == "" {
		return fmt.Errorf("indicator type is required")
	}
	
	if indicator.Value == "" {
		return fmt.Errorf("indicator value is required")
	}
	
	if indicator.Source == "" {
		return fmt.Errorf("indicator source is required")
	}
	
	if indicator.Confidence < 0 || indicator.Confidence > 1 {
		return fmt.Errorf("confidence must be between 0 and 1")
	}
	
	return nil
}

func (t *ThreatIntelligenceEngine) enrichIndicator(indicator *ThreatIndicator) error {
	// Set default values
	if indicator.FirstSeen.IsZero() {
		indicator.FirstSeen = time.Now()
	}
	
	if indicator.LastSeen.IsZero() {
		indicator.LastSeen = time.Now()
	}
	
	if indicator.Confidence == 0 {
		indicator.Confidence = 0.5 // Default confidence
	}
	
	if indicator.Severity == "" {
		indicator.Severity = SeverityMedium
	}
	
	if indicator.TLP == "" {
		indicator.TLP = TLPAmber
	}
	
	// Calculate risk score
	indicator.RiskScore = t.calculateRiskScore(indicator)
	
	// Calculate relevance score
	indicator.RelevanceScore = t.calculateRelevanceScore(indicator)
	
	// Calculate freshness factor
	indicator.FreshnessFactor = t.calculateFreshnessFactor(indicator)
	
	// Generate hash
	indicator.Hash = t.generateIndicatorHash(indicator)
	
	// Set as active
	indicator.Active = true
	indicator.Processed = true
	
	return nil
}

func (t *ThreatIntelligenceEngine) calculateRiskScore(indicator *ThreatIndicator) float64 {
	score := 0.0
	
	// Base score from confidence
	score += indicator.Confidence * 0.4
	
	// Severity multiplier
	switch indicator.Severity {
	case SeverityInfo:
		score += 0.1
	case SeverityLow:
		score += 0.2
	case SeverityMedium:
		score += 0.4
	case SeverityHigh:
		score += 0.7
	case SeverityCritical:
		score += 1.0
	}
	
	// Type-specific adjustments
	switch indicator.Type {
	case IndicatorTypeHash:
		score += 0.1
	case IndicatorTypeIP:
		score += 0.2
	case IndicatorTypeDomain:
		score += 0.15
	case IndicatorTypeURL:
		score += 0.15
	case IndicatorTypeFile:
		score += 0.1
	}
	
	// Campaign/Actor bonus
	if indicator.Campaign != "" {
		score += 0.1
	}
	
	if indicator.Actor != "" {
		score += 0.1
	}
	
	// Normalize to 0-1 range
	if score > 1.0 {
		score = 1.0
	}
	
	return score
}

func (t *ThreatIntelligenceEngine) calculateRelevanceScore(indicator *ThreatIndicator) float64 {
	score := 0.5 // Base relevance
	
	// Freshness factor
	age := time.Since(indicator.LastSeen)
	if age < 24*time.Hour {
		score += 0.3
	} else if age < 7*24*time.Hour {
		score += 0.2
	} else if age < 30*24*time.Hour {
		score += 0.1
	}
	
	// Source reliability
	if t.isReliableSource(indicator.Source) {
		score += 0.2
	}
	
	// Normalize to 0-1 range
	if score > 1.0 {
		score = 1.0
	}
	
	return score
}

func (t *ThreatIntelligenceEngine) calculateFreshnessFactor(indicator *ThreatIndicator) float64 {
	age := time.Since(indicator.LastSeen)
	if age < time.Hour {
		return 1.0
	} else if age < 24*time.Hour {
		return 0.8
	} else if age < 7*24*time.Hour {
		return 0.6
	} else if age < 30*24*time.Hour {
		return 0.4
	} else {
		return 0.2
	}
}

func (t *ThreatIntelligenceEngine) generateIndicatorID(indicator *ThreatIndicator) string {
	data := fmt.Sprintf("%s:%s:%s", indicator.Type, indicator.Value, indicator.Source)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)[:16]
}

func (t *ThreatIntelligenceEngine) generateIndicatorHash(indicator *ThreatIndicator) string {
	data := fmt.Sprintf("%s:%s", indicator.Type, indicator.Value)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)
}

func (t *ThreatIntelligenceEngine) generateEventID() string {
	data := fmt.Sprintf("%d:%s", time.Now().UnixNano(), "event")
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)[:16]
}

func (t *ThreatIntelligenceEngine) isReliableSource(source string) bool {
	reliableSources := []string{
		"misp", "otx", "virustotal", "internal", "cti", "government", "commercial"
	}
	
	for _, reliable := range reliableSources {
		if strings.Contains(strings.ToLower(source), reliable) {
			return true
		}
	}
	
	return false
}

func (t *ThreatIntelligenceEngine) matchesQuery(indicator *ThreatIndicator, query *ThreatQuery) bool {
	// Type filter
	if query.Type != "" && indicator.Type != query.Type {
		return false
	}
	
	// Value filter
	if query.Value != "" && !strings.Contains(indicator.Value, query.Value) {
		return false
	}
	
	// Source filter
	if query.Source != "" && indicator.Source != query.Source {
		return false
	}
	
	// Severity filter
	if query.Severity != "" && indicator.Severity != query.Severity {
		return false
	}
	
	// Confidence filter
	if query.MinConfidence > 0 && indicator.Confidence < query.MinConfidence {
		return false
	}
	
	// Risk score filter
	if query.MinRiskScore > 0 && indicator.RiskScore < query.MinRiskScore {
		return false
	}
	
	// Tags filter
	if len(query.Tags) > 0 {
		hasTag := false
		for _, queryTag := range query.Tags {
			for _, indicatorTag := range indicator.Tags {
				if strings.EqualFold(queryTag, indicatorTag) {
					hasTag = true
					break
				}
			}
			if hasTag {
				break
			}
		}
		if !hasTag {
			return false
		}
	}
	
	// Campaign filter
	if query.Campaign != "" && indicator.Campaign != query.Campaign {
		return false
	}
	
	// Actor filter
	if query.Actor != "" && indicator.Actor != query.Actor {
		return false
	}
	
	// Time range filter
	if !query.StartTime.IsZero() && indicator.LastSeen.Before(query.StartTime) {
		return false
	}
	
	if !query.EndTime.IsZero() && indicator.LastSeen.After(query.EndTime) {
		return false
	}
	
	// Active filter
	if query.Active != nil && indicator.Active != *query.Active {
		return false
	}
	
	// Expired filter
	if query.Expired != nil && indicator.Expired != *query.Expired {
		return false
	}
	
	return true
}

func (t *ThreatIntelligenceEngine) detectSignatures(data *DetectionData) ([]*ThreatDetection, error) {
	var detections []*ThreatDetection
	
	t.mutex.RLock()
	signatures := make([]*ThreatSignature, 0, len(t.signatures))
	for _, sig := range t.signatures {
		if sig.Active {
			signatures = append(signatures, sig)
		}
	}
	t.mutex.RUnlock()
	
	// Test each signature
	for _, signature := range signatures {
		if t.testSignature(signature, data) {
			detection := &ThreatDetection{
				ID:          t.generateDetectionID(),
				Type:        "signature",
				Timestamp:   time.Now(),
				Source:      "engine",
				Signature:   signature,
				Confidence:  signature.Confidence,
				Severity:    signature.Severity,
				RiskScore:   float64(signature.Severity == SeverityCritical),
				Description: fmt.Sprintf("Signature match: %s", signature.Name),
				Evidence:    []string{signature.Content},
				Context:     map[string]interface{}{"signature_id": signature.ID},
			}
			
			detections = append(detections, detection)
		}
	}
	
	return detections, nil
}

func (t *ThreatIntelligenceEngine) detectRules(data *DetectionData) ([]*ThreatDetection, error) {
	var detections []*ThreatDetection
	
	t.mutex.RLock()
	rules := make([]*DetectionRule, 0, len(t.rules))
	for _, rule := range t.rules {
		if rule.Active {
			rules = append(rules, rule)
		}
	}
	t.mutex.RUnlock()
	
	// Test each rule
	for _, rule := range rules {
		if t.testRule(rule, data) {
			detection := &ThreatDetection{
				ID:          t.generateDetectionID(),
				Type:        "rule",
				Timestamp:   time.Now(),
				Source:      "engine",
				Rule:        rule,
				Confidence:  rule.Confidence,
				Severity:    rule.Severity,
				RiskScore:   float64(rule.Severity == SeverityCritical),
				Description: fmt.Sprintf("Rule match: %s", rule.Name),
				Evidence:    []string{rule.Description},
				Context:     map[string]interface{}{"rule_id": rule.ID},
			}
			
			detections = append(detections, detection)
		}
	}
	
	return detections, nil
}

func (t *ThreatIntelligenceEngine) testSignature(signature *ThreatSignature, data *DetectionData) bool {
	// Simplified signature matching
	switch signature.Type {
	case SignatureTypeYara:
		return t.testYaraSignature(signature, data)
	case SignatureTypeSnort:
		return t.testSnortSignature(signature, data)
	case SignatureTypeRegex:
		return t.testRegexSignature(signature, data)
	case SignatureTypeHash:
		return t.testHashSignature(signature, data)
	default:
		return false
	}
}

func (t *ThreatIntelligenceEngine) testRule(rule *DetectionRule, data *DetectionData) bool {
	// Simplified rule matching
	matchedConditions := 0
	
	for _, condition := range rule.Conditions {
		if t.testCondition(condition, data) {
			matchedConditions++
		}
	}
	
	return matchedConditions >= rule.Threshold
}

func (t *ThreatIntelligenceEngine) testCondition(condition RuleCondition, data *DetectionData) bool {
	// Extract field value from data
	fieldValue := t.extractFieldValue(condition.Field, data)
	if fieldValue == nil {
		return false
	}
	
	// Test condition
	switch condition.Operator {
	case "equals":
		return t.compareValues(fieldValue, condition.Value, condition.CaseSensitive)
	case "contains":
		return t.containsValue(fieldValue, condition.Value, condition.CaseSensitive)
	case "matches":
		return t.matchesPattern(fieldValue, condition.Value)
	default:
		return false
	}
}

func (t *ThreatIntelligenceEngine) testYaraSignature(signature *ThreatSignature, data *DetectionData) bool {
	// Simplified YARA matching
	if data.FileData != nil {
		return strings.Contains(strings.ToLower(data.FileData.Name), strings.ToLower(signature.Content))
	}
	return false
}

func (t *ThreatIntelligenceEngine) testSnortSignature(signature *ThreatSignature, data *DetectionData) bool {
	// Simplified Snort matching
	if data.NetworkData != nil {
		return strings.Contains(strings.ToLower(data.NetworkData.URL), strings.ToLower(signature.Content))
	}
	return false
}

func (t *ThreatIntelligenceEngine) testRegexSignature(signature *ThreatSignature, data *DetectionData) bool {
	// Simplified regex matching
	dataString := t.dataToString(data)
	return strings.Contains(strings.ToLower(dataString), strings.ToLower(signature.Content))
}

func (t *ThreatIntelligenceEngine) testHashSignature(signature *ThreatSignature, data *DetectionData) bool {
	// Simplified hash matching
	if data.FileData != nil {
		return data.FileData.Hash == signature.Content ||
			   data.FileData.MD5 == signature.Content ||
			   data.FileData.SHA1 == signature.Content ||
			   data.FileData.SHA256 == signature.Content
	}
	return false
}

func (t *ThreatIntelligenceEngine) extractFieldValue(field string, data *DetectionData) interface{} {
	// Extract field value from detection data
	switch field {
	case "source_ip":
		if data.NetworkData != nil {
			return data.NetworkData.SourceIP
		}
	case "destination_ip":
		if data.NetworkData != nil {
			return data.NetworkData.DestinationIP
		}
	case "domain":
		if data.NetworkData != nil {
			return data.NetworkData.Domain
		}
	case "url":
		if data.NetworkData != nil {
			return data.NetworkData.URL
		}
	case "file_hash":
		if data.FileData != nil {
			return data.FileData.Hash
		}
	case "file_name":
		if data.FileData != nil {
			return data.FileData.Name
		}
	case "process_name":
		if data.ProcessData != nil {
			return data.ProcessData.Name
		}
	case "command_line":
		if data.ProcessData != nil {
			return data.ProcessData.CommandLine
		}
	default:
		if data.Data != nil {
			return data.Data[field]
		}
	}
	
	return nil
}

func (t *ThreatIntelligenceEngine) compareValues(a, b interface{}, caseSensitive bool) bool {
	aStr := fmt.Sprintf("%v", a)
	bStr := fmt.Sprintf("%v", b)
	
	if !caseSensitive {
		aStr = strings.ToLower(aStr)
		bStr = strings.ToLower(bStr)
	}
	
	return aStr == bStr
}

func (t *ThreatIntelligenceEngine) containsValue(a, b interface{}, caseSensitive bool) bool {
	aStr := fmt.Sprintf("%v", a)
	bStr := fmt.Sprintf("%v", b)
	
	if !caseSensitive {
		aStr = strings.ToLower(aStr)
		bStr = strings.ToLower(bStr)
	}
	
	return strings.Contains(aStr, bStr)
}

func (t *ThreatIntelligenceEngine) matchesPattern(a, b interface{}) bool {
	// Simplified pattern matching
	aStr := fmt.Sprintf("%v", a)
	bStr := fmt.Sprintf("%v", b)
	
	return strings.Contains(strings.ToLower(aStr), strings.ToLower(bStr))
}

func (t *ThreatIntelligenceEngine) dataToString(data *DetectionData) string {
	jsonData, _ := json.Marshal(data)
	return string(jsonData)
}

func (t *ThreatIntelligenceEngine) generateDetectionID() string {
	data := fmt.Sprintf("%d:%s", time.Now().UnixNano(), "detection")
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)[:16]
}

// Background workers

func (t *ThreatIntelligenceEngine) processingWorker() {
	ticker := time.NewTicker(t.config.ProcessingInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			t.processUpdates()
		case <-t.ctx.Done():
			return
		}
	}
}

func (t *ThreatIntelligenceEngine) correlationWorker() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			t.performCorrelation()
		case <-t.ctx.Done():
			return
		}
	}
}

func (t *ThreatIntelligenceEngine) analysisWorker() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			t.performAnalysis()
		case <-t.ctx.Done():
			return
		}
	}
}

func (t *ThreatIntelligenceEngine) cleanupWorker() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			t.performCleanup()
		case <-t.ctx.Done():
			return
		}
	}
}

func (t *ThreatIntelligenceEngine) eventProcessor() {
	for {
		select {
		case event := <-t.threatChannel:
			t.processEvent(event)
		case <-t.ctx.Done():
			return
		}
	}
}

func (t *ThreatIntelligenceEngine) alertProcessor() {
	for {
		select {
		case alert := <-t.alertChannel:
			t.processAlert(alert)
		case <-t.ctx.Done():
			return
		}
	}
}

func (t *ThreatIntelligenceEngine) processUpdates() {
	// Process pending updates
	t.mutex.RLock()
	indicatorCount := len(t.threatData)
	t.mutex.RUnlock()
	
	// Update metrics
	t.lastUpdate = time.Now()
	
	// Log processing statistics
	if indicatorCount > 0 {
		// Processing logic here
	}
}

func (t *ThreatIntelligenceEngine) performCorrelation() {
	// Perform correlation analysis
	t.correlations++
}

func (t *ThreatIntelligenceEngine) performAnalysis() {
	// Perform threat analysis
}

func (t *ThreatIntelligenceEngine) performCleanup() {
	// Clean up expired indicators
	t.mutex.Lock()
	defer t.mutex.Unlock()
	
	cutoff := time.Now().Add(-t.config.RetentionPeriod)
	
	for id, indicator := range t.threatData {
		if indicator.LastSeen.Before(cutoff) {
			delete(t.threatData, id)
		}
	}
}

func (t *ThreatIntelligenceEngine) processEvent(event *ThreatEvent) {
	// Process threat event
	event.Processed = true
}

func (t *ThreatIntelligenceEngine) processAlert(alert *ThreatAlert) {
	// Process threat alert
	alert.Status = AlertStatusInvestigating
}

func (t *ThreatIntelligenceEngine) initializeExternalFeeds() {
	// Initialize external threat intelligence feeds
	if t.config.EnableCloudFeeds {
		t.externalFeeds["misp"] = &ExternalFeed{
			Name:     "MISP",
			URL:      "https://misp.local/attributes/restSearch",
			Type:     "misp",
			Enabled:  true,
			Interval: 15 * time.Minute,
		}
		
		t.externalFeeds["otx"] = &ExternalFeed{
			Name:     "AlienVault OTX",
			URL:      "https://otx.alienvault.com/api/v1/indicators",
			Type:     "otx",
			Enabled:  true,
			Interval: 30 * time.Minute,
		}
	}
}

// Public API methods

func (t *ThreatIntelligenceEngine) GetMetrics() map[string]interface{} {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	
	return map[string]interface{}{
		"total_indicators":  t.totalIndicators,
		"active_feeds":      t.activeFeeds,
		"correlations":      t.correlations,
		"detections":        t.detections,
		"false_positives":   t.falsePositives,
		"last_update":       t.lastUpdate,
		"cache_size":        t.cache.Size(),
		"campaigns":         len(t.campaigns),
		"actors":            len(t.actors),
		"signatures":        len(t.signatures),
		"rules":             len(t.rules),
	}
}

func (t *ThreatIntelligenceEngine) GetStatus() map[string]interface{} {
	return map[string]interface{}{
		"status":            "running",
		"feeds":             t.feedManager.GetStatus(),
		"correlation":       t.correlationEngine.GetStatus(),
		"analysis":          t.analysisEngine.GetStatus(),
		"ioc_detection":     t.iocDetector.GetStatus(),
		"hunting":           t.huntingEngine.GetStatus(),
		"uptime":            time.Since(t.lastUpdate),
	}
}

// ExternalFeed represents an external threat intelligence feed
type ExternalFeed struct {
	Name     string
	URL      string
	Type     string
	Enabled  bool
	Interval time.Duration
	LastSync time.Time
	Status   string
}

// APIClient represents a client for external APIs
type APIClient struct {
	Name       string
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
	RateLimit  int
	LastCall   time.Time
} 