package threat_intelligence

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// CorrelationEngine finds relationships between threat indicators
type CorrelationEngine struct {
	config             *ThreatIntelConfig
	correlationRules   map[string]*CorrelationRule
	correlationCache   map[string][]*ThreatCorrelation
	mutex              sync.RWMutex
	cacheMutex         sync.RWMutex
	
	// Metrics
	totalCorrelations  int64
	cacheHits          int64
	cacheMisses        int64
	rulesProcessed     int64
	
	// Context
	ctx                context.Context
	cancel             context.CancelFunc
}

// CorrelationRule defines how to correlate threat indicators
type CorrelationRule struct {
	ID                 string
	Name               string
	Description        string
	Enabled            bool
	Priority           int
	CorrelationType    string
	SourceType         IndicatorType
	TargetType         IndicatorType
	Conditions         []CorrelationCondition
	Threshold          float64
	TimeWindow         time.Duration
	MaxDistance        int
	Weight             float64
	CreatedAt          time.Time
	UpdatedAt          time.Time
	
	// Statistics
	Matches            int64
	FalsePositives     int64
	LastMatch          time.Time
	AverageConfidence  float64
	
	// Metadata
	Author             string
	Tags               []string
	References         []string
	Active             bool
}

// CorrelationCondition defines a condition for correlation
type CorrelationCondition struct {
	Field              string
	Operator           string
	Value              interface{}
	Weight             float64
	Required           bool
	CaseSensitive      bool
	Regex              bool
}

// CorrelationGraph represents a graph of correlated indicators
type CorrelationGraph struct {
	Nodes              map[string]*CorrelationNode
	Edges              map[string]*CorrelationEdge
	CentralNodes       []string
	Clusters           [][]string
	MaxDepth           int
	TotalNodes         int
	TotalEdges         int
	Density            float64
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// CorrelationNode represents a node in the correlation graph
type CorrelationNode struct {
	ID                 string
	IndicatorID        string
	Type               IndicatorType
	Value              string
	Centrality         float64
	ClusterID          string
	ConnectedNodes     []string
	InboundEdges       []string
	OutboundEdges      []string
	Properties         map[string]interface{}
}

// CorrelationEdge represents an edge in the correlation graph
type CorrelationEdge struct {
	ID                 string
	SourceNodeID       string
	TargetNodeID       string
	CorrelationType    string
	Weight             float64
	Confidence         float64
	Evidence           []string
	Properties         map[string]interface{}
	CreatedAt          time.Time
}

// CorrelationResult represents the result of a correlation analysis
type CorrelationResult struct {
	IndicatorID        string
	Correlations       []*ThreatCorrelation
	Graph              *CorrelationGraph
	Clusters           []CorrelationCluster
	CentralIndicators  []string
	RiskScore          float64
	ConfidenceScore    float64
	TotalCorrelations  int
	UniqueCorrelations int
	AnalysisTime       time.Duration
	Timestamp          time.Time
}

// CorrelationCluster represents a cluster of correlated indicators
type CorrelationCluster struct {
	ID                 string
	Indicators         []string
	CorrelationType    string
	Confidence         float64
	Centrality         float64
	Properties         map[string]interface{}
	CreatedAt          time.Time
}

// ThreatCache implements a simple cache for threat intelligence
type ThreatCache struct {
	cache    map[string]interface{}
	mutex    sync.RWMutex
	maxSize  int
	ttl      time.Duration
	entries  map[string]time.Time
}

// NewCorrelationEngine creates a new correlation engine
func NewCorrelationEngine(config *ThreatIntelConfig) *CorrelationEngine {
	engine := &CorrelationEngine{
		config:           config,
		correlationRules: make(map[string]*CorrelationRule),
		correlationCache: make(map[string][]*ThreatCorrelation),
	}
	
	// Initialize default correlation rules
	engine.initializeDefaultRules()
	
	return engine
}

// Start starts the correlation engine
func (c *CorrelationEngine) Start(ctx context.Context) error {
	c.ctx, c.cancel = context.WithCancel(ctx)
	
	// Start background workers
	go c.cacheMaintenanceWorker()
	go c.correlationWorker()
	
	return nil
}

// Stop stops the correlation engine
func (c *CorrelationEngine) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
}

// FindCorrelations finds correlations for a threat indicator
func (c *CorrelationEngine) FindCorrelations(indicator *ThreatIndicator) ([]*ThreatCorrelation, error) {
	if indicator == nil {
		return nil, fmt.Errorf("indicator is nil")
	}
	
	// Check cache first
	c.cacheMutex.RLock()
	if cached, exists := c.correlationCache[indicator.ID]; exists {
		c.cacheMutex.RUnlock()
		c.cacheHits++
		return cached, nil
	}
	c.cacheMutex.RUnlock()
	
	c.cacheMisses++
	
	// Find correlations
	correlations := make([]*ThreatCorrelation, 0)
	
	// Apply correlation rules
	c.mutex.RLock()
	rules := make([]*CorrelationRule, 0, len(c.correlationRules))
	for _, rule := range c.correlationRules {
		if rule.Enabled && rule.Active {
			rules = append(rules, rule)
		}
	}
	c.mutex.RUnlock()
	
	// Process rules
	for _, rule := range rules {
		ruleCorrelations := c.applyCorrelationRule(indicator, rule)
		correlations = append(correlations, ruleCorrelations...)
		c.rulesProcessed++
	}
	
	// Deduplicate correlations
	correlations = c.deduplicateCorrelations(correlations)
	
	// Cache results
	c.cacheMutex.Lock()
	c.correlationCache[indicator.ID] = correlations
	c.cacheMutex.Unlock()
	
	c.totalCorrelations += int64(len(correlations))
	
	return correlations, nil
}

// AnalyzeCorrelations performs comprehensive correlation analysis
func (c *CorrelationEngine) AnalyzeCorrelations(indicator *ThreatIndicator) (*CorrelationResult, error) {
	startTime := time.Now()
	
	// Find correlations
	correlations, err := c.FindCorrelations(indicator)
	if err != nil {
		return nil, fmt.Errorf("failed to find correlations: %v", err)
	}
	
	// Build correlation graph
	graph := c.buildCorrelationGraph(indicator, correlations)
	
	// Identify clusters
	clusters := c.identifyClusters(graph)
	
	// Find central indicators
	centralIndicators := c.findCentralIndicators(graph)
	
	// Calculate scores
	riskScore := c.calculateRiskScore(correlations, graph)
	confidenceScore := c.calculateConfidenceScore(correlations)
	
	result := &CorrelationResult{
		IndicatorID:        indicator.ID,
		Correlations:       correlations,
		Graph:              graph,
		Clusters:           clusters,
		CentralIndicators:  centralIndicators,
		RiskScore:          riskScore,
		ConfidenceScore:    confidenceScore,
		TotalCorrelations:  len(correlations),
		UniqueCorrelations: len(c.getUniqueCorrelations(correlations)),
		AnalysisTime:       time.Since(startTime),
		Timestamp:          time.Now(),
	}
	
	return result, nil
}

// AddCorrelationRule adds a new correlation rule
func (c *CorrelationEngine) AddCorrelationRule(rule *CorrelationRule) error {
	if rule == nil {
		return fmt.Errorf("rule is nil")
	}
	
	// Validate rule
	err := c.validateCorrelationRule(rule)
	if err != nil {
		return fmt.Errorf("invalid correlation rule: %v", err)
	}
	
	// Generate ID if not provided
	if rule.ID == "" {
		rule.ID = c.generateRuleID(rule)
	}
	
	// Set defaults
	c.setRuleDefaults(rule)
	
	// Store rule
	c.mutex.Lock()
	c.correlationRules[rule.ID] = rule
	c.mutex.Unlock()
	
	return nil
}

// Implementation methods

func (c *CorrelationEngine) initializeDefaultRules() {
	// IP-to-IP correlation rule
	ipRule := &CorrelationRule{
		ID:              "ip-to-ip-subnet",
		Name:            "IP Address Subnet Correlation",
		Description:     "Correlates IP addresses in the same subnet",
		Enabled:         true,
		Priority:        1,
		CorrelationType: "subnet",
		SourceType:      IndicatorTypeIP,
		TargetType:      IndicatorTypeIP,
		Conditions: []CorrelationCondition{
			{
				Field:    "subnet",
				Operator: "same",
				Weight:   0.8,
				Required: true,
			},
		},
		Threshold:  0.7,
		TimeWindow: 24 * time.Hour,
		Weight:     0.8,
		Active:     true,
	}
	
	// Domain-to-IP correlation rule
	domainRule := &CorrelationRule{
		ID:              "domain-to-ip-resolution",
		Name:            "Domain to IP Resolution Correlation",
		Description:     "Correlates domains with their resolved IP addresses",
		Enabled:         true,
		Priority:        2,
		CorrelationType: "dns_resolution",
		SourceType:      IndicatorTypeDomain,
		TargetType:      IndicatorTypeIP,
		Conditions: []CorrelationCondition{
			{
				Field:    "dns_resolution",
				Operator: "resolves_to",
				Weight:   0.9,
				Required: true,
			},
		},
		Threshold:  0.8,
		TimeWindow: 48 * time.Hour,
		Weight:     0.9,
		Active:     true,
	}
	
	// Hash-to-Hash correlation rule
	hashRule := &CorrelationRule{
		ID:              "hash-similarity",
		Name:            "File Hash Similarity Correlation",
		Description:     "Correlates files with similar hashes",
		Enabled:         true,
		Priority:        3,
		CorrelationType: "file_similarity",
		SourceType:      IndicatorTypeHash,
		TargetType:      IndicatorTypeHash,
		Conditions: []CorrelationCondition{
			{
				Field:    "hash_similarity",
				Operator: "similar",
				Weight:   0.7,
				Required: true,
			},
		},
		Threshold:  0.6,
		TimeWindow: 72 * time.Hour,
		Weight:     0.7,
		Active:     true,
	}
	
	// Campaign correlation rule
	campaignRule := &CorrelationRule{
		ID:              "campaign-correlation",
		Name:            "Campaign Attribution Correlation",
		Description:     "Correlates indicators belonging to the same campaign",
		Enabled:         true,
		Priority:        4,
		CorrelationType: "campaign",
		SourceType:      "",
		TargetType:      "",
		Conditions: []CorrelationCondition{
			{
				Field:    "campaign",
				Operator: "equals",
				Weight:   0.95,
				Required: true,
			},
		},
		Threshold:  0.9,
		TimeWindow: 30 * 24 * time.Hour,
		Weight:     0.95,
		Active:     true,
	}
	
	// Add rules
	rules := []*CorrelationRule{ipRule, domainRule, hashRule, campaignRule}
	for _, rule := range rules {
		c.AddCorrelationRule(rule)
	}
}

func (c *CorrelationEngine) validateCorrelationRule(rule *CorrelationRule) error {
	if rule.Name == "" {
		return fmt.Errorf("rule name is required")
	}
	
	if rule.CorrelationType == "" {
		return fmt.Errorf("correlation type is required")
	}
	
	if len(rule.Conditions) == 0 {
		return fmt.Errorf("at least one condition is required")
	}
	
	if rule.Threshold < 0 || rule.Threshold > 1 {
		return fmt.Errorf("threshold must be between 0 and 1")
	}
	
	if rule.Weight < 0 || rule.Weight > 1 {
		return fmt.Errorf("weight must be between 0 and 1")
	}
	
	return nil
}

func (c *CorrelationEngine) setRuleDefaults(rule *CorrelationRule) {
	if rule.Priority == 0 {
		rule.Priority = 5
	}
	
	if rule.Threshold == 0 {
		rule.Threshold = 0.5
	}
	
	if rule.Weight == 0 {
		rule.Weight = 0.5
	}
	
	if rule.TimeWindow == 0 {
		rule.TimeWindow = 24 * time.Hour
	}
	
	if rule.MaxDistance == 0 {
		rule.MaxDistance = 3
	}
	
	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()
	rule.Active = true
}

func (c *CorrelationEngine) generateRuleID(rule *CorrelationRule) string {
	return fmt.Sprintf("%s-%s-%s", rule.CorrelationType, rule.SourceType, rule.TargetType)
}

func (c *CorrelationEngine) applyCorrelationRule(indicator *ThreatIndicator, rule *CorrelationRule) []*ThreatCorrelation {
	var correlations []*ThreatCorrelation
	
	// Check if rule applies to this indicator type
	if rule.SourceType != "" && rule.SourceType != indicator.Type {
		return correlations
	}
	
	// Apply rule conditions
	switch rule.CorrelationType {
	case "subnet":
		correlations = c.applySubnetCorrelation(indicator, rule)
	case "dns_resolution":
		correlations = c.applyDNSCorrelation(indicator, rule)
	case "file_similarity":
		correlations = c.applyFileSimilarityCorrelation(indicator, rule)
	case "campaign":
		correlations = c.applyCampaignCorrelation(indicator, rule)
	default:
		correlations = c.applyGenericCorrelation(indicator, rule)
	}
	
	// Update rule statistics
	if len(correlations) > 0 {
		rule.Matches++
		rule.LastMatch = time.Now()
	}
	
	return correlations
}

func (c *CorrelationEngine) applySubnetCorrelation(indicator *ThreatIndicator, rule *CorrelationRule) []*ThreatCorrelation {
	var correlations []*ThreatCorrelation
	
	if indicator.Type != IndicatorTypeIP {
		return correlations
	}
	
	// This is a simplified subnet correlation
	// In a real implementation, you'd parse IP addresses and check subnets
	subnet := c.getSubnet(indicator.Value)
	
	// Find other IPs in the same subnet
	relatedIPs := c.findIPsInSubnet(subnet)
	
	for _, relatedIP := range relatedIPs {
		if relatedIP != indicator.Value {
			correlation := &ThreatCorrelation{
				RelatedIndicator: relatedIP,
				CorrelationType:  "subnet",
				Confidence:       0.8,
				Evidence:         []string{fmt.Sprintf("Same subnet: %s", subnet)},
				Timestamp:        time.Now(),
			}
			correlations = append(correlations, correlation)
		}
	}
	
	return correlations
}

func (c *CorrelationEngine) applyDNSCorrelation(indicator *ThreatIndicator, rule *CorrelationRule) []*ThreatCorrelation {
	var correlations []*ThreatCorrelation
	
	if indicator.Type == IndicatorTypeDomain {
		// Find IPs that this domain resolves to
		resolvedIPs := c.resolveDomain(indicator.Value)
		
		for _, ip := range resolvedIPs {
			correlation := &ThreatCorrelation{
				RelatedIndicator: ip,
				CorrelationType:  "dns_resolution",
				Confidence:       0.9,
				Evidence:         []string{fmt.Sprintf("Domain %s resolves to %s", indicator.Value, ip)},
				Timestamp:        time.Now(),
			}
			correlations = append(correlations, correlation)
		}
	}
	
	if indicator.Type == IndicatorTypeIP {
		// Find domains that resolve to this IP
		domains := c.findDomainsForIP(indicator.Value)
		
		for _, domain := range domains {
			correlation := &ThreatCorrelation{
				RelatedIndicator: domain,
				CorrelationType:  "dns_resolution",
				Confidence:       0.9,
				Evidence:         []string{fmt.Sprintf("IP %s hosts domain %s", indicator.Value, domain)},
				Timestamp:        time.Now(),
			}
			correlations = append(correlations, correlation)
		}
	}
	
	return correlations
}

func (c *CorrelationEngine) applyFileSimilarityCorrelation(indicator *ThreatIndicator, rule *CorrelationRule) []*ThreatCorrelation {
	var correlations []*ThreatCorrelation
	
	if indicator.Type != IndicatorTypeHash {
		return correlations
	}
	
	// Find similar file hashes
	similarHashes := c.findSimilarHashes(indicator.Value)
	
	for _, hash := range similarHashes {
		if hash != indicator.Value {
			correlation := &ThreatCorrelation{
				RelatedIndicator: hash,
				CorrelationType:  "file_similarity",
				Confidence:       0.7,
				Evidence:         []string{fmt.Sprintf("Similar file hash: %s", hash)},
				Timestamp:        time.Now(),
			}
			correlations = append(correlations, correlation)
		}
	}
	
	return correlations
}

func (c *CorrelationEngine) applyCampaignCorrelation(indicator *ThreatIndicator, rule *CorrelationRule) []*ThreatCorrelation {
	var correlations []*ThreatCorrelation
	
	if indicator.Campaign == "" {
		return correlations
	}
	
	// Find other indicators in the same campaign
	campaignIndicators := c.findCampaignIndicators(indicator.Campaign)
	
	for _, campaignIndicator := range campaignIndicators {
		if campaignIndicator != indicator.Value {
			correlation := &ThreatCorrelation{
				RelatedIndicator: campaignIndicator,
				CorrelationType:  "campaign",
				Confidence:       0.95,
				Evidence:         []string{fmt.Sprintf("Same campaign: %s", indicator.Campaign)},
				Timestamp:        time.Now(),
			}
			correlations = append(correlations, correlation)
		}
	}
	
	return correlations
}

func (c *CorrelationEngine) applyGenericCorrelation(indicator *ThreatIndicator, rule *CorrelationRule) []*ThreatCorrelation {
	var correlations []*ThreatCorrelation
	
	// Apply generic correlation logic based on rule conditions
	for _, condition := range rule.Conditions {
		if condition.Required {
			// Check if condition is met
			if c.evaluateCondition(indicator, condition) {
				// Find related indicators
				relatedIndicators := c.findRelatedIndicators(indicator, condition)
				
				for _, related := range relatedIndicators {
					correlation := &ThreatCorrelation{
						RelatedIndicator: related,
						CorrelationType:  rule.CorrelationType,
						Confidence:       condition.Weight,
						Evidence:         []string{fmt.Sprintf("Condition: %s %s %v", condition.Field, condition.Operator, condition.Value)},
						Timestamp:        time.Now(),
					}
					correlations = append(correlations, correlation)
				}
			}
		}
	}
	
	return correlations
}

func (c *CorrelationEngine) evaluateCondition(indicator *ThreatIndicator, condition CorrelationCondition) bool {
	// Get field value from indicator
	fieldValue := c.getIndicatorFieldValue(indicator, condition.Field)
	
	// Evaluate condition
	switch condition.Operator {
	case "equals":
		return c.compareValues(fieldValue, condition.Value, condition.CaseSensitive)
	case "contains":
		return c.containsValue(fieldValue, condition.Value, condition.CaseSensitive)
	case "matches":
		return c.matchesPattern(fieldValue, condition.Value)
	case "same":
		return c.sameValue(fieldValue, condition.Value)
	case "similar":
		return c.similarValue(fieldValue, condition.Value)
	case "resolves_to":
		return c.resolvesToValue(fieldValue, condition.Value)
	default:
		return false
	}
}

func (c *CorrelationEngine) getIndicatorFieldValue(indicator *ThreatIndicator, field string) interface{} {
	switch field {
	case "type":
		return indicator.Type
	case "value":
		return indicator.Value
	case "source":
		return indicator.Source
	case "campaign":
		return indicator.Campaign
	case "actor":
		return indicator.Actor
	case "tags":
		return indicator.Tags
	case "subnet":
		return c.getSubnet(indicator.Value)
	case "dns_resolution":
		return c.resolveDomain(indicator.Value)
	case "hash_similarity":
		return c.getHashSimilarity(indicator.Value)
	default:
		return nil
	}
}

func (c *CorrelationEngine) compareValues(a, b interface{}, caseSensitive bool) bool {
	aStr := fmt.Sprintf("%v", a)
	bStr := fmt.Sprintf("%v", b)
	
	if !caseSensitive {
		aStr = strings.ToLower(aStr)
		bStr = strings.ToLower(bStr)
	}
	
	return aStr == bStr
}

func (c *CorrelationEngine) containsValue(a, b interface{}, caseSensitive bool) bool {
	aStr := fmt.Sprintf("%v", a)
	bStr := fmt.Sprintf("%v", b)
	
	if !caseSensitive {
		aStr = strings.ToLower(aStr)
		bStr = strings.ToLower(bStr)
	}
	
	return strings.Contains(aStr, bStr)
}

func (c *CorrelationEngine) matchesPattern(a, b interface{}) bool {
	// Simplified pattern matching
	return strings.Contains(strings.ToLower(fmt.Sprintf("%v", a)), strings.ToLower(fmt.Sprintf("%v", b)))
}

func (c *CorrelationEngine) sameValue(a, b interface{}) bool {
	return c.compareValues(a, b, false)
}

func (c *CorrelationEngine) similarValue(a, b interface{}) bool {
	// Simplified similarity check
	aStr := fmt.Sprintf("%v", a)
	bStr := fmt.Sprintf("%v", b)
	
	// Calculate simple similarity based on common characters
	common := 0
	for i, char := range aStr {
		if i < len(bStr) && byte(char) == bStr[i] {
			common++
		}
	}
	
	similarity := float64(common) / float64(len(aStr))
	return similarity > 0.7
}

func (c *CorrelationEngine) resolvesToValue(a, b interface{}) bool {
	// Check if domain resolves to IP
	domain := fmt.Sprintf("%v", a)
	ip := fmt.Sprintf("%v", b)
	
	resolvedIPs := c.resolveDomain(domain)
	for _, resolvedIP := range resolvedIPs {
		if resolvedIP == ip {
			return true
		}
	}
	
	return false
}

// Helper methods for correlation

func (c *CorrelationEngine) getSubnet(ip string) string {
	// Simplified subnet extraction
	parts := strings.Split(ip, ".")
	if len(parts) >= 3 {
		return strings.Join(parts[:3], ".") + ".0/24"
	}
	return ip
}

func (c *CorrelationEngine) findIPsInSubnet(subnet string) []string {
	// This would query a database or threat intelligence source
	// For now, return simulated data
	return []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"}
}

func (c *CorrelationEngine) resolveDomain(domain string) []string {
	// This would perform actual DNS resolution
	// For now, return simulated data
	return []string{"93.184.216.34", "93.184.216.35"}
}

func (c *CorrelationEngine) findDomainsForIP(ip string) []string {
	// This would query reverse DNS or threat intelligence
	// For now, return simulated data
	return []string{"example.com", "test.example.com"}
}

func (c *CorrelationEngine) findSimilarHashes(hash string) []string {
	// This would use fuzzy hashing or similarity algorithms
	// For now, return simulated data
	return []string{"abc123def456", "def456ghi789"}
}

func (c *CorrelationEngine) findCampaignIndicators(campaign string) []string {
	// This would query threat intelligence database
	// For now, return simulated data
	return []string{"malicious.com", "192.168.1.100", "evil.exe"}
}

func (c *CorrelationEngine) getHashSimilarity(hash string) float64 {
	// Calculate hash similarity
	return 0.8 // Simplified
}

func (c *CorrelationEngine) findRelatedIndicators(indicator *ThreatIndicator, condition CorrelationCondition) []string {
	// Find indicators that match the condition
	// This would query the threat intelligence database
	return []string{"related1", "related2"}
}

func (c *CorrelationEngine) deduplicateCorrelations(correlations []*ThreatCorrelation) []*ThreatCorrelation {
	seen := make(map[string]bool)
	var deduplicated []*ThreatCorrelation
	
	for _, correlation := range correlations {
		key := fmt.Sprintf("%s:%s", correlation.RelatedIndicator, correlation.CorrelationType)
		if !seen[key] {
			seen[key] = true
			deduplicated = append(deduplicated, correlation)
		}
	}
	
	return deduplicated
}

func (c *CorrelationEngine) buildCorrelationGraph(indicator *ThreatIndicator, correlations []*ThreatCorrelation) *CorrelationGraph {
	graph := &CorrelationGraph{
		Nodes:     make(map[string]*CorrelationNode),
		Edges:     make(map[string]*CorrelationEdge),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	
	// Add root node
	rootNode := &CorrelationNode{
		ID:            indicator.ID,
		IndicatorID:   indicator.ID,
		Type:          indicator.Type,
		Value:         indicator.Value,
		ConnectedNodes: make([]string, 0),
		Properties:    make(map[string]interface{}),
	}
	graph.Nodes[indicator.ID] = rootNode
	
	// Add correlated nodes and edges
	for i, correlation := range correlations {
		// Add node
		nodeID := fmt.Sprintf("node-%d", i)
		node := &CorrelationNode{
			ID:            nodeID,
			IndicatorID:   correlation.RelatedIndicator,
			Value:         correlation.RelatedIndicator,
			ConnectedNodes: []string{indicator.ID},
			Properties:    make(map[string]interface{}),
		}
		graph.Nodes[nodeID] = node
		
		// Add edge
		edgeID := fmt.Sprintf("edge-%d", i)
		edge := &CorrelationEdge{
			ID:              edgeID,
			SourceNodeID:    indicator.ID,
			TargetNodeID:    nodeID,
			CorrelationType: correlation.CorrelationType,
			Weight:          1.0,
			Confidence:      correlation.Confidence,
			Evidence:        correlation.Evidence,
			Properties:      make(map[string]interface{}),
			CreatedAt:       time.Now(),
		}
		graph.Edges[edgeID] = edge
		
		// Update root node connections
		rootNode.ConnectedNodes = append(rootNode.ConnectedNodes, nodeID)
	}
	
	graph.TotalNodes = len(graph.Nodes)
	graph.TotalEdges = len(graph.Edges)
	
	return graph
}

func (c *CorrelationEngine) identifyClusters(graph *CorrelationGraph) []CorrelationCluster {
	// Simplified clustering based on correlation types
	clusters := make([]CorrelationCluster, 0)
	
	typeGroups := make(map[string][]string)
	for _, edge := range graph.Edges {
		correlationType := edge.CorrelationType
		if typeGroups[correlationType] == nil {
			typeGroups[correlationType] = make([]string, 0)
		}
		typeGroups[correlationType] = append(typeGroups[correlationType], edge.SourceNodeID, edge.TargetNodeID)
	}
	
	for correlationType, indicators := range typeGroups {
		cluster := CorrelationCluster{
			ID:              fmt.Sprintf("cluster-%s", correlationType),
			Indicators:      c.deduplicateStrings(indicators),
			CorrelationType: correlationType,
			Confidence:      0.8,
			Properties:      make(map[string]interface{}),
			CreatedAt:       time.Now(),
		}
		clusters = append(clusters, cluster)
	}
	
	return clusters
}

func (c *CorrelationEngine) findCentralIndicators(graph *CorrelationGraph) []string {
	// Find nodes with highest centrality (most connections)
	centralNodes := make([]string, 0)
	
	for nodeID, node := range graph.Nodes {
		if len(node.ConnectedNodes) > 2 {
			centralNodes = append(centralNodes, nodeID)
		}
	}
	
	return centralNodes
}

func (c *CorrelationEngine) calculateRiskScore(correlations []*ThreatCorrelation, graph *CorrelationGraph) float64 {
	if len(correlations) == 0 {
		return 0.0
	}
	
	// Calculate risk based on number of correlations and their confidence
	totalConfidence := 0.0
	for _, correlation := range correlations {
		totalConfidence += correlation.Confidence
	}
	
	averageConfidence := totalConfidence / float64(len(correlations))
	
	// Adjust based on graph complexity
	complexityFactor := float64(graph.TotalNodes) / 10.0
	if complexityFactor > 1.0 {
		complexityFactor = 1.0
	}
	
	riskScore := averageConfidence * complexityFactor
	if riskScore > 1.0 {
		riskScore = 1.0
	}
	
	return riskScore
}

func (c *CorrelationEngine) calculateConfidenceScore(correlations []*ThreatCorrelation) float64 {
	if len(correlations) == 0 {
		return 0.0
	}
	
	totalConfidence := 0.0
	for _, correlation := range correlations {
		totalConfidence += correlation.Confidence
	}
	
	return totalConfidence / float64(len(correlations))
}

func (c *CorrelationEngine) getUniqueCorrelations(correlations []*ThreatCorrelation) []string {
	seen := make(map[string]bool)
	var unique []string
	
	for _, correlation := range correlations {
		if !seen[correlation.RelatedIndicator] {
			seen[correlation.RelatedIndicator] = true
			unique = append(unique, correlation.RelatedIndicator)
		}
	}
	
	return unique
}

func (c *CorrelationEngine) deduplicateStrings(strings []string) []string {
	seen := make(map[string]bool)
	var deduplicated []string
	
	for _, str := range strings {
		if !seen[str] {
			seen[str] = true
			deduplicated = append(deduplicated, str)
		}
	}
	
	return deduplicated
}

// Background workers

func (c *CorrelationEngine) cacheMaintenanceWorker() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			c.cleanupCache()
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *CorrelationEngine) correlationWorker() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			c.performBackgroundCorrelation()
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *CorrelationEngine) cleanupCache() {
	c.cacheMutex.Lock()
	defer c.cacheMutex.Unlock()
	
	// Simple cache cleanup - remove all entries
	// In a real implementation, you'd use TTL or LRU eviction
	c.correlationCache = make(map[string][]*ThreatCorrelation)
}

func (c *CorrelationEngine) performBackgroundCorrelation() {
	// Perform background correlation analysis
	// This would analyze new indicators and update correlations
}

// Public API methods

func (c *CorrelationEngine) GetStatus() map[string]interface{} {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	return map[string]interface{}{
		"total_correlations": c.totalCorrelations,
		"cache_hits":         c.cacheHits,
		"cache_misses":       c.cacheMisses,
		"rules_processed":    c.rulesProcessed,
		"active_rules":       len(c.correlationRules),
		"cache_size":         len(c.correlationCache),
	}
}

func (c *CorrelationEngine) GetMetrics() map[string]interface{} {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	return map[string]interface{}{
		"total_correlations": c.totalCorrelations,
		"cache_hits":         c.cacheHits,
		"cache_misses":       c.cacheMisses,
		"rules_processed":    c.rulesProcessed,
		"cache_hit_rate":     float64(c.cacheHits) / float64(c.cacheHits+c.cacheMisses),
	}
}

// ThreatCache implementation

func NewThreatCache(maxSize int) *ThreatCache {
	return &ThreatCache{
		cache:   make(map[string]interface{}),
		maxSize: maxSize,
		ttl:     time.Hour,
		entries: make(map[string]time.Time),
	}
}

func (t *ThreatCache) Get(key string) interface{} {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	
	// Check if entry exists and is not expired
	if expiry, exists := t.entries[key]; exists {
		if time.Now().Before(expiry) {
			return t.cache[key]
		}
		// Remove expired entry
		delete(t.cache, key)
		delete(t.entries, key)
	}
	
	return nil
}

func (t *ThreatCache) Set(key string, value interface{}) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	
	// Check cache size
	if len(t.cache) >= t.maxSize {
		// Remove oldest entry
		t.evictOldest()
	}
	
	t.cache[key] = value
	t.entries[key] = time.Now().Add(t.ttl)
}

func (t *ThreatCache) Size() int {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	
	return len(t.cache)
}

func (t *ThreatCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time
	
	for key, expiry := range t.entries {
		if oldestTime.IsZero() || expiry.Before(oldestTime) {
			oldestKey = key
			oldestTime = expiry
		}
	}
	
	if oldestKey != "" {
		delete(t.cache, oldestKey)
		delete(t.entries, oldestKey)
	}
} 