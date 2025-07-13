package threat_intelligence

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// FeedManager manages threat intelligence feeds
type FeedManager struct {
	config     *ThreatIntelConfig
	feeds      map[string]*ThreatFeed
	feedMutex  sync.RWMutex
	httpClient *http.Client

	// Metrics
	totalFeeds  int64
	activeFeeds int64
	feedUpdates int64
	feedErrors  int64
	lastSync    time.Time

	// Context
	ctx    context.Context
	cancel context.CancelFunc
}

// ThreatFeed represents a threat intelligence feed
type ThreatFeed struct {
	ID           string
	Name         string
	Type         FeedType
	URL          string
	Format       FeedFormat
	Enabled      bool
	Interval     time.Duration
	Timeout      time.Duration
	LastSync     time.Time
	NextSync     time.Time
	Status       FeedStatus
	ErrorCount   int64
	SuccessCount int64
	LastError    string

	// Authentication
	APIKey   string
	Username string
	Password string
	Headers  map[string]string

	// Configuration
	MaxSize         int64
	Compression     bool
	FollowRedirects bool
	VerifyTLS       bool

	// Parsing
	Parser          FeedParser
	Transformations []FeedTransformation
	Filters         []FeedFilter

	// Metadata
	Description string
	Vendor      string
	Version     string
	Tags        []string

	// Statistics
	TotalIndicators   int64
	NewIndicators     int64
	UpdatedIndicators int64
	ErrorIndicators   int64

	// Synchronization
	mutex sync.RWMutex
}

// FeedType represents the type of threat intelligence feed
type FeedType string

const (
	FeedTypeMISP       FeedType = "misp"
	FeedTypeOTX        FeedType = "otx"
	FeedTypeVirusTotal FeedType = "virustotal"
	FeedTypeRSS        FeedType = "rss"
	FeedTypeJSON       FeedType = "json"
	FeedTypeXML        FeedType = "xml"
	FeedTypeCSV        FeedType = "csv"
	FeedTypeSTIX       FeedType = "stix"
	FeedTypeTAXII      FeedType = "taxii"
	FeedTypeCustom     FeedType = "custom"
	FeedTypeInternal   FeedType = "internal"
)

// FeedFormat represents the format of the feed data
type FeedFormat string

const (
	FormatJSON  FeedFormat = "json"
	FormatXML   FeedFormat = "xml"
	FormatCSV   FeedFormat = "csv"
	FormatText  FeedFormat = "text"
	FormatSTIX  FeedFormat = "stix"
	FormatIOC   FeedFormat = "ioc"
	FormatYARA  FeedFormat = "yara"
	FormatSnort FeedFormat = "snort"
)

// FeedStatus represents the status of a feed
type FeedStatus string

const (
	FeedStatusActive   FeedStatus = "active"
	FeedStatusInactive FeedStatus = "inactive"
	FeedStatusError    FeedStatus = "error"
	FeedStatusSyncing  FeedStatus = "syncing"
	FeedStatusDisabled FeedStatus = "disabled"
)

// FeedParser defines the interface for feed parsers
type FeedParser interface {
	Parse(data []byte) ([]*ThreatIndicator, error)
	GetType() FeedType
	GetFormat() FeedFormat
}

// FeedTransformation represents a transformation to apply to feed data
type FeedTransformation struct {
	Type       string
	Parameters map[string]interface{}
	Enabled    bool
}

// FeedFilter represents a filter to apply to feed data
type FeedFilter struct {
	Type     string
	Field    string
	Operator string
	Value    interface{}
	Enabled  bool
}

// FeedSyncResult represents the result of a feed sync operation
type FeedSyncResult struct {
	FeedID            string
	Success           bool
	StartTime         time.Time
	EndTime           time.Time
	Duration          time.Duration
	TotalIndicators   int64
	NewIndicators     int64
	UpdatedIndicators int64
	ErrorIndicators   int64
	Error             error
	Status            string
}

// NewFeedManager creates a new feed manager
func NewFeedManager(config *ThreatIntelConfig) *FeedManager {
	// Create HTTP client with appropriate settings
	httpClient := &http.Client{
		Timeout: config.FeedTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     30 * time.Second,
		},
	}

	return &FeedManager{
		config:     config,
		feeds:      make(map[string]*ThreatFeed),
		httpClient: httpClient,
	}
}

// Start starts the feed manager
func (f *FeedManager) Start(ctx context.Context) error {
	f.ctx, f.cancel = context.WithCancel(ctx)

	// Initialize default feeds
	err := f.initializeDefaultFeeds()
	if err != nil {
		return fmt.Errorf("failed to initialize default feeds: %v", err)
	}

	// Start sync worker
	go f.syncWorker()

	// Start monitoring worker
	go f.monitoringWorker()

	return nil
}

// Stop stops the feed manager
func (f *FeedManager) Stop() {
	if f.cancel != nil {
		f.cancel()
	}
}

// AddFeed adds a new threat intelligence feed
func (f *FeedManager) AddFeed(feed *ThreatFeed) error {
	if feed == nil {
		return fmt.Errorf("feed is nil")
	}

	// Validate feed
	err := f.validateFeed(feed)
	if err != nil {
		return fmt.Errorf("invalid feed: %v", err)
	}

	// Generate ID if not provided
	if feed.ID == "" {
		feed.ID = f.generateFeedID(feed)
	}

	// Set defaults
	f.setFeedDefaults(feed)

	// Create parser
	parser, err := f.createParser(feed)
	if err != nil {
		return fmt.Errorf("failed to create parser: %v", err)
	}
	feed.Parser = parser

	// Store feed
	f.feedMutex.Lock()
	f.feeds[feed.ID] = feed
	f.totalFeeds++
	if feed.Enabled {
		f.activeFeeds++
	}
	f.feedMutex.Unlock()

	return nil
}

// RemoveFeed removes a threat intelligence feed
func (f *FeedManager) RemoveFeed(feedID string) error {
	f.feedMutex.Lock()
	defer f.feedMutex.Unlock()

	feed, exists := f.feeds[feedID]
	if !exists {
		return fmt.Errorf("feed %s not found", feedID)
	}

	if feed.Enabled {
		f.activeFeeds--
	}

	delete(f.feeds, feedID)
	f.totalFeeds--

	return nil
}

// GetFeed retrieves a threat intelligence feed
func (f *FeedManager) GetFeed(feedID string) (*ThreatFeed, error) {
	f.feedMutex.RLock()
	defer f.feedMutex.RUnlock()

	feed, exists := f.feeds[feedID]
	if !exists {
		return nil, fmt.Errorf("feed %s not found", feedID)
	}

	return feed, nil
}

// ListFeeds lists all threat intelligence feeds
func (f *FeedManager) ListFeeds() []*ThreatFeed {
	f.feedMutex.RLock()
	defer f.feedMutex.RUnlock()

	feeds := make([]*ThreatFeed, 0, len(f.feeds))
	for _, feed := range f.feeds {
		feeds = append(feeds, feed)
	}

	return feeds
}

// SyncFeed synchronizes a specific feed
func (f *FeedManager) SyncFeed(feedID string) (*FeedSyncResult, error) {
	feed, err := f.GetFeed(feedID)
	if err != nil {
		return nil, err
	}

	return f.syncFeedData(feed)
}

// SyncAllFeeds synchronizes all enabled feeds
func (f *FeedManager) SyncAllFeeds() ([]*FeedSyncResult, error) {
	f.feedMutex.RLock()
	feeds := make([]*ThreatFeed, 0)
	for _, feed := range f.feeds {
		if feed.Enabled {
			feeds = append(feeds, feed)
		}
	}
	f.feedMutex.RUnlock()

	results := make([]*FeedSyncResult, 0, len(feeds))

	// Sync feeds in parallel
	resultsChan := make(chan *FeedSyncResult, len(feeds))

	for _, feed := range feeds {
		go func(f *ThreatFeed) {
			result, _ := f.syncFeedData(f)
			resultsChan <- result
		}(feed)
	}

	// Collect results
	for i := 0; i < len(feeds); i++ {
		result := <-resultsChan
		results = append(results, result)
	}

	close(resultsChan)
	return results, nil
}

// Implementation methods

func (f *FeedManager) initializeDefaultFeeds() error {
	// MISP Feed
	mispFeed := &ThreatFeed{
		ID:       "misp-default",
		Name:     "MISP Default Feed",
		Type:     FeedTypeMISP,
		URL:      "https://misp.local/attributes/restSearch",
		Format:   FormatJSON,
		Enabled:  false, // Disabled by default, requires configuration
		Interval: 15 * time.Minute,
		Timeout:  30 * time.Second,
		Headers:  map[string]string{"Accept": "application/json"},
	}

	// OTX Feed
	otxFeed := &ThreatFeed{
		ID:       "otx-default",
		Name:     "AlienVault OTX Feed",
		Type:     FeedTypeOTX,
		URL:      "https://otx.alienvault.com/api/v1/indicators/export",
		Format:   FormatJSON,
		Enabled:  false, // Disabled by default, requires API key
		Interval: 30 * time.Minute,
		Timeout:  30 * time.Second,
		Headers:  map[string]string{"Accept": "application/json"},
	}

	// VirusTotal Feed
	vtFeed := &ThreatFeed{
		ID:       "virustotal-default",
		Name:     "VirusTotal Intelligence Feed",
		Type:     FeedTypeVirusTotal,
		URL:      "https://www.virustotal.com/intelligence/search/",
		Format:   FormatJSON,
		Enabled:  false, // Disabled by default, requires API key
		Interval: time.Hour,
		Timeout:  30 * time.Second,
		Headers:  map[string]string{"Accept": "application/json"},
	}

	// Internal Feed
	internalFeed := &ThreatFeed{
		ID:       "internal-default",
		Name:     "Internal Threat Intelligence",
		Type:     FeedTypeInternal,
		URL:      "internal://threat-intelligence",
		Format:   FormatJSON,
		Enabled:  true,
		Interval: 5 * time.Minute,
		Timeout:  10 * time.Second,
	}

	// Add feeds
	feeds := []*ThreatFeed{mispFeed, otxFeed, vtFeed, internalFeed}
	for _, feed := range feeds {
		err := f.AddFeed(feed)
		if err != nil {
			return fmt.Errorf("failed to add feed %s: %v", feed.Name, err)
		}
	}

	return nil
}

func (f *FeedManager) validateFeed(feed *ThreatFeed) error {
	if feed.Name == "" {
		return fmt.Errorf("feed name is required")
	}

	if feed.Type == "" {
		return fmt.Errorf("feed type is required")
	}

	if feed.URL == "" {
		return fmt.Errorf("feed URL is required")
	}

	if feed.Format == "" {
		return fmt.Errorf("feed format is required")
	}

	if feed.Interval <= 0 {
		return fmt.Errorf("feed interval must be positive")
	}

	if feed.Timeout <= 0 {
		return fmt.Errorf("feed timeout must be positive")
	}

	return nil
}

func (f *FeedManager) setFeedDefaults(feed *ThreatFeed) {
	if feed.Interval == 0 {
		feed.Interval = f.config.FeedUpdateInterval
	}

	if feed.Timeout == 0 {
		feed.Timeout = f.config.FeedTimeout
	}

	if feed.MaxSize == 0 {
		feed.MaxSize = f.config.MaxFeedSize
	}

	if feed.Headers == nil {
		feed.Headers = make(map[string]string)
	}

	if feed.Status == "" {
		feed.Status = FeedStatusInactive
	}

	feed.NextSync = time.Now().Add(feed.Interval)
}

func (f *FeedManager) generateFeedID(feed *ThreatFeed) string {
	return fmt.Sprintf("%s-%s", feed.Type, strings.ToLower(strings.ReplaceAll(feed.Name, " ", "-")))
}

func (f *FeedManager) createParser(feed *ThreatFeed) (FeedParser, error) {
	switch feed.Type {
	case FeedTypeMISP:
		return NewMISPParser(), nil
	case FeedTypeOTX:
		return NewOTXParser(), nil
	case FeedTypeVirusTotal:
		return NewVirusTotalParser(), nil
	case FeedTypeJSON:
		return NewJSONParser(), nil
	case FeedTypeXML:
		return NewXMLParser(), nil
	case FeedTypeCSV:
		return NewCSVParser(), nil
	case FeedTypeInternal:
		return NewInternalParser(), nil
	default:
		return NewGenericParser(feed.Format), nil
	}
}

func (f *FeedManager) syncFeedData(feed *ThreatFeed) (*FeedSyncResult, error) {
	result := &FeedSyncResult{
		FeedID:    feed.ID,
		StartTime: time.Now(),
	}

	// Update feed status
	feed.mutex.Lock()
	feed.Status = FeedStatusSyncing
	feed.mutex.Unlock()

	// Fetch feed data
	data, err := f.fetchFeedData(feed)
	if err != nil {
		result.Success = false
		result.Error = err
		result.Status = "fetch_failed"

		// Update feed error count
		feed.mutex.Lock()
		feed.ErrorCount++
		feed.LastError = err.Error()
		feed.Status = FeedStatusError
		feed.mutex.Unlock()

		f.feedErrors++
		return result, err
	}

	// Parse feed data
	indicators, err := f.parseFeedData(feed, data)
	if err != nil {
		result.Success = false
		result.Error = err
		result.Status = "parse_failed"

		// Update feed error count
		feed.mutex.Lock()
		feed.ErrorCount++
		feed.LastError = err.Error()
		feed.Status = FeedStatusError
		feed.mutex.Unlock()

		f.feedErrors++
		return result, err
	}

	// Process indicators
	newIndicators, updatedIndicators, errorIndicators := f.processIndicators(feed, indicators)

	// Update result
	result.Success = true
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	result.TotalIndicators = int64(len(indicators))
	result.NewIndicators = int64(newIndicators)
	result.UpdatedIndicators = int64(updatedIndicators)
	result.ErrorIndicators = int64(errorIndicators)
	result.Status = "success"

	// Update feed statistics
	feed.mutex.Lock()
	feed.LastSync = time.Now()
	feed.NextSync = feed.LastSync.Add(feed.Interval)
	feed.Status = FeedStatusActive
	feed.SuccessCount++
	feed.TotalIndicators += int64(len(indicators))
	feed.NewIndicators += int64(newIndicators)
	feed.UpdatedIndicators += int64(updatedIndicators)
	feed.ErrorIndicators += int64(errorIndicators)
	feed.mutex.Unlock()

	f.feedUpdates++
	f.lastSync = time.Now()

	return result, nil
}

func (f *FeedManager) fetchFeedData(feed *ThreatFeed) ([]byte, error) {
	// Handle internal feeds
	if feed.Type == FeedTypeInternal {
		return f.fetchInternalFeedData(feed)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(f.ctx, "GET", feed.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// Add headers
	for key, value := range feed.Headers {
		req.Header.Set(key, value)
	}

	// Add authentication
	if feed.APIKey != "" {
		req.Header.Set("X-API-Key", feed.APIKey)
	}

	if feed.Username != "" && feed.Password != "" {
		req.SetBasicAuth(feed.Username, feed.Password)
	}

	// Set User-Agent
	req.Header.Set("User-Agent", "CAM-ThreatIntel/1.0")

	// Make request
	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch feed data: %v", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error: %d %s", resp.StatusCode, resp.Status)
	}

	// Check content length
	if resp.ContentLength > feed.MaxSize {
		return nil, fmt.Errorf("response too large: %d bytes", resp.ContentLength)
	}

	// Read response body
	body, err := io.ReadAll(io.LimitReader(resp.Body, feed.MaxSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	return body, nil
}

func (f *FeedManager) fetchInternalFeedData(feed *ThreatFeed) ([]byte, error) {
	// Simulate internal feed data
	indicators := []map[string]interface{}{
		{
			"type":       "ip",
			"value":      "192.168.1.100",
			"source":     "internal",
			"confidence": 0.8,
			"severity":   "medium",
			"tags":       []string{"internal", "suspicious"},
		},
		{
			"type":       "domain",
			"value":      "suspicious.example.com",
			"source":     "internal",
			"confidence": 0.9,
			"severity":   "high",
			"tags":       []string{"internal", "malicious"},
		},
	}

	data, err := json.Marshal(indicators)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal internal data: %v", err)
	}

	return data, nil
}

func (f *FeedManager) parseFeedData(feed *ThreatFeed, data []byte) ([]*ThreatIndicator, error) {
	if feed.Parser == nil {
		return nil, fmt.Errorf("no parser configured for feed")
	}

	// Parse data
	indicators, err := feed.Parser.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse feed data: %v", err)
	}

	// Apply transformations
	for _, transformation := range feed.Transformations {
		if transformation.Enabled {
			indicators = f.applyTransformation(indicators, transformation)
		}
	}

	// Apply filters
	for _, filter := range feed.Filters {
		if filter.Enabled {
			indicators = f.applyFilter(indicators, filter)
		}
	}

	return indicators, nil
}

func (f *FeedManager) processIndicators(feed *ThreatFeed, indicators []*ThreatIndicator) (int, int, int) {
	newIndicators := 0
	updatedIndicators := 0
	errorIndicators := 0

	for _, indicator := range indicators {
		// Set feed source
		indicator.Source = feed.Name

		// Validate indicator
		if indicator.Type == "" || indicator.Value == "" {
			errorIndicators++
			continue
		}

		// Check if indicator exists
		existing := f.findExistingIndicator(indicator)
		if existing == nil {
			newIndicators++
		} else {
			updatedIndicators++
		}
	}

	return newIndicators, updatedIndicators, errorIndicators
}

func (f *FeedManager) findExistingIndicator(indicator *ThreatIndicator) *ThreatIndicator {
	// This would typically query the main threat intelligence database
	// For now, we'll return nil (indicating it's a new indicator)
	return nil
}

func (f *FeedManager) applyTransformation(indicators []*ThreatIndicator, transformation FeedTransformation) []*ThreatIndicator {
	// Apply transformation to indicators
	switch transformation.Type {
	case "normalize":
		return f.normalizeIndicators(indicators, transformation.Parameters)
	case "enrich":
		return f.enrichIndicators(indicators, transformation.Parameters)
	case "deduplicate":
		return f.deduplicateIndicators(indicators)
	default:
		return indicators
	}
}

func (f *FeedManager) applyFilter(indicators []*ThreatIndicator, filter FeedFilter) []*ThreatIndicator {
	var filtered []*ThreatIndicator

	for _, indicator := range indicators {
		if f.matchesFilter(indicator, filter) {
			filtered = append(filtered, indicator)
		}
	}

	return filtered
}

func (f *FeedManager) matchesFilter(indicator *ThreatIndicator, filter FeedFilter) bool {
	// Get field value
	fieldValue := f.getFieldValue(indicator, filter.Field)

	// Apply filter
	switch filter.Operator {
	case "equals":
		return fmt.Sprintf("%v", fieldValue) == fmt.Sprintf("%v", filter.Value)
	case "contains":
		return strings.Contains(strings.ToLower(fmt.Sprintf("%v", fieldValue)), strings.ToLower(fmt.Sprintf("%v", filter.Value)))
	case "regex":
		// Simplified regex matching
		return strings.Contains(strings.ToLower(fmt.Sprintf("%v", fieldValue)), strings.ToLower(fmt.Sprintf("%v", filter.Value)))
	default:
		return true
	}
}

func (f *FeedManager) getFieldValue(indicator *ThreatIndicator, field string) interface{} {
	switch field {
	case "type":
		return indicator.Type
	case "value":
		return indicator.Value
	case "source":
		return indicator.Source
	case "confidence":
		return indicator.Confidence
	case "severity":
		return indicator.Severity
	case "tags":
		return indicator.Tags
	default:
		return nil
	}
}

func (f *FeedManager) normalizeIndicators(indicators []*ThreatIndicator, params map[string]interface{}) []*ThreatIndicator {
	// Normalize indicator values
	for _, indicator := range indicators {
		switch indicator.Type {
		case IndicatorTypeIP:
			// Normalize IP addresses
			indicator.Value = strings.TrimSpace(indicator.Value)
		case IndicatorTypeDomain:
			// Normalize domains
			indicator.Value = strings.ToLower(strings.TrimSpace(indicator.Value))
		case IndicatorTypeURL:
			// Normalize URLs
			indicator.Value = strings.TrimSpace(indicator.Value)
		case IndicatorTypeHash:
			// Normalize hashes
			indicator.Value = strings.ToLower(strings.TrimSpace(indicator.Value))
		}
	}

	return indicators
}

func (f *FeedManager) enrichIndicators(indicators []*ThreatIndicator, params map[string]interface{}) []*ThreatIndicator {
	// Enrich indicators with additional information
	for _, indicator := range indicators {
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
	}

	return indicators
}

func (f *FeedManager) deduplicateIndicators(indicators []*ThreatIndicator) []*ThreatIndicator {
	// Remove duplicate indicators
	seen := make(map[string]bool)
	var deduplicated []*ThreatIndicator

	for _, indicator := range indicators {
		key := fmt.Sprintf("%s:%s", indicator.Type, indicator.Value)
		if !seen[key] {
			seen[key] = true
			deduplicated = append(deduplicated, indicator)
		}
	}

	return deduplicated
}

// Background workers

func (f *FeedManager) syncWorker() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			f.performScheduledSync()
		case <-f.ctx.Done():
			return
		}
	}
}

func (f *FeedManager) monitoringWorker() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			f.performHealthCheck()
		case <-f.ctx.Done():
			return
		}
	}
}

func (f *FeedManager) performScheduledSync() {
	now := time.Now()

	f.feedMutex.RLock()
	feedsToSync := make([]*ThreatFeed, 0)
	for _, feed := range f.feeds {
		if feed.Enabled && feed.Status != FeedStatusSyncing && now.After(feed.NextSync) {
			feedsToSync = append(feedsToSync, feed)
		}
	}
	f.feedMutex.RUnlock()

	// Sync feeds
	for _, feed := range feedsToSync {
		go func(f *ThreatFeed) {
			_, err := f.syncFeedData(f)
			if err != nil {
				// Log sync error
			}
		}(feed)
	}
}

func (f *FeedManager) performHealthCheck() {
	now := time.Now()

	f.feedMutex.RLock()
	defer f.feedMutex.RUnlock()

	for _, feed := range f.feeds {
		if feed.Enabled {
			// Check if feed is overdue
			if now.Sub(feed.LastSync) > feed.Interval*2 {
				feed.Status = FeedStatusError
				feed.LastError = "Feed sync overdue"
			}

			// Check error rate
			if feed.ErrorCount > 0 && feed.SuccessCount > 0 {
				errorRate := float64(feed.ErrorCount) / float64(feed.ErrorCount+feed.SuccessCount)
				if errorRate > 0.5 {
					feed.Status = FeedStatusError
					feed.LastError = "High error rate"
				}
			}
		}
	}
}

// Public API methods

func (f *FeedManager) GetStatus() map[string]interface{} {
	f.feedMutex.RLock()
	defer f.feedMutex.RUnlock()

	feedStatus := make(map[string]interface{})
	for id, feed := range f.feeds {
		feedStatus[id] = map[string]interface{}{
			"name":          feed.Name,
			"type":          feed.Type,
			"enabled":       feed.Enabled,
			"status":        feed.Status,
			"last_sync":     feed.LastSync,
			"next_sync":     feed.NextSync,
			"success_count": feed.SuccessCount,
			"error_count":   feed.ErrorCount,
			"last_error":    feed.LastError,
		}
	}

	return map[string]interface{}{
		"total_feeds":  f.totalFeeds,
		"active_feeds": f.activeFeeds,
		"feed_updates": f.feedUpdates,
		"feed_errors":  f.feedErrors,
		"last_sync":    f.lastSync,
		"feeds":        feedStatus,
	}
}

func (f *FeedManager) GetMetrics() map[string]interface{} {
	f.feedMutex.RLock()
	defer f.feedMutex.RUnlock()

	totalIndicators := int64(0)
	newIndicators := int64(0)
	updatedIndicators := int64(0)
	errorIndicators := int64(0)

	for _, feed := range f.feeds {
		totalIndicators += feed.TotalIndicators
		newIndicators += feed.NewIndicators
		updatedIndicators += feed.UpdatedIndicators
		errorIndicators += feed.ErrorIndicators
	}

	return map[string]interface{}{
		"total_feeds":        f.totalFeeds,
		"active_feeds":       f.activeFeeds,
		"feed_updates":       f.feedUpdates,
		"feed_errors":        f.feedErrors,
		"total_indicators":   totalIndicators,
		"new_indicators":     newIndicators,
		"updated_indicators": updatedIndicators,
		"error_indicators":   errorIndicators,
		"last_sync":          f.lastSync,
	}
}
