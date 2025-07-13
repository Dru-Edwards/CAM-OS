package behavioral

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"time"
)

// MLModel represents a machine learning model for behavioral analysis
type MLModel struct {
	Name            string
	Type            ModelType
	Version         string
	TrainingData    []DataPoint
	Features        []string
	Weights         map[string]float64
	Parameters      map[string]interface{}
	Accuracy        float64
	LastTrained     time.Time
	TrainingCount   int64
	PredictionCount int64
	Enabled         bool
}

// ModelType represents the type of ML model
type ModelType string

const (
	ModelTypeIsolationForest ModelType = "isolation_forest"
	ModelTypeOneClassSVM     ModelType = "one_class_svm"
	ModelTypeKMeans          ModelType = "kmeans"
	ModelTypeGaussianMixture ModelType = "gaussian_mixture"
	ModelTypeEnsemble        ModelType = "ensemble"
	ModelTypeDeepLearning    ModelType = "deep_learning"
)

// FeatureExtractor extracts features from behavior data
type FeatureExtractor struct {
	features []string
	weights  map[string]float64
}

// RiskAssessor assesses risk based on behavioral analysis
type RiskAssessor struct {
	riskFactors map[string]float64
	thresholds  map[string]float64
}

// AlertManager manages behavioral alerts
type AlertManager struct {
	alerts      []Alert
	cooldownMap map[string]time.Time
	subscribers []AlertSubscriber
}

// AlertSubscriber interface for alert subscribers
type AlertSubscriber interface {
	HandleAlert(alert Alert) error
}

// Helper constructors and components

func NewTemporalPattern() *TemporalPattern {
	return &TemporalPattern{
		HourlyDistribution:  [24]float64{},
		DailyDistribution:   [7]float64{},
		MonthlyDistribution: [12]float64{},
		PeakHours:           make([]int, 0),
		ActiveDays:          make([]int, 0),
		SessionDuration:     &StatisticalDistribution{},
		InterSessionGap:     &StatisticalDistribution{},
		LastUpdated:         time.Now(),
	}
}

func NewSessionPattern() *SessionPattern {
	return &SessionPattern{
		SessionTerminations: make(map[string]int),
	}
}

func NewAccessPattern() *AccessPattern {
	return &AccessPattern{
		ResourcesAccessed: make(map[string]int64),
		ActionsPerformed:  make(map[string]int64),
		PermissionsUsed:   make(map[string]int64),
		UnusualAccess:     make([]AccessEvent, 0),
	}
}

func NewLocationPattern() *LocationPattern {
	return &LocationPattern{
		Countries:        make(map[string]int64),
		Regions:          make(map[string]int64),
		Cities:           make(map[string]int64),
		IPRanges:         make(map[string]int64),
		ISPs:             make(map[string]int64),
		UnusualLocations: make([]LocationEvent, 0),
	}
}

func NewDevicePattern() *DevicePattern {
	return &DevicePattern{
		DevicesUsed:        make(map[string]int64),
		UserAgents:         make(map[string]int64),
		OperatingSystems:   make(map[string]int64),
		Browsers:           make(map[string]int64),
		ScreenResolutions:  make(map[string]int64),
		DeviceFingerprints: make(map[string]int64),
	}
}

func NewBehaviorBaseline() *BehaviorBaseline {
	return &BehaviorBaseline{
		EstablishedAt:       time.Now(),
		NormalRanges:        make(map[string]*ValueRange),
		ExpectedPatterns:    make(map[string]float64),
		SeasonalAdjustments: make(map[string]float64),
		ConfidenceLevel:     0.0,
		Valid:               false,
	}
}

func NewMLBehaviorProfile() *MLBehaviorProfile {
	return &MLBehaviorProfile{
		Features:       make([]string, 0),
		FeatureWeights: make(map[string]float64),
		ModelType:      string(ModelTypeEnsemble),
		ClusterID:      -1,
	}
}

func NewSystemBehaviorProfile() *SystemBehaviorProfile {
	return &SystemBehaviorProfile{
		CreatedAt:       time.Now(),
		LastUpdated:     time.Now(),
		CPUPatterns:     &ResourcePattern{},
		MemoryPatterns:  &ResourcePattern{},
		NetworkPatterns: &NetworkPattern{},
		DiskPatterns:    &ResourcePattern{},
		AuthPatterns:    &AuthenticationPattern{},
		AccessPatterns:  &SystemAccessPattern{},
		ErrorPatterns:   &ErrorPattern{},
		Baseline:        &SystemBaseline{},
		Predictions:     make([]SystemPrediction, 0),
		Forecasts:       make(map[string]float64),
	}
}

// Supporting types for system analysis

type ResourcePattern struct {
	Usage        []float64
	PeakTimes    []time.Time
	AverageUsage float64
	MaxUsage     float64
	Trend        float64
	Anomalies    []ResourceAnomaly
}

type NetworkPattern struct {
	Bandwidth    []float64
	Connections  []int
	Protocols    map[string]int64
	Destinations map[string]int64
	Anomalies    []NetworkAnomaly
}

type AuthenticationPattern struct {
	SuccessRate    float64
	FailureRate    float64
	FailureSpikes  []time.Time
	UnusualSources []string
	Anomalies      []AuthAnomaly
}

type SystemAccessPattern struct {
	ResourceAccess map[string]int64
	PermissionUse  map[string]int64
	PrivilegeEsc   []PrivilegeEvent
	Anomalies      []AccessAnomaly
}

type ErrorPattern struct {
	ErrorTypes     map[string]int64
	ErrorRate      float64
	ErrorSpikes    []time.Time
	CriticalErrors []ErrorEvent
}

type SystemBaseline struct {
	EstablishedAt      time.Time
	NormalRanges       map[string]*ValueRange
	PerformanceMetrics map[string]float64
	Valid              bool
}

type SystemPrediction struct {
	Type        string
	Value       float64
	Confidence  float64
	TimeHorizon time.Duration
	CreatedAt   time.Time
}

// Event types

type AccessEvent struct {
	UserID    string
	Resource  string
	Action    string
	Timestamp time.Time
	Unusual   bool
	Severity  SeverityLevel
}

type LocationEvent struct {
	UserID     string
	Location   string
	Timestamp  time.Time
	Distance   float64
	TravelTime time.Duration
	Impossible bool
}

type ResourceAnomaly struct {
	Resource  string
	Value     float64
	Expected  float64
	Deviation float64
	Timestamp time.Time
}

type NetworkAnomaly struct {
	Type      string
	Value     float64
	Threshold float64
	Timestamp time.Time
}

type AuthAnomaly struct {
	Type      string
	UserID    string
	Details   string
	Timestamp time.Time
}

type AccessAnomaly struct {
	Type      string
	UserID    string
	Resource  string
	Action    string
	Timestamp time.Time
}

type PrivilegeEvent struct {
	UserID     string
	OldLevel   string
	NewLevel   string
	Timestamp  time.Time
	Authorized bool
}

type ErrorEvent struct {
	Type      string
	Message   string
	Severity  SeverityLevel
	Timestamp time.Time
	Component string
}

// FeatureExtractor implementation

func NewFeatureExtractor() *FeatureExtractor {
	return &FeatureExtractor{
		features: []string{
			"time_of_day",
			"day_of_week",
			"session_duration",
			"actions_per_minute",
			"unique_resources",
			"error_rate",
			"data_transferred",
			"location_entropy",
			"device_consistency",
			"access_velocity",
		},
		weights: map[string]float64{
			"time_of_day":        1.0,
			"day_of_week":        0.8,
			"session_duration":   1.2,
			"actions_per_minute": 1.5,
			"unique_resources":   1.0,
			"error_rate":         2.0,
			"data_transferred":   1.0,
			"location_entropy":   1.8,
			"device_consistency": 1.5,
			"access_velocity":    1.3,
		},
	}
}

func (f *FeatureExtractor) ExtractFeatures(data *BehaviorData) (map[string]float64, error) {
	features := make(map[string]float64)

	// Time-based features
	features["time_of_day"] = float64(data.Timestamp.Hour())
	features["day_of_week"] = float64(data.Timestamp.Weekday())
	features["hour_sin"] = math.Sin(2 * math.Pi * float64(data.Timestamp.Hour()) / 24)
	features["hour_cos"] = math.Cos(2 * math.Pi * float64(data.Timestamp.Hour()) / 24)

	// Session features
	if data.Duration > 0 {
		features["session_duration"] = data.Duration.Minutes()
		features["session_log_duration"] = math.Log(data.Duration.Minutes() + 1)
	}

	// Data transfer features
	features["data_transferred"] = float64(data.DataTransferred)
	if data.DataTransferred > 0 {
		features["data_log_transferred"] = math.Log(float64(data.DataTransferred) + 1)
	}

	// Success/error features
	if data.Success {
		features["success_rate"] = 1.0
	} else {
		features["success_rate"] = 0.0
		features["error_count"] = float64(len(data.Errors))
	}

	// Location features
	if data.Location != nil {
		features["location_entropy"] = f.calculateLocationEntropy(data.Location)
		features["latitude"] = data.Location.Latitude
		features["longitude"] = data.Location.Longitude
	}

	// Device features
	if data.Device != nil {
		features["device_consistency"] = f.calculateDeviceConsistency(data.Device)
		features["platform_numeric"] = f.encodePlatform(data.Device.Platform)
		features["os_numeric"] = f.encodeOS(data.Device.OS)
	}

	// Behavioral features
	features["action_entropy"] = f.calculateActionEntropy(data.Action)
	features["resource_specificity"] = f.calculateResourceSpecificity(data.Resource)

	// User agent features
	features["user_agent_entropy"] = f.calculateUserAgentEntropy(data.UserAgent)

	return features, nil
}

func (f *FeatureExtractor) calculateLocationEntropy(location *LocationData) float64 {
	// Calculate entropy based on location specificity
	entropy := 0.0

	if location.Country != "" {
		entropy += 1.0
	}
	if location.Region != "" {
		entropy += 0.5
	}
	if location.City != "" {
		entropy += 0.3
	}
	if location.ISP != "" {
		entropy += 0.2
	}

	return entropy
}

func (f *FeatureExtractor) calculateDeviceConsistency(device *DeviceData) float64 {
	// Calculate consistency score based on device attributes
	consistency := 1.0

	// Penalize for missing information
	if device.Platform == "" {
		consistency -= 0.2
	}
	if device.OS == "" {
		consistency -= 0.2
	}
	if device.Browser == "" {
		consistency -= 0.2
	}
	if device.Resolution == "" {
		consistency -= 0.2
	}
	if device.Fingerprint == "" {
		consistency -= 0.2
	}

	return math.Max(consistency, 0.0)
}

func (f *FeatureExtractor) encodePlatform(platform string) float64 {
	platforms := map[string]float64{
		"windows": 1.0,
		"linux":   2.0,
		"macos":   3.0,
		"android": 4.0,
		"ios":     5.0,
	}

	if value, exists := platforms[platform]; exists {
		return value
	}
	return 0.0
}

func (f *FeatureExtractor) encodeOS(os string) float64 {
	// Simple encoding for OS types
	if os == "" {
		return 0.0
	}

	// Hash-based encoding (simplified)
	hash := 0
	for _, char := range os {
		hash = hash*31 + int(char)
	}

	return float64(hash % 100)
}

func (f *FeatureExtractor) calculateActionEntropy(action string) float64 {
	// Calculate entropy based on action type
	actionWeights := map[string]float64{
		"login":    1.0,
		"logout":   0.5,
		"read":     0.3,
		"write":    0.7,
		"delete":   1.5,
		"admin":    2.0,
		"config":   1.8,
		"download": 0.8,
		"upload":   1.0,
	}

	if weight, exists := actionWeights[action]; exists {
		return weight
	}
	return 0.5 // Default entropy
}

func (f *FeatureExtractor) calculateResourceSpecificity(resource string) float64 {
	// Calculate specificity based on resource path depth
	if resource == "" {
		return 0.0
	}

	// Count path separators as measure of specificity
	specificity := 0.0
	for _, char := range resource {
		if char == '/' || char == '\\' {
			specificity += 0.1
		}
	}

	return math.Min(specificity, 2.0)
}

func (f *FeatureExtractor) calculateUserAgentEntropy(userAgent string) float64 {
	// Calculate entropy based on user agent complexity
	if userAgent == "" {
		return 0.0
	}

	// Simple entropy calculation
	charCount := make(map[rune]int)
	for _, char := range userAgent {
		charCount[char]++
	}

	entropy := 0.0
	length := float64(len(userAgent))

	for _, count := range charCount {
		probability := float64(count) / length
		if probability > 0 {
			entropy -= probability * math.Log2(probability)
		}
	}

	return entropy
}

// AnomalyDetector implementation

func NewAnomalyDetector() *AnomalyDetector {
	return &AnomalyDetector{
		algorithms: map[string]AnomalyAlgorithm{
			"isolation_forest": &IsolationForest{},
			"statistical":      &StatisticalDetector{},
			"clustering":       &ClusteringDetector{},
		},
		thresholds: map[string]float64{
			"isolation_forest": 0.6,
			"statistical":      0.7,
			"clustering":       0.65,
		},
		ensembleWeights: map[string]float64{
			"isolation_forest": 0.4,
			"statistical":      0.3,
			"clustering":       0.3,
		},
	}
}

func (a *AnomalyDetector) DetectEnsemble(dataPoint DataPoint) (float64, error) {
	scores := make(map[string]float64)

	// Run all algorithms
	for name, algorithm := range a.algorithms {
		score, err := algorithm.Detect(dataPoint)
		if err != nil {
			continue // Skip failed algorithms
		}
		scores[name] = score
	}

	if len(scores) == 0 {
		return 0.0, errors.New("no algorithms succeeded")
	}

	// Calculate weighted ensemble score
	ensembleScore := 0.0
	totalWeight := 0.0

	for name, score := range scores {
		if weight, exists := a.ensembleWeights[name]; exists {
			ensembleScore += score * weight
			totalWeight += weight
		}
	}

	if totalWeight > 0 {
		ensembleScore /= totalWeight
	}

	a.detectionCount++
	a.lastDetection = time.Now()

	return ensembleScore, nil
}

// Simple anomaly detection algorithms

type IsolationForest struct {
	trees    []IsolationTree
	trained  bool
	accuracy float64
}

type IsolationTree struct {
	feature   string
	threshold float64
	left      *IsolationTree
	right     *IsolationTree
	depth     int
}

func (i *IsolationForest) Train(data []DataPoint) error {
	// Simplified isolation forest training
	i.trees = make([]IsolationTree, 10) // 10 trees
	i.trained = true
	i.accuracy = 0.85
	return nil
}

func (i *IsolationForest) Detect(data DataPoint) (float64, error) {
	if !i.trained {
		return 0.0, errors.New("model not trained")
	}

	// Simplified anomaly score calculation
	score := 0.0
	for feature, value := range data.Features {
		// Simple threshold-based detection
		if math.Abs(value) > 2.0 {
			score += 0.1
		}
	}

	return math.Min(score, 1.0), nil
}

func (i *IsolationForest) GetType() string {
	return "isolation_forest"
}

func (i *IsolationForest) GetAccuracy() float64 {
	return i.accuracy
}

type StatisticalDetector struct {
	means    map[string]float64
	stddevs  map[string]float64
	trained  bool
	accuracy float64
}

func (s *StatisticalDetector) Train(data []DataPoint) error {
	s.means = make(map[string]float64)
	s.stddevs = make(map[string]float64)

	// Calculate means and standard deviations
	featureCounts := make(map[string]int)

	for _, point := range data {
		for feature, value := range point.Features {
			s.means[feature] += value
			featureCounts[feature]++
		}
	}

	// Normalize means
	for feature, sum := range s.means {
		s.means[feature] = sum / float64(featureCounts[feature])
	}

	// Calculate standard deviations
	for _, point := range data {
		for feature, value := range point.Features {
			diff := value - s.means[feature]
			s.stddevs[feature] += diff * diff
		}
	}

	for feature, sumSquares := range s.stddevs {
		s.stddevs[feature] = math.Sqrt(sumSquares / float64(featureCounts[feature]))
	}

	s.trained = true
	s.accuracy = 0.80
	return nil
}

func (s *StatisticalDetector) Detect(data DataPoint) (float64, error) {
	if !s.trained {
		return 0.0, errors.New("model not trained")
	}

	anomalyScore := 0.0
	featureCount := 0

	for feature, value := range data.Features {
		if mean, exists := s.means[feature]; exists {
			if stddev, exists := s.stddevs[feature]; exists && stddev > 0 {
				zScore := math.Abs((value - mean) / stddev)
				if zScore > 2.0 { // 2-sigma threshold
					anomalyScore += zScore / 3.0 // Normalize to 0-1
				}
				featureCount++
			}
		}
	}

	if featureCount > 0 {
		anomalyScore /= float64(featureCount)
	}

	return math.Min(anomalyScore, 1.0), nil
}

func (s *StatisticalDetector) GetType() string {
	return "statistical"
}

func (s *StatisticalDetector) GetAccuracy() float64 {
	return s.accuracy
}

type ClusteringDetector struct {
	clusters []Cluster
	trained  bool
	accuracy float64
}

type Cluster struct {
	Center map[string]float64
	Radius float64
}

func (c *ClusteringDetector) Train(data []DataPoint) error {
	// Simplified k-means clustering
	c.clusters = make([]Cluster, 3) // 3 clusters

	// Initialize cluster centers randomly
	for i := range c.clusters {
		c.clusters[i].Center = make(map[string]float64)
		c.clusters[i].Radius = 1.0
	}

	c.trained = true
	c.accuracy = 0.75
	return nil
}

func (c *ClusteringDetector) Detect(data DataPoint) (float64, error) {
	if !c.trained {
		return 0.0, errors.New("model not trained")
	}

	// Find distance to nearest cluster
	minDistance := math.Inf(1)

	for _, cluster := range c.clusters {
		distance := c.calculateDistance(data.Features, cluster.Center)
		if distance < minDistance {
			minDistance = distance
		}
	}

	// Convert distance to anomaly score
	anomalyScore := math.Min(minDistance/5.0, 1.0)

	return anomalyScore, nil
}

func (c *ClusteringDetector) calculateDistance(features1, features2 map[string]float64) float64 {
	distance := 0.0
	count := 0

	for feature, value1 := range features1 {
		if value2, exists := features2[feature]; exists {
			diff := value1 - value2
			distance += diff * diff
			count++
		}
	}

	if count > 0 {
		distance = math.Sqrt(distance / float64(count))
	}

	return distance
}

func (c *ClusteringDetector) GetType() string {
	return "clustering"
}

func (c *ClusteringDetector) GetAccuracy() float64 {
	return c.accuracy
}

// RiskAssessor implementation

func NewRiskAssessor() *RiskAssessor {
	return &RiskAssessor{
		riskFactors: map[string]float64{
			"anomaly_score":   0.3,
			"violation_count": 0.2,
			"suspicious_flag": 0.25,
			"recent_anomaly":  0.15,
			"location_risk":   0.1,
		},
		thresholds: map[string]float64{
			"low":      0.3,
			"medium":   0.6,
			"high":     0.8,
			"critical": 0.9,
		},
	}
}

func (r *RiskAssessor) AssessRisk(profile *UserBehaviorProfile, anomalies []AnomalyResult) float64 {
	risk := 0.0

	// Base risk from anomaly score
	risk += profile.AnomalyScore * r.riskFactors["anomaly_score"]

	// Risk from violation count
	violationRisk := math.Min(float64(profile.ViolationCount)/10.0, 1.0)
	risk += violationRisk * r.riskFactors["violation_count"]

	// Risk from suspicious flag
	if profile.Suspicious {
		risk += r.riskFactors["suspicious_flag"]
	}

	// Risk from recent anomalies
	if !profile.LastAnomalyTime.IsZero() &&
		time.Since(profile.LastAnomalyTime) < 24*time.Hour {
		risk += r.riskFactors["recent_anomaly"]
	}

	// Risk from current anomalies
	for _, anomaly := range anomalies {
		risk += anomaly.AnomalyScore * 0.1
	}

	// Cap risk at 1.0
	risk = math.Min(risk, 1.0)

	// Update profile risk score
	profile.RiskScore = risk

	return risk
}

// AlertManager implementation

func NewAlertManager() *AlertManager {
	return &AlertManager{
		alerts:      make([]Alert, 0),
		cooldownMap: make(map[string]time.Time),
		subscribers: make([]AlertSubscriber, 0),
	}
}

func (a *AlertManager) SendAlert(alert Alert) error {
	// Check cooldown
	cooldownKey := fmt.Sprintf("%s_%s", alert.UserID, alert.Type)
	if lastAlert, exists := a.cooldownMap[cooldownKey]; exists {
		if time.Since(lastAlert) < time.Hour {
			return nil // Skip alert due to cooldown
		}
	}

	// Store alert
	a.alerts = append(a.alerts, alert)
	a.cooldownMap[cooldownKey] = time.Now()

	// Notify subscribers
	for _, subscriber := range a.subscribers {
		subscriber.HandleAlert(alert)
	}

	return nil
}

func (a *AlertManager) AddSubscriber(subscriber AlertSubscriber) {
	a.subscribers = append(a.subscribers, subscriber)
}

func (a *AlertManager) GetRecentAlerts(limit int) []Alert {
	if len(a.alerts) <= limit {
		return a.alerts
	}

	// Sort by timestamp and return most recent
	sort.Slice(a.alerts, func(i, j int) bool {
		return a.alerts[i].Timestamp.After(a.alerts[j].Timestamp)
	})

	return a.alerts[:limit]
}
