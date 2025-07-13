package behavioral

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"sync"
	"time"
)

// BehavioralAnalysisEngine provides ML-based behavioral analysis and anomaly detection
type BehavioralAnalysisEngine struct {
	config           *AnalysisConfig
	userProfiles     map[string]*UserBehaviorProfile
	systemProfile    *SystemBehaviorProfile
	anomalyDetector  *AnomalyDetector
	mlModels         map[string]*MLModel
	featureExtractor *FeatureExtractor
	riskAssessor     *RiskAssessor
	alertManager     *AlertManager

	// Thread safety
	profilesMutex sync.RWMutex
	modelsMutex   sync.RWMutex

	// Metrics and monitoring
	metrics       *AnalysisMetrics
	lastAnalysis  time.Time
	analysisCount int64

	// Context for shutdown
	ctx    context.Context
	cancel context.CancelFunc
}

// AnalysisConfig holds configuration for behavioral analysis
type AnalysisConfig struct {
	EnableUserAnalysis       bool
	EnableSystemAnalysis     bool
	EnableAnomalyDetection   bool
	EnableRiskAssessment     bool
	EnableRealTimeAlerts     bool
	LearningPeriod           time.Duration
	AnalysisInterval         time.Duration
	AnomalyThreshold         float64
	RiskThreshold            float64
	MaxUserProfiles          int
	ProfileRetentionPeriod   time.Duration
	MLModelType              string
	FeatureWindowSize        int
	MinDataPointsRequired    int
	AlertCooldownPeriod      time.Duration
	EnablePredictiveAnalysis bool
	EnableBehaviorBaseline   bool
}

// UserBehaviorProfile represents a user's behavioral profile
type UserBehaviorProfile struct {
	UserID        string
	CreatedAt     time.Time
	LastUpdated   time.Time
	TotalSessions int64

	// Temporal patterns
	LoginPatterns    *TemporalPattern
	ActivityPatterns *TemporalPattern
	SessionPatterns  *SessionPattern

	// Access patterns
	AccessPatterns   *AccessPattern
	LocationPatterns *LocationPattern
	DevicePatterns   *DevicePattern

	// Behavioral features
	Features     map[string]float64
	Baseline     *BehaviorBaseline
	AnomalyScore float64
	RiskScore    float64

	// Machine learning
	MLProfile   *MLBehaviorProfile
	Predictions []BehaviorPrediction

	// Status
	Active          bool
	Suspicious      bool
	LastAnomalyTime time.Time
	ViolationCount  int
}

// SystemBehaviorProfile represents system-wide behavioral patterns
type SystemBehaviorProfile struct {
	CreatedAt   time.Time
	LastUpdated time.Time

	// System metrics
	CPUPatterns     *ResourcePattern
	MemoryPatterns  *ResourcePattern
	NetworkPatterns *NetworkPattern
	DiskPatterns    *ResourcePattern

	// Security patterns
	AuthPatterns   *AuthenticationPattern
	AccessPatterns *SystemAccessPattern
	ErrorPatterns  *ErrorPattern

	// Baseline and anomalies
	Baseline     *SystemBaseline
	AnomalyScore float64
	ThreatLevel  ThreatLevel

	// Predictions
	Predictions []SystemPrediction
	Forecasts   map[string]float64
}

// TemporalPattern represents time-based behavioral patterns
type TemporalPattern struct {
	HourlyDistribution  [24]float64
	DailyDistribution   [7]float64
	MonthlyDistribution [12]float64
	PeakHours           []int
	ActiveDays          []int
	SessionDuration     *StatisticalDistribution
	InterSessionGap     *StatisticalDistribution
	LastUpdated         time.Time
}

// SessionPattern represents session behavioral patterns
type SessionPattern struct {
	AverageSessionDuration time.Duration
	MaxSessionDuration     time.Duration
	MinSessionDuration     time.Duration
	SessionsPerDay         float64
	SessionsPerWeek        float64
	ConcurrentSessions     int
	UnusualSessionTimes    []time.Time
	SessionTerminations    map[string]int // reason -> count
}

// AccessPattern represents access behavioral patterns
type AccessPattern struct {
	ResourcesAccessed     map[string]int64
	ActionsPerformed      map[string]int64
	PermissionsUsed       map[string]int64
	DataVolumeTransferred int64
	UnusualAccess         []AccessEvent
	AccessVelocity        float64 // requests per minute
	ErrorRate             float64
}

// LocationPattern represents geographical and network location patterns
type LocationPattern struct {
	Countries        map[string]int64
	Regions          map[string]int64
	Cities           map[string]int64
	IPRanges         map[string]int64
	ISPs             map[string]int64
	UnusualLocations []LocationEvent
	TravelSpeed      float64 // km/h between locations
	LocationChanges  int64
}

// DevicePattern represents device usage patterns
type DevicePattern struct {
	DevicesUsed        map[string]int64
	UserAgents         map[string]int64
	OperatingSystems   map[string]int64
	Browsers           map[string]int64
	ScreenResolutions  map[string]int64
	DeviceFingerprints map[string]int64
	NewDeviceFrequency float64
	DeviceCount        int
}

// BehaviorBaseline represents baseline behavior for comparison
type BehaviorBaseline struct {
	EstablishedAt       time.Time
	DataPoints          int64
	ConfidenceLevel     float64
	NormalRanges        map[string]*ValueRange
	ExpectedPatterns    map[string]float64
	SeasonalAdjustments map[string]float64
	LastRecalculated    time.Time
	Valid               bool
}

// ValueRange represents a range of normal values
type ValueRange struct {
	Min          float64
	Max          float64
	Mean         float64
	StdDev       float64
	Percentile95 float64
	Percentile99 float64
}

// StatisticalDistribution represents statistical distribution of values
type StatisticalDistribution struct {
	Mean      float64
	Median    float64
	StdDev    float64
	Min       float64
	Max       float64
	Count     int64
	Histogram map[string]int64
}

// MLBehaviorProfile represents machine learning behavioral profile
type MLBehaviorProfile struct {
	ModelType          string
	Features           []string
	FeatureWeights     map[string]float64
	ClusterID          int
	AnomalyScore       float64
	ConfidenceScore    float64
	LastTraining       time.Time
	ModelVersion       string
	PredictionAccuracy float64
}

// BehaviorPrediction represents a behavioral prediction
type BehaviorPrediction struct {
	PredictionID   string
	Type           PredictionType
	Confidence     float64
	PredictedValue float64
	TimeHorizon    time.Duration
	CreatedAt      time.Time
	Validated      bool
	Accuracy       float64
}

// PredictionType represents the type of prediction
type PredictionType string

const (
	PredictionTypeLoginTime     PredictionType = "login_time"
	PredictionTypeSessionLength PredictionType = "session_length"
	PredictionTypeAccessPattern PredictionType = "access_pattern"
	PredictionTypeRiskLevel     PredictionType = "risk_level"
	PredictionTypeAnomaly       PredictionType = "anomaly"
	PredictionTypeChurn         PredictionType = "churn"
)

// AnomalyDetector provides anomaly detection capabilities
type AnomalyDetector struct {
	algorithms        map[string]AnomalyAlgorithm
	thresholds        map[string]float64
	ensembleWeights   map[string]float64
	lastDetection     time.Time
	detectionCount    int64
	falsePositiveRate float64
	truePositiveRate  float64
}

// AnomalyAlgorithm interface for anomaly detection algorithms
type AnomalyAlgorithm interface {
	Train(data []DataPoint) error
	Detect(data DataPoint) (float64, error)
	GetType() string
	GetAccuracy() float64
}

// DataPoint represents a single data point for analysis
type DataPoint struct {
	Timestamp time.Time
	UserID    string
	Features  map[string]float64
	Labels    map[string]string
	Value     float64
	Category  string
	Metadata  map[string]interface{}
}

// AnomalyResult represents the result of anomaly detection
type AnomalyResult struct {
	UserID            string
	AnomalyScore      float64
	AnomalyType       AnomalyType
	Confidence        float64
	Features          []string
	Explanation       string
	Severity          SeverityLevel
	Timestamp         time.Time
	RecommendedAction string
}

// AnomalyType represents different types of anomalies
type AnomalyType string

const (
	AnomalyTypeStatistical  AnomalyType = "statistical"
	AnomalyTypeTemporal     AnomalyType = "temporal"
	AnomalyTypePatternBased AnomalyType = "pattern_based"
	AnomalyTypeMLBased      AnomalyType = "ml_based"
	AnomalyTypeContextual   AnomalyType = "contextual"
	AnomalyTypeCollective   AnomalyType = "collective"
)

// SeverityLevel represents the severity of an anomaly
type SeverityLevel int

const (
	SeverityLevelLow SeverityLevel = iota
	SeverityLevelMedium
	SeverityLevelHigh
	SeverityLevelCritical
)

// ThreatLevel represents system threat level
type ThreatLevel int

const (
	ThreatLevelMinimal ThreatLevel = iota
	ThreatLevelLow
	ThreatLevelMedium
	ThreatLevelHigh
	ThreatLevelCritical
)

// AnalysisMetrics tracks behavioral analysis metrics
type AnalysisMetrics struct {
	TotalAnalyses         int64
	AnomaliesDetected     int64
	FalsePositives        int64
	TruePositives         int64
	UserProfilesCreated   int64
	MLModelsTraned        int64
	PredictionsMade       int64
	PredictionAccuracy    float64
	AverageProcessingTime time.Duration
	LastReset             time.Time
	mutex                 sync.RWMutex
}

// NewBehavioralAnalysisEngine creates a new behavioral analysis engine
func NewBehavioralAnalysisEngine(config *AnalysisConfig) *BehavioralAnalysisEngine {
	if config == nil {
		config = &AnalysisConfig{
			EnableUserAnalysis:       true,
			EnableSystemAnalysis:     true,
			EnableAnomalyDetection:   true,
			EnableRiskAssessment:     true,
			EnableRealTimeAlerts:     true,
			LearningPeriod:           7 * 24 * time.Hour,
			AnalysisInterval:         time.Minute,
			AnomalyThreshold:         0.7,
			RiskThreshold:            0.8,
			MaxUserProfiles:          10000,
			ProfileRetentionPeriod:   90 * 24 * time.Hour,
			MLModelType:              "ensemble",
			FeatureWindowSize:        100,
			MinDataPointsRequired:    50,
			AlertCooldownPeriod:      time.Hour,
			EnablePredictiveAnalysis: true,
			EnableBehaviorBaseline:   true,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	engine := &BehavioralAnalysisEngine{
		config:       config,
		userProfiles: make(map[string]*UserBehaviorProfile),
		mlModels:     make(map[string]*MLModel),
		metrics:      &AnalysisMetrics{LastReset: time.Now()},
		ctx:          ctx,
		cancel:       cancel,
	}

	// Initialize components
	engine.anomalyDetector = NewAnomalyDetector()
	engine.featureExtractor = NewFeatureExtractor()
	engine.riskAssessor = NewRiskAssessor()
	engine.alertManager = NewAlertManager()
	engine.systemProfile = NewSystemBehaviorProfile()

	return engine
}

// Start starts the behavioral analysis engine
func (b *BehavioralAnalysisEngine) Start() error {
	// Start background workers
	go b.analysisWorker()
	go b.profileMaintenanceWorker()
	go b.modelTrainingWorker()
	go b.metricsWorker()

	if b.config.EnablePredictiveAnalysis {
		go b.predictionWorker()
	}

	return nil
}

// Stop stops the behavioral analysis engine
func (b *BehavioralAnalysisEngine) Stop() error {
	b.cancel()
	return nil
}

// AnalyzeBehavior analyzes user behavior and detects anomalies
func (b *BehavioralAnalysisEngine) AnalyzeBehavior(userID string, behaviorData *BehaviorData) (*AnalysisResult, error) {
	startTime := time.Now()

	// Get or create user profile
	profile := b.getUserProfile(userID)
	if profile == nil {
		profile = b.createUserProfile(userID)
	}

	// Extract features from behavior data
	features, err := b.featureExtractor.ExtractFeatures(behaviorData)
	if err != nil {
		return nil, fmt.Errorf("feature extraction failed: %v", err)
	}

	// Update user profile
	err = b.updateUserProfile(profile, behaviorData, features)
	if err != nil {
		return nil, fmt.Errorf("profile update failed: %v", err)
	}

	// Detect anomalies
	var anomalies []AnomalyResult
	if b.config.EnableAnomalyDetection {
		anomalies, err = b.detectAnomalies(profile, features)
		if err != nil {
			return nil, fmt.Errorf("anomaly detection failed: %v", err)
		}
	}

	// Assess risk
	var riskScore float64
	if b.config.EnableRiskAssessment {
		riskScore = b.riskAssessor.AssessRisk(profile, anomalies)
	}

	// Generate predictions
	var predictions []BehaviorPrediction
	if b.config.EnablePredictiveAnalysis {
		predictions = b.generatePredictions(profile, features)
	}

	// Create analysis result
	result := &AnalysisResult{
		UserID:          userID,
		Timestamp:       time.Now(),
		Profile:         profile,
		Features:        features,
		Anomalies:       anomalies,
		RiskScore:       riskScore,
		Predictions:     predictions,
		ProcessingTime:  time.Since(startTime),
		ConfidenceScore: b.calculateConfidenceScore(profile, anomalies),
	}

	// Generate alerts if necessary
	if b.config.EnableRealTimeAlerts {
		b.generateAlerts(result)
	}

	// Update metrics
	b.updateMetrics(result)

	return result, nil
}

// AnalysisResult represents the result of behavioral analysis
type AnalysisResult struct {
	UserID          string
	Timestamp       time.Time
	Profile         *UserBehaviorProfile
	Features        map[string]float64
	Anomalies       []AnomalyResult
	RiskScore       float64
	Predictions     []BehaviorPrediction
	ProcessingTime  time.Duration
	ConfidenceScore float64
	Recommendations []string
	Alerts          []Alert
}

// BehaviorData represents input behavior data
type BehaviorData struct {
	UserID          string
	SessionID       string
	Timestamp       time.Time
	Action          string
	Resource        string
	IPAddress       string
	UserAgent       string
	Location        *LocationData
	Device          *DeviceData
	Duration        time.Duration
	DataTransferred int64
	Success         bool
	Errors          []string
	Metadata        map[string]interface{}
}

// LocationData represents location information
type LocationData struct {
	Country   string
	Region    string
	City      string
	Latitude  float64
	Longitude float64
	ISP       string
	Timezone  string
}

// DeviceData represents device information
type DeviceData struct {
	DeviceID    string
	Platform    string
	OS          string
	Browser     string
	Resolution  string
	Fingerprint string
}

// Alert represents a behavioral alert
type Alert struct {
	AlertID      string
	Type         AlertType
	Severity     SeverityLevel
	UserID       string
	Message      string
	Details      map[string]interface{}
	Timestamp    time.Time
	Acknowledged bool
	Actions      []string
}

// AlertType represents different types of alerts
type AlertType string

const (
	AlertTypeAnomaly        AlertType = "anomaly"
	AlertTypeRiskEscalation AlertType = "risk_escalation"
	AlertTypePrediction     AlertType = "prediction"
	AlertTypePattern        AlertType = "pattern"
	AlertTypeThreat         AlertType = "threat"
)

// Implementation methods

func (b *BehavioralAnalysisEngine) getUserProfile(userID string) *UserBehaviorProfile {
	b.profilesMutex.RLock()
	defer b.profilesMutex.RUnlock()

	return b.userProfiles[userID]
}

func (b *BehavioralAnalysisEngine) createUserProfile(userID string) *UserBehaviorProfile {
	b.profilesMutex.Lock()
	defer b.profilesMutex.Unlock()

	if len(b.userProfiles) >= b.config.MaxUserProfiles {
		// Remove oldest inactive profile
		b.removeOldestProfile()
	}

	profile := &UserBehaviorProfile{
		UserID:           userID,
		CreatedAt:        time.Now(),
		LastUpdated:      time.Now(),
		LoginPatterns:    NewTemporalPattern(),
		ActivityPatterns: NewTemporalPattern(),
		SessionPatterns:  NewSessionPattern(),
		AccessPatterns:   NewAccessPattern(),
		LocationPatterns: NewLocationPattern(),
		DevicePatterns:   NewDevicePattern(),
		Features:         make(map[string]float64),
		Baseline:         NewBehaviorBaseline(),
		MLProfile:        NewMLBehaviorProfile(),
		Predictions:      make([]BehaviorPrediction, 0),
		Active:           true,
		Suspicious:       false,
	}

	b.userProfiles[userID] = profile
	b.metrics.UserProfilesCreated++

	return profile
}

func (b *BehavioralAnalysisEngine) updateUserProfile(profile *UserBehaviorProfile, data *BehaviorData, features map[string]float64) error {
	profile.LastUpdated = time.Now()
	profile.TotalSessions++

	// Update temporal patterns
	b.updateTemporalPatterns(profile, data)

	// Update session patterns
	b.updateSessionPatterns(profile, data)

	// Update access patterns
	b.updateAccessPatterns(profile, data)

	// Update location patterns
	if data.Location != nil {
		b.updateLocationPatterns(profile, data)
	}

	// Update device patterns
	if data.Device != nil {
		b.updateDevicePatterns(profile, data)
	}

	// Update features
	for feature, value := range features {
		profile.Features[feature] = value
	}

	// Update baseline if enough data
	if profile.TotalSessions >= int64(b.config.MinDataPointsRequired) {
		b.updateBaseline(profile)
	}

	return nil
}

func (b *BehavioralAnalysisEngine) detectAnomalies(profile *UserBehaviorProfile, features map[string]float64) ([]AnomalyResult, error) {
	anomalies := make([]AnomalyResult, 0)

	// Create data point for detection
	dataPoint := DataPoint{
		Timestamp: time.Now(),
		UserID:    profile.UserID,
		Features:  features,
		Metadata:  make(map[string]interface{}),
	}

	// Run ensemble anomaly detection
	ensembleScore, err := b.anomalyDetector.DetectEnsemble(dataPoint)
	if err != nil {
		return nil, fmt.Errorf("ensemble detection failed: %v", err)
	}

	if ensembleScore > b.config.AnomalyThreshold {
		anomaly := AnomalyResult{
			UserID:            profile.UserID,
			AnomalyScore:      ensembleScore,
			AnomalyType:       AnomalyTypeMLBased,
			Confidence:        ensembleScore,
			Explanation:       "ML ensemble detected behavioral anomaly",
			Severity:          b.calculateSeverity(ensembleScore),
			Timestamp:         time.Now(),
			RecommendedAction: b.recommendAction(ensembleScore),
		}

		anomalies = append(anomalies, anomaly)
	}

	// Detect statistical anomalies
	statAnomalies := b.detectStatisticalAnomalies(profile, features)
	anomalies = append(anomalies, statAnomalies...)

	// Detect temporal anomalies
	tempAnomalies := b.detectTemporalAnomalies(profile)
	anomalies = append(anomalies, tempAnomalies...)

	// Update profile anomaly information
	if len(anomalies) > 0 {
		profile.AnomalyScore = ensembleScore
		profile.LastAnomalyTime = time.Now()
		profile.ViolationCount++
		profile.Suspicious = ensembleScore > 0.8
	}

	return anomalies, nil
}

func (b *BehavioralAnalysisEngine) detectStatisticalAnomalies(profile *UserBehaviorProfile, features map[string]float64) []AnomalyResult {
	anomalies := make([]AnomalyResult, 0)

	if profile.Baseline == nil || !profile.Baseline.Valid {
		return anomalies
	}

	for feature, value := range features {
		if normalRange, exists := profile.Baseline.NormalRanges[feature]; exists {
			// Check if value is outside normal range
			if value < normalRange.Min || value > normalRange.Max {
				// Calculate z-score
				zScore := (value - normalRange.Mean) / normalRange.StdDev

				if math.Abs(zScore) > 3.0 { // 3-sigma rule
					anomaly := AnomalyResult{
						UserID:            profile.UserID,
						AnomalyScore:      math.Min(math.Abs(zScore)/3.0, 1.0),
						AnomalyType:       AnomalyTypeStatistical,
						Confidence:        0.8,
						Features:          []string{feature},
						Explanation:       fmt.Sprintf("Feature %s outside normal range (z-score: %.2f)", feature, zScore),
						Severity:          b.calculateSeverity(math.Abs(zScore) / 3.0),
						Timestamp:         time.Now(),
						RecommendedAction: "Review user activity patterns",
					}

					anomalies = append(anomalies, anomaly)
				}
			}
		}
	}

	return anomalies
}

func (b *BehavioralAnalysisEngine) detectTemporalAnomalies(profile *UserBehaviorProfile) []AnomalyResult {
	anomalies := make([]AnomalyResult, 0)

	currentHour := time.Now().Hour()
	currentDay := int(time.Now().Weekday())

	// Check if current time is unusual for this user
	hourlyScore := profile.LoginPatterns.HourlyDistribution[currentHour]
	dailyScore := profile.LoginPatterns.DailyDistribution[currentDay]

	// If both scores are very low, it's a temporal anomaly
	if hourlyScore < 0.1 && dailyScore < 0.2 {
		anomaly := AnomalyResult{
			UserID:            profile.UserID,
			AnomalyScore:      1.0 - (hourlyScore + dailyScore),
			AnomalyType:       AnomalyTypeTemporal,
			Confidence:        0.7,
			Features:          []string{"login_time"},
			Explanation:       fmt.Sprintf("Unusual login time: %d:00 on %s", currentHour, time.Now().Weekday()),
			Severity:          SeverityLevelMedium,
			Timestamp:         time.Now(),
			RecommendedAction: "Verify user identity",
		}

		anomalies = append(anomalies, anomaly)
	}

	return anomalies
}

func (b *BehavioralAnalysisEngine) generatePredictions(profile *UserBehaviorProfile, features map[string]float64) []BehaviorPrediction {
	predictions := make([]BehaviorPrediction, 0)

	// Predict next login time
	if loginPred := b.predictNextLogin(profile); loginPred != nil {
		predictions = append(predictions, *loginPred)
	}

	// Predict session length
	if sessionPred := b.predictSessionLength(profile, features); sessionPred != nil {
		predictions = append(predictions, *sessionPred)
	}

	// Predict risk escalation
	if riskPred := b.predictRiskEscalation(profile); riskPred != nil {
		predictions = append(predictions, *riskPred)
	}

	return predictions
}

func (b *BehavioralAnalysisEngine) predictNextLogin(profile *UserBehaviorProfile) *BehaviorPrediction {
	// Simple prediction based on historical patterns
	now := time.Now()
	currentHour := now.Hour()

	// Find most likely next login time
	maxProbability := 0.0
	nextHour := currentHour

	for hour := currentHour + 1; hour < currentHour+24; hour++ {
		hourIndex := hour % 24
		probability := profile.LoginPatterns.HourlyDistribution[hourIndex]
		if probability > maxProbability {
			maxProbability = probability
			nextHour = hourIndex
		}
	}

	if maxProbability > 0.1 {
		hoursUntil := nextHour - currentHour
		if hoursUntil <= 0 {
			hoursUntil += 24
		}

		return &BehaviorPrediction{
			PredictionID:   b.generatePredictionID(),
			Type:           PredictionTypeLoginTime,
			Confidence:     maxProbability,
			PredictedValue: float64(hoursUntil),
			TimeHorizon:    time.Duration(hoursUntil) * time.Hour,
			CreatedAt:      time.Now(),
		}
	}

	return nil
}

func (b *BehavioralAnalysisEngine) predictSessionLength(profile *UserBehaviorProfile, features map[string]float64) *BehaviorPrediction {
	if profile.SessionPatterns.AverageSessionDuration == 0 {
		return nil
	}

	// Use average session duration as baseline prediction
	avgMinutes := profile.SessionPatterns.AverageSessionDuration.Minutes()

	// Adjust based on current context (simplified)
	if timeOfDay, exists := features["time_of_day"]; exists {
		// Longer sessions during typical work hours
		if timeOfDay >= 9 && timeOfDay <= 17 {
			avgMinutes *= 1.2
		}
	}

	return &BehaviorPrediction{
		PredictionID:   b.generatePredictionID(),
		Type:           PredictionTypeSessionLength,
		Confidence:     0.6,
		PredictedValue: avgMinutes,
		TimeHorizon:    time.Duration(avgMinutes) * time.Minute,
		CreatedAt:      time.Now(),
	}
}

func (b *BehavioralAnalysisEngine) predictRiskEscalation(profile *UserBehaviorProfile) *BehaviorPrediction {
	// Predict if user risk will escalate based on recent patterns
	riskTrend := b.calculateRiskTrend(profile)

	if riskTrend > 0.3 {
		return &BehaviorPrediction{
			PredictionID:   b.generatePredictionID(),
			Type:           PredictionTypeRiskLevel,
			Confidence:     riskTrend,
			PredictedValue: profile.RiskScore + riskTrend,
			TimeHorizon:    24 * time.Hour,
			CreatedAt:      time.Now(),
		}
	}

	return nil
}

// Helper methods

func (b *BehavioralAnalysisEngine) updateTemporalPatterns(profile *UserBehaviorProfile, data *BehaviorData) {
	hour := data.Timestamp.Hour()
	day := int(data.Timestamp.Weekday())
	month := int(data.Timestamp.Month()) - 1

	// Update distributions with smoothing
	alpha := 0.1 // learning rate

	profile.LoginPatterns.HourlyDistribution[hour] =
		(1-alpha)*profile.LoginPatterns.HourlyDistribution[hour] + alpha*1.0

	profile.LoginPatterns.DailyDistribution[day] =
		(1-alpha)*profile.LoginPatterns.DailyDistribution[day] + alpha*1.0

	profile.LoginPatterns.MonthlyDistribution[month] =
		(1-alpha)*profile.LoginPatterns.MonthlyDistribution[month] + alpha*1.0

	profile.LoginPatterns.LastUpdated = time.Now()
}

func (b *BehavioralAnalysisEngine) updateSessionPatterns(profile *UserBehaviorProfile, data *BehaviorData) {
	if data.Duration > 0 {
		// Update session duration statistics
		if profile.SessionPatterns.AverageSessionDuration == 0 {
			profile.SessionPatterns.AverageSessionDuration = data.Duration
		} else {
			// Exponential moving average
			alpha := 0.1
			profile.SessionPatterns.AverageSessionDuration =
				time.Duration(float64(profile.SessionPatterns.AverageSessionDuration)*(1-alpha) +
					float64(data.Duration)*alpha)
		}

		if data.Duration > profile.SessionPatterns.MaxSessionDuration {
			profile.SessionPatterns.MaxSessionDuration = data.Duration
		}

		if profile.SessionPatterns.MinSessionDuration == 0 ||
			data.Duration < profile.SessionPatterns.MinSessionDuration {
			profile.SessionPatterns.MinSessionDuration = data.Duration
		}
	}
}

func (b *BehavioralAnalysisEngine) updateAccessPatterns(profile *UserBehaviorProfile, data *BehaviorData) {
	profile.AccessPatterns.ResourcesAccessed[data.Resource]++
	profile.AccessPatterns.ActionsPerformed[data.Action]++
	profile.AccessPatterns.DataVolumeTransferred += data.DataTransferred

	if !data.Success {
		profile.AccessPatterns.ErrorRate =
			(profile.AccessPatterns.ErrorRate * 0.9) + 0.1 // Increase error rate
	} else {
		profile.AccessPatterns.ErrorRate =
			profile.AccessPatterns.ErrorRate * 0.95 // Decrease error rate
	}
}

func (b *BehavioralAnalysisEngine) updateLocationPatterns(profile *UserBehaviorProfile, data *BehaviorData) {
	loc := data.Location
	profile.LocationPatterns.Countries[loc.Country]++
	profile.LocationPatterns.Regions[loc.Region]++
	profile.LocationPatterns.Cities[loc.City]++
	profile.LocationPatterns.ISPs[loc.ISP]++

	// Check for unusual travel speed
	// This would require storing previous location and calculating distance/time
	// Simplified implementation here
	profile.LocationPatterns.LocationChanges++
}

func (b *BehavioralAnalysisEngine) updateDevicePatterns(profile *UserBehaviorProfile, data *BehaviorData) {
	device := data.Device
	profile.DevicePatterns.DevicesUsed[device.DeviceID]++
	profile.DevicePatterns.OperatingSystems[device.OS]++
	profile.DevicePatterns.Browsers[device.Browser]++
	profile.DevicePatterns.DeviceFingerprints[device.Fingerprint]++

	// Check for new device
	if profile.DevicePatterns.DevicesUsed[device.DeviceID] == 1 {
		profile.DevicePatterns.NewDeviceFrequency += 0.1
		profile.DevicePatterns.DeviceCount++
	}
}

func (b *BehavioralAnalysisEngine) updateBaseline(profile *UserBehaviorProfile) {
	if profile.Baseline == nil {
		profile.Baseline = NewBehaviorBaseline()
	}

	// Recalculate baseline based on recent behavior
	profile.Baseline.NormalRanges = make(map[string]*ValueRange)

	for feature, value := range profile.Features {
		// Create or update value range for this feature
		// This is a simplified implementation
		valueRange := &ValueRange{
			Min:    value * 0.5,
			Max:    value * 1.5,
			Mean:   value,
			StdDev: value * 0.2,
		}

		profile.Baseline.NormalRanges[feature] = valueRange
	}

	profile.Baseline.LastRecalculated = time.Now()
	profile.Baseline.Valid = true
}

func (b *BehavioralAnalysisEngine) calculateConfidenceScore(profile *UserBehaviorProfile, anomalies []AnomalyResult) float64 {
	// Calculate confidence based on data points and anomaly scores
	dataPoints := float64(profile.TotalSessions)
	if dataPoints < float64(b.config.MinDataPointsRequired) {
		return dataPoints / float64(b.config.MinDataPointsRequired)
	}

	// Reduce confidence based on recent anomalies
	confidence := 1.0
	for _, anomaly := range anomalies {
		confidence -= anomaly.AnomalyScore * 0.1
	}

	return math.Max(confidence, 0.0)
}

func (b *BehavioralAnalysisEngine) calculateSeverity(score float64) SeverityLevel {
	switch {
	case score >= 0.9:
		return SeverityLevelCritical
	case score >= 0.7:
		return SeverityLevelHigh
	case score >= 0.5:
		return SeverityLevelMedium
	default:
		return SeverityLevelLow
	}
}

func (b *BehavioralAnalysisEngine) recommendAction(score float64) string {
	switch {
	case score >= 0.9:
		return "Immediate security review and potential account suspension"
	case score >= 0.7:
		return "Enhanced monitoring and additional authentication"
	case score >= 0.5:
		return "Review user activity and verify identity"
	default:
		return "Continue monitoring"
	}
}

func (b *BehavioralAnalysisEngine) calculateRiskTrend(profile *UserBehaviorProfile) float64 {
	// Simplified risk trend calculation
	trend := 0.0

	if profile.ViolationCount > 0 {
		trend += float64(profile.ViolationCount) * 0.1
	}

	if profile.Suspicious {
		trend += 0.3
	}

	if !profile.LastAnomalyTime.IsZero() &&
		time.Since(profile.LastAnomalyTime) < 24*time.Hour {
		trend += 0.2
	}

	return math.Min(trend, 1.0)
}

func (b *BehavioralAnalysisEngine) generatePredictionID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (b *BehavioralAnalysisEngine) generateAlerts(result *AnalysisResult) {
	for _, anomaly := range result.Anomalies {
		if anomaly.Severity >= SeverityLevelHigh {
			alert := Alert{
				AlertID:   b.generateAlertID(),
				Type:      AlertTypeAnomaly,
				Severity:  anomaly.Severity,
				UserID:    result.UserID,
				Message:   anomaly.Explanation,
				Details:   map[string]interface{}{"anomaly_score": anomaly.AnomalyScore},
				Timestamp: time.Now(),
				Actions:   []string{anomaly.RecommendedAction},
			}

			b.alertManager.SendAlert(alert)
		}
	}

	if result.RiskScore > b.config.RiskThreshold {
		alert := Alert{
			AlertID:   b.generateAlertID(),
			Type:      AlertTypeRiskEscalation,
			Severity:  SeverityLevelHigh,
			UserID:    result.UserID,
			Message:   fmt.Sprintf("User risk score elevated: %.2f", result.RiskScore),
			Details:   map[string]interface{}{"risk_score": result.RiskScore},
			Timestamp: time.Now(),
			Actions:   []string{"Enhanced monitoring recommended"},
		}

		b.alertManager.SendAlert(alert)
	}
}

func (b *BehavioralAnalysisEngine) generateAlertID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (b *BehavioralAnalysisEngine) updateMetrics(result *AnalysisResult) {
	b.metrics.mutex.Lock()
	defer b.metrics.mutex.Unlock()

	b.metrics.TotalAnalyses++
	b.metrics.AnomaliesDetected += int64(len(result.Anomalies))
	b.metrics.PredictionsMade += int64(len(result.Predictions))

	// Update average processing time
	if b.metrics.TotalAnalyses == 1 {
		b.metrics.AverageProcessingTime = result.ProcessingTime
	} else {
		alpha := 0.1
		b.metrics.AverageProcessingTime =
			time.Duration(float64(b.metrics.AverageProcessingTime)*(1-alpha) +
				float64(result.ProcessingTime)*alpha)
	}
}

func (b *BehavioralAnalysisEngine) removeOldestProfile() {
	oldestTime := time.Now()
	oldestUserID := ""

	for userID, profile := range b.userProfiles {
		if !profile.Active && profile.LastUpdated.Before(oldestTime) {
			oldestTime = profile.LastUpdated
			oldestUserID = userID
		}
	}

	if oldestUserID != "" {
		delete(b.userProfiles, oldestUserID)
	}
}

// Background workers

func (b *BehavioralAnalysisEngine) analysisWorker() {
	ticker := time.NewTicker(b.config.AnalysisInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			b.performPeriodicAnalysis()
		case <-b.ctx.Done():
			return
		}
	}
}

func (b *BehavioralAnalysisEngine) profileMaintenanceWorker() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			b.cleanupExpiredProfiles()
		case <-b.ctx.Done():
			return
		}
	}
}

func (b *BehavioralAnalysisEngine) modelTrainingWorker() {
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			b.retrainModels()
		case <-b.ctx.Done():
			return
		}
	}
}

func (b *BehavioralAnalysisEngine) metricsWorker() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			b.updateSystemMetrics()
		case <-b.ctx.Done():
			return
		}
	}
}

func (b *BehavioralAnalysisEngine) predictionWorker() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			b.validatePredictions()
		case <-b.ctx.Done():
			return
		}
	}
}

func (b *BehavioralAnalysisEngine) performPeriodicAnalysis() {
	// Perform system-wide analysis
	b.lastAnalysis = time.Now()
	b.analysisCount++
}

func (b *BehavioralAnalysisEngine) cleanupExpiredProfiles() {
	b.profilesMutex.Lock()
	defer b.profilesMutex.Unlock()

	cutoff := time.Now().Add(-b.config.ProfileRetentionPeriod)

	for userID, profile := range b.userProfiles {
		if profile.LastUpdated.Before(cutoff) && !profile.Active {
			delete(b.userProfiles, userID)
		}
	}
}

func (b *BehavioralAnalysisEngine) retrainModels() {
	// Retrain ML models with recent data
	b.modelsMutex.Lock()
	defer b.modelsMutex.Unlock()

	for modelName := range b.mlModels {
		// Simplified model retraining
		b.metrics.MLModelsTraned++
	}
}

func (b *BehavioralAnalysisEngine) updateSystemMetrics() {
	// Update system-wide metrics
}

func (b *BehavioralAnalysisEngine) validatePredictions() {
	// Validate previous predictions against actual outcomes
	for _, profile := range b.userProfiles {
		for i := range profile.Predictions {
			prediction := &profile.Predictions[i]
			if !prediction.Validated &&
				time.Since(prediction.CreatedAt) > prediction.TimeHorizon {
				// Validate prediction (simplified)
				prediction.Validated = true
				prediction.Accuracy = 0.8 // Simplified accuracy calculation
			}
		}
	}
}

// Public API methods

func (b *BehavioralAnalysisEngine) GetUserProfile(userID string) *UserBehaviorProfile {
	return b.getUserProfile(userID)
}

func (b *BehavioralAnalysisEngine) GetMetrics() *AnalysisMetrics {
	b.metrics.mutex.RLock()
	defer b.metrics.mutex.RUnlock()

	// Return copy of metrics
	return &AnalysisMetrics{
		TotalAnalyses:         b.metrics.TotalAnalyses,
		AnomaliesDetected:     b.metrics.AnomaliesDetected,
		FalsePositives:        b.metrics.FalsePositives,
		TruePositives:         b.metrics.TruePositives,
		UserProfilesCreated:   b.metrics.UserProfilesCreated,
		MLModelsTraned:        b.metrics.MLModelsTraned,
		PredictionsMade:       b.metrics.PredictionsMade,
		PredictionAccuracy:    b.metrics.PredictionAccuracy,
		AverageProcessingTime: b.metrics.AverageProcessingTime,
		LastReset:             b.metrics.LastReset,
	}
}

func (b *BehavioralAnalysisEngine) GetActiveUserCount() int {
	b.profilesMutex.RLock()
	defer b.profilesMutex.RUnlock()

	count := 0
	for _, profile := range b.userProfiles {
		if profile.Active {
			count++
		}
	}

	return count
}

func (b *BehavioralAnalysisEngine) GetSuspiciousUsers() []string {
	b.profilesMutex.RLock()
	defer b.profilesMutex.RUnlock()

	suspicious := make([]string, 0)
	for userID, profile := range b.userProfiles {
		if profile.Suspicious {
			suspicious = append(suspicious, userID)
		}
	}

	return suspicious
}
