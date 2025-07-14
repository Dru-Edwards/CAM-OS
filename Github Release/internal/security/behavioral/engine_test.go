package behavioral

import (
	"fmt"
	"testing"
	"time"
)

func TestBehavioralAnalysisEngine_NewEngine(t *testing.T) {
	config := createTestAnalysisConfig()
	engine := NewBehavioralAnalysisEngine(config)

	if engine == nil {
		t.Fatal("Expected non-nil engine")
	}

	if engine.config != config {
		t.Error("Expected config to be set")
	}

	if engine.anomalyDetector == nil {
		t.Error("Expected anomaly detector to be initialized")
	}

	if engine.featureExtractor == nil {
		t.Error("Expected feature extractor to be initialized")
	}

	if engine.riskAssessor == nil {
		t.Error("Expected risk assessor to be initialized")
	}

	if engine.alertManager == nil {
		t.Error("Expected alert manager to be initialized")
	}

	if engine.systemProfile == nil {
		t.Error("Expected system profile to be initialized")
	}
}

func TestBehavioralAnalysisEngine_AnalyzeBehavior(t *testing.T) {
	config := createTestAnalysisConfig()
	engine := NewBehavioralAnalysisEngine(config)

	// Create test behavior data
	behaviorData := &BehaviorData{
		UserID:    "test_user_001",
		SessionID: "session_123",
		Timestamp: time.Now(),
		Action:    "login",
		Resource:  "/api/dashboard",
		IPAddress: "192.168.1.100",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
		Location: &LocationData{
			Country:   "United States",
			Region:    "California",
			City:      "San Francisco",
			Latitude:  37.7749,
			Longitude: -122.4194,
			ISP:       "Example ISP",
			Timezone:  "America/Los_Angeles",
		},
		Device: &DeviceData{
			DeviceID:    "device_001",
			Platform:    "windows",
			OS:          "Windows 10",
			Browser:     "Chrome",
			Resolution:  "1920x1080",
			Fingerprint: "fp_12345",
		},
		Duration:        30 * time.Minute,
		DataTransferred: 1024,
		Success:         true,
		Errors:          make([]string, 0),
		Metadata:        map[string]interface{}{"test": true},
	}

	// Analyze behavior
	result, err := engine.AnalyzeBehavior("test_user_001", behaviorData)
	if err != nil {
		t.Fatalf("Expected no error analyzing behavior: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil analysis result")
	}

	if result.UserID != "test_user_001" {
		t.Error("Expected user ID to match")
	}

	if result.Profile == nil {
		t.Error("Expected user profile in result")
	}

	if len(result.Features) == 0 {
		t.Error("Expected features to be extracted")
	}

	if result.RiskScore < 0 || result.RiskScore > 1 {
		t.Error("Expected risk score to be between 0 and 1")
	}

	if result.ConfidenceScore < 0 || result.ConfidenceScore > 1 {
		t.Error("Expected confidence score to be between 0 and 1")
	}

	if result.ProcessingTime <= 0 {
		t.Error("Expected positive processing time")
	}
}

func TestBehavioralAnalysisEngine_UserProfile(t *testing.T) {
	config := createTestAnalysisConfig()
	engine := NewBehavioralAnalysisEngine(config)

	userID := "test_user_profile"

	// Initially no profile should exist
	profile := engine.GetUserProfile(userID)
	if profile != nil {
		t.Error("Expected no initial profile")
	}

	// Create behavior data to trigger profile creation
	behaviorData := createTestBehaviorData(userID)

	// Analyze behavior to create profile
	result, err := engine.AnalyzeBehavior(userID, behaviorData)
	if err != nil {
		t.Fatalf("Failed to analyze behavior: %v", err)
	}

	// Profile should now exist
	profile = engine.GetUserProfile(userID)
	if profile == nil {
		t.Fatal("Expected profile to be created")
	}

	if profile.UserID != userID {
		t.Error("Expected user ID to match")
	}

	if profile.TotalSessions != 1 {
		t.Error("Expected total sessions to be 1")
	}

	if profile.LoginPatterns == nil {
		t.Error("Expected login patterns to be initialized")
	}

	if profile.SessionPatterns == nil {
		t.Error("Expected session patterns to be initialized")
	}

	if profile.AccessPatterns == nil {
		t.Error("Expected access patterns to be initialized")
	}

	if profile.LocationPatterns == nil {
		t.Error("Expected location patterns to be initialized")
	}

	if profile.DevicePatterns == nil {
		t.Error("Expected device patterns to be initialized")
	}

	// Verify profile is in analysis result
	if result.Profile != profile {
		t.Error("Expected same profile instance in result")
	}
}

func TestBehavioralAnalysisEngine_AnomalyDetection(t *testing.T) {
	config := createTestAnalysisConfig()
	engine := NewBehavioralAnalysisEngine(config)

	userID := "test_anomaly_user"

	// Create normal behavior pattern
	for i := 0; i < 10; i++ {
		normalData := createTestBehaviorData(userID)
		normalData.Timestamp = time.Now().Add(-time.Duration(i) * time.Hour)
		normalData.Action = "read"

		_, err := engine.AnalyzeBehavior(userID, normalData)
		if err != nil {
			t.Fatalf("Failed to analyze normal behavior: %v", err)
		}
	}

	// Create anomalous behavior
	anomalousData := createTestBehaviorData(userID)
	anomalousData.Timestamp = time.Date(2023, 1, 1, 3, 0, 0, 0, time.UTC) // 3 AM - unusual time
	anomalousData.Action = "delete"                                       // Sensitive action
	anomalousData.Location.Country = "Unknown"                            // Suspicious location
	anomalousData.DataTransferred = 1000000                               // Large data transfer

	result, err := engine.AnalyzeBehavior(userID, anomalousData)
	if err != nil {
		t.Fatalf("Failed to analyze anomalous behavior: %v", err)
	}

	// Should detect anomalies
	if len(result.Anomalies) == 0 {
		t.Error("Expected anomalies to be detected")
	}

	// Risk score should be elevated
	if result.RiskScore <= 0.5 {
		t.Error("Expected elevated risk score for anomalous behavior")
	}

	// Profile should be marked as suspicious
	profile := engine.GetUserProfile(userID)
	if profile != nil && profile.AnomalyScore <= 0.5 {
		t.Error("Expected elevated anomaly score in profile")
	}
}

func TestBehavioralAnalysisEngine_FeatureExtraction(t *testing.T) {
	extractor := NewFeatureExtractor()

	behaviorData := createTestBehaviorData("test_user")

	features, err := extractor.ExtractFeatures(behaviorData)
	if err != nil {
		t.Fatalf("Expected no error extracting features: %v", err)
	}

	if len(features) == 0 {
		t.Error("Expected features to be extracted")
	}

	// Check for specific features
	expectedFeatures := []string{
		"time_of_day",
		"day_of_week",
		"session_duration",
		"data_transferred",
		"success_rate",
		"location_entropy",
		"device_consistency",
	}

	for _, expectedFeature := range expectedFeatures {
		if _, exists := features[expectedFeature]; !exists {
			t.Errorf("Expected feature %s to be extracted", expectedFeature)
		}
	}

	// Verify feature values are reasonable
	if timeOfDay := features["time_of_day"]; timeOfDay < 0 || timeOfDay >= 24 {
		t.Error("Expected time_of_day to be between 0 and 23")
	}

	if dayOfWeek := features["day_of_week"]; dayOfWeek < 0 || dayOfWeek >= 7 {
		t.Error("Expected day_of_week to be between 0 and 6")
	}

	if successRate := features["success_rate"]; successRate != 1.0 {
		t.Error("Expected success_rate to be 1.0 for successful operation")
	}
}

func TestBehavioralAnalysisEngine_RiskAssessment(t *testing.T) {
	assessor := NewRiskAssessor()

	// Create low-risk profile
	lowRiskProfile := &UserBehaviorProfile{
		UserID:         "low_risk_user",
		AnomalyScore:   0.1,
		ViolationCount: 0,
		Suspicious:     false,
		RiskScore:      0.0,
	}

	lowRiskAnomalies := []AnomalyResult{}

	lowRisk := assessor.AssessRisk(lowRiskProfile, lowRiskAnomalies)
	if lowRisk > 0.5 {
		t.Error("Expected low risk score for clean profile")
	}

	// Create high-risk profile
	highRiskProfile := &UserBehaviorProfile{
		UserID:          "high_risk_user",
		AnomalyScore:    0.8,
		ViolationCount:  5,
		Suspicious:      true,
		LastAnomalyTime: time.Now().Add(-time.Hour),
		RiskScore:       0.0,
	}

	highRiskAnomalies := []AnomalyResult{
		{
			AnomalyScore: 0.9,
			Severity:     SeverityLevelHigh,
		},
	}

	highRisk := assessor.AssessRisk(highRiskProfile, highRiskAnomalies)
	if highRisk <= 0.5 {
		t.Error("Expected high risk score for suspicious profile")
	}

	if highRisk <= lowRisk {
		t.Error("Expected high-risk profile to have higher risk than low-risk profile")
	}
}

func TestBehavioralAnalysisEngine_Predictions(t *testing.T) {
	config := createTestAnalysisConfig()
	engine := NewBehavioralAnalysisEngine(config)

	userID := "test_prediction_user"

	// Create consistent behavior pattern
	for hour := 9; hour <= 17; hour++ {
		behaviorData := createTestBehaviorData(userID)
		behaviorData.Timestamp = time.Date(2023, 1, 1, hour, 0, 0, 0, time.UTC)
		behaviorData.Duration = 2 * time.Hour

		_, err := engine.AnalyzeBehavior(userID, behaviorData)
		if err != nil {
			t.Fatalf("Failed to analyze behavior: %v", err)
		}
	}

	// Get updated profile
	profile := engine.GetUserProfile(userID)
	if profile == nil {
		t.Fatal("Expected profile to exist")
	}

	// Check if predictions were generated
	if len(profile.Predictions) == 0 {
		t.Error("Expected predictions to be generated")
	}

	// Verify prediction types
	predictionTypes := make(map[PredictionType]bool)
	for _, prediction := range profile.Predictions {
		predictionTypes[prediction.Type] = true

		if prediction.Confidence < 0 || prediction.Confidence > 1 {
			t.Error("Expected prediction confidence to be between 0 and 1")
		}

		if prediction.TimeHorizon <= 0 {
			t.Error("Expected positive time horizon for prediction")
		}
	}

	// Should have login time prediction
	if !predictionTypes[PredictionTypeLoginTime] {
		t.Error("Expected login time prediction")
	}
}

func TestBehavioralAnalysisEngine_StartStop(t *testing.T) {
	config := createTestAnalysisConfig()
	engine := NewBehavioralAnalysisEngine(config)

	err := engine.Start()
	if err != nil {
		t.Fatalf("Expected no error starting engine: %v", err)
	}

	// Give background workers time to start
	time.Sleep(100 * time.Millisecond)

	err = engine.Stop()
	if err != nil {
		t.Fatalf("Expected no error stopping engine: %v", err)
	}
}

func TestBehavioralAnalysisEngine_Metrics(t *testing.T) {
	config := createTestAnalysisConfig()
	engine := NewBehavioralAnalysisEngine(config)

	// Initial metrics should be zero
	metrics := engine.GetMetrics()
	if metrics.TotalAnalyses != 0 {
		t.Error("Expected initial total analyses to be 0")
	}

	// Perform analysis
	behaviorData := createTestBehaviorData("metrics_user")
	_, err := engine.AnalyzeBehavior("metrics_user", behaviorData)
	if err != nil {
		t.Fatalf("Failed to analyze behavior: %v", err)
	}

	// Check updated metrics
	metrics = engine.GetMetrics()
	if metrics.TotalAnalyses != 1 {
		t.Error("Expected total analyses to be 1")
	}

	if metrics.UserProfilesCreated != 1 {
		t.Error("Expected user profiles created to be 1")
	}

	if metrics.AverageProcessingTime <= 0 {
		t.Error("Expected positive average processing time")
	}
}

func TestBehavioralAnalysisEngine_AlertManager(t *testing.T) {
	alertManager := NewAlertManager()

	// Create test alert
	alert := Alert{
		AlertID:   "test_alert_001",
		Type:      AlertTypeAnomaly,
		Severity:  SeverityLevelHigh,
		UserID:    "test_user",
		Message:   "Test anomaly detected",
		Timestamp: time.Now(),
	}

	// Send alert
	err := alertManager.SendAlert(alert)
	if err != nil {
		t.Fatalf("Expected no error sending alert: %v", err)
	}

	// Get recent alerts
	recentAlerts := alertManager.GetRecentAlerts(10)
	if len(recentAlerts) != 1 {
		t.Error("Expected 1 recent alert")
	}

	if recentAlerts[0].AlertID != alert.AlertID {
		t.Error("Expected alert ID to match")
	}

	// Test cooldown period
	err = alertManager.SendAlert(alert)
	if err != nil {
		t.Fatalf("Expected no error sending duplicate alert: %v", err)
	}

	// Should still only have 1 alert due to cooldown
	recentAlerts = alertManager.GetRecentAlerts(10)
	if len(recentAlerts) != 1 {
		t.Error("Expected alert cooldown to prevent duplicate")
	}
}

func TestBehavioralAnalysisEngine_AnomalyAlgorithms(t *testing.T) {
	// Test statistical detector
	statDetector := &StatisticalDetector{}

	// Create training data
	trainingData := make([]DataPoint, 100)
	for i := range trainingData {
		trainingData[i] = DataPoint{
			Features: map[string]float64{
				"feature1": float64(i%10) + 1.0,
				"feature2": float64(i%5) + 0.5,
			},
		}
	}

	err := statDetector.Train(trainingData)
	if err != nil {
		t.Fatalf("Expected no error training statistical detector: %v", err)
	}

	// Test normal data point
	normalPoint := DataPoint{
		Features: map[string]float64{
			"feature1": 5.0,
			"feature2": 2.5,
		},
	}

	normalScore, err := statDetector.Detect(normalPoint)
	if err != nil {
		t.Fatalf("Expected no error detecting normal point: %v", err)
	}

	// Test anomalous data point
	anomalousPoint := DataPoint{
		Features: map[string]float64{
			"feature1": 100.0, // Very different from training data
			"feature2": 50.0,
		},
	}

	anomalousScore, err := statDetector.Detect(anomalousPoint)
	if err != nil {
		t.Fatalf("Expected no error detecting anomalous point: %v", err)
	}

	if anomalousScore <= normalScore {
		t.Error("Expected anomalous point to have higher score than normal point")
	}

	// Test isolation forest
	isoForest := &IsolationForest{}

	err = isoForest.Train(trainingData)
	if err != nil {
		t.Fatalf("Expected no error training isolation forest: %v", err)
	}

	isoScore, err := isoForest.Detect(anomalousPoint)
	if err != nil {
		t.Fatalf("Expected no error detecting with isolation forest: %v", err)
	}

	if isoScore < 0 || isoScore > 1 {
		t.Error("Expected isolation forest score to be between 0 and 1")
	}
}

func TestBehavioralAnalysisEngine_ConcurrentAnalysis(t *testing.T) {
	config := createTestAnalysisConfig()
	engine := NewBehavioralAnalysisEngine(config)

	// Test concurrent analysis
	const numGoroutines = 10
	const analysesPerGoroutine = 5

	resultChan := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			for j := 0; j < analysesPerGoroutine; j++ {
				userID := fmt.Sprintf("concurrent_user_%d_%d", goroutineID, j)
				behaviorData := createTestBehaviorData(userID)

				_, err := engine.AnalyzeBehavior(userID, behaviorData)
				if err != nil {
					resultChan <- err
					return
				}
			}
			resultChan <- nil
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		err := <-resultChan
		if err != nil {
			t.Fatalf("Concurrent analysis failed: %v", err)
		}
	}

	// Verify metrics
	metrics := engine.GetMetrics()
	expectedAnalyses := int64(numGoroutines * analysesPerGoroutine)
	if metrics.TotalAnalyses != expectedAnalyses {
		t.Errorf("Expected %d total analyses, got %d", expectedAnalyses, metrics.TotalAnalyses)
	}

	// Verify user profiles were created
	activeUserCount := engine.GetActiveUserCount()
	if activeUserCount != numGoroutines*analysesPerGoroutine {
		t.Errorf("Expected %d active users, got %d", numGoroutines*analysesPerGoroutine, activeUserCount)
	}
}

func BenchmarkBehavioralAnalysisEngine_AnalyzeBehavior(b *testing.B) {
	config := createTestAnalysisConfig()
	engine := NewBehavioralAnalysisEngine(config)

	behaviorData := createTestBehaviorData("benchmark_user")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		userCounter := 0
		for pb.Next() {
			userID := fmt.Sprintf("benchmark_user_%d", userCounter)
			_, err := engine.AnalyzeBehavior(userID, behaviorData)
			if err != nil {
				b.Fatalf("Analysis failed: %v", err)
			}
			userCounter++
		}
	})
}

func BenchmarkFeatureExtractor_ExtractFeatures(b *testing.B) {
	extractor := NewFeatureExtractor()
	behaviorData := createTestBehaviorData("benchmark_user")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := extractor.ExtractFeatures(behaviorData)
			if err != nil {
				b.Fatalf("Feature extraction failed: %v", err)
			}
		}
	})
}

func BenchmarkAnomalyDetector_DetectEnsemble(b *testing.B) {
	detector := NewAnomalyDetector()

	dataPoint := DataPoint{
		Features: map[string]float64{
			"feature1": 1.0,
			"feature2": 2.0,
			"feature3": 3.0,
		},
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := detector.DetectEnsemble(dataPoint)
			if err != nil {
				b.Fatalf("Anomaly detection failed: %v", err)
			}
		}
	})
}

// Helper functions

func createTestAnalysisConfig() *AnalysisConfig {
	return &AnalysisConfig{
		EnableUserAnalysis:       true,
		EnableSystemAnalysis:     true,
		EnableAnomalyDetection:   true,
		EnableRiskAssessment:     true,
		EnableRealTimeAlerts:     true,
		LearningPeriod:           24 * time.Hour,
		AnalysisInterval:         time.Minute,
		AnomalyThreshold:         0.7,
		RiskThreshold:            0.8,
		MaxUserProfiles:          1000,
		ProfileRetentionPeriod:   30 * 24 * time.Hour,
		MLModelType:              "ensemble",
		FeatureWindowSize:        50,
		MinDataPointsRequired:    10,
		AlertCooldownPeriod:      time.Hour,
		EnablePredictiveAnalysis: true,
		EnableBehaviorBaseline:   true,
	}
}

func createTestBehaviorData(userID string) *BehaviorData {
	return &BehaviorData{
		UserID:    userID,
		SessionID: "session_" + userID,
		Timestamp: time.Now(),
		Action:    "read",
		Resource:  "/api/data",
		IPAddress: "192.168.1.100",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		Location: &LocationData{
			Country:   "United States",
			Region:    "California",
			City:      "San Francisco",
			Latitude:  37.7749,
			Longitude: -122.4194,
			ISP:       "Example ISP",
			Timezone:  "America/Los_Angeles",
		},
		Device: &DeviceData{
			DeviceID:    "device_" + userID,
			Platform:    "windows",
			OS:          "Windows 10",
			Browser:     "Chrome",
			Resolution:  "1920x1080",
			Fingerprint: "fp_" + userID,
		},
		Duration:        time.Hour,
		DataTransferred: 1024,
		Success:         true,
		Errors:          make([]string, 0),
		Metadata:        map[string]interface{}{"test": true},
	}
}
