package zerotrust

import (
	"testing"
	"time"
)

func TestZeroTrustEngine_NewEngine(t *testing.T) {
	config := &Config{
		Enabled:               true,
		DefaultTrustLevel:     TrustLevelMedium,
		DefaultSecurityZone:   ZonePrivate,
		SessionTimeout:        30 * time.Minute,
		RiskThreshold:         0.7,
		ContinuousAuth:        true,
		DeviceVerification:    true,
		GeolocationEnabled:    true,
		BehaviorAnalysis:      true,
		NetworkSegmentation:   true,
		EncryptionRequired:    true,
		CertificateValidation: true,
		AuditLogging:          true,
		MaxSessions:           1000,
		MaxEntities:           5000,
		PolicyUpdateInterval:  time.Hour,
		RiskUpdateInterval:    15 * time.Minute,
	}

	engine := NewZeroTrustEngine(config)

	if engine == nil {
		t.Fatal("Expected non-nil engine")
	}

	if engine.config != config {
		t.Error("Expected config to be set")
	}

	if len(engine.policies) == 0 {
		t.Error("Expected default policies to be initialized")
	}

	if len(engine.networkZones) == 0 {
		t.Error("Expected default network zones to be initialized")
	}

	if engine.riskEngine == nil {
		t.Error("Expected risk engine to be initialized")
	}
}

func TestZeroTrustEngine_StartStop(t *testing.T) {
	config := &Config{
		Enabled:               true,
		DefaultTrustLevel:     TrustLevelMedium,
		DefaultSecurityZone:   ZonePrivate,
		SessionTimeout:        30 * time.Minute,
		RiskThreshold:         0.7,
		ContinuousAuth:        false,
		DeviceVerification:    true,
		GeolocationEnabled:    true,
		BehaviorAnalysis:      false,
		NetworkSegmentation:   true,
		EncryptionRequired:    true,
		CertificateValidation: true,
		AuditLogging:          true,
		MaxSessions:           1000,
		MaxEntities:           5000,
		PolicyUpdateInterval:  time.Hour,
		RiskUpdateInterval:    15 * time.Minute,
	}

	engine := NewZeroTrustEngine(config)

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

func TestZeroTrustEngine_RegisterEntity(t *testing.T) {
	config := createTestConfig()
	engine := NewZeroTrustEngine(config)

	entity := &Entity{
		ID:           "test_user_001",
		Type:         EntityTypeUser,
		Name:         "Test User",
		IPAddress:    "192.168.1.100",
		UserID:       "user123",
		TrustLevel:   TrustLevelMedium,
		SecurityZone: ZonePrivate,
		Attributes:   map[string]string{"department": "engineering"},
	}

	err := engine.RegisterEntity(entity)
	if err != nil {
		t.Fatalf("Expected no error registering entity: %v", err)
	}

	// Verify entity was registered
	registeredEntity, exists := engine.getEntity("test_user_001")
	if !exists {
		t.Error("Expected entity to be registered")
	}

	if registeredEntity.ID != "test_user_001" {
		t.Error("Expected entity ID to match")
	}

	if registeredEntity.RiskScore <= 0 {
		t.Error("Expected risk score to be calculated")
	}

	if engine.metrics.EntitiesRegistered != 1 {
		t.Error("Expected entities registered metric to be incremented")
	}
}

func TestZeroTrustEngine_EvaluateAccess_Allow(t *testing.T) {
	config := createTestConfig()
	engine := NewZeroTrustEngine(config)

	// Register entity
	entity := &Entity{
		ID:           "test_user_001",
		Type:         EntityTypeUser,
		Name:         "Test User",
		IPAddress:    "10.10.1.100",
		UserID:       "user123",
		TrustLevel:   TrustLevelHigh,
		SecurityZone: ZoneSecure,
		Attributes:   map[string]string{"department": "engineering"},
	}

	err := engine.RegisterEntity(entity)
	if err != nil {
		t.Fatalf("Failed to register entity: %v", err)
	}

	// Create access request
	request := &AccessRequest{
		ID:          "req_001",
		RequestorID: "test_user_001",
		ResourceID:  "secure_resource",
		Action:      "read",
		Timestamp:   time.Now(),
		IPAddress:   "10.10.1.100",
		UserAgent:   "TestClient/1.0",
		Context:     map[string]interface{}{"session_id": "sess_123"},
	}

	decision, err := engine.EvaluateAccess(request)
	if err != nil {
		t.Fatalf("Expected no error evaluating access: %v", err)
	}

	if decision.Decision != PolicyActionAllow {
		t.Errorf("Expected PolicyActionAllow, got %v", decision.Decision)
	}

	if decision.TrustLevel != TrustLevelHigh {
		t.Error("Expected trust level to match entity")
	}

	if decision.SecurityZone != ZoneSecure {
		t.Error("Expected security zone to match entity")
	}
}

func TestZeroTrustEngine_EvaluateAccess_Deny(t *testing.T) {
	config := createTestConfig()
	engine := NewZeroTrustEngine(config)

	// Register low-trust entity
	entity := &Entity{
		ID:           "test_user_002",
		Type:         EntityTypeUser,
		Name:         "Untrusted User",
		IPAddress:    "192.168.1.200",
		UserID:       "user456",
		TrustLevel:   TrustLevelLow,
		SecurityZone: ZonePublic,
		Attributes:   map[string]string{"department": "guest"},
	}

	err := engine.RegisterEntity(entity)
	if err != nil {
		t.Fatalf("Failed to register entity: %v", err)
	}

	// Create access request for sensitive resource
	request := &AccessRequest{
		ID:          "req_002",
		RequestorID: "test_user_002",
		ResourceID:  "admin_panel",
		Action:      "admin",
		Timestamp:   time.Now(),
		IPAddress:   "192.168.1.200",
		UserAgent:   "TestClient/1.0",
		Context:     map[string]interface{}{"session_id": "sess_456"},
	}

	decision, err := engine.EvaluateAccess(request)
	if err != nil {
		t.Fatalf("Expected no error evaluating access: %v", err)
	}

	if decision.Decision != PolicyActionDeny {
		t.Errorf("Expected PolicyActionDeny, got %v", decision.Decision)
	}

	if decision.Reason == "" {
		t.Error("Expected denial reason to be provided")
	}
}

func TestZeroTrustEngine_EvaluateAccess_Challenge(t *testing.T) {
	config := createTestConfig()
	config.RiskThreshold = 0.5 // Lower threshold for testing
	engine := NewZeroTrustEngine(config)

	// Register entity
	entity := &Entity{
		ID:           "test_user_003",
		Type:         EntityTypeUser,
		Name:         "Test User",
		IPAddress:    "192.168.1.150",
		UserID:       "user789",
		TrustLevel:   TrustLevelMedium,
		SecurityZone: ZonePrivate,
		Attributes:   map[string]string{"department": "finance"},
	}

	err := engine.RegisterEntity(entity)
	if err != nil {
		t.Fatalf("Failed to register entity: %v", err)
	}

	// Create high-risk access request
	request := &AccessRequest{
		ID:          "req_003",
		RequestorID: "test_user_003",
		ResourceID:  "financial_data",
		Action:      "delete",
		Timestamp:   time.Date(2023, 1, 1, 3, 0, 0, 0, time.UTC), // 3 AM - suspicious time
		IPAddress:   "192.168.1.150",
		UserAgent:   "TestClient/1.0",
		Context:     map[string]interface{}{"session_id": "sess_789"},
		Geolocation: &GeolocationData{
			Country:    "Unknown",
			Suspicious: true,
		},
	}

	decision, err := engine.EvaluateAccess(request)
	if err != nil {
		t.Fatalf("Expected no error evaluating access: %v", err)
	}

	if decision.Decision != PolicyActionChallenge {
		t.Errorf("Expected PolicyActionChallenge, got %v", decision.Decision)
	}

	if decision.RiskScore <= 0.5 {
		t.Error("Expected high risk score for suspicious request")
	}
}

func TestZeroTrustEngine_CreateSession(t *testing.T) {
	config := createTestConfig()
	engine := NewZeroTrustEngine(config)

	// Register entity
	entity := &Entity{
		ID:           "test_user_001",
		Type:         EntityTypeUser,
		Name:         "Test User",
		IPAddress:    "192.168.1.100",
		UserID:       "user123",
		TrustLevel:   TrustLevelMedium,
		SecurityZone: ZonePrivate,
		Attributes:   map[string]string{"department": "engineering"},
	}

	err := engine.RegisterEntity(entity)
	if err != nil {
		t.Fatalf("Failed to register entity: %v", err)
	}

	// Create session
	authData := map[string]interface{}{
		"ip_address": "192.168.1.100",
		"user_agent": "TestClient/1.0",
	}

	session, err := engine.CreateSession("test_user_001", authData)
	if err != nil {
		t.Fatalf("Expected no error creating session: %v", err)
	}

	if session.ID == "" {
		t.Error("Expected session ID to be generated")
	}

	if session.EntityID != "test_user_001" {
		t.Error("Expected entity ID to match")
	}

	if session.TrustLevel != TrustLevelMedium {
		t.Error("Expected trust level to match entity")
	}

	if !session.Verified {
		t.Error("Expected session to be verified")
	}

	if engine.metrics.ActiveSessions != 1 {
		t.Error("Expected active sessions metric to be incremented")
	}
}

func TestZeroTrustEngine_NetworkSegmentation(t *testing.T) {
	config := createTestConfig()
	engine := NewZeroTrustEngine(config)

	testCases := []struct {
		name     string
		sourceIP string
		destIP   string
		port     int
		expected bool
		reason   string
	}{
		{
			name:     "Public to Public",
			sourceIP: "203.0.113.1",
			destIP:   "203.0.113.2",
			port:     80,
			expected: true,
			reason:   "Public zone communication should be allowed",
		},
		{
			name:     "Private to Private",
			sourceIP: "192.168.1.1",
			destIP:   "192.168.1.2",
			port:     22,
			expected: true,
			reason:   "Private zone internal communication should be allowed",
		},
		{
			name:     "Public to Private",
			sourceIP: "203.0.113.1",
			destIP:   "192.168.1.1",
			port:     22,
			expected: false,
			reason:   "Public to private communication should be denied",
		},
		{
			name:     "Secure to Secure",
			sourceIP: "10.10.1.1",
			destIP:   "10.10.1.2",
			port:     443,
			expected: true,
			reason:   "Secure zone internal communication should be allowed",
		},
		{
			name:     "Private to Secure",
			sourceIP: "192.168.1.1",
			destIP:   "10.10.1.1",
			port:     443,
			expected: false,
			reason:   "Private to secure communication should be denied",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			decision, err := engine.VerifyNetworkSegmentation(tc.sourceIP, tc.destIP, tc.port)
			if err != nil {
				t.Fatalf("Expected no error: %v", err)
			}

			if decision.Allowed != tc.expected {
				t.Errorf("Expected allowed=%v, got allowed=%v. Reason: %s", tc.expected, decision.Allowed, tc.reason)
			}

			if decision.Reason == "" {
				t.Error("Expected reason to be provided")
			}
		})
	}
}

func TestZeroTrustEngine_RiskAssessment(t *testing.T) {
	config := createTestConfig()
	engine := NewZeroTrustEngine(config)

	testCases := []struct {
		name         string
		entity       *Entity
		request      *AccessRequest
		expectedRisk float64
	}{
		{
			name: "Low Risk User",
			entity: &Entity{
				ID:           "low_risk_user",
				Type:         EntityTypeUser,
				TrustLevel:   TrustLevelHigh,
				SecurityZone: ZoneSecure,
			},
			request: &AccessRequest{
				Action:    "read",
				Timestamp: time.Now(),
			},
			expectedRisk: 0.3,
		},
		{
			name: "High Risk User",
			entity: &Entity{
				ID:           "high_risk_user",
				Type:         EntityTypeUser,
				TrustLevel:   TrustLevelLow,
				SecurityZone: ZonePublic,
			},
			request: &AccessRequest{
				Action:    "delete",
				Timestamp: time.Date(2023, 1, 1, 2, 0, 0, 0, time.UTC), // 2 AM
				Geolocation: &GeolocationData{
					Country:    "Unknown",
					Suspicious: true,
				},
			},
			expectedRisk: 0.8,
		},
		{
			name: "Medium Risk Service",
			entity: &Entity{
				ID:           "medium_risk_service",
				Type:         EntityTypeService,
				TrustLevel:   TrustLevelMedium,
				SecurityZone: ZonePrivate,
			},
			request: &AccessRequest{
				Action:    "write",
				Timestamp: time.Now(),
			},
			expectedRisk: 0.5,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := engine.RegisterEntity(tc.entity)
			if err != nil {
				t.Fatalf("Failed to register entity: %v", err)
			}

			tc.request.RequestorID = tc.entity.ID
			tc.request.ID = "test_request"
			tc.request.ResourceID = "test_resource"

			actualRisk := engine.assessAccessRisk(tc.request, tc.entity)

			if actualRisk < tc.expectedRisk-0.2 || actualRisk > tc.expectedRisk+0.2 {
				t.Errorf("Expected risk around %f, got %f", tc.expectedRisk, actualRisk)
			}
		})
	}
}

func TestZeroTrustEngine_PolicyMatching(t *testing.T) {
	config := createTestConfig()
	engine := NewZeroTrustEngine(config)

	// Add custom policy
	customPolicy := &Policy{
		ID:          "custom_policy",
		Name:        "Engineering Access",
		Description: "Allow engineering team access to development resources",
		Zone:        ZonePrivate,
		Subjects:    []string{"eng_*"},
		Resources:   []string{"dev_*"},
		Actions:     []string{"read", "write"},
		Conditions: []Condition{
			{
				Type:     ConditionTypeTime,
				Operator: "hour_between",
				Value:    []int{9, 17}, // 9 AM to 5 PM
			},
		},
		Effect:    PolicyActionAllow,
		Priority:  50,
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	engine.policies["custom_policy"] = customPolicy

	// Register entity
	entity := &Entity{
		ID:           "eng_user_001",
		Type:         EntityTypeUser,
		Name:         "Engineering User",
		IPAddress:    "192.168.1.100",
		UserID:       "eng123",
		TrustLevel:   TrustLevelMedium,
		SecurityZone: ZonePrivate,
		Attributes:   map[string]string{"department": "engineering"},
	}

	err := engine.RegisterEntity(entity)
	if err != nil {
		t.Fatalf("Failed to register entity: %v", err)
	}

	// Test policy matching during business hours
	request := &AccessRequest{
		ID:          "policy_test",
		RequestorID: "eng_user_001",
		ResourceID:  "dev_server",
		Action:      "read",
		Timestamp:   time.Date(2023, 1, 1, 14, 0, 0, 0, time.UTC), // 2 PM
		IPAddress:   "192.168.1.100",
		UserAgent:   "TestClient/1.0",
		Context:     map[string]interface{}{"session_id": "sess_123"},
	}

	decision, err := engine.EvaluateAccess(request)
	if err != nil {
		t.Fatalf("Expected no error evaluating access: %v", err)
	}

	if decision.Decision != PolicyActionAllow {
		t.Errorf("Expected PolicyActionAllow during business hours, got %v", decision.Decision)
	}

	// Test policy matching outside business hours
	request.Timestamp = time.Date(2023, 1, 1, 22, 0, 0, 0, time.UTC) // 10 PM

	decision, err = engine.EvaluateAccess(request)
	if err != nil {
		t.Fatalf("Expected no error evaluating access: %v", err)
	}

	if decision.Decision != PolicyActionDeny {
		t.Errorf("Expected PolicyActionDeny outside business hours, got %v", decision.Decision)
	}
}

func TestZeroTrustEngine_SessionCleanup(t *testing.T) {
	config := createTestConfig()
	config.SessionTimeout = 100 * time.Millisecond // Very short timeout for testing
	engine := NewZeroTrustEngine(config)

	// Register entity
	entity := &Entity{
		ID:           "test_user_001",
		Type:         EntityTypeUser,
		Name:         "Test User",
		IPAddress:    "192.168.1.100",
		UserID:       "user123",
		TrustLevel:   TrustLevelMedium,
		SecurityZone: ZonePrivate,
		Attributes:   map[string]string{"department": "engineering"},
	}

	err := engine.RegisterEntity(entity)
	if err != nil {
		t.Fatalf("Failed to register entity: %v", err)
	}

	// Create session
	authData := map[string]interface{}{
		"ip_address": "192.168.1.100",
		"user_agent": "TestClient/1.0",
	}

	session, err := engine.CreateSession("test_user_001", authData)
	if err != nil {
		t.Fatalf("Expected no error creating session: %v", err)
	}

	// Check session exists
	if len(engine.sessions) != 1 {
		t.Error("Expected session to be created")
	}

	// Wait for session to expire
	time.Sleep(200 * time.Millisecond)

	// Manually trigger cleanup
	engine.cleanupExpiredSessions()

	// Check session was cleaned up
	if len(engine.sessions) != 0 {
		t.Error("Expected expired session to be cleaned up")
	}

	// Check that session ID is no longer valid
	if _, exists := engine.sessions[session.ID]; exists {
		t.Error("Expected session to be removed")
	}
}

func TestZeroTrustEngine_GeolocationRisk(t *testing.T) {
	config := createTestConfig()
	engine := NewZeroTrustEngine(config)

	// Register entity
	entity := &Entity{
		ID:           "test_user_001",
		Type:         EntityTypeUser,
		Name:         "Test User",
		IPAddress:    "192.168.1.100",
		UserID:       "user123",
		TrustLevel:   TrustLevelMedium,
		SecurityZone: ZonePrivate,
		Attributes:   map[string]string{"department": "engineering"},
	}

	err := engine.RegisterEntity(entity)
	if err != nil {
		t.Fatalf("Failed to register entity: %v", err)
	}

	// Test normal geolocation
	normalRequest := &AccessRequest{
		ID:          "geo_test_1",
		RequestorID: "test_user_001",
		ResourceID:  "test_resource",
		Action:      "read",
		Timestamp:   time.Now(),
		IPAddress:   "192.168.1.100",
		UserAgent:   "TestClient/1.0",
		Context:     map[string]interface{}{"session_id": "sess_123"},
		Geolocation: &GeolocationData{
			Country:    "United States",
			Region:     "California",
			City:       "San Francisco",
			Latitude:   37.7749,
			Longitude:  -122.4194,
			ISP:        "Example ISP",
			Timezone:   "America/Los_Angeles",
			Suspicious: false,
		},
	}

	normalRisk := engine.assessAccessRisk(normalRequest, entity)

	// Test suspicious geolocation
	suspiciousRequest := &AccessRequest{
		ID:          "geo_test_2",
		RequestorID: "test_user_001",
		ResourceID:  "test_resource",
		Action:      "read",
		Timestamp:   time.Now(),
		IPAddress:   "192.168.1.100",
		UserAgent:   "TestClient/1.0",
		Context:     map[string]interface{}{"session_id": "sess_123"},
		Geolocation: &GeolocationData{
			Country:    "Unknown",
			Region:     "Unknown",
			City:       "Unknown",
			Latitude:   0,
			Longitude:  0,
			ISP:        "Suspicious ISP",
			Timezone:   "Unknown",
			Suspicious: true,
		},
	}

	suspiciousRisk := engine.assessAccessRisk(suspiciousRequest, entity)

	if suspiciousRisk <= normalRisk {
		t.Error("Expected suspicious geolocation to increase risk score")
	}

	if suspiciousRisk-normalRisk < 0.25 {
		t.Error("Expected significant risk increase for suspicious geolocation")
	}
}

func TestZeroTrustEngine_Metrics(t *testing.T) {
	config := createTestConfig()
	engine := NewZeroTrustEngine(config)

	// Register entity
	entity := &Entity{
		ID:           "test_user_001",
		Type:         EntityTypeUser,
		Name:         "Test User",
		IPAddress:    "192.168.1.100",
		UserID:       "user123",
		TrustLevel:   TrustLevelMedium,
		SecurityZone: ZonePrivate,
		Attributes:   map[string]string{"department": "engineering"},
	}

	err := engine.RegisterEntity(entity)
	if err != nil {
		t.Fatalf("Failed to register entity: %v", err)
	}

	// Create session
	authData := map[string]interface{}{
		"ip_address": "192.168.1.100",
		"user_agent": "TestClient/1.0",
	}

	_, err = engine.CreateSession("test_user_001", authData)
	if err != nil {
		t.Fatalf("Expected no error creating session: %v", err)
	}

	// Make access request
	request := &AccessRequest{
		ID:          "metrics_test",
		RequestorID: "test_user_001",
		ResourceID:  "test_resource",
		Action:      "read",
		Timestamp:   time.Now(),
		IPAddress:   "192.168.1.100",
		UserAgent:   "TestClient/1.0",
		Context:     map[string]interface{}{"session_id": "sess_123"},
	}

	_, err = engine.EvaluateAccess(request)
	if err != nil {
		t.Fatalf("Expected no error evaluating access: %v", err)
	}

	// Check metrics
	metrics := engine.GetMetrics()

	if metrics.EntitiesRegistered != 1 {
		t.Error("Expected entities registered metric to be 1")
	}

	if metrics.ActiveSessions != 1 {
		t.Error("Expected active sessions metric to be 1")
	}

	if metrics.AccessRequests != 1 {
		t.Error("Expected access requests metric to be 1")
	}

	if metrics.PoliciesEvaluated != 1 {
		t.Error("Expected policies evaluated metric to be 1")
	}

	if metrics.RiskAssessments != 1 {
		t.Error("Expected risk assessments metric to be 1")
	}
}

func TestZeroTrustEngine_AuditLogging(t *testing.T) {
	config := createTestConfig()
	engine := NewZeroTrustEngine(config)

	// Register entity
	entity := &Entity{
		ID:           "test_user_001",
		Type:         EntityTypeUser,
		Name:         "Test User",
		IPAddress:    "192.168.1.100",
		UserID:       "user123",
		TrustLevel:   TrustLevelMedium,
		SecurityZone: ZonePrivate,
		Attributes:   map[string]string{"department": "engineering"},
	}

	err := engine.RegisterEntity(entity)
	if err != nil {
		t.Fatalf("Failed to register entity: %v", err)
	}

	// Make access request
	request := &AccessRequest{
		ID:          "audit_test",
		RequestorID: "test_user_001",
		ResourceID:  "test_resource",
		Action:      "read",
		Timestamp:   time.Now(),
		IPAddress:   "192.168.1.100",
		UserAgent:   "TestClient/1.0",
		Context:     map[string]interface{}{"session_id": "sess_123"},
	}

	_, err = engine.EvaluateAccess(request)
	if err != nil {
		t.Fatalf("Expected no error evaluating access: %v", err)
	}

	// Check audit events
	auditEvents := engine.GetAuditEvents(10)

	if len(auditEvents) < 2 {
		t.Error("Expected at least 2 audit events (registration and access)")
	}

	// Check entity registration event
	foundRegistration := false
	foundAccess := false

	for _, event := range auditEvents {
		if event.EventType == "entity_registration" {
			foundRegistration = true
			if event.EntityID != "test_user_001" {
				t.Error("Expected entity ID in registration event")
			}
		}
		if event.EventType == "access_evaluation" {
			foundAccess = true
			if event.EntityID != "test_user_001" {
				t.Error("Expected entity ID in access event")
			}
		}
	}

	if !foundRegistration {
		t.Error("Expected entity registration audit event")
	}

	if !foundAccess {
		t.Error("Expected access evaluation audit event")
	}
}

func TestZeroTrustEngine_DisabledEngine(t *testing.T) {
	config := createTestConfig()
	config.Enabled = false

	engine := NewZeroTrustEngine(config)

	// Start should succeed but do nothing
	err := engine.Start()
	if err != nil {
		t.Fatalf("Expected no error starting disabled engine: %v", err)
	}

	// Stop should succeed
	err = engine.Stop()
	if err != nil {
		t.Fatalf("Expected no error stopping disabled engine: %v", err)
	}
}

func BenchmarkZeroTrustEngine_EvaluateAccess(b *testing.B) {
	config := createTestConfig()
	engine := NewZeroTrustEngine(config)

	// Register entity
	entity := &Entity{
		ID:           "benchmark_user",
		Type:         EntityTypeUser,
		Name:         "Benchmark User",
		IPAddress:    "192.168.1.100",
		UserID:       "benchmark123",
		TrustLevel:   TrustLevelMedium,
		SecurityZone: ZonePrivate,
		Attributes:   map[string]string{"department": "engineering"},
	}

	err := engine.RegisterEntity(entity)
	if err != nil {
		b.Fatalf("Failed to register entity: %v", err)
	}

	// Create access request
	request := &AccessRequest{
		ID:          "benchmark_request",
		RequestorID: "benchmark_user",
		ResourceID:  "benchmark_resource",
		Action:      "read",
		Timestamp:   time.Now(),
		IPAddress:   "192.168.1.100",
		UserAgent:   "BenchmarkClient/1.0",
		Context:     map[string]interface{}{"session_id": "bench_sess"},
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := engine.EvaluateAccess(request)
			if err != nil {
				b.Fatalf("Unexpected error: %v", err)
			}
		}
	})
}

func BenchmarkZeroTrustEngine_NetworkSegmentation(b *testing.B) {
	config := createTestConfig()
	engine := NewZeroTrustEngine(config)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := engine.VerifyNetworkSegmentation("192.168.1.1", "192.168.1.2", 80)
			if err != nil {
				b.Fatalf("Unexpected error: %v", err)
			}
		}
	})
}

func BenchmarkZeroTrustEngine_RiskAssessment(b *testing.B) {
	config := createTestConfig()
	engine := NewZeroTrustEngine(config)

	entity := &Entity{
		ID:           "benchmark_user",
		Type:         EntityTypeUser,
		TrustLevel:   TrustLevelMedium,
		SecurityZone: ZonePrivate,
	}

	request := &AccessRequest{
		Action:    "read",
		Timestamp: time.Now(),
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = engine.assessAccessRisk(request, entity)
		}
	})
}

// Helper functions

func createTestConfig() *Config {
	return &Config{
		Enabled:               true,
		DefaultTrustLevel:     TrustLevelMedium,
		DefaultSecurityZone:   ZonePrivate,
		SessionTimeout:        30 * time.Minute,
		RiskThreshold:         0.7,
		ContinuousAuth:        false,
		DeviceVerification:    true,
		GeolocationEnabled:    true,
		BehaviorAnalysis:      false,
		NetworkSegmentation:   true,
		EncryptionRequired:    true,
		CertificateValidation: true,
		AuditLogging:          true,
		MaxSessions:           1000,
		MaxEntities:           5000,
		PolicyUpdateInterval:  time.Hour,
		RiskUpdateInterval:    15 * time.Minute,
	}
}
