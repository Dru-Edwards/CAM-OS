package rasp

import (
	"context"
	"testing"
	"time"
)

func TestRASPEngine_NewEngine(t *testing.T) {
	config := &Config{
		Enabled:            true,
		MaxThreatHistory:   1000,
		RateLimitWindow:    time.Minute,
		RateLimitThreshold: 100,
		SessionTimeout:     30 * time.Minute,
		MLEnabled:          true,
		RealTimeBlocking:   true,
		WhitelistedIPs:     []string{"127.0.0.1"},
		BlacklistedIPs:     []string{"192.168.1.100"},
	}

	engine := NewRASPEngine(config)
	
	if engine == nil {
		t.Fatal("Expected non-nil engine")
	}
	
	if engine.config != config {
		t.Error("Expected config to be set")
	}
	
	if len(engine.rules) == 0 {
		t.Error("Expected default rules to be initialized")
	}
	
	if engine.mlModel == nil {
		t.Error("Expected ML model to be initialized")
	}
}

func TestRASPEngine_StartStop(t *testing.T) {
	config := &Config{
		Enabled:            true,
		MaxThreatHistory:   1000,
		RateLimitWindow:    time.Minute,
		RateLimitThreshold: 100,
		SessionTimeout:     30 * time.Minute,
		MLEnabled:          false,
		RealTimeBlocking:   true,
	}

	engine := NewRASPEngine(config)
	
	err := engine.Start()
	if err != nil {
		t.Fatalf("Expected no error starting engine: %v", err)
	}
	
	// Give goroutines time to start
	time.Sleep(100 * time.Millisecond)
	
	err = engine.Stop()
	if err != nil {
		t.Fatalf("Expected no error stopping engine: %v", err)
	}
}

func TestRASPEngine_SQLInjectionDetection(t *testing.T) {
	config := &Config{
		Enabled:            true,
		MaxThreatHistory:   1000,
		RateLimitWindow:    time.Minute,
		RateLimitThreshold: 100,
		SessionTimeout:     30 * time.Minute,
		MLEnabled:          false,
		RealTimeBlocking:   true,
	}

	engine := NewRASPEngine(config)
	err := engine.Start()
	if err != nil {
		t.Fatalf("Failed to start engine: %v", err)
	}
	defer engine.Stop()

	// Test SQL injection patterns
	testCases := []struct {
		name     string
		request  *RequestContext
		expected bool
	}{
		{
			name: "Basic SQL Injection",
			request: &RequestContext{
				ID:         "test_1",
				Endpoint:   "/api/users",
				Method:     "GET",
				Body:       "id=1' OR '1'='1",
				ClientIP:   "192.168.1.1",
				UserAgent:  "TestAgent",
				UserID:     "test_user",
				Timestamp:  time.Now(),
				Parameters: map[string]string{"id": "1' OR '1'='1"},
				Headers:    make(map[string]string),
				Cookies:    make(map[string]string),
			},
			expected: false, // Should detect threat
		},
		{
			name: "UNION SQL Injection",
			request: &RequestContext{
				ID:         "test_2",
				Endpoint:   "/api/users",
				Method:     "POST",
				Body:       "username=admin&password=pass' UNION SELECT * FROM users--",
				ClientIP:   "192.168.1.1",
				UserAgent:  "TestAgent",
				UserID:     "test_user",
				Timestamp:  time.Now(),
				Parameters: map[string]string{"password": "pass' UNION SELECT * FROM users--"},
				Headers:    make(map[string]string),
				Cookies:    make(map[string]string),
			},
			expected: false, // Should detect threat
		},
		{
			name: "Clean Request",
			request: &RequestContext{
				ID:         "test_3",
				Endpoint:   "/api/users",
				Method:     "GET",
				Body:       "id=123",
				ClientIP:   "192.168.1.1",
				UserAgent:  "TestAgent",
				UserID:     "test_user",
				Timestamp:  time.Now(),
				Parameters: map[string]string{"id": "123"},
				Headers:    make(map[string]string),
				Cookies:    make(map[string]string),
			},
			expected: true, // Should be safe
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assessment, err := engine.AnalyzeRequest(tc.request)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			
			if assessment.Safe != tc.expected {
				t.Errorf("Expected safe=%v, got safe=%v", tc.expected, assessment.Safe)
			}
			
			if !tc.expected && len(assessment.Threats) == 0 {
				t.Error("Expected threats to be detected")
			}
		})
	}
}

func TestRASPEngine_XSSDetection(t *testing.T) {
	config := &Config{
		Enabled:            true,
		MaxThreatHistory:   1000,
		RateLimitWindow:    time.Minute,
		RateLimitThreshold: 100,
		SessionTimeout:     30 * time.Minute,
		MLEnabled:          false,
		RealTimeBlocking:   true,
	}

	engine := NewRASPEngine(config)
	err := engine.Start()
	if err != nil {
		t.Fatalf("Failed to start engine: %v", err)
	}
	defer engine.Stop()

	// Test XSS patterns
	testCases := []struct {
		name     string
		payload  string
		expected bool
	}{
		{
			name:     "Script Tag XSS",
			payload:  "<script>alert('XSS')</script>",
			expected: false,
		},
		{
			name:     "JavaScript URL XSS",
			payload:  "javascript:alert('XSS')",
			expected: false,
		},
		{
			name:     "OnError XSS",
			payload:  "<img src=x onerror=alert('XSS')>",
			expected: false,
		},
		{
			name:     "Clean Content",
			payload:  "Hello World",
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			request := &RequestContext{
				ID:         "test_xss",
				Endpoint:   "/api/comment",
				Method:     "POST",
				Body:       tc.payload,
				ClientIP:   "192.168.1.1",
				UserAgent:  "TestAgent",
				UserID:     "test_user",
				Timestamp:  time.Now(),
				Parameters: map[string]string{"comment": tc.payload},
				Headers:    make(map[string]string),
				Cookies:    make(map[string]string),
			}

			assessment, err := engine.AnalyzeRequest(request)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			
			if assessment.Safe != tc.expected {
				t.Errorf("Expected safe=%v, got safe=%v", tc.expected, assessment.Safe)
			}
		})
	}
}

func TestRASPEngine_RateLimiting(t *testing.T) {
	config := &Config{
		Enabled:            true,
		MaxThreatHistory:   1000,
		RateLimitWindow:    time.Second,
		RateLimitThreshold: 5, // Very low threshold for testing
		SessionTimeout:     30 * time.Minute,
		MLEnabled:          false,
		RealTimeBlocking:   true,
	}

	engine := NewRASPEngine(config)
	err := engine.Start()
	if err != nil {
		t.Fatalf("Failed to start engine: %v", err)
	}
	defer engine.Stop()

	clientIP := "192.168.1.50"
	
	// Send requests within rate limit
	for i := 0; i < 5; i++ {
		request := &RequestContext{
			ID:         "test_rate_limit",
			Endpoint:   "/api/test",
			Method:     "GET",
			Body:       "test",
			ClientIP:   clientIP,
			UserAgent:  "TestAgent",
			UserID:     "test_user",
			Timestamp:  time.Now(),
			Parameters: make(map[string]string),
			Headers:    make(map[string]string),
			Cookies:    make(map[string]string),
		}

		assessment, err := engine.AnalyzeRequest(request)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		
		if !assessment.Safe {
			t.Errorf("Request %d should be safe", i)
		}
	}
	
	// This request should exceed rate limit
	request := &RequestContext{
		ID:         "test_rate_limit_exceeded",
		Endpoint:   "/api/test",
		Method:     "GET",
		Body:       "test",
		ClientIP:   clientIP,
		UserAgent:  "TestAgent",
		UserID:     "test_user",
		Timestamp:  time.Now(),
		Parameters: make(map[string]string),
		Headers:    make(map[string]string),
		Cookies:    make(map[string]string),
	}

	assessment, err := engine.AnalyzeRequest(request)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	if assessment.Safe {
		t.Error("Request should be blocked due to rate limit")
	}
	
	// Check if DDoS threat is detected
	foundDDoS := false
	for _, threat := range assessment.Threats {
		if threat.Type == ThreatDDoS {
			foundDDoS = true
			break
		}
	}
	
	if !foundDDoS {
		t.Error("Expected DDoS threat to be detected")
	}
}

func TestRASPEngine_BlacklistDetection(t *testing.T) {
	config := &Config{
		Enabled:            true,
		MaxThreatHistory:   1000,
		RateLimitWindow:    time.Minute,
		RateLimitThreshold: 100,
		SessionTimeout:     30 * time.Minute,
		MLEnabled:          false,
		RealTimeBlocking:   true,
		BlacklistedIPs:     []string{"192.168.1.100", "10.0.0.0/8"},
	}

	engine := NewRASPEngine(config)
	err := engine.Start()
	if err != nil {
		t.Fatalf("Failed to start engine: %v", err)
	}
	defer engine.Stop()

	testCases := []struct {
		name     string
		clientIP string
		expected bool
	}{
		{
			name:     "Blacklisted IP",
			clientIP: "192.168.1.100",
			expected: false,
		},
		{
			name:     "IP in blacklisted range",
			clientIP: "10.0.0.50",
			expected: false,
		},
		{
			name:     "Clean IP",
			clientIP: "192.168.1.1",
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			request := &RequestContext{
				ID:         "test_blacklist",
				Endpoint:   "/api/test",
				Method:     "GET",
				Body:       "test",
				ClientIP:   tc.clientIP,
				UserAgent:  "TestAgent",
				UserID:     "test_user",
				Timestamp:  time.Now(),
				Parameters: make(map[string]string),
				Headers:    make(map[string]string),
				Cookies:    make(map[string]string),
			}

			assessment, err := engine.AnalyzeRequest(request)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			
			if assessment.Safe != tc.expected {
				t.Errorf("Expected safe=%v, got safe=%v", tc.expected, assessment.Safe)
			}
		})
	}
}

func TestRASPEngine_CommandInjectionDetection(t *testing.T) {
	config := &Config{
		Enabled:            true,
		MaxThreatHistory:   1000,
		RateLimitWindow:    time.Minute,
		RateLimitThreshold: 100,
		SessionTimeout:     30 * time.Minute,
		MLEnabled:          false,
		RealTimeBlocking:   true,
	}

	engine := NewRASPEngine(config)
	err := engine.Start()
	if err != nil {
		t.Fatalf("Failed to start engine: %v", err)
	}
	defer engine.Stop()

	testCases := []struct {
		name     string
		payload  string
		expected bool
	}{
		{
			name:     "Command Injection with semicolon",
			payload:  "file.txt; rm -rf /",
			expected: false,
		},
		{
			name:     "Command Injection with pipe",
			payload:  "ls | cat /etc/passwd",
			expected: false,
		},
		{
			name:     "Command Injection with &&",
			payload:  "echo hello && rm file",
			expected: false,
		},
		{
			name:     "Command Injection with backticks",
			payload:  "file`cat /etc/passwd`",
			expected: false,
		},
		{
			name:     "Clean filename",
			payload:  "document.pdf",
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			request := &RequestContext{
				ID:         "test_cmd_injection",
				Endpoint:   "/api/file",
				Method:     "POST",
				Body:       tc.payload,
				ClientIP:   "192.168.1.1",
				UserAgent:  "TestAgent",
				UserID:     "test_user",
				Timestamp:  time.Now(),
				Parameters: map[string]string{"filename": tc.payload},
				Headers:    make(map[string]string),
				Cookies:    make(map[string]string),
			}

			assessment, err := engine.AnalyzeRequest(request)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			
			if assessment.Safe != tc.expected {
				t.Errorf("Expected safe=%v, got safe=%v", tc.expected, assessment.Safe)
			}
		})
	}
}

func TestRASPEngine_PathTraversalDetection(t *testing.T) {
	config := &Config{
		Enabled:            true,
		MaxThreatHistory:   1000,
		RateLimitWindow:    time.Minute,
		RateLimitThreshold: 100,
		SessionTimeout:     30 * time.Minute,
		MLEnabled:          false,
		RealTimeBlocking:   true,
	}

	engine := NewRASPEngine(config)
	err := engine.Start()
	if err != nil {
		t.Fatalf("Failed to start engine: %v", err)
	}
	defer engine.Stop()

	testCases := []struct {
		name     string
		payload  string
		expected bool
	}{
		{
			name:     "Path traversal with ../",
			payload:  "../../../etc/passwd",
			expected: false,
		},
		{
			name:     "Path traversal with ..\\",
			payload:  "..\\..\\..\\windows\\system32\\config\\sam",
			expected: false,
		},
		{
			name:     "URL encoded path traversal",
			payload:  "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
			expected: false,
		},
		{
			name:     "Clean path",
			payload:  "documents/file.txt",
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			request := &RequestContext{
				ID:         "test_path_traversal",
				Endpoint:   "/api/file",
				Method:     "GET",
				Body:       "",
				ClientIP:   "192.168.1.1",
				UserAgent:  "TestAgent",
				UserID:     "test_user",
				Timestamp:  time.Now(),
				Parameters: map[string]string{"path": tc.payload},
				Headers:    make(map[string]string),
				Cookies:    make(map[string]string),
			}

			assessment, err := engine.AnalyzeRequest(request)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			
			if assessment.Safe != tc.expected {
				t.Errorf("Expected safe=%v, got safe=%v", tc.expected, assessment.Safe)
			}
		})
	}
}

func TestRASPEngine_MLAnalysis(t *testing.T) {
	config := &Config{
		Enabled:            true,
		MaxThreatHistory:   1000,
		RateLimitWindow:    time.Minute,
		RateLimitThreshold: 100,
		SessionTimeout:     30 * time.Minute,
		MLEnabled:          true,
		RealTimeBlocking:   true,
	}

	engine := NewRASPEngine(config)
	err := engine.Start()
	if err != nil {
		t.Fatalf("Failed to start engine: %v", err)
	}
	defer engine.Stop()

	// Test ML analysis with suspicious patterns
	request := &RequestContext{
		ID:         "test_ml",
		Endpoint:   "/api/eval",
		Method:     "POST",
		Body:       "eval(document.cookie)",
		ClientIP:   "192.168.1.1",
		UserAgent:  "TestAgent",
		UserID:     "test_user",
		Timestamp:  time.Date(2023, 1, 1, 3, 0, 0, 0, time.UTC), // 3 AM - suspicious time
		Parameters: map[string]string{"code": "eval(document.cookie)"},
		Headers:    make(map[string]string),
		Cookies:    make(map[string]string),
	}

	assessment, err := engine.AnalyzeRequest(request)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	// Should detect multiple threats including ML anomaly
	if assessment.Safe {
		t.Error("Expected ML analysis to detect threats")
	}
	
	// Check for ML-detected anomaly
	foundAnomaly := false
	for _, threat := range assessment.Threats {
		if threat.Type == "anomaly" {
			foundAnomaly = true
			break
		}
	}
	
	if !foundAnomaly {
		t.Error("Expected ML anomaly to be detected")
	}
}

func TestRASPEngine_BehavioralAnalysis(t *testing.T) {
	config := &Config{
		Enabled:            true,
		MaxThreatHistory:   1000,
		RateLimitWindow:    time.Minute,
		RateLimitThreshold: 100,
		SessionTimeout:     30 * time.Minute,
		MLEnabled:          false,
		RealTimeBlocking:   true,
	}

	engine := NewRASPEngine(config)
	err := engine.Start()
	if err != nil {
		t.Fatalf("Failed to start engine: %v", err)
	}
	defer engine.Stop()

	userID := "test_user"
	clientIP := "192.168.1.1"
	
	// Simulate high-frequency requests to trigger behavioral analysis
	for i := 0; i < 100; i++ {
		request := &RequestContext{
			ID:         "test_behavioral",
			Endpoint:   "/api/endpoint" + string(rune(i)), // Different endpoints
			Method:     "GET",
			Body:       "",
			ClientIP:   clientIP,
			UserAgent:  "TestAgent",
			UserID:     userID,
			Timestamp:  time.Now(),
			Parameters: make(map[string]string),
			Headers:    make(map[string]string),
			Cookies:    make(map[string]string),
		}

		assessment, err := engine.AnalyzeRequest(request)
		if err != nil {
			t.Fatalf("Unexpected error on request %d: %v", i, err)
		}
		
		// Later requests should trigger behavioral anomaly detection
		if i > 50 && assessment.Safe {
			t.Errorf("Expected behavioral anomaly to be detected on request %d", i)
		}
	}
}

func TestRASPEngine_ThreatConfidence(t *testing.T) {
	config := &Config{
		Enabled:            true,
		MaxThreatHistory:   1000,
		RateLimitWindow:    time.Minute,
		RateLimitThreshold: 100,
		SessionTimeout:     30 * time.Minute,
		MLEnabled:          false,
		RealTimeBlocking:   true,
	}

	engine := NewRASPEngine(config)
	err := engine.Start()
	if err != nil {
		t.Fatalf("Failed to start engine: %v", err)
	}
	defer engine.Stop()

	// Test high-confidence threat
	request := &RequestContext{
		ID:         "test_confidence",
		Endpoint:   "/api/test",
		Method:     "POST",
		Body:       "eval(malicious_code)",
		ClientIP:   "192.168.1.1",
		UserAgent:  "TestAgent",
		UserID:     "test_user",
		Timestamp:  time.Now(),
		Parameters: map[string]string{"code": "eval(malicious_code)"},
		Headers:    make(map[string]string),
		Cookies:    make(map[string]string),
	}

	assessment, err := engine.AnalyzeRequest(request)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	if assessment.Safe {
		t.Error("Expected threat to be detected")
	}
	
	if assessment.Confidence < 0.8 {
		t.Errorf("Expected high confidence, got %f", assessment.Confidence)
	}
	
	// Check individual threat confidences
	for _, threat := range assessment.Threats {
		if threat.Confidence < 0.7 {
			t.Errorf("Expected high threat confidence, got %f", threat.Confidence)
		}
	}
}

func TestRASPEngine_ThreatHistory(t *testing.T) {
	config := &Config{
		Enabled:            true,
		MaxThreatHistory:   5, // Small history for testing
		RateLimitWindow:    time.Minute,
		RateLimitThreshold: 100,
		SessionTimeout:     30 * time.Minute,
		MLEnabled:          false,
		RealTimeBlocking:   true,
	}

	engine := NewRASPEngine(config)
	err := engine.Start()
	if err != nil {
		t.Fatalf("Failed to start engine: %v", err)
	}
	defer engine.Stop()

	// Generate multiple threats
	for i := 0; i < 10; i++ {
		request := &RequestContext{
			ID:         "test_history",
			Endpoint:   "/api/test",
			Method:     "POST",
			Body:       "' OR '1'='1",
			ClientIP:   "192.168.1.1",
			UserAgent:  "TestAgent",
			UserID:     "test_user",
			Timestamp:  time.Now(),
			Parameters: map[string]string{"id": "' OR '1'='1"},
			Headers:    make(map[string]string),
			Cookies:    make(map[string]string),
		}

		_, err := engine.AnalyzeRequest(request)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		
		// Small delay to allow threat processing
		time.Sleep(10 * time.Millisecond)
	}
	
	// Check that history is limited to max size
	engine.threatsMutex.RLock()
	historySize := len(engine.threats)
	engine.threatsMutex.RUnlock()
	
	if historySize > config.MaxThreatHistory {
		t.Errorf("Expected history size <= %d, got %d", config.MaxThreatHistory, historySize)
	}
}

func TestRASPEngine_SessionCleanup(t *testing.T) {
	config := &Config{
		Enabled:            true,
		MaxThreatHistory:   1000,
		RateLimitWindow:    time.Minute,
		RateLimitThreshold: 100,
		SessionTimeout:     100 * time.Millisecond, // Very short timeout for testing
		MLEnabled:          false,
		RealTimeBlocking:   true,
	}

	engine := NewRASPEngine(config)
	err := engine.Start()
	if err != nil {
		t.Fatalf("Failed to start engine: %v", err)
	}
	defer engine.Stop()

	// Create a session
	request := &RequestContext{
		ID:         "test_session_cleanup",
		Endpoint:   "/api/test",
		Method:     "GET",
		Body:       "",
		ClientIP:   "192.168.1.1",
		UserAgent:  "TestAgent",
		UserID:     "test_user",
		Timestamp:  time.Now(),
		Parameters: make(map[string]string),
		Headers:    make(map[string]string),
		Cookies:    make(map[string]string),
	}

	_, err = engine.AnalyzeRequest(request)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	// Check session exists
	engine.sessionsMutex.RLock()
	initialSessionCount := len(engine.userSessions)
	engine.sessionsMutex.RUnlock()
	
	if initialSessionCount == 0 {
		t.Error("Expected session to be created")
	}
	
	// Wait for session to timeout and cleanup
	time.Sleep(200 * time.Millisecond)
	
	// Trigger cleanup manually
	engine.cleanupExpiredSessions()
	
	// Check session was cleaned up
	engine.sessionsMutex.RLock()
	finalSessionCount := len(engine.userSessions)
	engine.sessionsMutex.RUnlock()
	
	if finalSessionCount >= initialSessionCount {
		t.Error("Expected session cleanup to reduce session count")
	}
}

func TestRASPEngine_DisabledEngine(t *testing.T) {
	config := &Config{
		Enabled: false, // Disabled engine
	}

	engine := NewRASPEngine(config)
	err := engine.Start()
	if err != nil {
		t.Fatalf("Failed to start disabled engine: %v", err)
	}
	defer engine.Stop()

	// Even malicious request should pass through
	request := &RequestContext{
		ID:         "test_disabled",
		Endpoint:   "/api/test",
		Method:     "POST",
		Body:       "' OR '1'='1; DROP TABLE users;",
		ClientIP:   "192.168.1.1",
		UserAgent:  "TestAgent",
		UserID:     "test_user",
		Timestamp:  time.Now(),
		Parameters: map[string]string{"sql": "' OR '1'='1; DROP TABLE users;"},
		Headers:    make(map[string]string),
		Cookies:    make(map[string]string),
	}

	assessment, err := engine.AnalyzeRequest(request)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	if !assessment.Safe {
		t.Error("Expected disabled engine to allow all requests")
	}
	
	if len(assessment.Threats) > 0 {
		t.Error("Expected no threats to be detected when engine is disabled")
	}
}

func BenchmarkRASPEngine_AnalyzeRequest(b *testing.B) {
	config := &Config{
		Enabled:            true,
		MaxThreatHistory:   1000,
		RateLimitWindow:    time.Minute,
		RateLimitThreshold: 1000,
		SessionTimeout:     30 * time.Minute,
		MLEnabled:          true,
		RealTimeBlocking:   true,
	}

	engine := NewRASPEngine(config)
	err := engine.Start()
	if err != nil {
		b.Fatalf("Failed to start engine: %v", err)
	}
	defer engine.Stop()

	request := &RequestContext{
		ID:         "benchmark_request",
		Endpoint:   "/api/test",
		Method:     "POST",
		Body:       "username=test&password=pass123",
		ClientIP:   "192.168.1.1",
		UserAgent:  "BenchmarkAgent",
		UserID:     "benchmark_user",
		Timestamp:  time.Now(),
		Parameters: map[string]string{"username": "test", "password": "pass123"},
		Headers:    make(map[string]string),
		Cookies:    make(map[string]string),
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := engine.AnalyzeRequest(request)
			if err != nil {
				b.Fatalf("Unexpected error: %v", err)
			}
		}
	})
}

func BenchmarkRASPEngine_ThreatDetection(b *testing.B) {
	config := &Config{
		Enabled:            true,
		MaxThreatHistory:   1000,
		RateLimitWindow:    time.Minute,
		RateLimitThreshold: 1000,
		SessionTimeout:     30 * time.Minute,
		MLEnabled:          false,
		RealTimeBlocking:   true,
	}

	engine := NewRASPEngine(config)
	err := engine.Start()
	if err != nil {
		b.Fatalf("Failed to start engine: %v", err)
	}
	defer engine.Stop()

	// Malicious request for benchmark
	request := &RequestContext{
		ID:         "benchmark_threat",
		Endpoint:   "/api/sql",
		Method:     "POST",
		Body:       "id=1' OR '1'='1 UNION SELECT * FROM users",
		ClientIP:   "192.168.1.1",
		UserAgent:  "BenchmarkAgent",
		UserID:     "benchmark_user",
		Timestamp:  time.Now(),
		Parameters: map[string]string{"id": "1' OR '1'='1 UNION SELECT * FROM users"},
		Headers:    make(map[string]string),
		Cookies:    make(map[string]string),
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			assessment, err := engine.AnalyzeRequest(request)
			if err != nil {
				b.Fatalf("Unexpected error: %v", err)
			}
			if assessment.Safe {
				b.Error("Expected threat to be detected")
			}
		}
	})
}

// Helper function to create test configuration
func createTestConfig() *Config {
	return &Config{
		Enabled:            true,
		LogLevel:           "DEBUG",
		MaxThreatHistory:   1000,
		RateLimitWindow:    time.Minute,
		RateLimitThreshold: 100,
		SessionTimeout:     30 * time.Minute,
		MLEnabled:          false,
		RealTimeBlocking:   true,
		GeolocationEnabled: false,
		WhitelistedIPs:     []string{"127.0.0.1", "::1"},
		BlacklistedIPs:     []string{"192.168.1.100"},
		TrustedUserAgents:  []string{"TrustedBot/1.0"},
		SuspiciousPatterns: map[ThreatType][]string{
			ThreatSQLInjection: {"' OR '", "UNION SELECT", "DROP TABLE"},
			ThreatXSS:          {"<script>", "javascript:", "onerror="},
		},
	}
} 