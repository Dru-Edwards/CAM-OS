package validation

import (
	"testing"
	"time"
)

func TestNewProtoValidator(t *testing.T) {
	t.Run("create non-strict validator", func(t *testing.T) {
		validator := NewProtoValidator(false)
		if validator == nil {
			t.Error("Expected validator to be created")
		}
		if validator.strict {
			t.Error("Expected validator to be non-strict")
		}
	})

	t.Run("create strict validator", func(t *testing.T) {
		validator := NewProtoValidator(true)
		if validator == nil {
			t.Error("Expected validator to be created")
		}
		if !validator.strict {
			t.Error("Expected validator to be strict")
		}
	})
}

func TestProtoValidator_ValidateMessage_Basic(t *testing.T) {
	validator := NewProtoValidator(false)

	t.Run("nil message", func(t *testing.T) {
		result := validator.ValidateMessage(nil)
		if result.Valid {
			t.Error("Expected validation to fail for nil message")
		}
		if len(result.Errors) == 0 {
			t.Error("Expected validation errors for nil message")
		}
	})

	t.Run("valid task message", func(t *testing.T) {
		task := &TaskMessage{
			Id:          "test-task-1",
			Description: "Test task",
			Type:        "TASK_TYPE_ARBITRATION",
		}

		result := validator.ValidateMessage(task)
		if !result.Valid {
			t.Errorf("Expected validation to pass for valid task, got errors: %v", result.Errors)
		}
	})
}

func TestProtoValidator_ValidateTask_Basic(t *testing.T) {
	validator := NewProtoValidator(false)

	t.Run("nil task", func(t *testing.T) {
		result := validator.ValidateTask(nil)
		if result.Valid {
			t.Error("Expected validation to fail for nil task")
		}
		if len(result.Errors) == 0 {
			t.Error("Expected validation errors for nil task")
		}
	})

	t.Run("valid task", func(t *testing.T) {
		task := &TaskMessage{
			Id:          "test-task-1",
			Description: "Test task description",
			Type:        "TASK_TYPE_ARBITRATION",
			Priority:    50,
			AgentId:     "agent-1",
		}

		result := validator.ValidateTask(task)
		if !result.Valid {
			t.Errorf("Expected validation to pass for valid task, got errors: %v", result.Errors)
		}
	})

	t.Run("empty task ID", func(t *testing.T) {
		task := &TaskMessage{
			Id:          "",
			Description: "Test task",
			Type:        "TASK_TYPE_ARBITRATION",
		}

		result := validator.ValidateTask(task)
		if result.Valid {
			t.Error("Expected validation to fail for empty task ID")
		}

		// Check that we got the expected error
		found := false
		for _, err := range result.Errors {
			if err.Message == "task ID is required" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected 'task ID is required' error, got: %v", result.Errors)
		}
	})

	t.Run("empty description", func(t *testing.T) {
		task := &TaskMessage{
			Id:          "test-task-1",
			Description: "",
			Type:        "TASK_TYPE_ARBITRATION",
		}

		result := validator.ValidateTask(task)
		if result.Valid {
			t.Error("Expected validation to fail for empty description")
		}

		// Check that we got the expected error
		found := false
		for _, err := range result.Errors {
			if err.Message == "task description is required" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected 'task description is required' error, got: %v", result.Errors)
		}
	})

	t.Run("unspecified task type", func(t *testing.T) {
		task := &TaskMessage{
			Id:          "test-task-1",
			Description: "Test task",
			Type:        "TASK_TYPE_UNSPECIFIED",
		}

		result := validator.ValidateTask(task)
		if result.Valid {
			t.Error("Expected validation to fail for unspecified task type")
		}

		found := false
		for _, err := range result.Errors {
			if err.Message == "task type must be specified" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected 'task type must be specified' error, got: %v", result.Errors)
		}
	})

	t.Run("invalid priority", func(t *testing.T) {
		task := &TaskMessage{
			Id:          "test-task-1",
			Description: "Test task",
			Type:        "TASK_TYPE_ARBITRATION",
			Priority:    150,
		}

		result := validator.ValidateTask(task)
		if result.Valid {
			t.Error("Expected validation to fail for invalid priority")
		}

		found := false
		for _, err := range result.Errors {
			if err.Message == "priority must be between 0 and 100" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected 'priority must be between 0 and 100' error, got: %v", result.Errors)
		}
	})

	t.Run("past deadline", func(t *testing.T) {
		task := &TaskMessage{
			Id:          "test-task-1",
			Description: "Test task",
			Type:        "TASK_TYPE_ARBITRATION",
			Deadline:    time.Now().Add(-time.Hour).Unix(),
		}

		result := validator.ValidateTask(task)
		if result.Valid {
			t.Error("Expected validation to fail for past deadline")
		}

		found := false
		for _, err := range result.Errors {
			if err.Message == "deadline cannot be in the past" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected 'deadline cannot be in the past' error, got: %v", result.Errors)
		}
	})

	t.Run("invalid agent ID", func(t *testing.T) {
		task := &TaskMessage{
			Id:          "test-task-1",
			Description: "Test task",
			Type:        "TASK_TYPE_ARBITRATION",
			AgentId:     "invalid@agent",
		}

		result := validator.ValidateTask(task)
		if result.Valid {
			t.Error("Expected validation to fail for invalid agent ID")
		}

		found := false
		for _, err := range result.Errors {
			if err.Message == "agent ID contains invalid characters" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected 'agent ID contains invalid characters' error, got: %v", result.Errors)
		}
	})
}

func TestProtoValidator_ValidateArbitrateRequest(t *testing.T) {
	validator := NewProtoValidator(false)

	validTask := &TaskMessage{
		Id:          "test-task-1",
		Description: "Test task",
		Type:        "TASK_TYPE_ARBITRATION",
		Priority:    50,
		AgentId:     "agent-1",
	}

	t.Run("valid request", func(t *testing.T) {
		request := &ArbitrateRequestMessage{
			Task:     validTask,
			CallerId: "caller-1",
			PolicyId: "policy-1",
			Context:  map[string]string{"env": "test"},
		}

		result := validator.ValidateArbitrateRequest(request)
		if !result.Valid {
			t.Errorf("Expected validation to pass, got errors: %v", result.Errors)
		}
	})

	t.Run("nil request", func(t *testing.T) {
		result := validator.ValidateArbitrateRequest(nil)
		if result.Valid {
			t.Error("Expected validation to fail for nil request")
		}
		if len(result.Errors) == 0 {
			t.Error("Expected validation errors for nil request")
		}
	})

	t.Run("empty caller ID", func(t *testing.T) {
		request := &ArbitrateRequestMessage{
			Task:     validTask,
			CallerId: "",
		}

		result := validator.ValidateArbitrateRequest(request)
		if result.Valid {
			t.Error("Expected validation to fail for empty caller ID")
		}

		found := false
		for _, err := range result.Errors {
			if err.Message == "caller ID is required" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected 'caller ID is required' error, got: %v", result.Errors)
		}
	})

	t.Run("nil task", func(t *testing.T) {
		request := &ArbitrateRequestMessage{
			Task:     nil,
			CallerId: "caller-1",
		}

		result := validator.ValidateArbitrateRequest(request)
		if result.Valid {
			t.Error("Expected validation to fail for nil task")
		}

		found := false
		for _, err := range result.Errors {
			if err.Message == "task is required" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected 'task is required' error, got: %v", result.Errors)
		}
	})

	t.Run("invalid policy ID", func(t *testing.T) {
		request := &ArbitrateRequestMessage{
			Task:     validTask,
			CallerId: "caller-1",
			PolicyId: "-invalid-policy",
		}

		result := validator.ValidateArbitrateRequest(request)
		if result.Valid {
			t.Error("Expected validation to fail for invalid policy ID")
		}

		found := false
		for _, err := range result.Errors {
			if err.Message == "policy ID cannot start or end with dash" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected 'policy ID cannot start or end with dash' error, got: %v", result.Errors)
		}
	})
}

func TestProtoValidator_ValidateHealthCheckRequest(t *testing.T) {
	validator := NewProtoValidator(false)

	t.Run("valid request", func(t *testing.T) {
		request := &HealthCheckRequestMessage{
			CallerId: "caller-1",
			Detailed: true,
		}

		result := validator.ValidateHealthCheckRequest(request)
		if !result.Valid {
			t.Errorf("Expected validation to pass, got errors: %v", result.Errors)
		}
	})

	t.Run("nil request", func(t *testing.T) {
		result := validator.ValidateHealthCheckRequest(nil)
		if result.Valid {
			t.Error("Expected validation to fail for nil request")
		}
		if len(result.Errors) == 0 {
			t.Error("Expected validation errors for nil request")
		}
	})

	t.Run("empty caller ID", func(t *testing.T) {
		request := &HealthCheckRequestMessage{
			CallerId: "",
		}

		result := validator.ValidateHealthCheckRequest(request)
		if result.Valid {
			t.Error("Expected validation to fail for empty caller ID")
		}

		found := false
		for _, err := range result.Errors {
			if err.Message == "caller ID is required" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected 'caller ID is required' error, got: %v", result.Errors)
		}
	})

	t.Run("invalid caller ID", func(t *testing.T) {
		request := &HealthCheckRequestMessage{
			CallerId: "invalid@caller",
		}

		result := validator.ValidateHealthCheckRequest(request)
		if result.Valid {
			t.Error("Expected validation to fail for invalid caller ID")
		}

		found := false
		for _, err := range result.Errors {
			if err.Message == "agent ID contains invalid characters" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected 'agent ID contains invalid characters' error, got: %v", result.Errors)
		}
	})
}

func TestProtoValidator_ValidateArbitrationResult(t *testing.T) {
	validator := NewProtoValidator(false)

	t.Run("valid result", func(t *testing.T) {
		result := &ArbitrationResultMessage{
			TaskId:        "task-1",
			AssignedAgent: "agent-1",
			Provider:      "provider-1",
			Confidence:    0.95,
			Reasoning:     "Best match",
			Metadata:      map[string]string{"source": "test"},
			TraceId:       "trace-1",
			Timestamp:     time.Now().Unix(),
		}

		validationResult := validator.ValidateArbitrationResult(result)
		if !validationResult.Valid {
			t.Errorf("Expected validation to pass, got errors: %v", validationResult.Errors)
		}
	})

	t.Run("nil result", func(t *testing.T) {
		result := validator.ValidateArbitrationResult(nil)
		if result.Valid {
			t.Error("Expected validation to fail for nil result")
		}
		if len(result.Errors) == 0 {
			t.Error("Expected validation errors for nil result")
		}
	})

	t.Run("invalid confidence", func(t *testing.T) {
		result := &ArbitrationResultMessage{
			TaskId:        "task-1",
			AssignedAgent: "agent-1",
			Provider:      "provider-1",
			Confidence:    1.5,
		}

		validationResult := validator.ValidateArbitrationResult(result)
		if validationResult.Valid {
			t.Error("Expected validation to fail for invalid confidence")
		}

		found := false
		for _, err := range validationResult.Errors {
			if err.Message == "confidence must be between 0.0 and 1.0" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected 'confidence must be between 0.0 and 1.0' error, got: %v", validationResult.Errors)
		}
	})

	t.Run("empty task ID", func(t *testing.T) {
		result := &ArbitrationResultMessage{
			TaskId:        "",
			AssignedAgent: "agent-1",
			Provider:      "provider-1",
			Confidence:    0.95,
		}

		validationResult := validator.ValidateArbitrationResult(result)
		if validationResult.Valid {
			t.Error("Expected validation to fail for empty task ID")
		}

		found := false
		for _, err := range validationResult.Errors {
			if err.Message == "task ID is required" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected 'task ID is required' error, got: %v", validationResult.Errors)
		}
	})

	t.Run("empty assigned agent", func(t *testing.T) {
		result := &ArbitrationResultMessage{
			TaskId:        "task-1",
			AssignedAgent: "",
			Provider:      "provider-1",
			Confidence:    0.95,
		}

		validationResult := validator.ValidateArbitrationResult(result)
		if validationResult.Valid {
			t.Error("Expected validation to fail for empty assigned agent")
		}

		found := false
		for _, err := range validationResult.Errors {
			if err.Message == "assigned agent is required" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected 'assigned agent is required' error, got: %v", validationResult.Errors)
		}
	})
}

func TestProtoValidator_IsValidMessage(t *testing.T) {
	validator := NewProtoValidator(false)

	t.Run("nil message", func(t *testing.T) {
		if validator.IsValidMessage(nil) {
			t.Error("Expected nil message to be invalid")
		}
	})

	t.Run("valid message", func(t *testing.T) {
		task := &TaskMessage{
			Id:          "test-task-1",
			Description: "Test task",
			Type:        "TASK_TYPE_ARBITRATION",
		}

		if !validator.IsValidMessage(task) {
			t.Error("Expected valid message to be valid")
		}
	})
}

func TestValidationResult_AddError(t *testing.T) {
	result := &ValidationResult{Valid: true}

	// Initially valid
	if !result.Valid {
		t.Error("Expected result to be initially valid")
	}

	// Add an error
	result.AddError("field1", "error message", "value")

	// Should now be invalid
	if result.Valid {
		t.Error("Expected result to be invalid after adding error")
	}

	if len(result.Errors) != 1 {
		t.Errorf("Expected 1 error, got %d", len(result.Errors))
	}

	if result.Errors[0].Field != "field1" {
		t.Errorf("Expected field 'field1', got '%s'", result.Errors[0].Field)
	}

	if result.Errors[0].Message != "error message" {
		t.Errorf("Expected message 'error message', got '%s'", result.Errors[0].Message)
	}
}

func TestValidationError_Error(t *testing.T) {
	err := &ValidationError{
		Field:   "test_field",
		Message: "test message",
		Value:   "test_value",
	}

	expected := "validation error on field 'test_field': test message (value: test_value)"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestProtoValidator_CheckSchemaCompatibility(t *testing.T) {
	validator := NewProtoValidator(false)

	t.Run("nil message", func(t *testing.T) {
		result := validator.CheckSchemaCompatibility(nil)
		if result.Valid {
			t.Error("Expected schema check to fail for nil message")
		}
	})

	t.Run("known message type", func(t *testing.T) {
		task := &TaskMessage{
			Id:          "test-task-1",
			Description: "Test task",
			Type:        "TASK_TYPE_ARBITRATION",
		}

		result := validator.CheckSchemaCompatibility(task)
		if !result.Valid {
			t.Errorf("Expected schema check to pass for known message type, got errors: %v", result.Errors)
		}
	})
}

func TestProtoValidator_SanitizeMessage(t *testing.T) {
	validator := NewProtoValidator(false)

	t.Run("nil message", func(t *testing.T) {
		result := validator.SanitizeMessage(nil)
		if result != nil {
			t.Error("Expected sanitized nil message to be nil")
		}
	})

	t.Run("sanitize task with sensitive metadata", func(t *testing.T) {
		task := &TaskMessage{
			Id:          "test-task-1",
			Description: "Test task",
			Type:        "TASK_TYPE_ARBITRATION",
			Metadata: map[string]string{
				"normal_field": "value",
				"password":     "secret123",
				"api_key":      "key123",
			},
		}

		result := validator.SanitizeMessage(task)
		if result == nil {
			t.Error("Expected sanitized message to not be nil")
		}

		// Should be a copy, not the same instance
		if result == task {
			t.Error("Expected sanitized message to be a copy")
		}

		if sanitized, ok := result.(*TaskMessage); ok {
			if len(sanitized.Metadata) == 0 {
				t.Error("Expected sanitized message to have some metadata")
			}
			if _, exists := sanitized.Metadata["password"]; exists {
				t.Error("Expected password to be removed from sanitized message")
			}
			if _, exists := sanitized.Metadata["api_key"]; exists {
				t.Error("Expected api_key to be removed from sanitized message")
			}
			if _, exists := sanitized.Metadata["normal_field"]; !exists {
				t.Error("Expected normal_field to be preserved in sanitized message")
			}
		} else {
			t.Error("Expected sanitized message to be TaskMessage type")
		}
	})
}

// Performance test
func BenchmarkProtoValidator_ValidateTask(b *testing.B) {
	validator := NewProtoValidator(false)

	task := &TaskMessage{
		Id:          "test-task-1",
		Description: "Test task description",
		Type:        "TASK_TYPE_ARBITRATION",
		Priority:    50,
		AgentId:     "agent-1",
		Requirements: []string{"cpu:2", "memory:1GB"},
		Metadata:     map[string]string{"env": "test"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.ValidateTask(task)
	}
}

func BenchmarkProtoValidator_ValidateArbitrateRequest(b *testing.B) {
	validator := NewProtoValidator(false)

	request := &ArbitrateRequestMessage{
		Task: &TaskMessage{
			Id:          "test-task-1",
			Description: "Test task",
			Type:        "TASK_TYPE_ARBITRATION",
			Priority:    50,
			AgentId:     "agent-1",
		},
		CallerId: "caller-1",
		PolicyId: "policy-1",
		Context:  map[string]string{"env": "test"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.ValidateArbitrateRequest(request)
	}
}
