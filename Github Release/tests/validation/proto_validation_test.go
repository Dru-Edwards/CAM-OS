//go:build proto_validation
// +build proto_validation

package validation_test

import (
	"testing"
	"time"

	"github.com/cam-os/kernel/internal/syscall/validation"
	pb "github.com/cam-os/kernel/proto/generated"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProtoValidator_ValidateTask(t *testing.T) {
	validator := validation.NewProtoValidator(false)

	tests := []struct {
		name      string
		task      *pb.Task
		wantValid bool
		wantError string
	}{
		{
			name: "valid task",
			task: &pb.Task{
				Id:           "test-task-1",
				Description:  "Test task description",
				Type:         pb.TaskType_TASK_TYPE_ARBITRATION,
				Priority:     50,
				Deadline:     time.Now().Add(time.Hour).Unix(),
				AgentId:      "agent-1",
				Requirements: []string{"cpu:2", "memory:1GB"},
				Metadata:     map[string]string{"env": "test"},
			},
			wantValid: true,
		},
		{
			name:      "nil task",
			task:      nil,
			wantValid: false,
			wantError: "task cannot be nil",
		},
		{
			name: "empty task ID",
			task: &pb.Task{
				Id:          "",
				Description: "Test task",
				Type:        pb.TaskType_TASK_TYPE_ARBITRATION,
			},
			wantValid: false,
			wantError: "task ID is required",
		},
		{
			name: "empty description",
			task: &pb.Task{
				Id:          "test-task-1",
				Description: "",
				Type:        pb.TaskType_TASK_TYPE_ARBITRATION,
			},
			wantValid: false,
			wantError: "task description is required",
		},
		{
			name: "unspecified task type",
			task: &pb.Task{
				Id:          "test-task-1",
				Description: "Test task",
				Type:        pb.TaskType_TASK_TYPE_UNSPECIFIED,
			},
			wantValid: false,
			wantError: "task type must be specified",
		},
		{
			name: "invalid priority",
			task: &pb.Task{
				Id:          "test-task-1",
				Description: "Test task",
				Type:        pb.TaskType_TASK_TYPE_ARBITRATION,
				Priority:    150,
			},
			wantValid: false,
			wantError: "priority must be between 0 and 100",
		},
		{
			name: "past deadline",
			task: &pb.Task{
				Id:          "test-task-1",
				Description: "Test task",
				Type:        pb.TaskType_TASK_TYPE_ARBITRATION,
				Deadline:    time.Now().Add(-time.Hour).Unix(),
			},
			wantValid: false,
			wantError: "deadline cannot be in the past",
		},
		{
			name: "invalid agent ID",
			task: &pb.Task{
				Id:          "test-task-1",
				Description: "Test task",
				Type:        pb.TaskType_TASK_TYPE_ARBITRATION,
				AgentId:     "invalid@agent",
			},
			wantValid: false,
			wantError: "agent ID contains invalid characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateTask(tt.task)

			if tt.wantValid {
				if !result.Valid {
					t.Errorf("Expected validation to pass, got errors: %v", result.Errors)
				}
				if len(result.Errors) > 0 {
					t.Errorf("Expected no validation errors, got: %v", result.Errors)
				}
			} else {
				if result.Valid {
					t.Error("Expected validation to fail")
				}
				if len(result.Errors) == 0 {
					t.Error("Expected validation errors")
				}

				if tt.wantError != "" {
					found := false
					for _, err := range result.Errors {
						if err.Message == tt.wantError {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected error message '%s' not found in errors: %v", tt.wantError, result.Errors)
					}
				}
			}
		})
	}
}

func TestProtoValidator_ValidateArbitrateRequest(t *testing.T) {
	validator := validation.NewProtoValidator(false)

	validTask := &pb.Task{
		Id:          "test-task-1",
		Description: "Test task",
		Type:        pb.TaskType_TASK_TYPE_ARBITRATION,
		Priority:    50,
		AgentId:     "agent-1",
	}

	tests := []struct {
		name      string
		request   *pb.ArbitrateRequest
		wantValid bool
		wantError string
	}{
		{
			name: "valid request",
			request: &pb.ArbitrateRequest{
				Task:     validTask,
				CallerId: "caller-1",
				PolicyId: "policy-1",
				Context:  map[string]string{"env": "test"},
			},
			wantValid: true,
		},
		{
			name:      "nil request",
			request:   nil,
			wantValid: false,
			wantError: "request cannot be nil",
		},
		{
			name: "empty caller ID",
			request: &pb.ArbitrateRequest{
				Task:     validTask,
				CallerId: "",
			},
			wantValid: false,
			wantError: "caller ID is required",
		},
		{
			name: "nil task",
			request: &pb.ArbitrateRequest{
				Task:     nil,
				CallerId: "caller-1",
			},
			wantValid: false,
			wantError: "task is required",
		},
		{
			name: "invalid policy ID",
			request: &pb.ArbitrateRequest{
				Task:     validTask,
				CallerId: "caller-1",
				PolicyId: "-invalid-policy",
			},
			wantValid: false,
			wantError: "policy ID cannot start or end with dash",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateArbitrateRequest(tt.request)

			if tt.wantValid {
				if !result.Valid {
					t.Errorf("Expected validation to pass, got errors: %v", result.Errors)
				}
			} else {
				if result.Valid {
					t.Error("Expected validation to fail")
				}
				if len(result.Errors) == 0 {
					t.Error("Expected validation errors")
				}

				if tt.wantError != "" {
					found := false
					for _, err := range result.Errors {
						if err.Message == tt.wantError {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected error message '%s' not found in errors: %v", tt.wantError, result.Errors)
					}
				}
			}
		})
	}
}

func TestProtoValidator_ValidateHealthCheckRequest(t *testing.T) {
	validator := validation.NewProtoValidator(false)

	tests := []struct {
		name      string
		request   *pb.HealthCheckRequest
		wantValid bool
		wantError string
	}{
		{
			name: "valid request",
			request: &pb.HealthCheckRequest{
				CallerId: "caller-1",
				Detailed: true,
			},
			wantValid: true,
		},
		{
			name:      "nil request",
			request:   nil,
			wantValid: false,
			wantError: "request cannot be nil",
		},
		{
			name: "empty caller ID",
			request: &pb.HealthCheckRequest{
				CallerId: "",
			},
			wantValid: false,
			wantError: "caller ID is required",
		},
		{
			name: "invalid caller ID",
			request: &pb.HealthCheckRequest{
				CallerId: "invalid@caller",
			},
			wantValid: false,
			wantError: "agent ID contains invalid characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateHealthCheckRequest(tt.request)

			if tt.wantValid {
				if !result.Valid {
					t.Errorf("Expected validation to pass, got errors: %v", result.Errors)
				}
			} else {
				if result.Valid {
					t.Error("Expected validation to fail")
				}
				if len(result.Errors) == 0 {
					t.Error("Expected validation errors")
				}

				if tt.wantError != "" {
					found := false
					for _, err := range result.Errors {
						if err.Message == tt.wantError {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected error message '%s' not found in errors: %v", tt.wantError, result.Errors)
					}
				}
			}
		})
	}
}

func TestProtoValidator_ValidateArbitrationResult(t *testing.T) {
	validator := validation.NewProtoValidator(false)

	tests := []struct {
		name      string
		result    *pb.ArbitrationResult
		wantValid bool
		wantError string
	}{
		{
			name: "valid result",
			result: &pb.ArbitrationResult{
				TaskId:        "task-1",
				AssignedAgent: "agent-1",
				Provider:      "provider-1",
				Confidence:    0.95,
				Reasoning:     "Best match based on capabilities",
				Timestamp:     time.Now().Unix(),
				TraceId:       "trace-1",
				Metadata:      map[string]string{"env": "test"},
			},
			wantValid: true,
		},
		{
			name:      "nil result",
			result:    nil,
			wantValid: false,
			wantError: "result cannot be nil",
		},
		{
			name: "empty task ID",
			result: &pb.ArbitrationResult{
				TaskId:        "",
				AssignedAgent: "agent-1",
				Confidence:    0.95,
			},
			wantValid: false,
			wantError: "task ID is required",
		},
		{
			name: "empty assigned agent",
			result: &pb.ArbitrationResult{
				TaskId:        "task-1",
				AssignedAgent: "",
				Confidence:    0.95,
			},
			wantValid: false,
			wantError: "assigned agent is required",
		},
		{
			name: "invalid confidence",
			result: &pb.ArbitrationResult{
				TaskId:        "task-1",
				AssignedAgent: "agent-1",
				Confidence:    1.5,
			},
			wantValid: false,
			wantError: "confidence must be between 0 and 1",
		},
		{
			name: "future timestamp",
			result: &pb.ArbitrationResult{
				TaskId:        "task-1",
				AssignedAgent: "agent-1",
				Confidence:    0.95,
				Timestamp:     time.Now().Add(time.Hour).Unix(),
			},
			wantValid: false,
			wantError: "timestamp cannot be in the future",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateArbitrationResult(tt.result)

			if tt.wantValid {
				assert.True(t, result.Valid, "Expected validation to pass")
				assert.Empty(t, result.Errors, "Expected no validation errors")
			} else {
				assert.False(t, result.Valid, "Expected validation to fail")
				assert.NotEmpty(t, result.Errors, "Expected validation errors")

				if tt.wantError != "" {
					found := false
					for _, err := range result.Errors {
						if err.Message == tt.wantError {
							found = true
							break
						}
					}
					assert.True(t, found, "Expected error message '%s' not found in errors: %v", tt.wantError, result.Errors)
				}
			}
		})
	}
}

func TestProtoValidator_ValidateMessage(t *testing.T) {
	validator := validation.NewProtoValidator(false)

	t.Run("valid message", func(t *testing.T) {
		task := &pb.Task{
			Id:          "test-task-1",
			Description: "Test task",
			Type:        pb.TaskType_TASK_TYPE_ARBITRATION,
		}

		result := validator.ValidateMessage(task)
		if !result.Valid {
			t.Errorf("Expected validation to pass, got errors: %v", result.Errors)
		}
		if len(result.Errors) > 0 {
			t.Errorf("Expected no errors, got: %v", result.Errors)
		}
	})

	t.Run("nil message", func(t *testing.T) {
		result := validator.ValidateMessage(nil)
		if result.Valid {
			t.Error("Expected validation to fail for nil message")
		}
		if len(result.Errors) == 0 {
			t.Error("Expected validation errors for nil message")
		}
		if result.Errors[0].Message != "message cannot be nil" {
			t.Errorf("Expected 'message cannot be nil', got '%s'", result.Errors[0].Message)
		}
	})
}

func TestProtoValidator_IsValidMessage(t *testing.T) {
	validator := validation.NewProtoValidator(false)

	t.Run("valid message", func(t *testing.T) {
		task := &pb.Task{
			Id:          "test-task-1",
			Description: "Test task",
			Type:        pb.TaskType_TASK_TYPE_ARBITRATION,
		}

		isValid := validator.IsValidMessage(task)
		if !isValid {
			t.Error("Expected message to be valid")
		}
	})

	t.Run("nil message", func(t *testing.T) {
		isValid := validator.IsValidMessage(nil)
		if isValid {
			t.Error("Expected nil message to be invalid")
		}
	})
}

func TestProtoValidator_StrictMode(t *testing.T) {
	strictValidator := validation.NewProtoValidator(true)
	lenientValidator := validation.NewProtoValidator(false)

	// Test with a minimal task that might trigger strict validation
	task := &pb.Task{
		Id:          "test-task-1",
		Description: "Test task",
		Type:        pb.TaskType_TASK_TYPE_ARBITRATION,
	}

	strictResult := strictValidator.ValidateTask(task)
	lenientResult := lenientValidator.ValidateTask(task)

	// Both should be valid for this basic task
	assert.True(t, strictResult.Valid)
	assert.True(t, lenientResult.Valid)
}

func TestProtoValidator_MustValidate(t *testing.T) {
	validator := validation.NewProtoValidator(false)

	t.Run("valid message - no panic", func(t *testing.T) {
		task := &pb.Task{
			Id:          "test-task-1",
			Description: "Test task",
			Type:        pb.TaskType_TASK_TYPE_ARBITRATION,
		}

		// Should not panic
		require.NotPanics(t, func() {
			validator.MustValidate(task)
		})
	})

	t.Run("invalid message - should panic", func(t *testing.T) {
		// Should panic with nil message
		require.Panics(t, func() {
			validator.MustValidate(nil)
		})
	})
}

func TestProtoValidator_ValidateAndSanitize(t *testing.T) {
	validator := validation.NewProtoValidator(false)

	task := &pb.Task{
		Id:          "test-task-1",
		Description: "Test task",
		Type:        pb.TaskType_TASK_TYPE_ARBITRATION,
	}

	result, sanitized := validator.ValidateAndSanitize(task)

	assert.True(t, result.Valid)
	assert.NotNil(t, sanitized)
	assert.Equal(t, task.Id, sanitized.(*pb.Task).Id)
}

// Benchmark tests for performance validation
func BenchmarkProtoValidator_ValidateTask(b *testing.B) {
	validator := validation.NewProtoValidator(false)

	task := &pb.Task{
		Id:           "test-task-1",
		Description:  "Test task description",
		Type:         pb.TaskType_TASK_TYPE_ARBITRATION,
		Priority:     50,
		AgentId:      "agent-1",
		Requirements: []string{"cpu:2", "memory:1GB"},
		Metadata:     map[string]string{"env": "test"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.ValidateTask(task)
	}
}

func BenchmarkProtoValidator_ValidateArbitrateRequest(b *testing.B) {
	validator := validation.NewProtoValidator(false)

	request := &pb.ArbitrateRequest{
		Task: &pb.Task{
			Id:          "test-task-1",
			Description: "Test task",
			Type:        pb.TaskType_TASK_TYPE_ARBITRATION,
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
