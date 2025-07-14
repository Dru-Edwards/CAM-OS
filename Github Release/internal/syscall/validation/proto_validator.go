package validation

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ValidationError represents a validation error
type ValidationError struct {
	Field   string
	Message string
	Value   interface{}
}

// Error implements the error interface
func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error on field '%s': %s (value: %v)", e.Field, e.Message, e.Value)
}

// ValidationResult holds the result of a validation operation
type ValidationResult struct {
	Valid  bool
	Errors []*ValidationError
}

// AddError adds a validation error to the result
func (r *ValidationResult) AddError(field, message string, value interface{}) {
	r.Valid = false
	r.Errors = append(r.Errors, &ValidationError{
		Field:   field,
		Message: message,
		Value:   value,
	})
}

// ProtoValidator validates protobuf messages
type ProtoValidator struct {
	strict bool
}

// NewProtoValidator creates a new protobuf validator
func NewProtoValidator(strict bool) *ProtoValidator {
	return &ProtoValidator{strict: strict}
}

// Generic message interface for validation
type Message interface {
	GetId() string
	GetDescription() string
	GetType() string
}

// TaskMessage represents a task message for validation
type TaskMessage struct {
	Id           string
	Description  string
	Requirements []string
	Metadata     map[string]string
	Priority     int64
	Deadline     int64
	Type         string
	AgentId      string
}

func (t *TaskMessage) GetId() string          { return t.Id }
func (t *TaskMessage) GetDescription() string { return t.Description }
func (t *TaskMessage) GetType() string        { return t.Type }

// ArbitrateRequestMessage represents an arbitrate request
type ArbitrateRequestMessage struct {
	Task     *TaskMessage
	PolicyId string
	CallerId string
	Context  map[string]string
}

func (a *ArbitrateRequestMessage) GetId() string          { return a.CallerId }
func (a *ArbitrateRequestMessage) GetDescription() string { return "arbitrate request" }
func (a *ArbitrateRequestMessage) GetType() string        { return "ArbitrateRequest" }

// HealthCheckRequestMessage represents a health check request
type HealthCheckRequestMessage struct {
	CallerId string
	Detailed bool
}

func (h *HealthCheckRequestMessage) GetId() string          { return h.CallerId }
func (h *HealthCheckRequestMessage) GetDescription() string { return "health check request" }
func (h *HealthCheckRequestMessage) GetType() string        { return "HealthCheckRequest" }

// ArbitrationResultMessage represents an arbitration result
type ArbitrationResultMessage struct {
	TaskId        string
	AssignedAgent string
	Provider      string
	Confidence    float64
	Reasoning     string
	Metadata      map[string]string
	TraceId       string
	Timestamp     int64
}

func (a *ArbitrationResultMessage) GetId() string          { return a.TaskId }
func (a *ArbitrationResultMessage) GetDescription() string { return "arbitration result" }
func (a *ArbitrationResultMessage) GetType() string        { return "ArbitrationResult" }

// ValidateMessage validates a generic message
func (v *ProtoValidator) ValidateMessage(msg Message) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if msg == nil {
		result.AddError("message", "message cannot be nil", nil)
		return result
	}

	// Validate based on message type
	switch m := msg.(type) {
	case *TaskMessage:
		v.validateTaskMessage(m, result)
	case *ArbitrateRequestMessage:
		v.validateArbitrateRequestMessage(m, result)
	case *HealthCheckRequestMessage:
		v.validateHealthCheckRequestMessage(m, result)
	case *ArbitrationResultMessage:
		v.validateArbitrationResultMessage(m, result)
	default:
		result.AddError("type", "unknown message type", msg.GetType())
	}

	return result
}

// validateTaskMessage validates Task-specific fields
func (v *ProtoValidator) validateTaskMessage(task *TaskMessage, result *ValidationResult) {
	// Validate task ID
	if task.Id == "" {
		result.AddError("id", "task ID is required", task.Id)
	} else if len(task.Id) > 100 {
		result.AddError("id", "task ID too long", task.Id)
	}

	// Validate description
	if task.Description == "" {
		result.AddError("description", "task description is required", task.Description)
	}

	// Validate type
	if task.Type == "" || task.Type == "TASK_TYPE_UNSPECIFIED" {
		result.AddError("type", "task type must be specified", task.Type)
	}

	// Validate priority
	if task.Priority < 0 || task.Priority > 100 {
		result.AddError("priority", "priority must be between 0 and 100", task.Priority)
	}

	// Validate deadline
	if task.Deadline > 0 && task.Deadline < time.Now().Unix() {
		result.AddError("deadline", "deadline cannot be in the past", task.Deadline)
	}

	// Validate agent ID
	if task.AgentId != "" {
		if matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, task.AgentId); !matched {
			result.AddError("agent_id", "agent ID contains invalid characters", task.AgentId)
		}
	}
}

// validateArbitrateRequestMessage validates ArbitrateRequest-specific fields
func (v *ProtoValidator) validateArbitrateRequestMessage(req *ArbitrateRequestMessage, result *ValidationResult) {
	// Validate caller ID
	if req.CallerId == "" {
		result.AddError("caller_id", "caller ID is required", req.CallerId)
	}

	// Validate task field
	if req.Task == nil {
		result.AddError("task", "task is required", nil)
	} else {
		// Validate nested task
		taskResult := v.ValidateMessage(req.Task)
		if !taskResult.Valid {
			for _, err := range taskResult.Errors {
				result.AddError("task."+err.Field, err.Message, err.Value)
			}
		}
	}

	// Validate policy ID format
	if req.PolicyId != "" {
		if strings.HasPrefix(req.PolicyId, "-") || strings.HasSuffix(req.PolicyId, "-") {
			result.AddError("policy_id", "policy ID cannot start or end with dash", req.PolicyId)
		}
	}
}

// validateHealthCheckRequestMessage validates HealthCheckRequest-specific fields
func (v *ProtoValidator) validateHealthCheckRequestMessage(req *HealthCheckRequestMessage, result *ValidationResult) {
	// Validate caller ID
	if req.CallerId == "" {
		result.AddError("caller_id", "caller ID is required", req.CallerId)
	} else if matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, req.CallerId); !matched {
		result.AddError("caller_id", "agent ID contains invalid characters", req.CallerId)
	}
}

// validateArbitrationResultMessage validates ArbitrationResult-specific fields
func (v *ProtoValidator) validateArbitrationResultMessage(res *ArbitrationResultMessage, result *ValidationResult) {
	// Validate confidence score
	if res.Confidence < 0.0 || res.Confidence > 1.0 {
		result.AddError("confidence", "confidence must be between 0.0 and 1.0", res.Confidence)
	}

	// Validate task ID
	if res.TaskId == "" {
		result.AddError("task_id", "task ID is required", res.TaskId)
	}

	// Validate assigned agent
	if res.AssignedAgent == "" {
		result.AddError("assigned_agent", "assigned agent is required", res.AssignedAgent)
	}
}

// IsValidMessage checks if a message is valid
func (v *ProtoValidator) IsValidMessage(msg Message) bool {
	result := v.ValidateMessage(msg)
	return result.Valid
}

// ValidateTask validates a task
func (v *ProtoValidator) ValidateTask(task *TaskMessage) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if task == nil {
		result.AddError("task", "task cannot be nil", nil)
		return result
	}

	v.validateTaskMessage(task, result)
	return result
}

// ValidateArbitrateRequest validates an arbitrate request
func (v *ProtoValidator) ValidateArbitrateRequest(request *ArbitrateRequestMessage) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if request == nil {
		result.AddError("request", "request cannot be nil", nil)
		return result
	}

	v.validateArbitrateRequestMessage(request, result)
	return result
}

// ValidateHealthCheckRequest validates a health check request
func (v *ProtoValidator) ValidateHealthCheckRequest(request *HealthCheckRequestMessage) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if request == nil {
		result.AddError("request", "request cannot be nil", nil)
		return result
	}

	v.validateHealthCheckRequestMessage(request, result)
	return result
}

// ValidateArbitrationResult validates an arbitration result
func (v *ProtoValidator) ValidateArbitrationResult(result_msg *ArbitrationResultMessage) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if result_msg == nil {
		result.AddError("result", "result cannot be nil", nil)
		return result
	}

	v.validateArbitrationResultMessage(result_msg, result)
	return result
}

// CheckSchemaCompatibility checks if the message is compatible with expected schema
func (v *ProtoValidator) CheckSchemaCompatibility(msg Message) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if msg == nil {
		result.AddError("schema", "message cannot be nil for schema check", nil)
		return result
	}

	// Check if message type is known
	isKnown := false
	switch msg.(type) {
	case *TaskMessage, *ArbitrateRequestMessage, *HealthCheckRequestMessage, *ArbitrationResultMessage:
		isKnown = true
	}

	if !isKnown {
		result.AddError("schema", "unknown message type", msg.GetType())
	}

	return result
}

// SanitizeMessage removes sensitive information from messages
func (v *ProtoValidator) SanitizeMessage(msg Message) Message {
	if msg == nil {
		return nil
	}

	// Create a copy and sanitize based on type
	switch m := msg.(type) {
	case *TaskMessage:
		sanitized := *m
		// Remove sensitive metadata
		if sanitized.Metadata != nil {
			sanitized.Metadata = make(map[string]string)
			for k, value := range m.Metadata {
				if !v.isSensitiveField(k) {
					sanitized.Metadata[k] = value
				}
			}
		}
		return &sanitized
	case *ArbitrateRequestMessage:
		sanitized := *m
		// Remove sensitive context
		if sanitized.Context != nil {
			sanitized.Context = make(map[string]string)
			for k, value := range m.Context {
				if !v.isSensitiveField(k) {
					sanitized.Context[k] = value
				}
			}
		}
		return &sanitized
	default:
		return msg
	}
}

// isSensitiveField checks if a field name indicates sensitive data
func (v *ProtoValidator) isSensitiveField(fieldName string) bool {
	sensitiveFields := []string{"password", "secret", "key", "token", "credential", "auth", "bearer"}
	fieldLower := strings.ToLower(fieldName)

	for _, sensitive := range sensitiveFields {
		if strings.Contains(fieldLower, sensitive) {
			return true
		}
	}
	return false
}
