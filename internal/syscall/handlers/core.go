package handlers

import (
	"context"
	"fmt"
	"time"

	"github.com/cam-os/kernel/internal/arbitration"
	"github.com/cam-os/kernel/internal/errors"
	"github.com/cam-os/kernel/internal/explainability"
	"github.com/cam-os/kernel/internal/policy"
	"github.com/cam-os/kernel/internal/validation"
	pb "github.com/cam-os/kernel/proto/generated"
	"google.golang.org/grpc/codes"
)

// Config represents the configuration for handlers
type Config struct {
	SyscallTimeout     time.Duration
	ArbitrationTimeout time.Duration
	RedactErrorDetails bool
}

// ErrorRedactor handles comprehensive error redaction (H-5 requirement)
type ErrorRedactor struct {
	*errors.ErrorRedactor
}

// NewErrorRedactor creates a new error redactor for handlers
func NewErrorRedactor(config *Config) *ErrorRedactor {
	redactionConfig := &errors.ErrorRedactionConfig{
		RedactAllErrors:       config.RedactErrorDetails,
		LogDetailedErrors:     true,
		GenerateCorrelationID: true,
		RedactionPatterns: []string{
			// H-5 requirement: redact file paths and IPs
			`[A-Za-z]:[\\\/][^\\\/\s]+`,         // Windows file paths
			`\/[^\\\/\s]+(?:\/[^\\\/\s]+)*`,     // Unix file paths
			`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`, // IP addresses
			`:[0-9]{1,5}\b`,                     // Port numbers
			`[a-zA-Z]+://[^\s]+`,                // Connection strings
			`at\s+[a-zA-Z0-9_.]+\([^)]+\)`,      // Stack traces
		},
	}

	baseRedactor := errors.NewErrorRedactor(redactionConfig)
	return &ErrorRedactor{ErrorRedactor: baseRedactor}
}

// RedactError wraps the base redaction function for handlers (H-5 requirement)
func (e *ErrorRedactor) RedactError(ctx context.Context, err error, operation, userID string) error {
	return e.ErrorRedactor.RedactError(ctx, err, operation, userID)
}

// ValidateAgentID validates agent ID format
func (c *Config) ValidateAgentID(agentID string) error {
	return validation.ValidateAgentID(agentID)
}

// ValidateKey validates key format
func (c *Config) ValidateKey(key string) error {
	return validation.ValidateKey(key)
}

// TimeoutError represents a timeout error
type TimeoutError struct {
	operation string
}

func (e *TimeoutError) Error() string {
	return "operation timed out"
}

// NewTimeoutError creates a new timeout error
func NewTimeoutError(operation string) error {
	return &TimeoutError{operation: operation}
}

// coreHandler implements CoreHandler interface with proper error redaction
type coreHandler struct {
	arbitrationEngine    *arbitration.Engine
	policyEngine         *policy.Engine
	explainabilityEngine *explainability.Engine
	config               *Config
	errorRedactor        *ErrorRedactor
}

// NewCoreHandler creates a new core handler with error redaction (H-5)
func NewCoreHandler(
	arbitrationEngine *arbitration.Engine,
	policyEngine *policy.Engine,
	explainabilityEngine *explainability.Engine,
	config *Config,
	errorRedactor interface{}, // Accept legacy interface for compatibility
) CoreHandler {
	// Create proper error redactor for H-5 compliance
	redactor := NewErrorRedactor(config)

	return &coreHandler{
		arbitrationEngine:    arbitrationEngine,
		policyEngine:         policyEngine,
		explainabilityEngine: explainabilityEngine,
		config:               config,
		errorRedactor:        redactor,
	}
}

// Arbitrate handles arbitration syscalls with proper error redaction (H-5)
func (h *coreHandler) Arbitrate(ctx context.Context, req *pb.ArbitrateRequest) (*pb.ArbitrateResponse, error) {
	startTime := time.Now()
	operation := "arbitrate"

	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, h.config.ArbitrationTimeout)
	defer cancel()

	// Validate request
	if req.Task == nil {
		// H-5: Use RedactError for all errors
		err := fmt.Errorf("task is required")
		redactedErr := h.errorRedactor.RedactError(ctx, err, operation, req.CallerId)
		return &pb.ArbitrateResponse{
			Error:      redactedErr.Error(),
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}

	// Validate agent ID if present
	if req.Task.AgentId != "" {
		if err := h.config.ValidateAgentID(req.Task.AgentId); err != nil {
			// H-5: Use RedactError for validation errors
			redactedErr := h.errorRedactor.RedactError(ctx, err, operation, req.CallerId)
			return &pb.ArbitrateResponse{
				Error:      redactedErr.Error(),
				StatusCode: int32(codes.InvalidArgument),
			}, nil
		}
	}

	// Validate policy ID if present
	if req.PolicyId != "" {
		if err := h.config.ValidateKey(req.PolicyId); err != nil {
			// H-5: Use RedactError for validation errors
			redactedErr := h.errorRedactor.RedactError(ctx, err, operation, req.CallerId)
			return &pb.ArbitrateResponse{
				Error:      redactedErr.Error(),
				StatusCode: int32(codes.InvalidArgument),
			}, nil
		}
	}

	// Convert protobuf task to internal task
	task := &arbitration.Task{
		ID:           req.Task.Id,
		Description:  req.Task.Description,
		Requirements: req.Task.Requirements,
		Metadata:     req.Task.Metadata,
		Priority:     req.Task.Priority,
		Deadline:     time.Unix(req.Task.Deadline, 0),
		Type:         convertTaskType(req.Task.Type),
		AgentID:      req.Task.AgentId,
	}

	// Perform arbitration with timeout protection
	result, err := h.arbitrationEngine.Arbitrate(ctx, task, req.PolicyId)
	if err != nil {
		// Handle context timeout
		if ctx.Err() == context.DeadlineExceeded {
			err = NewTimeoutError(operation)
		}

		// H-5: Use RedactError for all internal errors
		redactedErr := h.errorRedactor.RedactError(ctx, err, operation, req.CallerId)
		return &pb.ArbitrateResponse{
			Error:      redactedErr.Error(),
			StatusCode: int32(codes.Internal),
		}, nil
	}

	// Record performance metrics
	latency := time.Since(startTime)
	recordSyscallMetrics(operation, latency, true)

	// Create audit trail
	h.explainabilityEngine.RecordDecision(ctx, &explainability.Decision{
		TraceID:    result.TraceID,
		TaskID:     result.TaskID,
		AgentID:    result.AssignedAgent,
		Decision:   fmt.Sprintf("Assigned to %s via %s", result.AssignedAgent, result.Provider),
		Reasoning:  result.Reasoning,
		Confidence: result.Confidence,
		Timestamp:  time.Now(),
		CallerID:   req.CallerId,
	})

	return &pb.ArbitrateResponse{
		Result: &pb.ArbitrationResult{
			TaskId:        result.TaskID,
			AssignedAgent: result.AssignedAgent,
			Provider:      result.Provider,
			Confidence:    result.Confidence,
			Reasoning:     result.Reasoning,
			Metadata:      result.Metadata,
			TraceId:       result.TraceID,
			Timestamp:     result.Timestamp.Unix(),
		},
		StatusCode: int32(codes.OK),
	}, nil
}

// CommitTask handles task commitment syscalls with error redaction
func (h *coreHandler) CommitTask(ctx context.Context, req *pb.CommitTaskRequest) (*pb.CommitTaskResponse, error) {
	startTime := time.Now()
	operation := "commit_task"

	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, h.config.ArbitrationTimeout)
	defer cancel()

	// Validate request
	if req.Task == nil || req.AgentId == "" {
		err := fmt.Errorf("task and agent_id are required")
		redactedErr := h.errorRedactor.RedactError(ctx, err, operation, req.CallerId)
		return &pb.CommitTaskResponse{
			Error:      redactedErr.Error(),
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}

	// Validate agent ID
	if err := h.config.ValidateAgentID(req.AgentId); err != nil {
		redactedErr := h.errorRedactor.RedactError(ctx, err, operation, req.CallerId)
		return &pb.CommitTaskResponse{
			Error:      redactedErr.Error(),
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}

	// Convert and commit task
	task := &arbitration.Task{
		ID:           req.Task.Id,
		Description:  req.Task.Description,
		Requirements: req.Task.Requirements,
		Metadata:     req.Task.Metadata,
		Priority:     req.Task.Priority,
		Deadline:     time.Unix(req.Task.Deadline, 0),
		Type:         convertTaskType(req.Task.Type),
		AgentID:      req.Task.AgentId,
	}

	commitID, err := h.arbitrationEngine.CommitTask(ctx, task, req.AgentId)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			err = NewTimeoutError(operation)
		}

		// H-5: Use RedactError for all errors
		redactedErr := h.errorRedactor.RedactError(ctx, err, operation, req.CallerId)
		return &pb.CommitTaskResponse{
			Error:      redactedErr.Error(),
			StatusCode: int32(codes.Internal),
		}, nil
	}

	// Record metrics
	latency := time.Since(startTime)
	recordSyscallMetrics(operation, latency, true)

	return &pb.CommitTaskResponse{
		TaskId:     req.Task.Id,
		CommitId:   commitID,
		StatusCode: int32(codes.OK),
	}, nil
}

// TaskRollback handles task rollback syscalls
func (h *coreHandler) TaskRollback(ctx context.Context, req *pb.TaskRollbackRequest) (*pb.TaskRollbackResponse, error) {
	startTime := time.Now()
	operation := "task_rollback"

	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, h.config.ArbitrationTimeout)
	defer cancel()

	// Validate request
	if req.TaskId == "" {
		err := fmt.Errorf("task_id is required")
		redactedErr := h.errorRedactor.RedactError(ctx, err, operation, req.CallerId)
		return &pb.TaskRollbackResponse{
			Error:      redactedErr.Error(),
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}

	// Perform rollback
	err := h.arbitrationEngine.RollbackTask(ctx, req.TaskId, req.Reason)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			err = NewTimeoutError(operation)
		}

		// H-5: Use RedactError for all errors
		redactedErr := h.errorRedactor.RedactError(ctx, err, operation, req.CallerId)
		return &pb.TaskRollbackResponse{
			Error:      redactedErr.Error(),
			StatusCode: int32(codes.Internal),
		}, nil
	}

	// Record metrics
	latency := time.Since(startTime)
	recordSyscallMetrics(operation, latency, true)

	return &pb.TaskRollbackResponse{
		TaskId:     req.TaskId,
		StatusCode: int32(codes.OK),
	}, nil
}

// AgentRegister handles agent registration syscalls
func (h *coreHandler) AgentRegister(ctx context.Context, req *pb.AgentRegisterRequest) (*pb.AgentRegisterResponse, error) {
	startTime := time.Now()
	operation := "agent_register"

	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, h.config.SyscallTimeout)
	defer cancel()

	// Validate request
	if req.AgentId == "" {
		err := fmt.Errorf("agent_id is required")
		redactedErr := h.errorRedactor.RedactError(ctx, err, operation, req.CallerId)
		return &pb.AgentRegisterResponse{
			Error:      redactedErr.Error(),
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}

	// Validate agent ID
	if err := h.config.ValidateAgentID(req.AgentId); err != nil {
		redactedErr := h.errorRedactor.RedactError(ctx, err, operation, req.CallerId)
		return &pb.AgentRegisterResponse{
			Error:      redactedErr.Error(),
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}

	// Register agent
	err := h.arbitrationEngine.RegisterAgent(ctx, req.AgentId, req.Capabilities, req.Metadata)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			err = NewTimeoutError(operation)
		}

		// H-5: Use RedactError for all errors
		redactedErr := h.errorRedactor.RedactError(ctx, err, operation, req.CallerId)
		return &pb.AgentRegisterResponse{
			Error:      redactedErr.Error(),
			StatusCode: int32(codes.Internal),
		}, nil
	}

	// Record metrics
	latency := time.Since(startTime)
	recordSyscallMetrics(operation, latency, true)

	return &pb.AgentRegisterResponse{
		AgentId:    req.AgentId,
		StatusCode: int32(codes.OK),
	}, nil
}

// QueryPolicy handles policy query syscalls
func (h *coreHandler) QueryPolicy(ctx context.Context, req *pb.QueryPolicyRequest) (*pb.QueryPolicyResponse, error) {
	startTime := time.Now()
	operation := "query_policy"

	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, h.config.SyscallTimeout)
	defer cancel()

	// Validate policy ID
	if req.PolicyId != "" {
		if err := h.config.ValidateKey(req.PolicyId); err != nil {
			err := fmt.Errorf("policy_id is required")
			redactedErr := h.errorRedactor.RedactError(ctx, err, operation, req.CallerId)
			return &pb.QueryPolicyResponse{
				Error:      redactedErr.Error(),
				StatusCode: int32(codes.InvalidArgument),
			}, nil
		}
	}

	// Query policy
	result, err := h.policyEngine.Query(ctx, req.PolicyId, req.Query, req.Context)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			err = NewTimeoutError(operation)
		}

		// H-5: Use RedactError for all errors
		redactedErr := h.errorRedactor.RedactError(ctx, err, operation, req.CallerId)
		return &pb.QueryPolicyResponse{
			Error:      redactedErr.Error(),
			StatusCode: int32(codes.Internal),
		}, nil
	}

	// Record metrics
	latency := time.Since(startTime)
	recordSyscallMetrics(operation, latency, true)

	return &pb.QueryPolicyResponse{
		Allowed:    result.Allowed,
		Reason:     result.Reason,
		StatusCode: int32(codes.OK),
	}, nil
}

// PolicyUpdate handles policy update syscalls
func (h *coreHandler) PolicyUpdate(ctx context.Context, req *pb.PolicyUpdateRequest) (*pb.PolicyUpdateResponse, error) {
	startTime := time.Now()
	operation := "policy_update"

	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, h.config.SyscallTimeout)
	defer cancel()

	// Validate request
	if req.PolicyId == "" {
		err := fmt.Errorf("policy_id is required")
		redactedErr := h.errorRedactor.RedactError(ctx, err, operation, req.CallerId)
		return &pb.PolicyUpdateResponse{
			Error:      redactedErr.Error(),
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}

	// Validate policy ID
	if err := h.config.ValidateKey(req.PolicyId); err != nil {
		redactedErr := h.errorRedactor.RedactError(ctx, err, operation, req.CallerId)
		return &pb.PolicyUpdateResponse{
			Error:      redactedErr.Error(),
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}

	// Update policy
	version, err := h.policyEngine.Update(ctx, req.PolicyId, req.PolicyData, req.Metadata)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			err = NewTimeoutError(operation)
		}

		// H-5: Use RedactError for all errors
		redactedErr := h.errorRedactor.RedactError(ctx, err, operation, req.CallerId)
		return &pb.PolicyUpdateResponse{
			Error:      redactedErr.Error(),
			StatusCode: int32(codes.Internal),
		}, nil
	}

	// Record metrics
	latency := time.Since(startTime)
	recordSyscallMetrics(operation, latency, true)

	return &pb.PolicyUpdateResponse{
		PolicyId:   req.PolicyId,
		Version:    version,
		StatusCode: int32(codes.OK),
	}, nil
}

// HealthCheck handles health check syscalls
func (h *coreHandler) HealthCheck(ctx context.Context, req *pb.HealthCheckRequest) (*pb.HealthCheckResponse, error) {
	startTime := time.Now()
	operation := "health_check"

	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, h.config.SyscallTimeout)
	defer cancel()

	// Check component health
	components := make(map[string]string)

	// Check arbitration engine
	if err := h.arbitrationEngine.HealthCheck(ctx); err != nil {
		components["arbitration"] = "unhealthy: " + err.Error()
	} else {
		components["arbitration"] = "healthy"
	}

	// Check policy engine
	if err := h.policyEngine.HealthCheck(ctx); err != nil {
		components["policy"] = "unhealthy: " + err.Error()
	} else {
		components["policy"] = "healthy"
	}

	// Determine overall status
	status := "healthy"
	for _, componentStatus := range components {
		if componentStatus != "healthy" {
			if status == "healthy" {
				status = "degraded"
			}
			if componentStatus == "unhealthy" {
				status = "unhealthy"
				break
			}
		}
	}

	// Record metrics
	latency := time.Since(startTime)
	recordSyscallMetrics(operation, latency, true)

	return &pb.HealthCheckResponse{
		Status:     status,
		Components: components,
		Timestamp:  time.Now().Unix(),
		StatusCode: int32(codes.OK),
	}, nil
}

// Helper functions
func convertTaskType(pbType pb.TaskType) arbitration.TaskType {
	switch pbType {
	case pb.TaskType_TASK_TYPE_COMPUTE:
		return arbitration.TaskTypeCompute
	case pb.TaskType_TASK_TYPE_MEMORY:
		return arbitration.TaskTypeMemory
	case pb.TaskType_TASK_TYPE_NETWORK:
		return arbitration.TaskTypeNetwork
	case pb.TaskType_TASK_TYPE_STORAGE:
		return arbitration.TaskTypeStorage
	case pb.TaskType_TASK_TYPE_COGNITIVE:
		return arbitration.TaskTypeCognitive
	default:
		return arbitration.TaskTypeUnknown
	}
}

func recordSyscallMetrics(syscallName string, latency time.Duration, success bool) {
	// Implementation for metrics recording
	// This would integrate with your metrics system (Prometheus, etc.)
}
