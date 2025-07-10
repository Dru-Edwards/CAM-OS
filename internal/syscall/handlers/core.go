package handlers

import (
	"context"
	"fmt"
	"time"

	"github.com/cam-os/kernel/internal/arbitration"
	"github.com/cam-os/kernel/internal/explainability"
	"github.com/cam-os/kernel/internal/policy"
	pb "github.com/cam-os/kernel/proto/generated"
	"google.golang.org/grpc/codes"
)

// Config represents the configuration for handlers
type Config struct {
	SyscallTimeout     time.Duration
	ArbitrationTimeout time.Duration
	RedactErrorDetails bool
}

// ErrorSanitizer handles error sanitization
type ErrorSanitizer struct {
	redactDetails bool
}

// NewErrorSanitizer creates a new error sanitizer
func NewErrorSanitizer(redactDetails bool) *ErrorSanitizer {
	return &ErrorSanitizer{redactDetails: redactDetails}
}

// SanitizeError sanitizes errors for external consumption
func (e *ErrorSanitizer) SanitizeError(err error, operation, callerID string) (codes.Code, string) {
	if err == nil {
		return codes.OK, ""
	}
	
	// Check for timeout errors
	if err.Error() == "operation timed out" {
		return codes.DeadlineExceeded, "operation timed out"
	}
	
	// If redaction is enabled, return generic error
	if e.redactDetails {
		return codes.Internal, "internal error occurred"
	}
	
	// Return original error
	return codes.Internal, err.Error()
}

// ValidateAgentID validates agent ID format
func (c *Config) ValidateAgentID(agentID string) error {
	if len(agentID) == 0 {
		return fmt.Errorf("agent ID cannot be empty")
	}
	if len(agentID) > 255 {
		return fmt.Errorf("agent ID too long")
	}
	return nil
}

// ValidateKey validates key format
func (c *Config) ValidateKey(key string) error {
	if len(key) == 0 {
		return fmt.Errorf("key cannot be empty")
	}
	if len(key) > 255 {
		return fmt.Errorf("key too long")
	}
	return nil
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

// coreHandler implements CoreHandler interface
type coreHandler struct {
	arbitrationEngine   *arbitration.Engine
	policyEngine       *policy.Engine
	explainabilityEngine *explainability.Engine
	config             *Config
	errorSanitizer     *ErrorSanitizer
}

// NewCoreHandler creates a new core handler
func NewCoreHandler(
	arbitrationEngine *arbitration.Engine,
	policyEngine *policy.Engine,
	explainabilityEngine *explainability.Engine,
	config *Config,
	errorSanitizer *ErrorSanitizer,
) CoreHandler {
	return &coreHandler{
		arbitrationEngine:   arbitrationEngine,
		policyEngine:       policyEngine,
		explainabilityEngine: explainabilityEngine,
		config:             config,
		errorSanitizer:     errorSanitizer,
	}
}

// Arbitrate handles arbitration syscalls with timeout and validation
func (h *coreHandler) Arbitrate(ctx context.Context, req *pb.ArbitrateRequest) (*pb.ArbitrateResponse, error) {
	startTime := time.Now()
	operation := "arbitrate"
	
	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, h.config.ArbitrationTimeout)
	defer cancel()
	
	// Validate request
	if req.Task == nil {
		return &pb.ArbitrateResponse{
			Error:      "task is required",
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}
	
	// Validate agent ID if present
	if req.Task.AgentId != "" {
		if err := h.config.ValidateAgentID(req.Task.AgentId); err != nil {
			return &pb.ArbitrateResponse{
				Error:      err.Error(),
				StatusCode: int32(codes.InvalidArgument),
			}, nil
		}
	}
	
	// Validate policy ID if present
	if req.PolicyId != "" {
		if err := h.config.ValidateKey(req.PolicyId); err != nil {
			return &pb.ArbitrateResponse{
				Error:      err.Error(),
				StatusCode: int32(codes.InvalidArgument),
			}, nil
		}
	}
	
	// Convert protobuf task to internal task
	task := &arbitration.Task{
		ID:          req.Task.Id,
		Description: req.Task.Description,
		Requirements: req.Task.Requirements,
		Metadata:    req.Task.Metadata,
		Priority:    req.Task.Priority,
		Deadline:    time.Unix(req.Task.Deadline, 0),
		Type:        convertTaskType(req.Task.Type),
		AgentID:     req.Task.AgentId,
	}
	
	// Perform arbitration with timeout protection
	result, err := h.arbitrationEngine.Arbitrate(ctx, task, req.PolicyId)
	if err != nil {
		// Handle context timeout
		if ctx.Err() == context.DeadlineExceeded {
			err = NewTimeoutError(operation)
		}
		
		code, message := h.errorSanitizer.SanitizeError(err, operation, req.CallerId)
		return &pb.ArbitrateResponse{
			Error:      message,
			StatusCode: int32(code),
		}, nil
	}
	
	// Record performance metrics
	latency := time.Since(startTime)
	recordSyscallMetrics(operation, latency, true)
	
	// Create audit trail
	h.explainabilityEngine.RecordDecision(ctx, &explainability.Decision{
		TraceID:     result.TraceID,
		TaskID:      result.TaskID,
		AgentID:     result.AssignedAgent,
		Decision:    fmt.Sprintf("Assigned to %s via %s", result.AssignedAgent, result.Provider),
		Reasoning:   result.Reasoning,
		Confidence:  result.Confidence,
		Timestamp:   time.Now(),
		CallerID:    req.CallerId,
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

// CommitTask handles task commitment syscalls
func (h *coreHandler) CommitTask(ctx context.Context, req *pb.CommitTaskRequest) (*pb.CommitTaskResponse, error) {
	startTime := time.Now()
	operation := "commit_task"
	
	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, h.config.ArbitrationTimeout)
	defer cancel()
	
	// Validate request
	if req.Task == nil || req.AgentId == "" {
		return &pb.CommitTaskResponse{
			Error:      "task and agent_id are required",
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}
	
	// Validate agent ID
	if err := h.config.ValidateAgentID(req.AgentId); err != nil {
		return &pb.CommitTaskResponse{
			Error:      err.Error(),
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}
	
	// Convert and commit task
	task := &arbitration.Task{
		ID:          req.Task.Id,
		Description: req.Task.Description,
		Requirements: req.Task.Requirements,
		Metadata:    req.Task.Metadata,
		Priority:    req.Task.Priority,
		Deadline:    time.Unix(req.Task.Deadline, 0),
		Type:        convertTaskType(req.Task.Type),
		AgentID:     req.Task.AgentId,
	}
	
	commitID, err := h.arbitrationEngine.CommitTask(ctx, task, req.AgentId)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			err = NewTimeoutError(operation)
		}
		
		code, message := h.errorSanitizer.SanitizeError(err, operation, req.CallerId)
		return &pb.CommitTaskResponse{
			Error:      message,
			StatusCode: int32(code),
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
		return &pb.TaskRollbackResponse{
			Error:      "task_id is required",
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}
	
	// Perform rollback
	err := h.arbitrationEngine.RollbackTask(ctx, req.TaskId, req.Reason)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			err = NewTimeoutError(operation)
		}
		
		code, message := h.errorSanitizer.SanitizeError(err, operation, req.CallerId)
		return &pb.TaskRollbackResponse{
			Error:      message,
			StatusCode: int32(code),
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
		return &pb.AgentRegisterResponse{
			Error:      "agent_id is required",
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}
	
	// Validate agent ID
	if err := h.config.ValidateAgentID(req.AgentId); err != nil {
		return &pb.AgentRegisterResponse{
			Error:      err.Error(),
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}
	
	// Register agent
	err := h.arbitrationEngine.RegisterAgent(ctx, req.AgentId, req.Capabilities, req.Metadata)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			err = NewTimeoutError(operation)
		}
		
		code, message := h.errorSanitizer.SanitizeError(err, operation, req.CallerId)
		return &pb.AgentRegisterResponse{
			Error:      message,
			StatusCode: int32(code),
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
			return &pb.QueryPolicyResponse{
				Error:      err.Error(),
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
		
		code, message := h.errorSanitizer.SanitizeError(err, operation, req.CallerId)
		return &pb.QueryPolicyResponse{
			Error:      message,
			StatusCode: int32(code),
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
		return &pb.PolicyUpdateResponse{
			Error:      "policy_id is required",
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}
	
	// Validate policy ID
	if err := h.config.ValidateKey(req.PolicyId); err != nil {
		return &pb.PolicyUpdateResponse{
			Error:      err.Error(),
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}
	
	// Update policy
	version, err := h.policyEngine.Update(ctx, req.PolicyId, req.PolicyData, req.Metadata)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			err = NewTimeoutError(operation)
		}
		
		code, message := h.errorSanitizer.SanitizeError(err, operation, req.CallerId)
		return &pb.PolicyUpdateResponse{
			Error:      message,
			StatusCode: int32(code),
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