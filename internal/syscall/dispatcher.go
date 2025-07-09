package syscall

import (
	"context"
	"fmt"
	"time"

	"github.com/cam-os/kernel/internal/arbitration"
	"github.com/cam-os/kernel/internal/explainability"
	"github.com/cam-os/kernel/internal/memory"
	"github.com/cam-os/kernel/internal/policy"
	"github.com/cam-os/kernel/internal/security"
	pb "github.com/cam-os/kernel/proto/generated"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Config holds the syscall dispatcher configuration
type Config struct {
	ArbitrationEngine   *arbitration.Engine
	MemoryManager      *memory.ContextManager
	PolicyEngine       *policy.Engine
	SecurityManager    *security.Manager
	ExplainabilityEngine *explainability.Engine
}

// Dispatcher handles all syscall requests - Enhanced for CAM-OS Fork v1.1
type Dispatcher struct {
	pb.UnimplementedSyscallServiceServer
	
	arbitrationEngine   *arbitration.Engine
	memoryManager      *memory.ContextManager
	policyEngine       *policy.Engine
	securityManager    *security.Manager
	explainabilityEngine *explainability.Engine
}

// NewDispatcher creates a new syscall dispatcher
func NewDispatcher(config *Config) *Dispatcher {
	return &Dispatcher{
		arbitrationEngine:   config.ArbitrationEngine,
		memoryManager:      config.MemoryManager,
		policyEngine:       config.PolicyEngine,
		securityManager:    config.SecurityManager,
		explainabilityEngine: config.ExplainabilityEngine,
	}
}

// Arbitrate handles arbitration syscalls
func (d *Dispatcher) Arbitrate(ctx context.Context, req *pb.ArbitrateRequest) (*pb.ArbitrateResponse, error) {
	startTime := time.Now()
	
	// Validate request
	if req.Task == nil {
		return &pb.ArbitrateResponse{
			Error:      "task is required",
			StatusCode: int32(codes.InvalidArgument),
		}, nil
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
	
	// Perform arbitration
	result, err := d.arbitrationEngine.Arbitrate(ctx, task, req.PolicyId)
	if err != nil {
		return &pb.ArbitrateResponse{
			Error:      err.Error(),
			StatusCode: int32(codes.Internal),
		}, nil
	}
	
	// Record performance metrics
	latency := time.Since(startTime)
	d.recordSyscallMetrics("arbitrate", latency, err == nil)
	
	// Create audit trail
	d.explainabilityEngine.RecordDecision(ctx, &explainability.Decision{
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
func (d *Dispatcher) CommitTask(ctx context.Context, req *pb.CommitTaskRequest) (*pb.CommitTaskResponse, error) {
	startTime := time.Now()
	
	// Validate request
	if req.Task == nil || req.AgentId == "" {
		return &pb.CommitTaskResponse{
			Error:      "task and agent_id are required",
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
	
	commitID, err := d.arbitrationEngine.CommitTask(ctx, task, req.AgentId)
	if err != nil {
		return &pb.CommitTaskResponse{
			Error:      err.Error(),
			StatusCode: int32(codes.Internal),
		}, nil
	}
	
	// Record metrics
	latency := time.Since(startTime)
	d.recordSyscallMetrics("commit_task", latency, err == nil)
	
	return &pb.CommitTaskResponse{
		TaskId:     req.Task.Id,
		CommitId:   commitID,
		StatusCode: int32(codes.OK),
	}, nil
}

// QueryPolicy handles policy query syscalls
func (d *Dispatcher) QueryPolicy(ctx context.Context, req *pb.QueryPolicyRequest) (*pb.QueryPolicyResponse, error) {
	startTime := time.Now()
	
	// Query policy
	result, err := d.policyEngine.Query(ctx, req.PolicyId, req.Query, req.Context)
	if err != nil {
		return &pb.QueryPolicyResponse{
			Error:      err.Error(),
			StatusCode: int32(codes.Internal),
		}, nil
	}
	
	// Record metrics
	latency := time.Since(startTime)
	d.recordSyscallMetrics("query_policy", latency, err == nil)
	
	return &pb.QueryPolicyResponse{
		Allowed:    result.Allowed,
		Reason:     result.Reason,
		StatusCode: int32(codes.OK),
	}, nil
}

// ExplainAction handles explanation syscalls
func (d *Dispatcher) ExplainAction(ctx context.Context, req *pb.ExplainActionRequest) (*pb.ExplainActionResponse, error) {
	startTime := time.Now()
	
	// Get explanation
	explanation, err := d.explainabilityEngine.Explain(ctx, req.TraceId, req.IncludeReasoning)
	if err != nil {
		return &pb.ExplainActionResponse{
			Error:      err.Error(),
			StatusCode: int32(codes.Internal),
		}, nil
	}
	
	// Record metrics
	latency := time.Since(startTime)
	d.recordSyscallMetrics("explain_action", latency, err == nil)
	
	return &pb.ExplainActionResponse{
		Explanation:    explanation.Explanation,
		ReasoningChain: explanation.ReasoningChain,
		Evidence:       explanation.Evidence,
		StatusCode:     int32(codes.OK),
	}, nil
}

// ContextRead handles context read syscalls
func (d *Dispatcher) ContextRead(ctx context.Context, req *pb.ContextReadRequest) (*pb.ContextReadResponse, error) {
	startTime := time.Now()
	
	// Read context data
	data, err := d.memoryManager.Read(ctx, req.Namespace, req.Key, req.Version)
	if err != nil {
		return &pb.ContextReadResponse{
			Error:      err.Error(),
			StatusCode: int32(codes.Internal),
		}, nil
	}
	
	// Record metrics
	latency := time.Since(startTime)
	d.recordSyscallMetrics("context_read", latency, err == nil)
	
	return &pb.ContextReadResponse{
		Data:       data.Data,
		Version:    data.Version,
		Hash:       data.Hash,
		StatusCode: int32(codes.OK),
	}, nil
}

// ContextWrite handles context write syscalls
func (d *Dispatcher) ContextWrite(ctx context.Context, req *pb.ContextWriteRequest) (*pb.ContextWriteResponse, error) {
	startTime := time.Now()
	
	// Write context data
	result, err := d.memoryManager.Write(ctx, req.Namespace, req.Key, req.Data, req.Metadata)
	if err != nil {
		return &pb.ContextWriteResponse{
			Error:      err.Error(),
			StatusCode: int32(codes.Internal),
		}, nil
	}
	
	// Record metrics
	latency := time.Since(startTime)
	d.recordSyscallMetrics("context_write", latency, err == nil)
	
	return &pb.ContextWriteResponse{
		Version:    result.Version,
		Hash:       result.Hash,
		StatusCode: int32(codes.OK),
	}, nil
}

// ContextSnapshot handles context snapshot syscalls
func (d *Dispatcher) ContextSnapshot(ctx context.Context, req *pb.ContextSnapshotRequest) (*pb.ContextSnapshotResponse, error) {
	startTime := time.Now()
	
	// Create snapshot
	snapshotID, err := d.memoryManager.Snapshot(ctx, req.Namespace, req.Description)
	if err != nil {
		return &pb.ContextSnapshotResponse{
			Error:      err.Error(),
			StatusCode: int32(codes.Internal),
		}, nil
	}
	
	// Record metrics
	latency := time.Since(startTime)
	d.recordSyscallMetrics("context_snapshot", latency, err == nil)
	
	return &pb.ContextSnapshotResponse{
		SnapshotId: snapshotID,
		Timestamp:  time.Now().Unix(),
		StatusCode: int32(codes.OK),
	}, nil
}

// ContextRestore handles context restore syscalls
func (d *Dispatcher) ContextRestore(ctx context.Context, req *pb.ContextRestoreRequest) (*pb.ContextRestoreResponse, error) {
	startTime := time.Now()
	
	// Restore from snapshot
	result, err := d.memoryManager.Restore(ctx, req.SnapshotId, req.Force)
	if err != nil {
		return &pb.ContextRestoreResponse{
			Error:      err.Error(),
			StatusCode: int32(codes.Internal),
		}, nil
	}
	
	// Record metrics
	latency := time.Since(startTime)
	d.recordSyscallMetrics("context_restore", latency, err == nil)
	
	return &pb.ContextRestoreResponse{
		Namespace:     result.Namespace,
		RestoredItems: result.RestoredItems,
		StatusCode:    int32(codes.OK),
	}, nil
}

// TpmSign handles TPM signing syscalls
func (d *Dispatcher) TpmSign(ctx context.Context, req *pb.TmpSignRequest) (*pb.TmpSignResponse, error) {
	startTime := time.Now()
	
	// Sign data with TPM
	signature, algorithm, err := d.securityManager.TpmSign(ctx, req.Data, req.KeyId)
	if err != nil {
		return &pb.TmpSignResponse{
			Error:      err.Error(),
			StatusCode: int32(codes.Internal),
		}, nil
	}
	
	// Record metrics
	latency := time.Since(startTime)
	d.recordSyscallMetrics("tpm_sign", latency, err == nil)
	
	return &pb.TmpSignResponse{
		Signature:  signature,
		Algorithm:  algorithm,
		StatusCode: int32(codes.OK),
	}, nil
}

// VerifyManifest handles manifest verification syscalls
func (d *Dispatcher) VerifyManifest(ctx context.Context, req *pb.VerifyManifestRequest) (*pb.VerifyManifestResponse, error) {
	startTime := time.Now()
	
	// Verify manifest
	result, err := d.securityManager.VerifyManifest(ctx, req.Manifest, req.Signature, req.PublicKey)
	if err != nil {
		return &pb.VerifyManifestResponse{
			Error:      err.Error(),
			StatusCode: int32(codes.Internal),
		}, nil
	}
	
	// Record metrics
	latency := time.Since(startTime)
	d.recordSyscallMetrics("verify_manifest", latency, err == nil)
	
	return &pb.VerifyManifestResponse{
		Valid:      result.Valid,
		Issuer:     result.Issuer,
		ExpiresAt:  result.ExpiresAt.Unix(),
		StatusCode: int32(codes.OK),
	}, nil
}

// EstablishSecureChannel handles secure channel establishment
func (d *Dispatcher) EstablishSecureChannel(ctx context.Context, req *pb.EstablishSecureChannelRequest) (*pb.EstablishSecureChannelResponse, error) {
	startTime := time.Now()
	
	// Establish secure channel
	channelID, sessionKey, err := d.securityManager.EstablishSecureChannel(ctx, req.PeerId, req.Protocol)
	if err != nil {
		return &pb.EstablishSecureChannelResponse{
			Error:      err.Error(),
			StatusCode: int32(codes.Internal),
		}, nil
	}
	
	// Record metrics
	latency := time.Since(startTime)
	d.recordSyscallMetrics("establish_secure_channel", latency, err == nil)
	
	return &pb.EstablishSecureChannelResponse{
		ChannelId:  channelID,
		SessionKey: sessionKey,
		StatusCode: int32(codes.OK),
	}, nil
}

// EmitTrace handles trace emission syscalls
func (d *Dispatcher) EmitTrace(ctx context.Context, req *pb.EmitTraceRequest) (*pb.EmitTraceResponse, error) {
	startTime := time.Now()
	
	// Emit trace
	err := d.explainabilityEngine.EmitTrace(ctx, &explainability.TraceEvent{
		TraceID:       req.TraceId,
		SpanID:        req.SpanId,
		OperationName: req.OperationName,
		StartTime:     time.Unix(0, req.StartTime),
		EndTime:       time.Unix(0, req.EndTime),
		Tags:          req.Tags,
	})
	if err != nil {
		return &pb.EmitTraceResponse{
			Error:      err.Error(),
			StatusCode: int32(codes.Internal),
		}, nil
	}
	
	// Record metrics
	latency := time.Since(startTime)
	d.recordSyscallMetrics("emit_trace", latency, err == nil)
	
	return &pb.EmitTraceResponse{
		TraceId:    req.TraceId,
		StatusCode: int32(codes.OK),
	}, nil
}

// EmitMetric handles metric emission syscalls
func (d *Dispatcher) EmitMetric(ctx context.Context, req *pb.EmitMetricRequest) (*pb.EmitMetricResponse, error) {
	startTime := time.Now()
	
	// Emit metric
	metricID, err := d.explainabilityEngine.EmitMetric(ctx, &explainability.MetricEvent{
		Name:      req.Name,
		Value:     req.Value,
		Type:      req.Type,
		Labels:    req.Labels,
		Timestamp: time.Unix(0, req.Timestamp),
	})
	if err != nil {
		return &pb.EmitMetricResponse{
			Error:      err.Error(),
			StatusCode: int32(codes.Internal),
		}, nil
	}
	
	// Record metrics
	latency := time.Since(startTime)
	d.recordSyscallMetrics("emit_metric", latency, err == nil)
	
	return &pb.EmitMetricResponse{
		MetricId:   metricID,
		StatusCode: int32(codes.OK),
	}, nil
}

// HealthCheck handles health check syscalls
func (d *Dispatcher) HealthCheck(ctx context.Context, req *pb.HealthCheckRequest) (*pb.HealthCheckResponse, error) {
	startTime := time.Now()
	
	// Check component health
	components := make(map[string]string)
	
	// Check arbitration engine
	if err := d.arbitrationEngine.HealthCheck(ctx); err != nil {
		components["arbitration"] = "unhealthy: " + err.Error()
	} else {
		components["arbitration"] = "healthy"
	}
	
	// Check memory manager
	if err := d.memoryManager.HealthCheck(ctx); err != nil {
		components["memory"] = "unhealthy: " + err.Error()
	} else {
		components["memory"] = "healthy"
	}
	
	// Check policy engine
	if err := d.policyEngine.HealthCheck(ctx); err != nil {
		components["policy"] = "unhealthy: " + err.Error()
	} else {
		components["policy"] = "healthy"
	}
	
	// Check security manager
	if err := d.securityManager.HealthCheck(ctx); err != nil {
		components["security"] = "unhealthy: " + err.Error()
	} else {
		components["security"] = "healthy"
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
	d.recordSyscallMetrics("health_check", latency, true)
	
	return &pb.HealthCheckResponse{
		Status:     status,
		Components: components,
		Timestamp:  time.Now().Unix(),
		StatusCode: int32(codes.OK),
	}, nil
}

// Implement missing syscalls with placeholders
func (d *Dispatcher) SnapshotContext(ctx context.Context, req *pb.SnapshotContextRequest) (*pb.SnapshotContextResponse, error) {
	// This is a duplicate of ContextSnapshot - redirecting
	return d.ContextSnapshot(ctx, &pb.ContextSnapshotRequest{
		Namespace: req.Namespace,
		CallerId:  req.CallerId,
		Description: "",
	})
}

// Fork expansion syscalls (new cognitive verbs)

// TaskRollback handles task rollback syscalls
func (d *Dispatcher) TaskRollback(ctx context.Context, req *pb.TaskRollbackRequest) (*pb.TaskRollbackResponse, error) {
	startTime := time.Now()
	
	// Validate request
	if req.TaskId == "" || req.CommitId == "" || req.RollbackToken == "" {
		return &pb.TaskRollbackResponse{
			Success:    false,
			Error:      "task_id, commit_id, and rollback_token are required",
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}
	
	// Perform rollback
	rollbackID, err := d.arbitrationEngine.RollbackTask(ctx, req.TaskId, req.CommitId, req.RollbackToken, req.Reason)
	if err != nil {
		return &pb.TaskRollbackResponse{
			Success:    false,
			Error:      err.Error(),
			StatusCode: int32(codes.Internal),
		}, nil
	}
	
	// Record metrics
	latency := time.Since(startTime)
	d.recordSyscallMetrics("task_rollback", latency, err == nil)
	
	// Create audit trail
	d.explainabilityEngine.RecordDecision(ctx, &explainability.Decision{
		TraceID:     fmt.Sprintf("rollback-%s", rollbackID),
		TaskID:      req.TaskId,
		Decision:    fmt.Sprintf("Task %s rolled back from commit %s", req.TaskId, req.CommitId),
		Reasoning:   req.Reason,
		Confidence:  1.0,
		Timestamp:   time.Now(),
		CallerID:    req.CallerId,
	})
	
	return &pb.TaskRollbackResponse{
		Success:    true,
		RollbackId: rollbackID,
		StatusCode: int32(codes.OK),
		Result: &pb.RollbackResult{
			PreviousState:      fmt.Sprintf("committed:%s", req.CommitId),
			CurrentState:       "rolled_back",
			AffectedResources:  []string{req.TaskId},
			RollbackTimestamp:  time.Now().Unix(),
		},
	}, nil
}

// PolicyUpdate handles policy update syscalls
func (d *Dispatcher) PolicyUpdate(ctx context.Context, req *pb.PolicyUpdateRequest) (*pb.PolicyUpdateResponse, error) {
	startTime := time.Now()
	
	// Validate request
	if req.PolicyId == "" || req.PolicyContent == "" {
		return &pb.PolicyUpdateResponse{
			Success:    false,
			Error:      "policy_id and policy_content are required",
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}
	
	// Update policy
	policyVersion, validationErrors, warnings, err := d.policyEngine.UpdatePolicy(ctx, req.PolicyId, req.PolicyContent, req.PolicyLanguage, req.DryRun)
	if err != nil {
		return &pb.PolicyUpdateResponse{
			Success:    false,
			Error:      err.Error(),
			StatusCode: int32(codes.Internal),
		}, nil
	}
	
	// Record metrics
	latency := time.Since(startTime)
	d.recordSyscallMetrics("policy_update", latency, err == nil)
	
	// Create audit trail
	d.explainabilityEngine.RecordDecision(ctx, &explainability.Decision{
		TraceID:     fmt.Sprintf("policy-update-%s", req.PolicyId),
		TaskID:      req.PolicyId,
		Decision:    fmt.Sprintf("Policy %s updated to version %s", req.PolicyId, policyVersion),
		Reasoning:   fmt.Sprintf("Policy update requested by %s", req.CallerId),
		Confidence:  1.0,
		Timestamp:   time.Now(),
		CallerID:    req.CallerId,
	})
	
	return &pb.PolicyUpdateResponse{
		Success:       true,
		PolicyVersion: policyVersion,
		StatusCode:    int32(codes.OK),
		Result: &pb.PolicyUpdateResult{
			ValidationErrors: validationErrors,
			Warnings:        warnings,
			ImpactAnalysis:  map[string]string{"affected_agents": "all", "reload_required": "true"},
			RequiresRestart: len(validationErrors) == 0 && !req.DryRun,
		},
	}, nil
}

// AgentRegister handles agent registration syscalls
func (d *Dispatcher) AgentRegister(ctx context.Context, req *pb.AgentRegisterRequest) (*pb.AgentRegisterResponse, error) {
	startTime := time.Now()
	
	// Validate request
	if req.AgentId == "" || req.AgentName == "" {
		return &pb.AgentRegisterResponse{
			Success:    false,
			Error:      "agent_id and agent_name are required",
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}
	
	// Register agent
	registrationID, grantedCapabilities, deniedCapabilities, expiresAt, err := d.arbitrationEngine.RegisterAgent(ctx, req.AgentId, req.AgentName, req.Capabilities, req.Metadata, req.Spec)
	if err != nil {
		return &pb.AgentRegisterResponse{
			Success:    false,
			Error:      err.Error(),
			StatusCode: int32(codes.Internal),
		}, nil
	}
	
	// Record metrics
	latency := time.Since(startTime)
	d.recordSyscallMetrics("agent_register", latency, err == nil)
	
	// Create audit trail
	d.explainabilityEngine.RecordDecision(ctx, &explainability.Decision{
		TraceID:     fmt.Sprintf("agent-register-%s", req.AgentId),
		TaskID:      req.AgentId,
		AgentID:     req.AgentId,
		Decision:    fmt.Sprintf("Agent %s registered with ID %s", req.AgentName, registrationID),
		Reasoning:   fmt.Sprintf("Agent registration requested by %s", req.CallerId),
		Confidence:  1.0,
		Timestamp:   time.Now(),
		CallerID:    req.CallerId,
	})
	
	return &pb.AgentRegisterResponse{
		Success:        true,
		RegistrationId: registrationID,
		StatusCode:     int32(codes.OK),
		Result: &pb.AgentRegistrationResult{
			AssignedId:            registrationID,
			GrantedCapabilities:   grantedCapabilities,
			DeniedCapabilities:    deniedCapabilities,
			RegistrationTimestamp: time.Now().Unix(),
			ExpiresAt:            expiresAt.Unix(),
		},
	}, nil
}

// ContextVersionList handles context version listing syscalls
func (d *Dispatcher) ContextVersionList(ctx context.Context, req *pb.ContextVersionListRequest) (*pb.ContextVersionListResponse, error) {
	startTime := time.Now()
	
	// Validate request
	if req.Namespace == "" || req.Key == "" {
		return &pb.ContextVersionListResponse{
			Error:      "namespace and key are required",
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}
	
	// List versions
	versions, hasMore, nextToken, err := d.memoryManager.ListVersions(ctx, req.Namespace, req.Key, req.Limit, req.SinceVersion)
	if err != nil {
		return &pb.ContextVersionListResponse{
			Error:      err.Error(),
			StatusCode: int32(codes.Internal),
		}, nil
	}
	
	// Convert to protobuf format
	pbVersions := make([]*pb.ContextVersion, len(versions))
	for i, v := range versions {
		pbVersions[i] = &pb.ContextVersion{
			Version:     v.Version,
			Timestamp:   v.Timestamp.Unix(),
			Author:      v.Author,
			Description: v.Description,
			Hash:        v.Hash,
		}
	}
	
	// Record metrics
	latency := time.Since(startTime)
	d.recordSyscallMetrics("context_version_list", latency, err == nil)
	
	return &pb.ContextVersionListResponse{
		Versions:   pbVersions,
		StatusCode: int32(codes.OK),
		HasMore:    hasMore,
		NextToken:  nextToken,
	}, nil
}

// SystemTuning handles system tuning syscalls
func (d *Dispatcher) SystemTuning(ctx context.Context, req *pb.SystemTuningRequest) (*pb.SystemTuningResponse, error) {
	startTime := time.Now()
	
	// Validate request
	if len(req.Parameters) == 0 && req.TuningProfile == "" {
		return &pb.SystemTuningResponse{
			Success:    false,
			Error:      "either parameters or tuning_profile must be specified",
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}
	
	// Apply system tuning
	appliedChanges, performanceImpact, recommendations, requiresRestart, err := d.applySystemTuning(ctx, req.Parameters, req.TuningProfile, req.DryRun)
	if err != nil {
		return &pb.SystemTuningResponse{
			Success:    false,
			Error:      err.Error(),
			StatusCode: int32(codes.Internal),
		}, nil
	}
	
	// Record metrics
	latency := time.Since(startTime)
	d.recordSyscallMetrics("system_tuning", latency, err == nil)
	
	// Create audit trail
	d.explainabilityEngine.RecordDecision(ctx, &explainability.Decision{
		TraceID:     fmt.Sprintf("system-tuning-%d", time.Now().Unix()),
		TaskID:      "system_tuning",
		Decision:    fmt.Sprintf("System tuning applied with profile %s", req.TuningProfile),
		Reasoning:   fmt.Sprintf("System tuning requested by %s", req.CallerId),
		Confidence:  1.0,
		Timestamp:   time.Now(),
		CallerID:    req.CallerId,
	})
	
	return &pb.SystemTuningResponse{
		Success:    true,
		StatusCode: int32(codes.OK),
		Result: &pb.SystemTuningResult{
			AppliedChanges:     appliedChanges,
			PerformanceImpact:  performanceImpact,
			Recommendations:    recommendations,
			RequiresRestart:    requiresRestart,
		},
	}, nil
}

// Helper function for system tuning
func (d *Dispatcher) applySystemTuning(ctx context.Context, parameters map[string]string, tuningProfile string, dryRun bool) (map[string]string, map[string]string, []string, bool, error) {
	appliedChanges := make(map[string]string)
	performanceImpact := make(map[string]string)
	recommendations := []string{}
	requiresRestart := false
	
	// Apply tuning profile
	switch tuningProfile {
	case "performance":
		appliedChanges["scheduler_priority_boost"] = "high"
		appliedChanges["memory_gc_target"] = "50"
		appliedChanges["arbitration_timeout"] = "50ms"
		performanceImpact["latency"] = "-30%"
		performanceImpact["throughput"] = "+50%"
		performanceImpact["memory_usage"] = "+20%"
		recommendations = append(recommendations, "Monitor memory usage closely")
		
	case "efficiency":
		appliedChanges["scheduler_priority_boost"] = "medium"
		appliedChanges["memory_gc_target"] = "75"
		appliedChanges["arbitration_timeout"] = "100ms"
		performanceImpact["latency"] = "stable"
		performanceImpact["throughput"] = "stable"
		performanceImpact["memory_usage"] = "-10%"
		recommendations = append(recommendations, "Balanced configuration applied")
		
	case "balanced":
		appliedChanges["scheduler_priority_boost"] = "medium"
		appliedChanges["memory_gc_target"] = "60"
		appliedChanges["arbitration_timeout"] = "75ms"
		performanceImpact["latency"] = "-10%"
		performanceImpact["throughput"] = "+15%"
		performanceImpact["memory_usage"] = "stable"
		recommendations = append(recommendations, "Optimal for most workloads")
	}
	
	// Apply custom parameters
	for key, value := range parameters {
		appliedChanges[key] = value
		switch key {
		case "max_concurrent_tasks":
			if value != "10000" {
				requiresRestart = true
			}
		case "redis_connection_pool_size":
			if value != "100" {
				requiresRestart = true
			}
		}
	}
	
	if dryRun {
		recommendations = append(recommendations, "Dry run completed - no changes applied")
		return appliedChanges, performanceImpact, recommendations, requiresRestart, nil
	}
	
	// Apply changes to actual system components
	for key, value := range appliedChanges {
		switch key {
		case "scheduler_priority_boost":
			// Apply to scheduler
			if err := d.arbitrationEngine.UpdateSchedulerConfig(ctx, map[string]interface{}{"priority_boost": value}); err != nil {
				return nil, nil, nil, false, fmt.Errorf("failed to update scheduler config: %v", err)
			}
		case "memory_gc_target":
			// Apply to memory manager
			if err := d.memoryManager.UpdateConfig(ctx, map[string]interface{}{"gc_target": value}); err != nil {
				return nil, nil, nil, false, fmt.Errorf("failed to update memory config: %v", err)
			}
		case "arbitration_timeout":
			// Apply to arbitration engine
			if err := d.arbitrationEngine.UpdateConfig(ctx, map[string]interface{}{"timeout": value}); err != nil {
				return nil, nil, nil, false, fmt.Errorf("failed to update arbitration config: %v", err)
			}
		}
	}
	
	return appliedChanges, performanceImpact, recommendations, requiresRestart, nil
}

// Helper functions

// convertTaskType converts protobuf TaskType to internal TaskType
func convertTaskType(pbType pb.TaskType) arbitration.TaskType {
	switch pbType {
	case pb.TaskType_TASK_TYPE_ARBITRATION:
		return arbitration.TaskTypeArbitration
	case pb.TaskType_TASK_TYPE_COLLABORATION:
		return arbitration.TaskTypeCollaboration
	case pb.TaskType_TASK_TYPE_ROUTING:
		return arbitration.TaskTypeRouting
	case pb.TaskType_TASK_TYPE_ANALYSIS:
		return arbitration.TaskTypeAnalysis
	default:
		return arbitration.TaskTypeArbitration
	}
}

// recordSyscallMetrics records performance metrics for syscalls
func (d *Dispatcher) recordSyscallMetrics(syscallName string, latency time.Duration, success bool) {
	// Record syscall latency
	d.explainabilityEngine.EmitMetric(context.Background(), &explainability.MetricEvent{
		Name:  "cam_syscall_latency_seconds",
		Value: latency.Seconds(),
		Type:  "histogram",
		Labels: map[string]string{
			"syscall": syscallName,
			"success": fmt.Sprintf("%t", success),
		},
		Timestamp: time.Now(),
	})
	
	// Record syscall count
	d.explainabilityEngine.EmitMetric(context.Background(), &explainability.MetricEvent{
		Name:  "cam_syscall_total",
		Value: 1,
		Type:  "counter",
		Labels: map[string]string{
			"syscall": syscallName,
			"success": fmt.Sprintf("%t", success),
		},
		Timestamp: time.Now(),
	})
} 