package handlers

import (
	"context"
	"time"

	"github.com/cam-os/kernel/internal/explainability"
	"github.com/cam-os/kernel/internal/syscall"
	pb "github.com/cam-os/kernel/proto/generated"
	"google.golang.org/grpc/codes"
)

// observabilityHandler implements ObservabilityHandler interface
type observabilityHandler struct {
	explainabilityEngine *explainability.Engine
	config               *syscall.Config
	errorSanitizer       *syscall.ErrorSanitizer
}

// NewObservabilityHandler creates a new observability handler
func NewObservabilityHandler(
	explainabilityEngine *explainability.Engine,
	config *syscall.Config,
	errorSanitizer *syscall.ErrorSanitizer,
) ObservabilityHandler {
	return &observabilityHandler{
		explainabilityEngine: explainabilityEngine,
		config:               config,
		errorSanitizer:       errorSanitizer,
	}
}

// ExplainAction handles explanation syscalls
func (h *observabilityHandler) ExplainAction(ctx context.Context, req *pb.ExplainActionRequest) (*pb.ExplainActionResponse, error) {
	startTime := time.Now()
	operation := "explain_action"
	
	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, h.config.ExplainabilityTimeout)
	defer cancel()
	
	// Validate request
	if req.TraceId == "" {
		return &pb.ExplainActionResponse{
			Error:      "trace_id is required",
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}
	
	// Validate trace ID format
	if err := h.config.ValidateKey(req.TraceId); err != nil {
		return &pb.ExplainActionResponse{
			Error:      "trace_id " + err.Error(),
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}
	
	// Get explanation
	explanation, err := h.explainabilityEngine.Explain(ctx, req.TraceId, req.IncludeReasoning)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			err = syscall.NewTimeoutError(operation)
		}
		
		code, message := h.errorSanitizer.SanitizeError(err, operation, req.CallerId)
		return &pb.ExplainActionResponse{
			Error:      message,
			StatusCode: int32(code),
		}, nil
	}
	
	// Record metrics
	latency := time.Since(startTime)
	recordSyscallMetrics(operation, latency, true)
	
	return &pb.ExplainActionResponse{
		Explanation:    explanation.Explanation,
		ReasoningChain: explanation.ReasoningChain,
		Evidence:       explanation.Evidence,
		Confidence:     explanation.Confidence,    // Enhanced: Return confidence score
		TrustScore:     explanation.TrustScore,    // Enhanced: Return trust score
		StatusCode:     int32(codes.OK),
	}, nil
}

// EmitTrace handles trace emission syscalls with rate limiting protection
func (h *observabilityHandler) EmitTrace(ctx context.Context, req *pb.EmitTraceRequest) (*pb.EmitTraceResponse, error) {
	startTime := time.Now()
	operation := "emit_trace"
	
	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, h.config.ExplainabilityTimeout)
	defer cancel()
	
	// Validate request
	if req.TraceId == "" {
		return &pb.EmitTraceResponse{
			Error:      "trace_id is required",
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}
	
	if req.OperationName == "" {
		return &pb.EmitTraceResponse{
			Error:      "operation_name is required",
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}
	
	// Validate trace ID format
	if err := h.config.ValidateKey(req.TraceId); err != nil {
		return &pb.EmitTraceResponse{
			Error:      "trace_id " + err.Error(),
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}
	
	// Validate span ID format if provided
	if req.SpanId != "" {
		if err := h.config.ValidateKey(req.SpanId); err != nil {
			return &pb.EmitTraceResponse{
				Error:      "span_id " + err.Error(),
				StatusCode: int32(codes.InvalidArgument),
			}, nil
		}
	}
	
	// Validate operation name length
	if len(req.OperationName) > 256 {
		return &pb.EmitTraceResponse{
			Error:      "operation_name too long (max 256 chars)",
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}
	
	// Validate timestamp order
	if req.EndTime > 0 && req.StartTime > 0 && req.EndTime < req.StartTime {
		return &pb.EmitTraceResponse{
			Error:      "end_time cannot be before start_time",
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}
	
	// Emit trace
	err := h.explainabilityEngine.EmitTrace(ctx, &explainability.TraceEvent{
		TraceID:       req.TraceId,
		SpanID:        req.SpanId,
		OperationName: req.OperationName,
		StartTime:     time.Unix(0, req.StartTime),
		EndTime:       time.Unix(0, req.EndTime),
		Tags:          req.Tags,
	})
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			err = syscall.NewTimeoutError(operation)
		}
		
		code, message := h.errorSanitizer.SanitizeError(err, operation, req.CallerId)
		return &pb.EmitTraceResponse{
			Error:      message,
			StatusCode: int32(code),
		}, nil
	}
	
	// Record metrics
	latency := time.Since(startTime)
	recordSyscallMetrics(operation, latency, true)
	
	return &pb.EmitTraceResponse{
		TraceId:    req.TraceId,
		StatusCode: int32(codes.OK),
	}, nil
}

// EmitMetric handles metric emission syscalls with rate limiting protection
func (h *observabilityHandler) EmitMetric(ctx context.Context, req *pb.EmitMetricRequest) (*pb.EmitMetricResponse, error) {
	startTime := time.Now()
	operation := "emit_metric"
	
	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, h.config.ExplainabilityTimeout)
	defer cancel()
	
	// Validate request
	if req.Name == "" {
		return &pb.EmitMetricResponse{
			Error:      "name is required",
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}
	
	// Validate metric name format (alphanumeric, underscore, dot)
	if len(req.Name) > 256 {
		return &pb.EmitMetricResponse{
			Error:      "name too long (max 256 chars)",
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}
	
	// Validate metric type
	validTypes := map[string]bool{
		"counter":   true,
		"gauge":     true,
		"histogram": true,
		"summary":   true,
	}
	
	if req.Type != "" && !validTypes[req.Type] {
		return &pb.EmitMetricResponse{
			Error:      "invalid metric type: " + req.Type,
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}
	
	// Validate labels count (prevent label explosion)
	if len(req.Labels) > 20 {
		return &pb.EmitMetricResponse{
			Error:      "too many labels (max 20)",
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}
	
	// Validate label values
	for key, value := range req.Labels {
		if len(key) > 128 {
			return &pb.EmitMetricResponse{
				Error:      "label key too long (max 128 chars): " + key,
				StatusCode: int32(codes.InvalidArgument),
			}, nil
		}
		if len(value) > 256 {
			return &pb.EmitMetricResponse{
				Error:      "label value too long (max 256 chars): " + key,
				StatusCode: int32(codes.InvalidArgument),
			}, nil
		}
	}
	
	// Emit metric
	metricID, err := h.explainabilityEngine.EmitMetric(ctx, &explainability.MetricEvent{
		Name:      req.Name,
		Value:     req.Value,
		Type:      req.Type,
		Labels:    req.Labels,
		Timestamp: time.Unix(0, req.Timestamp),
	})
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			err = syscall.NewTimeoutError(operation)
		}
		
		code, message := h.errorSanitizer.SanitizeError(err, operation, req.CallerId)
		return &pb.EmitMetricResponse{
			Error:      message,
			StatusCode: int32(code),
		}, nil
	}
	
	// Record metrics
	latency := time.Since(startTime)
	recordSyscallMetrics(operation, latency, true)
	
	return &pb.EmitMetricResponse{
		MetricId:   metricID,
		StatusCode: int32(codes.OK),
	}, nil
}

// SystemTuning handles system tuning syscalls
func (h *observabilityHandler) SystemTuning(ctx context.Context, req *pb.SystemTuningRequest) (*pb.SystemTuningResponse, error) {
	startTime := time.Now()
	operation := "system_tuning"
	
	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, h.config.SyscallTimeout)
	defer cancel()
	
	// Validate request
	if len(req.Parameters) == 0 && req.TuningProfile == "" {
		return &pb.SystemTuningResponse{
			Error:      "parameters or tuning_profile is required",
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}
	
	// Validate tuning profile
	validProfiles := map[string]bool{
		"performance": true,
		"memory":      true,
		"latency":     true,
		"throughput":  true,
		"balanced":    true,
		"eco":         true,
	}
	
	if req.TuningProfile != "" && !validProfiles[req.TuningProfile] {
		return &pb.SystemTuningResponse{
			Error:      "invalid tuning profile: " + req.TuningProfile,
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}
	
	// Validate parameters count
	if len(req.Parameters) > 50 {
		return &pb.SystemTuningResponse{
			Error:      "too many parameters (max 50)",
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}
	
	// Validate parameter keys and values
	for key, value := range req.Parameters {
		if len(key) > 128 {
			return &pb.SystemTuningResponse{
				Error:      "parameter key too long (max 128 chars): " + key,
				StatusCode: int32(codes.InvalidArgument),
			}, nil
		}
		if len(value) > 256 {
			return &pb.SystemTuningResponse{
				Error:      "parameter value too long (max 256 chars): " + key,
				StatusCode: int32(codes.InvalidArgument),
			}, nil
		}
	}
	
	// Apply system tuning
	result, err := h.explainabilityEngine.ApplySystemTuning(ctx, req.Parameters, req.TuningProfile, req.DryRun)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			err = syscall.NewTimeoutError(operation)
		}
		
		code, message := h.errorSanitizer.SanitizeError(err, operation, req.CallerId)
		return &pb.SystemTuningResponse{
			Error:      message,
			StatusCode: int32(code),
		}, nil
	}
	
	// Record metrics
	latency := time.Since(startTime)
	recordSyscallMetrics(operation, latency, true)
	
	return &pb.SystemTuningResponse{
		AppliedParameters: result.AppliedParameters,
		RejectedParameters: result.RejectedParameters,
		Warnings:          result.Warnings,
		RequiresRestart:   result.RequiresRestart,
		StatusCode:        int32(codes.OK),
	}, nil
} 