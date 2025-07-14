package syscall

import (
	"context"
	"log"
	"os"

	"github.com/cam-os/kernel/internal/arbitration"
	"github.com/cam-os/kernel/internal/explainability"
	"github.com/cam-os/kernel/internal/memory"
	"github.com/cam-os/kernel/internal/policy"
	"github.com/cam-os/kernel/internal/security"
	"github.com/cam-os/kernel/internal/syscall/handlers"
	pb "github.com/cam-os/kernel/proto/generated"
)

// HardenedDispatcher is the new secure, modular syscall dispatcher
type HardenedDispatcher struct {
	pb.UnimplementedSyscallServiceServer

	// Handler interfaces
	coreHandler          handlers.CoreHandler
	memoryHandler        handlers.MemoryHandler
	securityHandler      handlers.SecurityHandler
	observabilityHandler handlers.ObservabilityHandler

	// Configuration and utilities
	config      *Config
	auditLogger *log.Logger
}

// NewHardenedDispatcher creates a new hardened syscall dispatcher
func NewHardenedDispatcher(
	arbitrationEngine *arbitration.Engine,
	memoryManager *memory.ContextManager,
	policyEngine *policy.Engine,
	securityManager *security.Manager,
	explainabilityEngine *explainability.Engine,
	config *Config,
) *HardenedDispatcher {
	if config == nil {
		config = DefaultConfig()
	}

	// Create audit logger
	auditLogger := log.New(os.Stdout, "[AUDIT] ", log.LstdFlags|log.Lmicroseconds)

	// Create error sanitizer
	errorSanitizer := handlers.NewErrorSanitizer(config.RedactErrorDetails)

	// Create handlers configuration
	handlerConfig := &handlers.Config{
		SyscallTimeout:     config.SyscallTimeout,
		ArbitrationTimeout: config.ArbitrationTimeout,
		RedactErrorDetails: config.RedactErrorDetails,
	}

	// Create handlers
	coreHandler := handlers.NewCoreHandler(
		arbitrationEngine,
		policyEngine,
		explainabilityEngine,
		handlerConfig,
		errorSanitizer,
	)

	memoryHandler := handlers.NewMemoryHandler(
		memoryManager,
		handlerConfig,
		errorSanitizer,
	)

	securityHandler := handlers.NewSecurityHandler(
		securityManager,
		handlerConfig,
		errorSanitizer,
	)

	observabilityHandler := handlers.NewObservabilityHandler(
		explainabilityEngine,
		handlerConfig,
		errorSanitizer,
	)

	return &HardenedDispatcher{
		coreHandler:          coreHandler,
		memoryHandler:        memoryHandler,
		securityHandler:      securityHandler,
		observabilityHandler: observabilityHandler,
		config:               config,
		auditLogger:          auditLogger,
	}
}

// Core syscalls - delegate to core handler
func (d *HardenedDispatcher) Arbitrate(ctx context.Context, req *pb.ArbitrateRequest) (*pb.ArbitrateResponse, error) {
	d.auditLogger.Printf("Arbitrate called by %s", req.CallerId)
	return d.coreHandler.Arbitrate(ctx, req)
}

func (d *HardenedDispatcher) CommitTask(ctx context.Context, req *pb.CommitTaskRequest) (*pb.CommitTaskResponse, error) {
	d.auditLogger.Printf("CommitTask called by %s", req.CallerId)
	return d.coreHandler.CommitTask(ctx, req)
}

func (d *HardenedDispatcher) TaskRollback(ctx context.Context, req *pb.TaskRollbackRequest) (*pb.TaskRollbackResponse, error) {
	d.auditLogger.Printf("TaskRollback called by %s", req.CallerId)
	return d.coreHandler.TaskRollback(ctx, req)
}

func (d *HardenedDispatcher) AgentRegister(ctx context.Context, req *pb.AgentRegisterRequest) (*pb.AgentRegisterResponse, error) {
	d.auditLogger.Printf("AgentRegister called by %s", req.CallerId)
	return d.coreHandler.AgentRegister(ctx, req)
}

func (d *HardenedDispatcher) QueryPolicy(ctx context.Context, req *pb.QueryPolicyRequest) (*pb.QueryPolicyResponse, error) {
	d.auditLogger.Printf("QueryPolicy called by %s", req.CallerId)
	return d.coreHandler.QueryPolicy(ctx, req)
}

func (d *HardenedDispatcher) PolicyUpdate(ctx context.Context, req *pb.PolicyUpdateRequest) (*pb.PolicyUpdateResponse, error) {
	d.auditLogger.Printf("PolicyUpdate called by %s", req.CallerId)
	return d.coreHandler.PolicyUpdate(ctx, req)
}

func (d *HardenedDispatcher) HealthCheck(ctx context.Context, req *pb.HealthCheckRequest) (*pb.HealthCheckResponse, error) {
	// Health checks don't need audit logging (too noisy)
	return d.coreHandler.HealthCheck(ctx, req)
}

// Memory syscalls - delegate to memory handler
func (d *HardenedDispatcher) ContextRead(ctx context.Context, req *pb.ContextReadRequest) (*pb.ContextReadResponse, error) {
	d.auditLogger.Printf("ContextRead called by %s for %s/%s", req.CallerId, req.Namespace, req.Key)
	return d.memoryHandler.ContextRead(ctx, req)
}

func (d *HardenedDispatcher) ContextWrite(ctx context.Context, req *pb.ContextWriteRequest) (*pb.ContextWriteResponse, error) {
	d.auditLogger.Printf("ContextWrite called by %s for %s/%s", req.CallerId, req.Namespace, req.Key)
	return d.memoryHandler.ContextWrite(ctx, req)
}

func (d *HardenedDispatcher) ContextSnapshot(ctx context.Context, req *pb.ContextSnapshotRequest) (*pb.ContextSnapshotResponse, error) {
	d.auditLogger.Printf("ContextSnapshot called by %s for %s", req.CallerId, req.Namespace)
	return d.memoryHandler.ContextSnapshot(ctx, req)
}

func (d *HardenedDispatcher) ContextRestore(ctx context.Context, req *pb.ContextRestoreRequest) (*pb.ContextRestoreResponse, error) {
	d.auditLogger.Printf("ContextRestore called by %s for %s", req.CallerId, req.SnapshotId)
	return d.memoryHandler.ContextRestore(ctx, req)
}

func (d *HardenedDispatcher) SnapshotContext(ctx context.Context, req *pb.SnapshotContextRequest) (*pb.SnapshotContextResponse, error) {
	d.auditLogger.Printf("SnapshotContext called by %s for %s", req.CallerId, req.Namespace)
	return d.memoryHandler.SnapshotContext(ctx, req)
}

func (d *HardenedDispatcher) ContextVersionList(ctx context.Context, req *pb.ContextVersionListRequest) (*pb.ContextVersionListResponse, error) {
	d.auditLogger.Printf("ContextVersionList called by %s for %s/%s", req.CallerId, req.Namespace, req.Key)
	return d.memoryHandler.ContextVersionList(ctx, req)
}

// Security syscalls - delegate to security handler
func (d *HardenedDispatcher) TmpSign(ctx context.Context, req *pb.TmpSignRequest) (*pb.TmpSignResponse, error) {
	d.auditLogger.Printf("TmpSign called by %s", req.CallerId)
	return d.securityHandler.TmpSign(ctx, req)
}

func (d *HardenedDispatcher) VerifyManifest(ctx context.Context, req *pb.VerifyManifestRequest) (*pb.VerifyManifestResponse, error) {
	d.auditLogger.Printf("VerifyManifest called by %s", req.CallerId)
	return d.securityHandler.VerifyManifest(ctx, req)
}

func (d *HardenedDispatcher) EstablishSecureChannel(ctx context.Context, req *pb.EstablishSecureChannelRequest) (*pb.EstablishSecureChannelResponse, error) {
	d.auditLogger.Printf("EstablishSecureChannel called by %s for peer %s", req.CallerId, req.PeerId)
	return d.securityHandler.EstablishSecureChannel(ctx, req)
}

// Observability syscalls - delegate to observability handler
func (d *HardenedDispatcher) ExplainAction(ctx context.Context, req *pb.ExplainActionRequest) (*pb.ExplainActionResponse, error) {
	d.auditLogger.Printf("ExplainAction called by %s for trace %s", req.CallerId, req.TraceId)
	return d.observabilityHandler.ExplainAction(ctx, req)
}

func (d *HardenedDispatcher) EmitTrace(ctx context.Context, req *pb.EmitTraceRequest) (*pb.EmitTraceResponse, error) {
	// Trace emissions are high-volume, only log errors
	return d.observabilityHandler.EmitTrace(ctx, req)
}

func (d *HardenedDispatcher) EmitMetric(ctx context.Context, req *pb.EmitMetricRequest) (*pb.EmitMetricResponse, error) {
	// Metric emissions are high-volume, only log errors
	return d.observabilityHandler.EmitMetric(ctx, req)
}

func (d *HardenedDispatcher) SystemTuning(ctx context.Context, req *pb.SystemTuningRequest) (*pb.SystemTuningResponse, error) {
	d.auditLogger.Printf("SystemTuning called by %s with profile %s", req.CallerId, req.TuningProfile)
	return d.observabilityHandler.SystemTuning(ctx, req)
}
