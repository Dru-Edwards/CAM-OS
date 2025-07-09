package handlers

import (
	"context"
	pb "github.com/cam-os/kernel/proto/generated"
)

// CoreHandler handles core arbitration and task management syscalls
type CoreHandler interface {
	Arbitrate(ctx context.Context, req *pb.ArbitrateRequest) (*pb.ArbitrateResponse, error)
	CommitTask(ctx context.Context, req *pb.CommitTaskRequest) (*pb.CommitTaskResponse, error)
	TaskRollback(ctx context.Context, req *pb.TaskRollbackRequest) (*pb.TaskRollbackResponse, error)
	AgentRegister(ctx context.Context, req *pb.AgentRegisterRequest) (*pb.AgentRegisterResponse, error)
	QueryPolicy(ctx context.Context, req *pb.QueryPolicyRequest) (*pb.QueryPolicyResponse, error)
	PolicyUpdate(ctx context.Context, req *pb.PolicyUpdateRequest) (*pb.PolicyUpdateResponse, error)
	HealthCheck(ctx context.Context, req *pb.HealthCheckRequest) (*pb.HealthCheckResponse, error)
}

// MemoryHandler handles context and memory management syscalls
type MemoryHandler interface {
	ContextRead(ctx context.Context, req *pb.ContextReadRequest) (*pb.ContextReadResponse, error)
	ContextWrite(ctx context.Context, req *pb.ContextWriteRequest) (*pb.ContextWriteResponse, error)
	ContextSnapshot(ctx context.Context, req *pb.ContextSnapshotRequest) (*pb.ContextSnapshotResponse, error)
	ContextRestore(ctx context.Context, req *pb.ContextRestoreRequest) (*pb.ContextRestoreResponse, error)
	SnapshotContext(ctx context.Context, req *pb.SnapshotContextRequest) (*pb.SnapshotContextResponse, error)
	ContextVersionList(ctx context.Context, req *pb.ContextVersionListRequest) (*pb.ContextVersionListResponse, error)
}

// SecurityHandler handles security and cryptographic syscalls
type SecurityHandler interface {
	TmpSign(ctx context.Context, req *pb.TmpSignRequest) (*pb.TmpSignResponse, error)
	VerifyManifest(ctx context.Context, req *pb.VerifyManifestRequest) (*pb.VerifyManifestResponse, error)
	EstablishSecureChannel(ctx context.Context, req *pb.EstablishSecureChannelRequest) (*pb.EstablishSecureChannelResponse, error)
}

// ObservabilityHandler handles monitoring, tracing, and explainability syscalls
type ObservabilityHandler interface {
	ExplainAction(ctx context.Context, req *pb.ExplainActionRequest) (*pb.ExplainActionResponse, error)
	EmitTrace(ctx context.Context, req *pb.EmitTraceRequest) (*pb.EmitTraceResponse, error)
	EmitMetric(ctx context.Context, req *pb.EmitMetricRequest) (*pb.EmitMetricResponse, error)
	SystemTuning(ctx context.Context, req *pb.SystemTuningRequest) (*pb.SystemTuningResponse, error)
} 