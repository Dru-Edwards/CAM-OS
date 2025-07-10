package handlers

import (
	"context"
	"fmt"
	"time"

	"github.com/cam-os/kernel/internal/memory"
	pb "github.com/cam-os/kernel/proto/generated"
	"google.golang.org/grpc/codes"
)

// memoryHandler implements MemoryHandler interface
type memoryHandler struct {
	memoryManager  *memory.ContextManager
	config         *Config
	errorSanitizer *ErrorSanitizer
}

// NewMemoryHandler creates a new memory handler
func NewMemoryHandler(
	memoryManager *memory.ContextManager,
	config *Config,
	errorSanitizer *ErrorSanitizer,
) MemoryHandler {
	return &memoryHandler{
		memoryManager:  memoryManager,
		config:         config,
		errorSanitizer: errorSanitizer,
	}
}

// ValidateNamespace validates namespace format
func (c *Config) ValidateNamespace(namespace string) error {
	if len(namespace) == 0 {
		return fmt.Errorf("namespace cannot be empty")
	}
	if len(namespace) > 255 {
		return fmt.Errorf("namespace too long")
	}
	return nil
}

// ValidatePayloadSize validates payload size
func (c *Config) ValidatePayloadSize(size int) error {
	maxSize := 100 * 1024 * 1024 // 100MB
	if size > maxSize {
		return fmt.Errorf("payload too large")
	}
	return nil
}

// ContextRead handles context read syscalls with strict validation
func (h *memoryHandler) ContextRead(ctx context.Context, req *pb.ContextReadRequest) (*pb.ContextReadResponse, error) {
	startTime := time.Now()
	operation := "context_read"

	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, h.config.SyscallTimeout)
	defer cancel()

	// Validate namespace
	if err := h.config.ValidateNamespace(req.Namespace); err != nil {
		return &pb.ContextReadResponse{
			Error:      err.Error(),
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}

	// Validate key
	if err := h.config.ValidateKey(req.Key); err != nil {
		return &pb.ContextReadResponse{
			Error:      err.Error(),
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}

	// Read context data
	data, err := h.memoryManager.Read(ctx, req.Namespace, req.Key, req.Version)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			err = NewTimeoutError(operation)
		}

		code, message := h.errorSanitizer.SanitizeError(err, operation, req.CallerId)
		return &pb.ContextReadResponse{
			Error:      message,
			StatusCode: int32(code),
		}, nil
	}

	// Record metrics
	latency := time.Since(startTime)
	recordSyscallMetrics(operation, latency, true)

	return &pb.ContextReadResponse{
		Data:       data.Data,
		Version:    data.Version,
		Hash:       data.Hash,
		StatusCode: int32(codes.OK),
	}, nil
}

// ContextWrite handles context write syscalls with validation and size limits
func (h *memoryHandler) ContextWrite(ctx context.Context, req *pb.ContextWriteRequest) (*pb.ContextWriteResponse, error) {
	startTime := time.Now()
	operation := "context_write"

	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, h.config.SyscallTimeout)
	defer cancel()

	// Validate namespace
	if err := h.config.ValidateNamespace(req.Namespace); err != nil {
		return &pb.ContextWriteResponse{
			Error:      err.Error(),
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}

	// Validate key
	if err := h.config.ValidateKey(req.Key); err != nil {
		return &pb.ContextWriteResponse{
			Error:      err.Error(),
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}

	// Validate payload size
	if err := h.config.ValidatePayloadSize(len(req.Data)); err != nil {
		return &pb.ContextWriteResponse{
			Error:      err.Error(),
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}

	// Write context data
	result, err := h.memoryManager.Write(ctx, req.Namespace, req.Key, req.Data, req.Metadata)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			err = NewTimeoutError(operation)
		}

		code, message := h.errorSanitizer.SanitizeError(err, operation, req.CallerId)
		return &pb.ContextWriteResponse{
			Error:      message,
			StatusCode: int32(code),
		}, nil
	}

	// Record metrics
	latency := time.Since(startTime)
	recordSyscallMetrics(operation, latency, true)

	return &pb.ContextWriteResponse{
		Version:    result.Version,
		Hash:       result.Hash,
		StatusCode: int32(codes.OK),
	}, nil
}

// ContextSnapshot handles context snapshot syscalls
func (h *memoryHandler) ContextSnapshot(ctx context.Context, req *pb.ContextSnapshotRequest) (*pb.ContextSnapshotResponse, error) {
	startTime := time.Now()
	operation := "context_snapshot"

	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, h.config.SyscallTimeout)
	defer cancel()

	// Validate namespace
	if err := h.config.ValidateNamespace(req.Namespace); err != nil {
		return &pb.ContextSnapshotResponse{
			Error:      err.Error(),
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}

	// Create snapshot
	snapshotID, err := h.memoryManager.Snapshot(ctx, req.Namespace, req.Description)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			err = NewTimeoutError(operation)
		}

		code, message := h.errorSanitizer.SanitizeError(err, operation, req.CallerId)
		return &pb.ContextSnapshotResponse{
			Error:      message,
			StatusCode: int32(code),
		}, nil
	}

	// Record metrics
	latency := time.Since(startTime)
	recordSyscallMetrics(operation, latency, true)

	return &pb.ContextSnapshotResponse{
		SnapshotId: snapshotID,
		Timestamp:  time.Now().Unix(),
		StatusCode: int32(codes.OK),
	}, nil
}

// ContextRestore handles context restore syscalls
func (h *memoryHandler) ContextRestore(ctx context.Context, req *pb.ContextRestoreRequest) (*pb.ContextRestoreResponse, error) {
	startTime := time.Now()
	operation := "context_restore"

	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, h.config.SyscallTimeout)
	defer cancel()

	// Validate snapshot ID
	if req.SnapshotId == "" {
		return &pb.ContextRestoreResponse{
			Error:      "snapshot_id is required",
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}

	// Restore from snapshot
	result, err := h.memoryManager.Restore(ctx, req.SnapshotId, req.Force)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			err = NewTimeoutError(operation)
		}

		code, message := h.errorSanitizer.SanitizeError(err, operation, req.CallerId)
		return &pb.ContextRestoreResponse{
			Error:      message,
			StatusCode: int32(code),
		}, nil
	}

	// Record metrics
	latency := time.Since(startTime)
	recordSyscallMetrics(operation, latency, true)

	return &pb.ContextRestoreResponse{
		Namespace:     result.Namespace,
		RestoredItems: result.RestoredItems,
		StatusCode:    int32(codes.OK),
	}, nil
}

// SnapshotContext handles snapshot context syscalls (alias for ContextSnapshot)
func (h *memoryHandler) SnapshotContext(ctx context.Context, req *pb.SnapshotContextRequest) (*pb.SnapshotContextResponse, error) {
	// Convert to ContextSnapshotRequest
	snapshotReq := &pb.ContextSnapshotRequest{
		Namespace:   req.Namespace,
		Description: req.Description,
		CallerId:    req.CallerId,
	}

	// Call ContextSnapshot
	snapshotResp, err := h.ContextSnapshot(ctx, snapshotReq)
	if err != nil {
		return nil, err
	}

	// Convert response
	return &pb.SnapshotContextResponse{
		SnapshotId: snapshotResp.SnapshotId,
		Timestamp:  snapshotResp.Timestamp,
		Error:      snapshotResp.Error,
		StatusCode: snapshotResp.StatusCode,
	}, nil
}

// ContextVersionList handles context version list syscalls
func (h *memoryHandler) ContextVersionList(ctx context.Context, req *pb.ContextVersionListRequest) (*pb.ContextVersionListResponse, error) {
	startTime := time.Now()
	operation := "context_version_list"

	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, h.config.SyscallTimeout)
	defer cancel()

	// Validate namespace
	if err := h.config.ValidateNamespace(req.Namespace); err != nil {
		return &pb.ContextVersionListResponse{
			Error:      err.Error(),
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}

	// Validate key
	if err := h.config.ValidateKey(req.Key); err != nil {
		return &pb.ContextVersionListResponse{
			Error:      err.Error(),
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}

	// List versions
	versions, _, _, err := h.memoryManager.ListVersions(ctx, req.Namespace, req.Key, req.Limit, 0)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			err = NewTimeoutError(operation)
		}

		code, message := h.errorSanitizer.SanitizeError(err, operation, req.CallerId)
		return &pb.ContextVersionListResponse{
			Error:      message,
			StatusCode: int32(code),
		}, nil
	}

	// Convert versions to protobuf format
	pbVersions := make([]*pb.ContextVersion, len(versions))
	for i, version := range versions {
		pbVersions[i] = &pb.ContextVersion{
			Version:   version.Version,
			Hash:      version.Hash,
			Timestamp: version.Timestamp.Unix(),
			Size:      version.Size,
			Metadata:  version.Tags, // Changed from version.Metadata to version.Tags
		}
	}

	// Record metrics
	latency := time.Since(startTime)
	recordSyscallMetrics(operation, latency, true)

	return &pb.ContextVersionListResponse{
		Versions:   pbVersions,
		StatusCode: int32(codes.OK),
	}, nil
}
