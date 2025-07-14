package handlers

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
)

// HandlerConfig represents the configuration for handlers
type HandlerConfig struct {
	SyscallTimeout     time.Duration
	ArbitrationTimeout time.Duration
	RedactErrorDetails bool
	EnableValidation   bool // H-10: Enable protobuf validation
	StrictValidation   bool // H-10: Enable strict validation mode
}

// CoreHandler handles core system operations
type CoreHandler interface {
	Arbitrate(ctx context.Context, req *pb.ArbitrateRequest) (*pb.ArbitrateResponse, error)
	HealthCheck(ctx context.Context, req *pb.HealthCheckRequest) (*pb.HealthCheckResponse, error)
}

// MemoryHandler handles memory operations
type MemoryHandler interface {
	ContextRead(ctx context.Context, req *pb.ContextReadRequest) (*pb.ContextReadResponse, error)
	ContextWrite(ctx context.Context, req *pb.ContextWriteRequest) (*pb.ContextWriteResponse, error)
}

// SecurityHandler handles security operations
type SecurityHandler interface {
	TmpSign(ctx context.Context, req *pb.TmpSignRequest) (*pb.TmpSignResponse, error)
	VerifyManifest(ctx context.Context, req *pb.VerifyManifestRequest) (*pb.VerifyManifestResponse, error)
	EstablishSecureChannel(ctx context.Context, req *pb.EstablishSecureChannelRequest) (*pb.EstablishSecureChannelResponse, error)
}

// ObservabilityHandler handles observability operations
type ObservabilityHandler interface {
	EmitTrace(ctx context.Context, req *pb.EmitTraceRequest) (*pb.EmitTraceResponse, error)
	EmitMetric(ctx context.Context, req *pb.EmitMetricRequest) (*pb.EmitMetricResponse, error)
}

// HandlerDependencies contains all dependencies for handlers
type HandlerDependencies struct {
	ArbitrationEngine    *arbitration.Engine
	MemoryManager        *memory.ContextManager
	PolicyEngine         *policy.Engine
	SecurityManager      *security.Manager
	ExplainabilityEngine *explainability.Engine
	Config               *HandlerConfig
	ErrorRedactor        *ErrorRedactor // Updated to use ErrorRedactor
}

// NewHandlerDependencies creates a new handler dependencies struct
func NewHandlerDependencies(
	arbitrationEngine *arbitration.Engine,
	memoryManager *memory.ContextManager,
	policyEngine *policy.Engine,
	securityManager *security.Manager,
	explainabilityEngine *explainability.Engine,
	config *HandlerConfig,
	errorRedactor *ErrorRedactor, // Updated to use ErrorRedactor
) *HandlerDependencies {
	return &HandlerDependencies{
		ArbitrationEngine:    arbitrationEngine,
		MemoryManager:        memoryManager,
		PolicyEngine:         policyEngine,
		SecurityManager:      securityManager,
		ExplainabilityEngine: explainabilityEngine,
		Config:               config,
		ErrorRedactor:        errorRedactor,
	}
}

// ValidateRequest validates a protobuf request if validation is enabled
func (hd *HandlerDependencies) ValidateRequest(req interface{}) error {
	if !hd.Config.EnableValidation {
		return nil
	}

	// Simplified validation - just check for nil
	if req == nil {
		return &ValidationError{
			Field:   "request",
			Message: "request cannot be nil",
		}
	}

	return nil
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error on field %s: %s", e.Field, e.Message)
}

// ValidateTmpCertificateChain validates TPM certificate chain field
func (hd *HandlerDependencies) ValidateTmpCertificateChain(chain *pb.TpmCertificateChain) *ValidationResult {
	result := &ValidationResult{
		Valid:   true,
		Errors:  []string{},
		Context: make(map[string]interface{}),
	}

	if chain == nil {
		return result // nil is valid (optional field)
	}

	// Basic validation
	if chain.KeyId == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "key_id cannot be empty")
	}

	if len(chain.CertificateChain) == 0 {
		result.Valid = false
		result.Errors = append(result.Errors, "certificate_chain cannot be empty")
	}

	return result
}

// ValidationResult represents the result of validation
type ValidationResult struct {
	Valid   bool
	Errors  []string
	Context map[string]interface{}
}
