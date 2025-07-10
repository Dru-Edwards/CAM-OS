package handlers

import (
	"context"
	"time"

	"github.com/cam-os/kernel/internal/security"
	pb "github.com/cam-os/kernel/proto/generated"
	"google.golang.org/grpc/codes"
)

// securityHandler implements SecurityHandler interface
type securityHandler struct {
	securityManager *security.Manager
	config          *Config
	errorSanitizer  *ErrorSanitizer
}

// NewSecurityHandler creates a new security handler
func NewSecurityHandler(
	securityManager *security.Manager,
	config *Config,
	errorSanitizer *ErrorSanitizer,
) SecurityHandler {
	return &securityHandler{
		securityManager: securityManager,
		config:          config,
		errorSanitizer:  errorSanitizer,
	}
}

// TmpSign handles TPM signing syscalls with enhanced response including keyID and certificate chain
func (h *securityHandler) TmpSign(ctx context.Context, req *pb.TmpSignRequest) (*pb.TmpSignResponse, error) {
	startTime := time.Now()
	operation := "tmp_sign"

	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, h.config.SyscallTimeout)
	defer cancel()

	// Validate request
	if len(req.Data) == 0 {
		return &pb.TmpSignResponse{
			Error:      "data is required",
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}

	// Validate payload size
	if err := h.config.ValidatePayloadSize(len(req.Data)); err != nil {
		return &pb.TmpSignResponse{
			Error:      err.Error(),
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}

	// Validate key ID if provided
	if req.KeyId != "" {
		if err := h.config.ValidateKey(req.KeyId); err != nil {
			return &pb.TmpSignResponse{
				Error:      err.Error(),
				StatusCode: int32(codes.InvalidArgument),
			}, nil
		}
	}

	// Sign data with TPM - Enhanced API with certificate chain
	result, err := h.securityManager.TmpSignEnhanced(ctx, req.Data, req.KeyId)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			err = NewTimeoutError(operation)
		}

		code, message := h.errorSanitizer.SanitizeError(err, operation, req.CallerId)
		return &pb.TmpSignResponse{
			Error:      message,
			StatusCode: int32(code),
		}, nil
	}

	// Record metrics
	latency := time.Since(startTime)
	recordSyscallMetrics(operation, latency, true)

	return &pb.TmpSignResponse{
		Signature:  result.Signature,
		Algorithm:  result.Algorithm,
		KeyId:      result.KeyID,     // Enhanced: Return key ID
		KeyHandle:  result.KeyHandle, // Enhanced: Return key handle
		CertChain:  result.CertChain, // Enhanced: Return certificate chain
		Timestamp:  result.Timestamp.Unix(),
		StatusCode: int32(codes.OK),
	}, nil
}

// VerifyManifest handles manifest verification syscalls
func (h *securityHandler) VerifyManifest(ctx context.Context, req *pb.VerifyManifestRequest) (*pb.VerifyManifestResponse, error) {
	startTime := time.Now()
	operation := "verify_manifest"

	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, h.config.SyscallTimeout)
	defer cancel()

	// Validate request
	if len(req.Manifest) == 0 {
		return &pb.VerifyManifestResponse{
			Error:      "manifest is required",
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}

	if len(req.Signature) == 0 {
		return &pb.VerifyManifestResponse{
			Error:      "signature is required",
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}

	if len(req.PublicKey) == 0 {
		return &pb.VerifyManifestResponse{
			Error:      "public_key is required",
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}

	// Validate payload sizes
	if err := h.config.ValidatePayloadSize(len(req.Manifest)); err != nil {
		return &pb.VerifyManifestResponse{
			Error:      "manifest " + err.Error(),
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}

	// Verify manifest
	result, err := h.securityManager.VerifyManifest(ctx, req.Manifest, req.Signature, string(req.PublicKey))
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			err = NewTimeoutError(operation)
		}

		code, message := h.errorSanitizer.SanitizeError(err, operation, req.CallerId)
		return &pb.VerifyManifestResponse{
			Error:      message,
			StatusCode: int32(code),
		}, nil
	}

	// Record metrics
	latency := time.Since(startTime)
	recordSyscallMetrics(operation, latency, true)

	return &pb.VerifyManifestResponse{
		Valid:      result.Valid,
		Issuer:     result.Issuer,
		ExpiresAt:  result.ExpiresAt.Unix(),
		TrustLevel: float64(result.TrustLevel), // Enhanced: Return trust level (converted to float64)
		Warnings:   result.Warnings,            // Enhanced: Return any warnings
		StatusCode: int32(codes.OK),
	}, nil
}

// EstablishSecureChannel handles secure channel establishment
func (h *securityHandler) EstablishSecureChannel(ctx context.Context, req *pb.EstablishSecureChannelRequest) (*pb.EstablishSecureChannelResponse, error) {
	startTime := time.Now()
	operation := "establish_secure_channel"

	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, h.config.SyscallTimeout)
	defer cancel()

	// Validate request
	if req.PeerId == "" {
		return &pb.EstablishSecureChannelResponse{
			Error:      "peer_id is required",
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}

	// Validate peer ID
	if err := h.config.ValidateAgentID(req.PeerId); err != nil {
		return &pb.EstablishSecureChannelResponse{
			Error:      "peer_id " + err.Error(),
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}

	// Validate protocol
	validProtocols := map[string]bool{
		"kyber768":   true,
		"dilithium3": true,
		"tls13":      true,
		"noise":      true,
	}

	if req.Protocol != "" && !validProtocols[req.Protocol] {
		return &pb.EstablishSecureChannelResponse{
			Error:      "unsupported protocol: " + req.Protocol,
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}

	// Establish secure channel
	result, err := h.securityManager.EstablishSecureChannel(ctx, req.PeerId, req.Protocol)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			err = NewTimeoutError(operation)
		}

		code, message := h.errorSanitizer.SanitizeError(err, operation, req.CallerId)
		return &pb.EstablishSecureChannelResponse{
			Error:      message,
			StatusCode: int32(code),
		}, nil
	}

	// Record metrics
	latency := time.Since(startTime)
	recordSyscallMetrics(operation, latency, true)

	return &pb.EstablishSecureChannelResponse{
		ChannelId:  result.ChannelID,
		SessionKey: result.SessionKey,
		Protocol:   result.Protocol,         // Enhanced: Return actual protocol used
		ExpiresAt:  result.ExpiresAt.Unix(), // Enhanced: Return expiration
		StatusCode: int32(codes.OK),
	}, nil
}
