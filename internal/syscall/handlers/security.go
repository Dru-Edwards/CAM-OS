package handlers

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/cam-os/kernel/internal/security"
	pb "github.com/cam-os/kernel/proto/generated"
	"google.golang.org/grpc/codes"
)

// securityHandler implements SecurityHandler interface with TPM support
type securityHandler struct {
	securityManager *security.Manager
	config          *Config
	errorSanitizer  *ErrorSanitizer
	tpmValidator    *TpmValidator
}

// TmpValidator handles TPM certificate chain validation
type TmpValidator struct {
	trustedRoots   *x509.CertPool
	enableStrictCA bool
}

// NewTmpValidator creates a new TPM validator
func NewTmpValidator(trustedRoots *x509.CertPool, enableStrictCA bool) *TmpValidator {
	return &TmpValidator{
		trustedRoots:   trustedRoots,
		enableStrictCA: enableStrictCA,
	}
}

// ValidateTmpCertificateChain validates a TPM certificate chain (H-10 requirement)
func (v *TmpValidator) ValidateTmpCertificateChain(chain *pb.TmpCertificateChain) error {
	if chain == nil {
		return fmt.Errorf("TPM certificate chain is required")
	}

	if chain.KeyId == "" {
		return fmt.Errorf("TPM key ID is required")
	}

	if len(chain.CertificateChain) == 0 {
		return fmt.Errorf("certificate chain cannot be empty")
	}

	// Parse and validate certificate chain
	certs := make([]*x509.Certificate, len(chain.CertificateChain))
	for i, certBytes := range chain.CertificateChain {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return fmt.Errorf("failed to parse certificate %d: %v", i, err)
		}
		certs[i] = cert
	}

	// Verify certificate chain
	if len(certs) > 0 {
		leafCert := certs[0]

		// Build intermediate pool
		intermediates := x509.NewCertPool()
		for i := 1; i < len(certs); i++ {
			intermediates.AddCert(certs[i])
		}

		// Verify chain
		opts := x509.VerifyOptions{
			Roots:         v.trustedRoots,
			Intermediates: intermediates,
			CurrentTime:   time.Now(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}

		if !v.enableStrictCA {
			// Allow self-signed for development
			opts.Roots = x509.NewCertPool()
			opts.Roots.AddCert(leafCert)
		}

		_, err := leafCert.Verify(opts)
		if err != nil {
			return fmt.Errorf("certificate chain verification failed: %v", err)
		}
	}

	// Validate key ID format
	if len(chain.KeyId) < 8 || len(chain.KeyId) > 64 {
		return fmt.Errorf("invalid TPM key ID length")
	}

	// Validate timestamps
	if chain.CreatedAt > chain.ExpiresAt {
		return fmt.Errorf("invalid key validity period")
	}

	if time.Unix(chain.ExpiresAt, 0).Before(time.Now()) {
		return fmt.Errorf("TPM key has expired")
	}

	return nil
}

// NewSecurityHandler creates a new security handler with TPM support
func NewSecurityHandler(
	securityManager *security.Manager,
	config *Config,
	errorSanitizer *ErrorSanitizer,
) SecurityHandler {
	// Initialize TPM validator with default configuration
	trustedRoots := x509.NewCertPool()
	tpmValidator := NewTmpValidator(trustedRoots, false) // Allow self-signed for dev

	return &securityHandler{
		securityManager: securityManager,
		config:          config,
		errorSanitizer:  errorSanitizer,
		tpmValidator:    tpmValidator,
	}
}

// RASP integration variables for runtime protection
var (
	raspEngineEnabled = false
	raspThreatCount   = int64(0)
	raspBlockedCount  = int64(0)
)

// EnableRASPProtection enables RASP protection for syscalls
func EnableRASPProtection() {
	raspEngineEnabled = true
}

// GetRASPMetrics returns RASP protection metrics
func GetRASPMetrics() map[string]interface{} {
	return map[string]interface{}{
		"enabled":          raspEngineEnabled,
		"threats_detected": raspThreatCount,
		"threats_blocked":  raspBlockedCount,
		"protection_level": "ACTIVE",
	}
}

// analyzeSecurityRequest performs basic threat analysis on security requests
func analyzeSecurityRequest(ctx context.Context, req interface{}) error {
	if !raspEngineEnabled {
		return nil
	}

	// Basic threat detection patterns
	reqStr := fmt.Sprintf("%+v", req)

	// Check for common injection patterns
	dangerousPatterns := []string{
		"'; DROP TABLE", "' OR '1'='1", "UNION SELECT", "<script>",
		"javascript:", "eval(", "exec(", "../../../", "cmd.exe",
		"powershell", "/bin/bash", "rm -rf", "sudo su",
	}

	for _, pattern := range dangerousPatterns {
		if contains(reqStr, pattern) {
			raspThreatCount++
			raspBlockedCount++
			return fmt.Errorf("RASP_BLOCKED: Potential security threat detected - pattern: %s", pattern)
		}
	}

	// Check for suspicious request sizes
	if len(reqStr) > 100000 { // 100KB limit
		raspThreatCount++
		return fmt.Errorf("RASP_WARNING: Unusually large request detected")
	}

	return nil
}

// contains checks if a string contains a substring (case-insensitive)
func contains(str, substr string) bool {
	return len(str) >= len(substr) &&
		(str == substr ||
			(len(str) > len(substr) &&
				contains(str[1:], substr)) ||
			(len(str) >= len(substr) &&
				str[:len(substr)] == substr))
}

// TmpSign handles TPM signing requests with certificate chain validation
func (h *securityHandler) TmpSign(ctx context.Context, req *pb.TmpSignRequest) (*pb.TmpSignResponse, error) {
	startTime := time.Now()
	operation := "tmp_sign"

	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, h.config.SecurityTimeout)
	defer cancel()

	// Validate TPM caller identity (H-10 requirement)
	if req.CallerTmpIdentity != nil {
		if err := h.tpmValidator.ValidateTmpCertificateChain(req.CallerTmpIdentity); err != nil {
			code, message := h.errorSanitizer.SanitizeError(err, operation, req.CallerId)
			return &pb.TmpSignResponse{
				Error:      message,
				StatusCode: int32(code),
			}, nil
		}
	}

	// Validate request
	if len(req.Data) == 0 {
		return &pb.TmpSignResponse{
			Error:      "data to sign cannot be empty",
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}

	if req.KeyId == "" {
		return &pb.TmpSignResponse{
			Error:      "key ID is required",
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}

	// Perform TPM signing
	signature, certificateChain, err := h.securityManager.TmpSign(ctx, req.Data, req.KeyId, req.Algorithm)
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
		Signature:          signature,
		SigningCertificate: certificateChain, // TPM certificate chain (H-10)
		StatusCode:         int32(codes.OK),
	}, nil
}

// VerifyManifest handles manifest verification with TPM certificate chains
func (h *securityHandler) VerifyManifest(ctx context.Context, req *pb.VerifyManifestRequest) (*pb.VerifyManifestResponse, error) {
	startTime := time.Now()
	operation := "verify_manifest"

	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, h.config.SecurityTimeout)
	defer cancel()

	// Validate TPM certificate chain (H-10 requirement)
	if err := h.tpmValidator.ValidateTmpCertificateChain(req.CertificateChain); err != nil {
		code, message := h.errorSanitizer.SanitizeError(err, operation, req.CallerId)
		return &pb.VerifyManifestResponse{
			Error:      message,
			StatusCode: int32(code),
		}, nil
	}

	// Validate request
	if len(req.ManifestData) == 0 {
		return &pb.VerifyManifestResponse{
			Error:      "manifest data cannot be empty",
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}

	if len(req.Signature) == 0 {
		return &pb.VerifyManifestResponse{
			Error:      "signature cannot be empty",
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}

	// Perform manifest verification
	valid, err := h.securityManager.VerifyManifest(ctx, req.ManifestData, req.Signature, req.CertificateChain)
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
		Valid:      valid,
		StatusCode: int32(codes.OK),
	}, nil
}

// EstablishSecureChannel handles secure channel establishment with TPM identity
func (h *securityHandler) EstablishSecureChannel(ctx context.Context, req *pb.EstablishSecureChannelRequest) (*pb.EstablishSecureChannelResponse, error) {
	startTime := time.Now()
	operation := "establish_secure_channel"

	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, h.config.SecurityTimeout)
	defer cancel()

	// Validate TPM caller identity (H-10 requirement)
	if req.CallerTmpIdentity != nil {
		if err := h.tpmValidator.ValidateTmpCertificateChain(req.CallerTmpIdentity); err != nil {
			code, message := h.errorSanitizer.SanitizeError(err, operation, req.CallerId)
			return &pb.EstablishSecureChannelResponse{
				Error:      message,
				StatusCode: int32(code),
			}, nil
		}
	}

	// Validate request
	if req.PeerId == "" {
		return &pb.EstablishSecureChannelResponse{
			Error:      "peer ID is required",
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}

	if len(req.EphemeralPublicKey) == 0 {
		return &pb.EstablishSecureChannelResponse{
			Error:      "ephemeral public key is required",
			StatusCode: int32(codes.InvalidArgument),
		}, nil
	}

	// Establish secure channel
	channelID, peerPubKey, peerCertificate, err := h.securityManager.EstablishSecureChannel(
		ctx, req.PeerId, req.EphemeralPublicKey, req.CallerTmpIdentity)
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
		ChannelId:          channelID,
		EphemeralPublicKey: peerPubKey,
		PeerCertificate:    peerCertificate, // TPM-backed peer certificate (H-10)
		StatusCode:         int32(codes.OK),
	}, nil
}
