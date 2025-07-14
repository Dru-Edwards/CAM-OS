package tpm

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	pb "github.com/cam-os/kernel/proto/generated"
)

// TPMValidator validates TPM certificate chains (H-10 requirement)
type TPMValidator struct {
	trustedRoots       *x509.CertPool
	allowedKeyUsages   []x509.ExtKeyUsage
	maxChainLength     int
	clockSkewTolerance time.Duration
}

// ValidationError represents a TPM validation error
type ValidationError struct {
	Code    ValidationErrorCode
	Message string
	Details map[string]interface{}
}

// ValidationErrorCode represents different types of validation errors
type ValidationErrorCode int

const (
	ValidationErrorInvalidChain ValidationErrorCode = iota
	ValidationErrorExpiredCert
	ValidationErrorInvalidSignature
	ValidationErrorInvalidKeyUsage
	ValidationErrorInvalidAlgorithm
	ValidationErrorMissingAttestation
	ValidationErrorInvalidKeyID
	ValidationErrorChainTooLong
	ValidationErrorUntrustedRoot
)

func (e *ValidationError) Error() string {
	return fmt.Sprintf("TPM validation failed [%d]: %s", e.Code, e.Message)
}

// NewTPMValidator creates a new TPM certificate chain validator
func NewTPMValidator(trustedRoots *x509.CertPool) *TPMValidator {
	return &TPMValidator{
		trustedRoots:       trustedRoots,
		allowedKeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		maxChainLength:     5,
		clockSkewTolerance: 5 * time.Minute,
	}
}

// ValidateTmpCertificateChain validates a TPM certificate chain (H-10 requirement)
func (v *TPMValidator) ValidateTmpCertificateChain(chain *pb.TmpCertificateChain) error {
	if chain == nil {
		return &ValidationError{
			Code:    ValidationErrorInvalidChain,
			Message: "certificate chain is nil",
		}
	}

	// Validate key ID
	if err := v.validateKeyID(chain.KeyId); err != nil {
		return err
	}

	// Validate certificate chain length
	if len(chain.CertificateChain) == 0 {
		return &ValidationError{
			Code:    ValidationErrorInvalidChain,
			Message: "certificate chain is empty",
		}
	}

	if len(chain.CertificateChain) > v.maxChainLength {
		return &ValidationError{
			Code:    ValidationErrorChainTooLong,
			Message: fmt.Sprintf("certificate chain too long (max %d)", v.maxChainLength),
		}
	}

	// Validate algorithm
	if err := v.validateAlgorithm(chain.Algorithm); err != nil {
		return err
	}

	// Parse and validate certificates
	certs, err := v.parseCertificateChain(chain.CertificateChain)
	if err != nil {
		return &ValidationError{
			Code:    ValidationErrorInvalidChain,
			Message: fmt.Sprintf("failed to parse certificate chain: %v", err),
		}
	}

	// Validate certificate chain
	if err := v.validateCertificateChain(certs); err != nil {
		return err
	}

	// Validate attestation data
	if err := v.validateAttestationData(chain.AttestationData, certs[0], chain.KeyId); err != nil {
		return err
	}

	// Validate timestamps
	if err := v.validateTimestamps(chain.CreatedAt, chain.ExpiresAt); err != nil {
		return err
	}

	return nil
}

// validateKeyID validates the TPM key identifier
func (v *TPMValidator) validateKeyID(keyID string) error {
	if keyID == "" {
		return &ValidationError{
			Code:    ValidationErrorInvalidKeyID,
			Message: "key ID is empty",
		}
	}

	// TPM key IDs should be hex-encoded handles or persistent handles
	if len(keyID) < 8 || len(keyID) > 16 {
		return &ValidationError{
			Code:    ValidationErrorInvalidKeyID,
			Message: "key ID length invalid (expected 8-16 hex chars)",
		}
	}

	// Validate hex format
	for _, c := range keyID {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return &ValidationError{
				Code:    ValidationErrorInvalidKeyID,
				Message: "key ID must be hex-encoded",
			}
		}
	}

	return nil
}

// validateAlgorithm validates the signing algorithm
func (v *TPMValidator) validateAlgorithm(algorithm string) error {
	allowedAlgorithms := map[string]bool{
		"RSA-PSS":      true,
		"RSA-PKCS1v15": true,
		"ECDSA-SHA256": true,
		"ECDSA-SHA384": true,
		"ECDSA-SHA512": true,
	}

	if !allowedAlgorithms[algorithm] {
		return &ValidationError{
			Code:    ValidationErrorInvalidAlgorithm,
			Message: fmt.Sprintf("unsupported algorithm: %s", algorithm),
		}
	}

	return nil
}

// parseCertificateChain parses the DER-encoded certificate chain
func (v *TPMValidator) parseCertificateChain(chainData [][]byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for i, certData := range chainData {
		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate %d: %v", i, err)
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

// validateCertificateChain validates the X.509 certificate chain
func (v *TPMValidator) validateCertificateChain(certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return &ValidationError{
			Code:    ValidationErrorInvalidChain,
			Message: "empty certificate chain",
		}
	}

	// Validate leaf certificate
	leafCert := certs[0]
	if err := v.validateLeafCertificate(leafCert); err != nil {
		return err
	}

	// Validate chain integrity
	for i := 0; i < len(certs)-1; i++ {
		if err := v.validateCertificateSignature(certs[i], certs[i+1]); err != nil {
			return &ValidationError{
				Code:    ValidationErrorInvalidSignature,
				Message: fmt.Sprintf("certificate %d signature validation failed: %v", i, err),
			}
		}
	}

	// Validate against trusted roots
	if err := v.validateTrustedChain(certs); err != nil {
		return err
	}

	return nil
}

// validateLeafCertificate validates the leaf certificate
func (v *TPMValidator) validateLeafCertificate(cert *x509.Certificate) error {
	now := time.Now()
	tolerance := v.clockSkewTolerance

	// Check validity period with clock skew tolerance
	if now.Before(cert.NotBefore.Add(-tolerance)) {
		return &ValidationError{
			Code:    ValidationErrorExpiredCert,
			Message: "certificate not yet valid",
		}
	}

	if now.After(cert.NotAfter.Add(tolerance)) {
		return &ValidationError{
			Code:    ValidationErrorExpiredCert,
			Message: "certificate expired",
		}
	}

	// Check key usage
	validKeyUsage := false
	for _, usage := range v.allowedKeyUsages {
		for _, certUsage := range cert.ExtKeyUsage {
			if usage == certUsage {
				validKeyUsage = true
				break
			}
		}
		if validKeyUsage {
			break
		}
	}

	if !validKeyUsage {
		return &ValidationError{
			Code:    ValidationErrorInvalidKeyUsage,
			Message: "certificate key usage not valid for TPM authentication",
		}
	}

	return nil
}

// validateCertificateSignature validates that child certificate is signed by parent
func (v *TPMValidator) validateCertificateSignature(child, parent *x509.Certificate) error {
	return child.CheckSignatureFrom(parent)
}

// validateTrustedChain validates the chain against trusted roots
func (v *TPMValidator) validateTrustedChain(certs []*x509.Certificate) error {
	if v.trustedRoots == nil {
		return nil // Skip validation if no trusted roots configured
	}

	opts := x509.VerifyOptions{
		Roots:       v.trustedRoots,
		CurrentTime: time.Now(),
		KeyUsages:   v.allowedKeyUsages,
	}

	// Build intermediate pool
	if len(certs) > 1 {
		opts.Intermediates = x509.NewCertPool()
		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}
	}

	_, err := certs[0].Verify(opts)
	if err != nil {
		return &ValidationError{
			Code:    ValidationErrorUntrustedRoot,
			Message: fmt.Sprintf("certificate chain validation failed: %v", err),
		}
	}

	return nil
}

// validateAttestationData validates TPM attestation data
func (v *TPMValidator) validateAttestationData(attestationData []byte, cert *x509.Certificate, keyID string) error {
	if len(attestationData) == 0 {
		return &ValidationError{
			Code:    ValidationErrorMissingAttestation,
			Message: "attestation data is empty",
		}
	}

	// Parse attestation data (simplified for this implementation)
	// In a real implementation, this would parse TPM 2.0 attestation structures
	attestation, err := v.parseAttestationData(attestationData)
	if err != nil {
		return &ValidationError{
			Code:    ValidationErrorMissingAttestation,
			Message: fmt.Sprintf("failed to parse attestation data: %v", err),
		}
	}

	// Validate attestation matches certificate
	if err := v.validateAttestationBinding(attestation, cert, keyID); err != nil {
		return err
	}

	return nil
}

// AttestationData represents parsed TPM attestation data
type AttestationData struct {
	Magic            uint32
	Type             uint32
	QualifiedSigner  []byte
	ExtraData        []byte
	ClockInfo        []byte
	FirmwareVersion  uint64
	AttestationKeyID string
}

// parseAttestationData parses TPM attestation data
func (v *TPMValidator) parseAttestationData(data []byte) (*AttestationData, error) {
	// Simplified parsing - in real implementation, this would use TPM 2.0 structures
	if len(data) < 32 {
		return nil, errors.New("attestation data too short")
	}

	// Basic validation of magic number (TPM 2.0 magic)
	if len(data) >= 4 {
		magic := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
		if magic != 0xFF544347 { // TPM_GENERATED_VALUE
			return nil, errors.New("invalid TPM magic number")
		}
	}

	return &AttestationData{
		Magic:            0xFF544347,
		Type:             1, // TPM_ST_ATTEST_QUOTE
		ExtraData:        data[16:32],
		AttestationKeyID: fmt.Sprintf("%x", sha256.Sum256(data)[:8]),
	}, nil
}

// validateAttestationBinding validates attestation is bound to certificate
func (v *TPMValidator) validateAttestationBinding(attestation *AttestationData, cert *x509.Certificate, keyID string) error {
	// Validate key ID matches
	if attestation.AttestationKeyID != keyID {
		return &ValidationError{
			Code:    ValidationErrorInvalidKeyID,
			Message: "attestation key ID does not match certificate",
		}
	}

	// Validate public key matches
	certPubKeyHash := v.hashPublicKey(cert.PublicKey)
	if len(attestation.ExtraData) >= 16 {
		attestedPubKeyHash := attestation.ExtraData[:16]
		if !v.compareHashes(certPubKeyHash, attestedPubKeyHash) {
			return &ValidationError{
				Code:    ValidationErrorInvalidSignature,
				Message: "attestation public key does not match certificate",
			}
		}
	}

	return nil
}

// validateTimestamps validates creation and expiration timestamps
func (v *TPMValidator) validateTimestamps(createdAt, expiresAt int64) error {
	if createdAt <= 0 {
		return &ValidationError{
			Code:    ValidationErrorInvalidChain,
			Message: "invalid creation timestamp",
		}
	}

	if expiresAt <= 0 {
		return &ValidationError{
			Code:    ValidationErrorInvalidChain,
			Message: "invalid expiration timestamp",
		}
	}

	if expiresAt <= createdAt {
		return &ValidationError{
			Code:    ValidationErrorExpiredCert,
			Message: "expiration timestamp before creation timestamp",
		}
	}

	now := time.Now().Unix()
	if now > expiresAt {
		return &ValidationError{
			Code:    ValidationErrorExpiredCert,
			Message: "TPM key expired",
		}
	}

	return nil
}

// hashPublicKey creates a hash of the public key
func (v *TPMValidator) hashPublicKey(pubKey interface{}) []byte {
	var keyBytes []byte

	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		keyBytes = key.N.Bytes()
	case *ecdsa.PublicKey:
		keyBytes = append(key.X.Bytes(), key.Y.Bytes()...)
	default:
		return nil
	}

	hash := sha256.Sum256(keyBytes)
	return hash[:]
}

// compareHashes compares two hash values
func (v *TPMValidator) compareHashes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// GetValidationStats returns validation statistics
func (v *TPMValidator) GetValidationStats() map[string]interface{} {
	return map[string]interface{}{
		"max_chain_length":     v.maxChainLength,
		"allowed_key_usages":   v.allowedKeyUsages,
		"clock_skew_tolerance": v.clockSkewTolerance,
		"has_trusted_roots":    v.trustedRoots != nil,
	}
}
