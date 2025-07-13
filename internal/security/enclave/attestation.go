package enclave

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// EnclaveAttestation manages attestation for secure enclaves
type EnclaveAttestation struct {
	// Attestation cache
	attestations map[string]*CachedAttestation
	mutex        sync.RWMutex

	// Configuration
	cacheTimeout     time.Duration
	maxAttestations  int
	verificationKeys [][]byte
	trustedIssuers   []string

	// Metrics
	totalAttestations   int64
	validAttestations   int64
	invalidAttestations int64
	cacheHits           int64
	cacheMisses         int64

	// Root of trust
	rootCertificate   []byte
	intermediateCerts [][]byte

	// Platform trust anchors
	sgxTrustAnchors       [][]byte
	trustZoneTrustAnchors [][]byte

	// Policy engine
	policyEngine *AttestationPolicyEngine
}

// CachedAttestation represents a cached attestation result
type CachedAttestation struct {
	Result     *AttestationResult
	Timestamp  time.Time
	ExpiresAt  time.Time
	UsageCount int
	MaxUsage   int
	EnclaveID  string
	Platform   Platform
}

// AttestationPolicy represents an attestation policy
type AttestationPolicy struct {
	ID           string
	Name         string
	Version      string
	CreatedAt    time.Time
	LastModified time.Time
	Enabled      bool

	// Platform requirements
	AllowedPlatforms       []Platform
	RequiredSecurityLevel  SecurityLevel
	RequiredIsolationLevel IsolationLevel

	// Measurement requirements
	RequiredMeasurements  map[string][]byte
	AllowedMeasurements   map[string][][]byte
	ForbiddenMeasurements map[string][]byte

	// Certificate requirements
	RequiredCertChain  bool
	TrustedIssuers     []string
	RequiredExtensions []string

	// Freshness requirements
	MaxAge           time.Duration
	RequireNonce     bool
	RequireTimestamp bool

	// Custom validation
	CustomValidators []string
	ValidationScript string

	// Policy metadata
	Description string
	Tags        []string
	Owner       string
	Environment string
}

// AttestationPolicyEngine manages attestation policies
type AttestationPolicyEngine struct {
	policies      map[string]*AttestationPolicy
	mutex         sync.RWMutex
	defaultPolicy *AttestationPolicy
}

// AttestationRequest represents a request for attestation
type AttestationRequest struct {
	EnclaveID     string
	Platform      Platform
	Nonce         []byte
	PolicyID      string
	Context       map[string]interface{}
	RequiredLevel SecurityLevel
	Timestamp     time.Time
	UserData      []byte
}

// AttestationEvidence represents evidence for attestation
type AttestationEvidence struct {
	Type         string
	Platform     Platform
	Measurements map[string][]byte
	Signature    []byte
	Certificate  []byte
	CertChain    [][]byte
	Timestamp    time.Time
	Nonce        []byte
	UserData     []byte
	PlatformData map[string]interface{}
}

// AttestationVerificationResult represents the result of attestation verification
type AttestationVerificationResult struct {
	Valid             bool
	PolicyID          string
	TrustLevel        SecurityLevel
	Violations        []string
	Warnings          []string
	VerifiedClaims    map[string]interface{}
	CertificateChain  [][]byte
	SignatureValid    bool
	MeasurementsValid bool
	FreshnessValid    bool
	PolicyCompliant   bool
	TrustAnchorValid  bool
	Error             error
}

// NewEnclaveAttestation creates a new enclave attestation service
func NewEnclaveAttestation() *EnclaveAttestation {
	attestation := &EnclaveAttestation{
		attestations:     make(map[string]*CachedAttestation),
		cacheTimeout:     time.Hour,
		maxAttestations:  1000,
		verificationKeys: make([][]byte, 0),
		trustedIssuers:   make([]string, 0),
		policyEngine:     NewAttestationPolicyEngine(),
	}

	// Initialize trust anchors
	attestation.initializeTrustAnchors()

	// Create default policy
	attestation.createDefaultPolicy()

	// Start background cleanup
	go attestation.cleanupWorker()

	return attestation
}

// VerifyAttestation verifies an attestation with policy enforcement
func (a *EnclaveAttestation) VerifyAttestation(request *AttestationRequest, evidence *AttestationEvidence) (*AttestationVerificationResult, error) {
	// Check cache first
	if cached := a.getCachedAttestation(request.EnclaveID); cached != nil {
		a.cacheHits++
		return a.attestationResultToVerificationResult(cached.Result), nil
	}

	a.cacheMisses++

	// Get policy
	policy, err := a.policyEngine.GetPolicy(request.PolicyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get attestation policy: %v", err)
	}

	// Verify attestation
	result := &AttestationVerificationResult{
		PolicyID:       request.PolicyID,
		VerifiedClaims: make(map[string]interface{}),
		Violations:     make([]string, 0),
		Warnings:       make([]string, 0),
	}

	// Verify platform
	err = a.verifyPlatform(evidence, policy, result)
	if err != nil {
		result.Valid = false
		result.Error = err
		return result, nil
	}

	// Verify measurements
	err = a.verifyMeasurements(evidence, policy, result)
	if err != nil {
		result.Valid = false
		result.Error = err
		return result, nil
	}

	// Verify certificate chain
	err = a.verifyCertificateChain(evidence, policy, result)
	if err != nil {
		result.Valid = false
		result.Error = err
		return result, nil
	}

	// Verify signature
	err = a.verifySignature(evidence, policy, result)
	if err != nil {
		result.Valid = false
		result.Error = err
		return result, nil
	}

	// Verify freshness
	err = a.verifyFreshness(evidence, policy, result)
	if err != nil {
		result.Valid = false
		result.Error = err
		return result, nil
	}

	// Check policy compliance
	result.PolicyCompliant = len(result.Violations) == 0
	result.Valid = result.PolicyCompliant && result.SignatureValid && result.MeasurementsValid && result.FreshnessValid

	// Determine trust level
	if result.Valid {
		result.TrustLevel = a.calculateTrustLevel(evidence, policy, result)
		a.validAttestations++
	} else {
		result.TrustLevel = SecurityLevelBasic
		a.invalidAttestations++
	}

	a.totalAttestations++

	// Cache result
	a.cacheAttestation(request.EnclaveID, &AttestationResult{
		EnclaveID:       request.EnclaveID,
		Valid:           result.Valid,
		TrustLevel:      result.TrustLevel,
		Timestamp:       time.Now(),
		Measurements:    evidence.Measurements,
		Certificate:     evidence.Certificate,
		Signature:       evidence.Signature,
		AttestationData: a.serializeEvidence(evidence),
	})

	return result, nil
}

// CreateAttestation creates a new attestation for an enclave
func (a *EnclaveAttestation) CreateAttestation(enclave *SecureEnclave, request *AttestationRequest) (*AttestationEvidence, error) {
	evidence := &AttestationEvidence{
		Type:         string(enclave.Type),
		Platform:     enclave.Platform,
		Measurements: make(map[string][]byte),
		Timestamp:    time.Now(),
		Nonce:        request.Nonce,
		UserData:     request.UserData,
		PlatformData: make(map[string]interface{}),
	}

	// Create platform-specific attestation
	switch enclave.Platform {
	case PlatformIntelSGX:
		return a.createSGXAttestation(enclave, evidence)
	case PlatformARMTZ:
		return a.createTrustZoneAttestation(enclave, evidence)
	case PlatformSimulated:
		return a.createSimulatedAttestation(enclave, evidence)
	default:
		return nil, fmt.Errorf("unsupported platform: %s", enclave.Platform)
	}
}

// Platform-specific attestation creation

func (a *EnclaveAttestation) createSGXAttestation(enclave *SecureEnclave, evidence *AttestationEvidence) (*AttestationEvidence, error) {
	if enclave.SGXData == nil {
		return nil, errors.New("SGX data not available")
	}

	// Add SGX measurements
	evidence.Measurements["mrenclave"] = enclave.SGXData.MRENCLAVE[:]
	evidence.Measurements["mrsigner"] = enclave.SGXData.MRSIGNER[:]

	// Add platform data
	evidence.PlatformData["isv_prod_id"] = enclave.SGXData.ISVProdID
	evidence.PlatformData["isv_svn"] = enclave.SGXData.ISVRevision
	evidence.PlatformData["debug_mode"] = enclave.SGXData.Debug
	evidence.PlatformData["mode_64bit"] = enclave.SGXData.Mode64Bit

	// Generate quote
	quote := a.generateSGXQuote(enclave, evidence)
	evidence.Signature = quote

	// Generate certificate
	cert := a.generateSGXCertificate(enclave, evidence)
	evidence.Certificate = cert

	return evidence, nil
}

func (a *EnclaveAttestation) createTrustZoneAttestation(enclave *SecureEnclave, evidence *AttestationEvidence) (*AttestationEvidence, error) {
	if enclave.TrustZoneData == nil {
		return nil, errors.New("TrustZone data not available")
	}

	// Add TrustZone measurements
	evidence.Measurements["ta_uuid"] = enclave.TrustZoneData.UUID[:]
	evidence.Measurements["device_key"] = a.hashKey(enclave.TrustZoneData.DeviceKey)

	// Add platform data
	evidence.PlatformData["session_id"] = enclave.TrustZoneData.SessionID
	evidence.PlatformData["secure_world_id"] = enclave.TrustZoneData.SecureWorldID
	evidence.PlatformData["memory_type"] = enclave.TrustZoneData.MemoryType
	evidence.PlatformData["flags"] = enclave.TrustZoneData.Flags

	// Generate attestation token
	token := a.generateTrustZoneToken(enclave, evidence)
	evidence.Signature = token

	// Generate certificate
	cert := a.generateTrustZoneCertificate(enclave, evidence)
	evidence.Certificate = cert

	return evidence, nil
}

func (a *EnclaveAttestation) createSimulatedAttestation(enclave *SecureEnclave, evidence *AttestationEvidence) (*AttestationEvidence, error) {
	// Create simulated measurements
	evidence.Measurements["simulated_hash"] = a.hashKey([]byte(enclave.ID))
	evidence.Measurements["creation_time"] = a.hashKey([]byte(enclave.CreatedAt.String()))

	// Add platform data
	evidence.PlatformData["simulation_mode"] = true
	evidence.PlatformData["security_level"] = enclave.SecurityLevel
	evidence.PlatformData["isolation_level"] = enclave.IsolationLevel

	// Generate simulated signature
	sigData := a.serializeEvidence(evidence)
	evidence.Signature = a.signData(sigData, []byte("simulated_key"))

	// Generate simulated certificate
	evidence.Certificate = a.generateSimulatedCertificate(enclave, evidence)

	return evidence, nil
}

// Verification methods

func (a *EnclaveAttestation) verifyPlatform(evidence *AttestationEvidence, policy *AttestationPolicy, result *AttestationVerificationResult) error {
	// Check if platform is allowed
	platformAllowed := false
	for _, allowedPlatform := range policy.AllowedPlatforms {
		if evidence.Platform == allowedPlatform {
			platformAllowed = true
			break
		}
	}

	if !platformAllowed {
		result.Violations = append(result.Violations, fmt.Sprintf("platform %s not allowed", evidence.Platform))
	}

	result.VerifiedClaims["platform"] = evidence.Platform
	return nil
}

func (a *EnclaveAttestation) verifyMeasurements(evidence *AttestationEvidence, policy *AttestationPolicy, result *AttestationVerificationResult) error {
	// Check required measurements
	for name, requiredValue := range policy.RequiredMeasurements {
		if actualValue, exists := evidence.Measurements[name]; !exists {
			result.Violations = append(result.Violations, fmt.Sprintf("required measurement %s missing", name))
		} else if !a.compareMeasurements(actualValue, requiredValue) {
			result.Violations = append(result.Violations, fmt.Sprintf("measurement %s does not match required value", name))
		}
	}

	// Check forbidden measurements
	for name, forbiddenValue := range policy.ForbiddenMeasurements {
		if actualValue, exists := evidence.Measurements[name]; exists {
			if a.compareMeasurements(actualValue, forbiddenValue) {
				result.Violations = append(result.Violations, fmt.Sprintf("forbidden measurement %s found", name))
			}
		}
	}

	result.MeasurementsValid = len(result.Violations) == 0
	result.VerifiedClaims["measurements"] = evidence.Measurements
	return nil
}

func (a *EnclaveAttestation) verifyCertificateChain(evidence *AttestationEvidence, policy *AttestationPolicy, result *AttestationVerificationResult) error {
	if policy.RequiredCertChain {
		if len(evidence.Certificate) == 0 {
			result.Violations = append(result.Violations, "certificate required but not provided")
			return nil
		}

		// Verify certificate chain
		valid := a.verifyCertChain(evidence.Certificate, evidence.CertChain)
		if !valid {
			result.Violations = append(result.Violations, "certificate chain verification failed")
		}

		result.CertificateChain = evidence.CertChain
	}

	result.TrustAnchorValid = len(result.Violations) == 0
	return nil
}

func (a *EnclaveAttestation) verifySignature(evidence *AttestationEvidence, policy *AttestationPolicy, result *AttestationVerificationResult) error {
	if len(evidence.Signature) == 0 {
		result.Violations = append(result.Violations, "signature required but not provided")
		return nil
	}

	// Verify signature based on platform
	var valid bool
	switch evidence.Platform {
	case PlatformIntelSGX:
		valid = a.verifySGXSignature(evidence)
	case PlatformARMTZ:
		valid = a.verifyTrustZoneSignature(evidence)
	case PlatformSimulated:
		valid = a.verifySimulatedSignature(evidence)
	default:
		result.Violations = append(result.Violations, fmt.Sprintf("unsupported platform for signature verification: %s", evidence.Platform))
		return nil
	}

	if !valid {
		result.Violations = append(result.Violations, "signature verification failed")
	}

	result.SignatureValid = valid
	return nil
}

func (a *EnclaveAttestation) verifyFreshness(evidence *AttestationEvidence, policy *AttestationPolicy, result *AttestationVerificationResult) error {
	now := time.Now()

	// Check age
	if policy.MaxAge > 0 {
		if now.Sub(evidence.Timestamp) > policy.MaxAge {
			result.Violations = append(result.Violations, "attestation too old")
		}
	}

	// Check nonce
	if policy.RequireNonce && len(evidence.Nonce) == 0 {
		result.Violations = append(result.Violations, "nonce required but not provided")
	}

	// Check timestamp
	if policy.RequireTimestamp && evidence.Timestamp.IsZero() {
		result.Violations = append(result.Violations, "timestamp required but not provided")
	}

	result.FreshnessValid = len(result.Violations) == 0
	return nil
}

// Helper methods

func (a *EnclaveAttestation) calculateTrustLevel(evidence *AttestationEvidence, policy *AttestationPolicy, result *AttestationVerificationResult) SecurityLevel {
	// Base trust level from policy
	trustLevel := policy.RequiredSecurityLevel

	// Adjust based on platform
	switch evidence.Platform {
	case PlatformIntelSGX:
		if trustLevel < SecurityLevelHigh {
			trustLevel = SecurityLevelHigh
		}
	case PlatformARMTZ:
		if trustLevel < SecurityLevelStandard {
			trustLevel = SecurityLevelStandard
		}
	case PlatformSimulated:
		if trustLevel > SecurityLevelBasic {
			trustLevel = SecurityLevelBasic
		}
	}

	// Adjust based on violations
	if len(result.Violations) > 0 {
		if trustLevel > SecurityLevelBasic {
			trustLevel = SecurityLevelBasic
		}
	}

	return trustLevel
}

func (a *EnclaveAttestation) compareMeasurements(actual, expected []byte) bool {
	if len(actual) != len(expected) {
		return false
	}

	for i := range actual {
		if actual[i] != expected[i] {
			return false
		}
	}

	return true
}

func (a *EnclaveAttestation) hashKey(key []byte) []byte {
	hash := sha256.Sum256(key)
	return hash[:]
}

func (a *EnclaveAttestation) signData(data, key []byte) []byte {
	// Simplified signing
	hash := sha256.Sum256(append(data, key...))
	return hash[:]
}

func (a *EnclaveAttestation) serializeEvidence(evidence *AttestationEvidence) []byte {
	// Simplified serialization
	data, _ := json.Marshal(evidence)
	return data
}

func (a *EnclaveAttestation) generateSGXQuote(enclave *SecureEnclave, evidence *AttestationEvidence) []byte {
	// Simplified SGX quote generation
	quoteData := append(evidence.Measurements["mrenclave"], evidence.Measurements["mrsigner"]...)
	quoteData = append(quoteData, evidence.Nonce...)
	hash := sha256.Sum256(quoteData)
	return hash[:]
}

func (a *EnclaveAttestation) generateSGXCertificate(enclave *SecureEnclave, evidence *AttestationEvidence) []byte {
	// Simplified SGX certificate generation
	certData := []byte("SGX_CERT")
	certData = append(certData, evidence.Measurements["mrenclave"]...)
	certData = append(certData, evidence.Signature...)
	return certData
}

func (a *EnclaveAttestation) generateTrustZoneToken(enclave *SecureEnclave, evidence *AttestationEvidence) []byte {
	// Simplified TrustZone token generation
	tokenData := append(evidence.Measurements["ta_uuid"], evidence.Measurements["device_key"]...)
	tokenData = append(tokenData, evidence.Nonce...)
	hash := sha256.Sum256(tokenData)
	return hash[:]
}

func (a *EnclaveAttestation) generateTrustZoneCertificate(enclave *SecureEnclave, evidence *AttestationEvidence) []byte {
	// Simplified TrustZone certificate generation
	certData := []byte("TZ_CERT")
	certData = append(certData, evidence.Measurements["ta_uuid"]...)
	certData = append(certData, evidence.Signature...)
	return certData
}

func (a *EnclaveAttestation) generateSimulatedCertificate(enclave *SecureEnclave, evidence *AttestationEvidence) []byte {
	// Simplified simulated certificate generation
	certData := []byte("SIM_CERT")
	certData = append(certData, evidence.Measurements["simulated_hash"]...)
	certData = append(certData, evidence.Signature...)
	return certData
}

func (a *EnclaveAttestation) verifySGXSignature(evidence *AttestationEvidence) bool {
	// Simplified SGX signature verification
	return len(evidence.Signature) == 32
}

func (a *EnclaveAttestation) verifyTrustZoneSignature(evidence *AttestationEvidence) bool {
	// Simplified TrustZone signature verification
	return len(evidence.Signature) == 32
}

func (a *EnclaveAttestation) verifySimulatedSignature(evidence *AttestationEvidence) bool {
	// Simplified simulated signature verification
	return len(evidence.Signature) == 32
}

func (a *EnclaveAttestation) verifyCertChain(cert []byte, chain [][]byte) bool {
	// Simplified certificate chain verification
	return len(cert) > 0
}

// Cache management

func (a *EnclaveAttestation) getCachedAttestation(enclaveID string) *CachedAttestation {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	cached, exists := a.attestations[enclaveID]
	if !exists {
		return nil
	}

	if time.Now().After(cached.ExpiresAt) {
		return nil
	}

	cached.UsageCount++
	return cached
}

func (a *EnclaveAttestation) cacheAttestation(enclaveID string, result *AttestationResult) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	// Check cache size
	if len(a.attestations) >= a.maxAttestations {
		a.evictOldestAttestation()
	}

	cached := &CachedAttestation{
		Result:     result,
		Timestamp:  time.Now(),
		ExpiresAt:  time.Now().Add(a.cacheTimeout),
		UsageCount: 0,
		MaxUsage:   100,
		EnclaveID:  enclaveID,
	}

	a.attestations[enclaveID] = cached
}

func (a *EnclaveAttestation) evictOldestAttestation() {
	var oldestID string
	var oldestTime time.Time

	for id, cached := range a.attestations {
		if oldestTime.IsZero() || cached.Timestamp.Before(oldestTime) {
			oldestID = id
			oldestTime = cached.Timestamp
		}
	}

	if oldestID != "" {
		delete(a.attestations, oldestID)
	}
}

func (a *EnclaveAttestation) attestationResultToVerificationResult(result *AttestationResult) *AttestationVerificationResult {
	return &AttestationVerificationResult{
		Valid:             result.Valid,
		TrustLevel:        result.TrustLevel,
		VerifiedClaims:    map[string]interface{}{"measurements": result.Measurements},
		SignatureValid:    result.Valid,
		MeasurementsValid: result.Valid,
		FreshnessValid:    result.Valid,
		PolicyCompliant:   result.Valid,
		TrustAnchorValid:  result.Valid,
	}
}

// Background cleanup

func (a *EnclaveAttestation) cleanupWorker() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		a.cleanupExpiredAttestations()
	}
}

func (a *EnclaveAttestation) cleanupExpiredAttestations() {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	now := time.Now()
	expiredIDs := make([]string, 0)

	for id, cached := range a.attestations {
		if now.After(cached.ExpiresAt) {
			expiredIDs = append(expiredIDs, id)
		}
	}

	for _, id := range expiredIDs {
		delete(a.attestations, id)
	}
}

// Initialization methods

func (a *EnclaveAttestation) initializeTrustAnchors() {
	// Initialize SGX trust anchors
	a.sgxTrustAnchors = [][]byte{
		[]byte("sgx_root_ca_cert"),
		[]byte("sgx_intermediate_ca_cert"),
	}

	// Initialize TrustZone trust anchors
	a.trustZoneTrustAnchors = [][]byte{
		[]byte("trustzone_root_ca_cert"),
		[]byte("trustzone_intermediate_ca_cert"),
	}
}

func (a *EnclaveAttestation) createDefaultPolicy() {
	defaultPolicy := &AttestationPolicy{
		ID:                     "default",
		Name:                   "Default Attestation Policy",
		Version:                "1.0",
		CreatedAt:              time.Now(),
		LastModified:           time.Now(),
		Enabled:                true,
		AllowedPlatforms:       []Platform{PlatformIntelSGX, PlatformARMTZ, PlatformSimulated},
		RequiredSecurityLevel:  SecurityLevelStandard,
		RequiredIsolationLevel: IsolationLevelHardware,
		RequiredMeasurements:   make(map[string][]byte),
		AllowedMeasurements:    make(map[string][][]byte),
		ForbiddenMeasurements:  make(map[string][]byte),
		RequiredCertChain:      false,
		TrustedIssuers:         []string{"intel", "arm", "simulator"},
		MaxAge:                 24 * time.Hour,
		RequireNonce:           false,
		RequireTimestamp:       true,
		Description:            "Default policy for enclave attestation",
		Tags:                   []string{"default", "standard"},
		Owner:                  "system",
		Environment:            "production",
	}

	a.policyEngine.AddPolicy(defaultPolicy)
}

// Policy engine methods

func NewAttestationPolicyEngine() *AttestationPolicyEngine {
	return &AttestationPolicyEngine{
		policies: make(map[string]*AttestationPolicy),
	}
}

func (p *AttestationPolicyEngine) AddPolicy(policy *AttestationPolicy) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.policies[policy.ID] = policy
	return nil
}

func (p *AttestationPolicyEngine) GetPolicy(policyID string) (*AttestationPolicy, error) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	if policyID == "" {
		policyID = "default"
	}

	policy, exists := p.policies[policyID]
	if !exists {
		return nil, fmt.Errorf("policy %s not found", policyID)
	}

	if !policy.Enabled {
		return nil, fmt.Errorf("policy %s is disabled", policyID)
	}

	return policy, nil
}

func (p *AttestationPolicyEngine) ListPolicies() []*AttestationPolicy {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	policies := make([]*AttestationPolicy, 0, len(p.policies))
	for _, policy := range p.policies {
		policies = append(policies, policy)
	}

	return policies
}

func (p *AttestationPolicyEngine) RemovePolicy(policyID string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if policyID == "default" {
		return errors.New("cannot remove default policy")
	}

	delete(p.policies, policyID)
	return nil
}

// Public API methods

func (a *EnclaveAttestation) GetMetrics() map[string]interface{} {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	return map[string]interface{}{
		"total_attestations":   a.totalAttestations,
		"valid_attestations":   a.validAttestations,
		"invalid_attestations": a.invalidAttestations,
		"cache_hits":           a.cacheHits,
		"cache_misses":         a.cacheMisses,
		"cached_attestations":  len(a.attestations),
		"max_cache_size":       a.maxAttestations,
		"cache_timeout":        a.cacheTimeout,
	}
}

func (a *EnclaveAttestation) ClearCache() {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	a.attestations = make(map[string]*CachedAttestation)
}

func (a *EnclaveAttestation) GetCachedAttestations() map[string]*CachedAttestation {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	result := make(map[string]*CachedAttestation)
	for id, cached := range a.attestations {
		result[id] = cached
	}

	return result
}
