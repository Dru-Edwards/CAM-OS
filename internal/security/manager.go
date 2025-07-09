package security

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"sync"
	"time"
)

// Post-quantum cryptography algorithms
const (
	AlgorithmKyber768    = "kyber768"
	AlgorithmDilithium3  = "dilithium3"
	AlgorithmRSAPSS      = "rsa-pss"
	AlgorithmECDSA       = "ecdsa"
)

// Trust levels for security assessment
type TrustLevel int

const (
	TrustLevelUntrusted TrustLevel = iota
	TrustLevelLow
	TrustLevelMedium
	TrustLevelHigh
	TrustLevelUltimate
)

// VerificationResult represents the result of manifest verification
type VerificationResult struct {
	Valid            bool
	Issuer           string
	ExpiresAt        time.Time
	SignatureValid   bool
	CertificateValid bool
	NotExpired       bool
	NotRevoked       bool
	Warnings         []string
	TrustLevel       TrustLevel
}

// TrustEnvelope represents the CAM Trust Envelope
type TrustEnvelope struct {
	TPMKeyID           string
	PostQuantumKeyPair *PostQuantumKeyPair
	Certificates       [][]byte
	RevocationList     []string
}

// PostQuantumKeyPair represents a post-quantum key pair
type PostQuantumKeyPair struct {
	Algorithm  string
	PublicKey  []byte
	PrivateKey []byte
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// SecureChannel represents an established secure channel
type SecureChannel struct {
	ID               string
	PeerID           string
	Protocol         string
	SessionKey       []byte
	EstablishedAt    time.Time
	ExpiresAt        time.Time
	MutualAuth       bool
	NegotiatedCipher string
}

// Config holds the security manager configuration - Enhanced for CAM-OS Fork
type Config struct {
	PostQuantumEnabled   bool
	TLSEnabled          bool
	TPMPath             string
	CertificateStore    string
	TrustPolicyPath     string
	RevocationCheckURL  string
	KeyRotationInterval time.Duration
	MaxChannelLifetime  time.Duration
}

// Manager handles security operations - Enhanced for Post-Quantum Security
type Manager struct {
	config       *Config
	trustEnv     *TrustEnvelope
	channels     map[string]*SecureChannel
	channelMutex sync.RWMutex
	keyCache     map[string]*PostQuantumKeyPair
	cacheMutex   sync.RWMutex
}

// NewManager creates a new enhanced security manager
func NewManager(config *Config) *Manager {
	return &Manager{
		config:   config,
		channels: make(map[string]*SecureChannel),
		keyCache: make(map[string]*PostQuantumKeyPair),
	}
}

// Initialize initializes the enhanced security manager
func (m *Manager) Initialize(ctx context.Context) error {
	// Initialize TPM 2.0 Trust Envelope
	if err := m.initializeTPMTrustEnvelope(ctx); err != nil {
		return fmt.Errorf("failed to initialize TPM trust envelope: %v", err)
	}
	
	// Initialize post-quantum key pairs
	if m.config.PostQuantumEnabled {
		if err := m.initializePostQuantumKeys(ctx); err != nil {
			return fmt.Errorf("failed to initialize post-quantum keys: %v", err)
		}
	}
	
	// Start key rotation if configured
	if m.config.KeyRotationInterval > 0 {
		go m.keyRotationWorker(ctx)
	}
	
	// Start channel cleanup worker
	go m.channelCleanupWorker(ctx)
	
	return nil
}

// initializeTPMTrustEnvelope initializes the TPM 2.0 trust envelope
func (m *Manager) initializeTPMTrustEnvelope(ctx context.Context) error {
	// In a real implementation, this would:
	// 1. Connect to TPM 2.0 device
	// 2. Verify platform configuration registers (PCRs)
	// 3. Create or load attestation identity key (AIK)
	// 4. Establish secure boot chain of trust
	
	m.trustEnv = &TrustEnvelope{
		TPMKeyID:       "tpm-aik-001",
		Certificates:   make([][]byte, 0),
		RevocationList: make([]string, 0),
	}
	
	return nil
}

// initializePostQuantumKeys initializes post-quantum cryptographic keys
func (m *Manager) initializePostQuantumKeys(ctx context.Context) error {
	// Generate Kyber768 key pair for key exchange
	kyberKeyPair, err := m.generatePostQuantumKeyPair(AlgorithmKyber768)
	if err != nil {
		return fmt.Errorf("failed to generate Kyber768 key pair: %v", err)
	}
	
	// Generate Dilithium3 key pair for signatures
	dilithiumKeyPair, err := m.generatePostQuantumKeyPair(AlgorithmDilithium3)
	if err != nil {
		return fmt.Errorf("failed to generate Dilithium3 key pair: %v", err)
	}
	
	// Cache the key pairs
	m.cacheMutex.Lock()
	m.keyCache[AlgorithmKyber768] = kyberKeyPair
	m.keyCache[AlgorithmDilithium3] = dilithiumKeyPair
	m.cacheMutex.Unlock()
	
	// Store in trust envelope
	m.trustEnv.PostQuantumKeyPair = dilithiumKeyPair
	
	return nil
}

// generatePostQuantumKeyPair generates a post-quantum key pair
func (m *Manager) generatePostQuantumKeyPair(algorithm string) (*PostQuantumKeyPair, error) {
	// Mock implementation - in real deployment, this would use actual PQC libraries
	// like liboqs or similar post-quantum cryptography implementations
	
	var publicKeySize, privateKeySize int
	switch algorithm {
	case AlgorithmKyber768:
		publicKeySize = 1184  // Kyber768 public key size
		privateKeySize = 2400 // Kyber768 private key size
	case AlgorithmDilithium3:
		publicKeySize = 1952  // Dilithium3 public key size
		privateKeySize = 4000 // Dilithium3 private key size
	default:
		return nil, fmt.Errorf("unsupported post-quantum algorithm: %s", algorithm)
	}
	
	publicKey := make([]byte, publicKeySize)
	privateKey := make([]byte, privateKeySize)
	
	if _, err := rand.Read(publicKey); err != nil {
		return nil, fmt.Errorf("failed to generate public key: %v", err)
	}
	if _, err := rand.Read(privateKey); err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}
	
	return &PostQuantumKeyPair{
		Algorithm:  algorithm,
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(365 * 24 * time.Hour), // 1 year
	}, nil
}

// Shutdown shuts down the security manager
func (m *Manager) Shutdown(ctx context.Context) error {
	// Close all secure channels
	m.channelMutex.Lock()
	for id := range m.channels {
		delete(m.channels, id)
	}
	m.channelMutex.Unlock()
	
	// Clear key cache
	m.cacheMutex.Lock()
	for id := range m.keyCache {
		delete(m.keyCache, id)
	}
	m.cacheMutex.Unlock()
	
	// Cleanup TPM resources
	// In real implementation: disconnect from TPM, clear session state
	
	return nil
}

// TmpSign signs data using TPM 2.0 with post-quantum algorithms
func (m *Manager) TmpSign(ctx context.Context, data []byte, keyID string) ([]byte, string, error) {
	// Hash the data
	hash := sha256.Sum256(data)
	
	var signature []byte
	var algorithm string
	
	if m.config.PostQuantumEnabled {
		// Use Dilithium3 for post-quantum signatures
		keyPair, err := m.getPostQuantumKeyPair(AlgorithmDilithium3)
		if err != nil {
			return nil, "", fmt.Errorf("failed to get Dilithium3 key pair: %v", err)
		}
		
		// Mock Dilithium3 signature - in real implementation use actual PQC library
		signature = make([]byte, 3293) // Dilithium3 signature size
		if _, err := rand.Read(signature); err != nil {
			return nil, "", fmt.Errorf("failed to generate signature: %v", err)
		}
		
		// Add hash and timestamp to signature
		copy(signature[:32], hash[:])
		timestamp := time.Now().Unix()
		for i := 0; i < 8; i++ {
			signature[32+i] = byte(timestamp >> (8 * i))
		}
		
		algorithm = "TPM2-Dilithium3"
	} else {
		// Fallback to traditional TPM signing
		signature = make([]byte, 64)
		if _, err := rand.Read(signature); err != nil {
			return nil, "", fmt.Errorf("failed to generate signature: %v", err)
		}
		algorithm = "TPM2-SHA256"
	}
	
	return signature, algorithm, nil
}

// VerifyManifest verifies a driver manifest with enhanced security checks
func (m *Manager) VerifyManifest(ctx context.Context, manifest, signature []byte, publicKey string) (*VerificationResult, error) {
	result := &VerificationResult{
		Warnings: make([]string, 0),
	}
	
	// Parse public key
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return &VerificationResult{
			Valid:      false,
			TrustLevel: TrustLevelUntrusted,
		}, fmt.Errorf("failed to parse public key")
	}
	
	// Verify certificate chain
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		result.Warnings = append(result.Warnings, "Failed to parse certificate")
		result.CertificateValid = false
	} else {
		result.CertificateValid = true
		result.Issuer = cert.Issuer.String()
		result.ExpiresAt = cert.NotAfter
		
		// Check expiration
		if time.Now().After(cert.NotAfter) {
			result.NotExpired = false
			result.Warnings = append(result.Warnings, "Certificate has expired")
		} else {
			result.NotExpired = true
		}
	}
	
	// Check revocation status
	result.NotRevoked = m.checkRevocationStatus(ctx, hex.EncodeToString(signature))
	if !result.NotRevoked {
		result.Warnings = append(result.Warnings, "Certificate has been revoked")
	}
	
	// Verify signature
	if m.config.PostQuantumEnabled {
		result.SignatureValid = m.verifyPostQuantumSignature(manifest, signature)
	} else {
		result.SignatureValid = m.verifyTraditionalSignature(manifest, signature, publicKey)
	}
	
	// Determine trust level
	result.TrustLevel = m.calculateTrustLevel(result)
	
	// Overall validity
	result.Valid = result.SignatureValid && result.CertificateValid && result.NotExpired && result.NotRevoked
	
	return result, nil
}

// EstablishSecureChannel establishes a post-quantum secure channel
func (m *Manager) EstablishSecureChannel(ctx context.Context, peerID, protocol string) (string, []byte, error) {
	channelID := fmt.Sprintf("channel_%s_%d", peerID, time.Now().UnixNano())
	
	var sessionKey []byte
	var cipher string
	var err error
	
	if m.config.PostQuantumEnabled && protocol == AlgorithmKyber768 {
		// Use Kyber768 for post-quantum key exchange
		sessionKey, cipher, err = m.performKyberKeyExchange(ctx, peerID)
		if err != nil {
			return "", nil, fmt.Errorf("Kyber768 key exchange failed: %v", err)
		}
	} else {
		// Fallback to traditional key exchange
		sessionKey = make([]byte, 32)
		if _, err := rand.Read(sessionKey); err != nil {
			return "", nil, fmt.Errorf("failed to generate session key: %v", err)
		}
		cipher = "AES-256-GCM"
	}
	
	// Create secure channel
	channel := &SecureChannel{
		ID:               channelID,
		PeerID:           peerID,
		Protocol:         protocol,
		SessionKey:       sessionKey,
		EstablishedAt:    time.Now(),
		ExpiresAt:        time.Now().Add(m.config.MaxChannelLifetime),
		MutualAuth:       true,
		NegotiatedCipher: cipher,
	}
	
	// Store channel
	m.channelMutex.Lock()
	m.channels[channelID] = channel
	m.channelMutex.Unlock()
	
	return channelID, sessionKey, nil
}

// performKyberKeyExchange performs Kyber768 key exchange
func (m *Manager) performKyberKeyExchange(ctx context.Context, peerID string) ([]byte, string, error) {
	// Mock Kyber768 implementation - in real deployment use actual PQC library
	keyPair, err := m.getPostQuantumKeyPair(AlgorithmKyber768)
	if err != nil {
		return nil, "", err
	}
	
	// Generate shared secret (mock)
	sharedSecret := make([]byte, 32)
	if _, err := rand.Read(sharedSecret); err != nil {
		return nil, "", fmt.Errorf("failed to generate shared secret: %v", err)
	}
	
	// Derive session key from shared secret
	hash := sha256.Sum256(append(keyPair.PublicKey[:32], sharedSecret...))
	sessionKey := hash[:]
	
	return sessionKey, "Kyber768-AES-256", nil
}

// Helper methods

func (m *Manager) getPostQuantumKeyPair(algorithm string) (*PostQuantumKeyPair, error) {
	m.cacheMutex.RLock()
	keyPair, exists := m.keyCache[algorithm]
	m.cacheMutex.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("key pair not found for algorithm: %s", algorithm)
	}
	
	if time.Now().After(keyPair.ExpiresAt) {
		return nil, fmt.Errorf("key pair has expired")
	}
	
	return keyPair, nil
}

func (m *Manager) checkRevocationStatus(ctx context.Context, signatureHash string) bool {
	// Check against revocation list
	for _, revokedHash := range m.trustEnv.RevocationList {
		if revokedHash == signatureHash {
			return false
		}
	}
	return true
}

func (m *Manager) verifyPostQuantumSignature(data, signature []byte) bool {
	// Mock Dilithium3 verification - in real implementation use actual PQC library
	// This would involve:
	// 1. Parse Dilithium3 signature
	// 2. Verify against public key using Dilithium3 algorithm
	// 3. Check timestamp and hash integrity
	
	if len(signature) < 40 {
		return false
	}
	
	// Extract hash and timestamp from signature
	signatureHash := signature[:32]
	timestamp := int64(0)
	for i := 0; i < 8; i++ {
		timestamp |= int64(signature[32+i]) << (8 * i)
	}
	
	// Verify hash
	dataHash := sha256.Sum256(data)
	if !equalBytes(signatureHash, dataHash[:]) {
		return false
	}
	
	// Check timestamp (must be within reasonable range)
	now := time.Now().Unix()
	if timestamp < now-3600 || timestamp > now+300 { // 1 hour past to 5 minutes future
		return false
	}
	
	return true
}

func (m *Manager) verifyTraditionalSignature(data, signature []byte, publicKey string) bool {
	// Mock traditional signature verification
	// In real implementation, use crypto/rsa or crypto/ecdsa
	return len(signature) > 0 && len(publicKey) > 0
}

func (m *Manager) calculateTrustLevel(result *VerificationResult) TrustLevel {
	if !result.SignatureValid {
		return TrustLevelUntrusted
	}
	
	score := 0
	if result.CertificateValid {
		score += 2
	}
	if result.NotExpired {
		score += 2
	}
	if result.NotRevoked {
		score += 2
	}
	if len(result.Warnings) == 0 {
		score += 1
	}
	
	switch {
	case score >= 7:
		return TrustLevelUltimate
	case score >= 5:
		return TrustLevelHigh
	case score >= 3:
		return TrustLevelMedium
	case score >= 1:
		return TrustLevelLow
	default:
		return TrustLevelUntrusted
	}
}

// Worker functions

func (m *Manager) keyRotationWorker(ctx context.Context) {
	ticker := time.NewTicker(m.config.KeyRotationInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.rotateKeys(ctx)
		}
	}
}

func (m *Manager) rotateKeys(ctx context.Context) {
	// Rotate post-quantum keys
	if m.config.PostQuantumEnabled {
		for algorithm := range m.keyCache {
			newKeyPair, err := m.generatePostQuantumKeyPair(algorithm)
			if err != nil {
				continue
			}
			
			m.cacheMutex.Lock()
			m.keyCache[algorithm] = newKeyPair
			m.cacheMutex.Unlock()
		}
	}
}

func (m *Manager) channelCleanupWorker(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.cleanupExpiredChannels()
		}
	}
}

func (m *Manager) cleanupExpiredChannels() {
	now := time.Now()
	
	m.channelMutex.Lock()
	defer m.channelMutex.Unlock()
	
	for id, channel := range m.channels {
		if now.After(channel.ExpiresAt) {
			delete(m.channels, id)
		}
	}
}

// HealthCheck performs comprehensive health check on the security manager
func (m *Manager) HealthCheck(ctx context.Context) error {
	// Check TPM connection
	if m.trustEnv == nil {
		return fmt.Errorf("TPM trust envelope not initialized")
	}
	
	// Check post-quantum keys
	if m.config.PostQuantumEnabled {
		m.cacheMutex.RLock()
		kyberKey, kyberExists := m.keyCache[AlgorithmKyber768]
		dilithiumKey, dilithiumExists := m.keyCache[AlgorithmDilithium3]
		m.cacheMutex.RUnlock()
		
		if !kyberExists || !dilithiumExists {
			return fmt.Errorf("post-quantum keys not available")
		}
		
		if time.Now().After(kyberKey.ExpiresAt) || time.Now().After(dilithiumKey.ExpiresAt) {
			return fmt.Errorf("post-quantum keys have expired")
		}
	}
	
	// Check channel health
	m.channelMutex.RLock()
	activeChannels := len(m.channels)
	m.channelMutex.RUnlock()
	
	if activeChannels > 10000 {
		return fmt.Errorf("too many active channels: %d", activeChannels)
	}
	
	return nil
}

// Utility functions

func equalBytes(a, b []byte) bool {
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