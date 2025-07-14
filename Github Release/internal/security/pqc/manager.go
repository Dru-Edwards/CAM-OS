package pqc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"
)

// PostQuantumCryptoManager manages post-quantum cryptographic operations
type PostQuantumCryptoManager struct {
	kyberEngine     *Kyber768Engine
	dilithiumEngine *Dilithium3Engine
	keyStore        *KeyStore
	config          *PQCConfig
	metrics         *PQCMetrics

	// Key rotation
	keyRotationMutex sync.RWMutex
	rotationTicker   *time.Ticker

	// Context for shutdown
	ctx    context.Context
	cancel context.CancelFunc
}

// PQCConfig holds configuration for post-quantum cryptography operations
type PQCConfig struct {
	EnableKyber768      bool
	EnableDilithium3    bool
	EnableKeyRotation   bool
	KeyRotationInterval time.Duration
	KeyValidityPeriod   time.Duration
	MaxKeyAge           time.Duration
	KeyStoreEnabled     bool
	KeyStoreCapacity    int
	MetricsEnabled      bool
	PerformanceMode     bool
	SecurityLevel       string
	PreHashMode         bool
	ContextSeparation   bool
}

// PQCMetrics tracks post-quantum cryptography metrics
type PQCMetrics struct {
	KeyPairsGenerated   int64
	EncapsulationOps    int64
	DecapsulationOps    int64
	SignatureOps        int64
	VerificationOps     int64
	KeyRotations        int64
	KeyValidationErrors int64
	PerformanceMetrics  map[string]time.Duration
	LastRotation        time.Time
	ActiveKeys          int64
	ExpiredKeys         int64
	FailedOperations    int64
	mutex               sync.RWMutex
}

// KeyStore manages cryptographic keys
type KeyStore struct {
	kyberKeys     map[string]*Kyber768KeyPair
	dilithiumKeys map[string]*Dilithium3KeyPair
	keyMetadata   map[string]*KeyMetadata
	capacity      int
	mutex         sync.RWMutex
}

// KeyMetadata contains metadata about cryptographic keys
type KeyMetadata struct {
	KeyID      string
	KeyType    string
	Algorithm  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastUsed   time.Time
	UsageCount int64
	Purpose    string
	Owner      string
	Status     KeyStatus
}

// KeyStatus represents the status of a cryptographic key
type KeyStatus string

const (
	KeyStatusActive   KeyStatus = "active"
	KeyStatusExpired  KeyStatus = "expired"
	KeyStatusRevoked  KeyStatus = "revoked"
	KeyStatusRotating KeyStatus = "rotating"
	KeyStatusPending  KeyStatus = "pending"
)

// HybridKeyPair represents a hybrid key pair with both KEM and signature keys
type HybridKeyPair struct {
	KeyID            string
	KyberKeyPair     *Kyber768KeyPair
	DilithiumKeyPair *Dilithium3KeyPair
	CreatedAt        time.Time
	ExpiresAt        time.Time
	Purpose          string
	Owner            string
}

// HybridOperationResult represents the result of a hybrid cryptographic operation
type HybridOperationResult struct {
	KeyID           string
	EncapsulatedKey []byte
	SharedSecret    []byte
	Signature       []byte
	Timestamp       time.Time
	Algorithm       string
	Success         bool
	Error           error
}

// NewPostQuantumCryptoManager creates a new PQC manager
func NewPostQuantumCryptoManager(config *PQCConfig) *PostQuantumCryptoManager {
	if config == nil {
		config = &PQCConfig{
			EnableKyber768:      true,
			EnableDilithium3:    true,
			EnableKeyRotation:   true,
			KeyRotationInterval: 24 * time.Hour,
			KeyValidityPeriod:   48 * time.Hour,
			MaxKeyAge:           72 * time.Hour,
			KeyStoreEnabled:     true,
			KeyStoreCapacity:    1000,
			MetricsEnabled:      true,
			PerformanceMode:     false,
			SecurityLevel:       "NIST-Level-3",
			PreHashMode:         false,
			ContextSeparation:   true,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	manager := &PostQuantumCryptoManager{
		config: config,
		metrics: &PQCMetrics{
			PerformanceMetrics: make(map[string]time.Duration),
		},
		ctx:    ctx,
		cancel: cancel,
	}

	// Initialize engines
	if config.EnableKyber768 {
		kyberConfig := &Kyber768Config{
			KeyValidityPeriod: config.KeyValidityPeriod,
			EnableKeyRotation: config.EnableKeyRotation,
			SecureRandom:      !config.PerformanceMode,
			DebugMode:         false,
		}
		manager.kyberEngine = NewKyber768Engine(kyberConfig)
	}

	if config.EnableDilithium3 {
		dilithiumConfig := &Dilithium3Config{
			KeyValidityPeriod: config.KeyValidityPeriod,
			EnableKeyRotation: config.EnableKeyRotation,
			SecureRandom:      !config.PerformanceMode,
			DebugMode:         false,
			PreHashMode:       config.PreHashMode,
			ContextSeparation: config.ContextSeparation,
		}
		manager.dilithiumEngine = NewDilithium3Engine(dilithiumConfig)
	}

	// Initialize key store
	if config.KeyStoreEnabled {
		manager.keyStore = &KeyStore{
			kyberKeys:     make(map[string]*Kyber768KeyPair),
			dilithiumKeys: make(map[string]*Dilithium3KeyPair),
			keyMetadata:   make(map[string]*KeyMetadata),
			capacity:      config.KeyStoreCapacity,
		}
	}

	return manager
}

// Start starts the PQC manager
func (m *PostQuantumCryptoManager) Start() error {
	if m.config.EnableKeyRotation {
		m.rotationTicker = time.NewTicker(m.config.KeyRotationInterval)
		go m.keyRotationWorker()
	}

	if m.config.MetricsEnabled {
		go m.metricsWorker()
	}

	return nil
}

// Stop stops the PQC manager
func (m *PostQuantumCryptoManager) Stop() error {
	m.cancel()

	if m.rotationTicker != nil {
		m.rotationTicker.Stop()
	}

	return nil
}

// GenerateHybridKeyPair generates a hybrid key pair with both KEM and signature keys
func (m *PostQuantumCryptoManager) GenerateHybridKeyPair(purpose, owner string) (*HybridKeyPair, error) {
	startTime := time.Now()

	keyID := m.generateKeyID()

	var kyberKeyPair *Kyber768KeyPair
	var dilithiumKeyPair *Dilithium3KeyPair
	var err error

	// Generate Kyber768 key pair for key encapsulation
	if m.config.EnableKyber768 && m.kyberEngine != nil {
		kyberKeyPair, err = m.kyberEngine.GenerateKeyPair()
		if err != nil {
			return nil, fmt.Errorf("failed to generate Kyber768 key pair: %v", err)
		}
	}

	// Generate Dilithium3 key pair for digital signatures
	if m.config.EnableDilithium3 && m.dilithiumEngine != nil {
		dilithiumKeyPair, err = m.dilithiumEngine.GenerateKeyPair()
		if err != nil {
			return nil, fmt.Errorf("failed to generate Dilithium3 key pair: %v", err)
		}
	}

	// Create hybrid key pair
	hybridKeyPair := &HybridKeyPair{
		KeyID:            keyID,
		KyberKeyPair:     kyberKeyPair,
		DilithiumKeyPair: dilithiumKeyPair,
		CreatedAt:        time.Now(),
		ExpiresAt:        time.Now().Add(m.config.KeyValidityPeriod),
		Purpose:          purpose,
		Owner:            owner,
	}

	// Store in key store
	if m.config.KeyStoreEnabled {
		err = m.storeKeyPair(hybridKeyPair)
		if err != nil {
			return nil, fmt.Errorf("failed to store key pair: %v", err)
		}
	}

	// Update metrics
	m.updateMetrics(func(metrics *PQCMetrics) {
		metrics.KeyPairsGenerated++
		metrics.PerformanceMetrics["keygen"] = time.Since(startTime)
		metrics.ActiveKeys++
	})

	return hybridKeyPair, nil
}

// EncapsulateKey performs key encapsulation using Kyber768
func (m *PostQuantumCryptoManager) EncapsulateKey(keyID string, publicKey []byte) (*HybridOperationResult, error) {
	startTime := time.Now()

	if !m.config.EnableKyber768 || m.kyberEngine == nil {
		return nil, errors.New("Kyber768 is not enabled")
	}

	encapsulation, err := m.kyberEngine.Encapsulate(publicKey)
	if err != nil {
		m.updateMetrics(func(metrics *PQCMetrics) {
			metrics.FailedOperations++
		})
		return &HybridOperationResult{
			KeyID:     keyID,
			Success:   false,
			Error:     err,
			Timestamp: time.Now(),
		}, err
	}

	result := &HybridOperationResult{
		KeyID:           keyID,
		EncapsulatedKey: encapsulation.Ciphertext,
		SharedSecret:    encapsulation.SharedKey,
		Timestamp:       time.Now(),
		Algorithm:       "Kyber768",
		Success:         true,
	}

	// Update metrics
	m.updateMetrics(func(metrics *PQCMetrics) {
		metrics.EncapsulationOps++
		metrics.PerformanceMetrics["encapsulation"] = time.Since(startTime)
	})

	return result, nil
}

// DecapsulateKey performs key decapsulation using Kyber768
func (m *PostQuantumCryptoManager) DecapsulateKey(keyID string, privateKey, ciphertext []byte) (*HybridOperationResult, error) {
	startTime := time.Now()

	if !m.config.EnableKyber768 || m.kyberEngine == nil {
		return nil, errors.New("Kyber768 is not enabled")
	}

	sharedSecret, err := m.kyberEngine.Decapsulate(privateKey, ciphertext)
	if err != nil {
		m.updateMetrics(func(metrics *PQCMetrics) {
			metrics.FailedOperations++
		})
		return &HybridOperationResult{
			KeyID:     keyID,
			Success:   false,
			Error:     err,
			Timestamp: time.Now(),
		}, err
	}

	result := &HybridOperationResult{
		KeyID:        keyID,
		SharedSecret: sharedSecret,
		Timestamp:    time.Now(),
		Algorithm:    "Kyber768",
		Success:      true,
	}

	// Update metrics
	m.updateMetrics(func(metrics *PQCMetrics) {
		metrics.DecapsulationOps++
		metrics.PerformanceMetrics["decapsulation"] = time.Since(startTime)
	})

	return result, nil
}

// SignMessage signs a message using Dilithium3
func (m *PostQuantumCryptoManager) SignMessage(keyID string, privateKey, message []byte) (*HybridOperationResult, error) {
	startTime := time.Now()

	if !m.config.EnableDilithium3 || m.dilithiumEngine == nil {
		return nil, errors.New("Dilithium3 is not enabled")
	}

	signature, err := m.dilithiumEngine.Sign(privateKey, message)
	if err != nil {
		m.updateMetrics(func(metrics *PQCMetrics) {
			metrics.FailedOperations++
		})
		return &HybridOperationResult{
			KeyID:     keyID,
			Success:   false,
			Error:     err,
			Timestamp: time.Now(),
		}, err
	}

	result := &HybridOperationResult{
		KeyID:     keyID,
		Signature: signature.Signature,
		Timestamp: time.Now(),
		Algorithm: "Dilithium3",
		Success:   true,
	}

	// Update metrics
	m.updateMetrics(func(metrics *PQCMetrics) {
		metrics.SignatureOps++
		metrics.PerformanceMetrics["signing"] = time.Since(startTime)
	})

	return result, nil
}

// VerifySignature verifies a signature using Dilithium3
func (m *PostQuantumCryptoManager) VerifySignature(keyID string, publicKey, message, signature []byte) (*HybridOperationResult, error) {
	startTime := time.Now()

	if !m.config.EnableDilithium3 || m.dilithiumEngine == nil {
		return nil, errors.New("Dilithium3 is not enabled")
	}

	// Create signature object
	sig := &Dilithium3Signature{
		Signature: signature,
		Message:   message,
		Timestamp: time.Now(),
		Signer:    keyID,
	}

	valid, err := m.dilithiumEngine.Verify(publicKey, sig)
	if err != nil {
		m.updateMetrics(func(metrics *PQCMetrics) {
			metrics.FailedOperations++
		})
		return &HybridOperationResult{
			KeyID:     keyID,
			Success:   false,
			Error:     err,
			Timestamp: time.Now(),
		}, err
	}

	result := &HybridOperationResult{
		KeyID:     keyID,
		Success:   valid,
		Timestamp: time.Now(),
		Algorithm: "Dilithium3",
	}

	if !valid {
		result.Error = errors.New("signature verification failed")
	}

	// Update metrics
	m.updateMetrics(func(metrics *PQCMetrics) {
		metrics.VerificationOps++
		metrics.PerformanceMetrics["verification"] = time.Since(startTime)
	})

	return result, nil
}

// GetKeyPair retrieves a key pair from the key store
func (m *PostQuantumCryptoManager) GetKeyPair(keyID string) (*HybridKeyPair, error) {
	if !m.config.KeyStoreEnabled || m.keyStore == nil {
		return nil, errors.New("key store is not enabled")
	}

	m.keyStore.mutex.RLock()
	defer m.keyStore.mutex.RUnlock()

	// Get key metadata
	metadata, exists := m.keyStore.keyMetadata[keyID]
	if !exists {
		return nil, fmt.Errorf("key pair not found: %s", keyID)
	}

	// Check if key has expired
	if time.Now().After(metadata.ExpiresAt) {
		return nil, fmt.Errorf("key pair has expired: %s", keyID)
	}

	// Get keys
	kyberKey := m.keyStore.kyberKeys[keyID]
	dilithiumKey := m.keyStore.dilithiumKeys[keyID]

	hybridKeyPair := &HybridKeyPair{
		KeyID:            keyID,
		KyberKeyPair:     kyberKey,
		DilithiumKeyPair: dilithiumKey,
		CreatedAt:        metadata.CreatedAt,
		ExpiresAt:        metadata.ExpiresAt,
		Purpose:          metadata.Purpose,
		Owner:            metadata.Owner,
	}

	// Update last used
	metadata.LastUsed = time.Now()
	metadata.UsageCount++

	return hybridKeyPair, nil
}

// ValidateKeyPair validates a hybrid key pair
func (m *PostQuantumCryptoManager) ValidateKeyPair(keyPair *HybridKeyPair) error {
	if keyPair == nil {
		return errors.New("key pair is nil")
	}

	// Check expiration
	if time.Now().After(keyPair.ExpiresAt) {
		return errors.New("key pair has expired")
	}

	// Validate Kyber768 key pair
	if keyPair.KyberKeyPair != nil && m.kyberEngine != nil {
		err := m.kyberEngine.ValidateKeyPair(keyPair.KyberKeyPair)
		if err != nil {
			m.updateMetrics(func(metrics *PQCMetrics) {
				metrics.KeyValidationErrors++
			})
			return fmt.Errorf("Kyber768 key validation failed: %v", err)
		}
	}

	// Validate Dilithium3 key pair
	if keyPair.DilithiumKeyPair != nil && m.dilithiumEngine != nil {
		err := m.dilithiumEngine.ValidateKeyPair(keyPair.DilithiumKeyPair)
		if err != nil {
			m.updateMetrics(func(metrics *PQCMetrics) {
				metrics.KeyValidationErrors++
			})
			return fmt.Errorf("Dilithium3 key validation failed: %v", err)
		}
	}

	return nil
}

// RotateKeys rotates expired keys
func (m *PostQuantumCryptoManager) RotateKeys() error {
	if !m.config.EnableKeyRotation {
		return errors.New("key rotation is not enabled")
	}

	m.keyRotationMutex.Lock()
	defer m.keyRotationMutex.Unlock()

	if !m.config.KeyStoreEnabled || m.keyStore == nil {
		return errors.New("key store is not enabled")
	}

	m.keyStore.mutex.Lock()
	defer m.keyStore.mutex.Unlock()

	now := time.Now()
	keysRotated := 0

	// Find expired keys
	for keyID, metadata := range m.keyStore.keyMetadata {
		if now.After(metadata.ExpiresAt) || now.Sub(metadata.CreatedAt) > m.config.MaxKeyAge {
			// Generate new key pair
			newKeyPair, err := m.GenerateHybridKeyPair(metadata.Purpose, metadata.Owner)
			if err != nil {
				return fmt.Errorf("failed to generate replacement key pair: %v", err)
			}

			// Mark old key as expired
			metadata.Status = KeyStatusExpired

			// Store new key pair
			err = m.storeKeyPairLocked(newKeyPair)
			if err != nil {
				return fmt.Errorf("failed to store new key pair: %v", err)
			}

			keysRotated++
		}
	}

	// Update metrics
	m.updateMetrics(func(metrics *PQCMetrics) {
		metrics.KeyRotations += int64(keysRotated)
		metrics.LastRotation = now
	})

	return nil
}

// GetMetrics returns PQC metrics
func (m *PostQuantumCryptoManager) GetMetrics() *PQCMetrics {
	m.metrics.mutex.RLock()
	defer m.metrics.mutex.RUnlock()

	// Create copy of metrics
	metrics := &PQCMetrics{
		KeyPairsGenerated:   m.metrics.KeyPairsGenerated,
		EncapsulationOps:    m.metrics.EncapsulationOps,
		DecapsulationOps:    m.metrics.DecapsulationOps,
		SignatureOps:        m.metrics.SignatureOps,
		VerificationOps:     m.metrics.VerificationOps,
		KeyRotations:        m.metrics.KeyRotations,
		KeyValidationErrors: m.metrics.KeyValidationErrors,
		LastRotation:        m.metrics.LastRotation,
		ActiveKeys:          m.metrics.ActiveKeys,
		ExpiredKeys:         m.metrics.ExpiredKeys,
		FailedOperations:    m.metrics.FailedOperations,
		PerformanceMetrics:  make(map[string]time.Duration),
	}

	// Copy performance metrics
	for key, value := range m.metrics.PerformanceMetrics {
		metrics.PerformanceMetrics[key] = value
	}

	return metrics
}

// GetAlgorithmInfo returns information about supported algorithms
func (m *PostQuantumCryptoManager) GetAlgorithmInfo() map[string]interface{} {
	info := map[string]interface{}{
		"manager_version": "1.0.0",
		"security_level":  m.config.SecurityLevel,
		"enabled_algorithms": map[string]bool{
			"Kyber768":   m.config.EnableKyber768,
			"Dilithium3": m.config.EnableDilithium3,
		},
	}

	if m.config.EnableKyber768 && m.kyberEngine != nil {
		info["kyber768"] = m.kyberEngine.GetAlgorithmInfo()
	}

	if m.config.EnableDilithium3 && m.dilithiumEngine != nil {
		info["dilithium3"] = m.dilithiumEngine.GetAlgorithmInfo()
	}

	return info
}

// Helper methods

func (m *PostQuantumCryptoManager) generateKeyID() string {
	// Generate unique key ID
	bytes := make([]byte, 16)
	rand.Read(bytes)
	hash := sha256.Sum256(bytes)
	return fmt.Sprintf("pqc_%x", hash[:8])
}

func (m *PostQuantumCryptoManager) storeKeyPair(keyPair *HybridKeyPair) error {
	m.keyStore.mutex.Lock()
	defer m.keyStore.mutex.Unlock()

	return m.storeKeyPairLocked(keyPair)
}

func (m *PostQuantumCryptoManager) storeKeyPairLocked(keyPair *HybridKeyPair) error {
	// Check capacity
	if len(m.keyStore.keyMetadata) >= m.keyStore.capacity {
		return errors.New("key store capacity exceeded")
	}

	// Store keys
	if keyPair.KyberKeyPair != nil {
		m.keyStore.kyberKeys[keyPair.KeyID] = keyPair.KyberKeyPair
	}

	if keyPair.DilithiumKeyPair != nil {
		m.keyStore.dilithiumKeys[keyPair.KeyID] = keyPair.DilithiumKeyPair
	}

	// Store metadata
	metadata := &KeyMetadata{
		KeyID:      keyPair.KeyID,
		KeyType:    "hybrid",
		Algorithm:  "Kyber768+Dilithium3",
		CreatedAt:  keyPair.CreatedAt,
		ExpiresAt:  keyPair.ExpiresAt,
		LastUsed:   time.Now(),
		UsageCount: 0,
		Purpose:    keyPair.Purpose,
		Owner:      keyPair.Owner,
		Status:     KeyStatusActive,
	}

	m.keyStore.keyMetadata[keyPair.KeyID] = metadata

	return nil
}

func (m *PostQuantumCryptoManager) updateMetrics(fn func(*PQCMetrics)) {
	if !m.config.MetricsEnabled {
		return
	}

	m.metrics.mutex.Lock()
	defer m.metrics.mutex.Unlock()

	fn(m.metrics)
}

// Background workers

func (m *PostQuantumCryptoManager) keyRotationWorker() {
	for {
		select {
		case <-m.rotationTicker.C:
			err := m.RotateKeys()
			if err != nil {
				// Log error in production
				fmt.Printf("Key rotation failed: %v\n", err)
			}
		case <-m.ctx.Done():
			return
		}
	}
}

func (m *PostQuantumCryptoManager) metricsWorker() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.updateActiveKeyCount()
		case <-m.ctx.Done():
			return
		}
	}
}

func (m *PostQuantumCryptoManager) updateActiveKeyCount() {
	if !m.config.KeyStoreEnabled || m.keyStore == nil {
		return
	}

	m.keyStore.mutex.RLock()
	defer m.keyStore.mutex.RUnlock()

	activeKeys := int64(0)
	expiredKeys := int64(0)
	now := time.Now()

	for _, metadata := range m.keyStore.keyMetadata {
		if now.After(metadata.ExpiresAt) || metadata.Status == KeyStatusExpired {
			expiredKeys++
		} else {
			activeKeys++
		}
	}

	m.updateMetrics(func(metrics *PQCMetrics) {
		metrics.ActiveKeys = activeKeys
		metrics.ExpiredKeys = expiredKeys
	})
}
