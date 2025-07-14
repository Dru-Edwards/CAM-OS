package enclave

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// EnclaveKeyManager manages cryptographic keys for secure enclaves
type EnclaveKeyManager struct {
	keys      map[string]*EnclaveKey
	keysMutex sync.RWMutex

	// Key derivation settings
	masterKey []byte
	saltSize  int
	keySize   int

	// Key rotation settings
	rotationInterval time.Duration
	maxKeyAge        time.Duration

	// Metrics
	totalKeys   int64
	activeKeys  int64
	rotatedKeys int64
	derivedKeys int64

	// Context for shutdown
	stopChan chan struct{}

	// Configuration
	enableRotation bool
	enableMetrics  bool
}

// EnclaveKey represents a cryptographic key for enclave operations
type EnclaveKey struct {
	ID         string
	Type       KeyType
	Purpose    KeyPurpose
	Algorithm  KeyAlgorithm
	KeyData    []byte
	PublicKey  []byte
	PrivateKey []byte

	// Metadata
	EnclaveID string
	CreatedAt time.Time
	LastUsed  time.Time
	ExpiresAt time.Time
	Version   int

	// Key derivation info
	DerivedFrom    string
	DerivationPath string
	Salt           []byte

	// Usage tracking
	UsageCount int64
	MaxUsage   int64

	// Status and flags
	Status     KeyStatus
	Revoked    bool
	Exportable bool
	Persistent bool

	// Access control
	AllowedOps    []string
	RequiredLevel SecurityLevel

	// Synchronization
	mutex sync.RWMutex
}

// KeyType represents the type of cryptographic key
type KeyType string

const (
	KeyTypeSymmetric   KeyType = "symmetric"
	KeyTypeAsymmetric  KeyType = "asymmetric"
	KeyTypeHMAC        KeyType = "hmac"
	KeyTypeDerivation  KeyType = "derivation"
	KeyTypeSealing     KeyType = "sealing"
	KeyTypeAttestation KeyType = "attestation"
	KeyTypeTransport   KeyType = "transport"
	KeyTypeStorage     KeyType = "storage"
)

// KeyPurpose represents the purpose of the key
type KeyPurpose string

const (
	KeyPurposeEncryption   KeyPurpose = "encryption"
	KeyPurposeDecryption   KeyPurpose = "decryption"
	KeyPurposeSigning      KeyPurpose = "signing"
	KeyPurposeVerification KeyPurpose = "verification"
	KeyPurposeMAC          KeyPurpose = "mac"
	KeyPurposeKDF          KeyPurpose = "kdf"
	KeyPurposeSealing      KeyPurpose = "sealing"
	KeyPurposeAttestation  KeyPurpose = "attestation"
	KeyPurposeTransport    KeyPurpose = "transport"
	KeyPurposeStorage      KeyPurpose = "storage"
)

// KeyAlgorithm represents the cryptographic algorithm
type KeyAlgorithm string

const (
	KeyAlgorithmAES128     KeyAlgorithm = "AES-128"
	KeyAlgorithmAES256     KeyAlgorithm = "AES-256"
	KeyAlgorithmRSA2048    KeyAlgorithm = "RSA-2048"
	KeyAlgorithmRSA4096    KeyAlgorithm = "RSA-4096"
	KeyAlgorithmECDSAP256  KeyAlgorithm = "ECDSA-P256"
	KeyAlgorithmECDSAP384  KeyAlgorithm = "ECDSA-P384"
	KeyAlgorithmECDSAP521  KeyAlgorithm = "ECDSA-P521"
	KeyAlgorithmECDHE      KeyAlgorithm = "ECDHE"
	KeyAlgorithmHMACSHA256 KeyAlgorithm = "HMAC-SHA256"
	KeyAlgorithmHMACSHA384 KeyAlgorithm = "HMAC-SHA384"
	KeyAlgorithmHMACSHA512 KeyAlgorithm = "HMAC-SHA512"
	KeyAlgorithmHKDF       KeyAlgorithm = "HKDF"
	KeyAlgorithmPBKDF2     KeyAlgorithm = "PBKDF2"
	KeyAlgorithmKyber768   KeyAlgorithm = "Kyber768"
	KeyAlgorithmDilithium3 KeyAlgorithm = "Dilithium3"
)

// KeyStatus represents the status of a key
type KeyStatus string

const (
	KeyStatusActive      KeyStatus = "active"
	KeyStatusInactive    KeyStatus = "inactive"
	KeyStatusExpired     KeyStatus = "expired"
	KeyStatusRevoked     KeyStatus = "revoked"
	KeyStatusCompromised KeyStatus = "compromised"
	KeyStatusRotating    KeyStatus = "rotating"
)

// KeyGenerationRequest represents a request to generate a new key
type KeyGenerationRequest struct {
	EnclaveID      string
	KeyType        KeyType
	Purpose        KeyPurpose
	Algorithm      KeyAlgorithm
	KeySize        int
	Exportable     bool
	Persistent     bool
	MaxUsage       int64
	ExpiresAt      time.Time
	AllowedOps     []string
	RequiredLevel  SecurityLevel
	DerivationPath string
	Salt           []byte
}

// KeyDerivationRequest represents a request to derive a key
type KeyDerivationRequest struct {
	ParentKeyID    string
	EnclaveID      string
	Purpose        KeyPurpose
	Algorithm      KeyAlgorithm
	DerivationPath string
	Salt           []byte
	KeySize        int
	Info           []byte
}

// NewEnclaveKeyManager creates a new enclave key manager
func NewEnclaveKeyManager() *EnclaveKeyManager {
	// Generate master key
	masterKey := make([]byte, 32)
	rand.Read(masterKey)

	manager := &EnclaveKeyManager{
		keys:             make(map[string]*EnclaveKey),
		masterKey:        masterKey,
		saltSize:         16,
		keySize:          32,
		rotationInterval: 24 * time.Hour,
		maxKeyAge:        30 * 24 * time.Hour,
		enableRotation:   true,
		enableMetrics:    true,
		stopChan:         make(chan struct{}),
	}

	// Start background workers
	go manager.rotationWorker()
	go manager.cleanupWorker()

	return manager
}

// Stop stops the key manager
func (k *EnclaveKeyManager) Stop() {
	close(k.stopChan)
}

// GenerateKey generates a new cryptographic key
func (k *EnclaveKeyManager) GenerateKey(request *KeyGenerationRequest) (*EnclaveKey, error) {
	if request == nil {
		return nil, errors.New("key generation request is nil")
	}

	// Validate request
	err := k.validateKeyRequest(request)
	if err != nil {
		return nil, fmt.Errorf("invalid key request: %v", err)
	}

	// Generate key ID
	keyID := k.generateKeyID(request)

	// Check if key already exists
	k.keysMutex.RLock()
	if _, exists := k.keys[keyID]; exists {
		k.keysMutex.RUnlock()
		return nil, fmt.Errorf("key with ID %s already exists", keyID)
	}
	k.keysMutex.RUnlock()

	// Generate key material
	keyData, publicKey, privateKey, err := k.generateKeyMaterial(request)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key material: %v", err)
	}

	// Create key object
	key := &EnclaveKey{
		ID:             keyID,
		Type:           request.KeyType,
		Purpose:        request.Purpose,
		Algorithm:      request.Algorithm,
		KeyData:        keyData,
		PublicKey:      publicKey,
		PrivateKey:     privateKey,
		EnclaveID:      request.EnclaveID,
		CreatedAt:      time.Now(),
		LastUsed:       time.Now(),
		ExpiresAt:      request.ExpiresAt,
		Version:        1,
		DerivationPath: request.DerivationPath,
		Salt:           request.Salt,
		UsageCount:     0,
		MaxUsage:       request.MaxUsage,
		Status:         KeyStatusActive,
		Revoked:        false,
		Exportable:     request.Exportable,
		Persistent:     request.Persistent,
		AllowedOps:     request.AllowedOps,
		RequiredLevel:  request.RequiredLevel,
	}

	// Store key
	k.keysMutex.Lock()
	k.keys[keyID] = key
	k.totalKeys++
	k.activeKeys++
	k.keysMutex.Unlock()

	return key, nil
}

// DeriveKey derives a new key from an existing key
func (k *EnclaveKeyManager) DeriveKey(request *KeyDerivationRequest) (*EnclaveKey, error) {
	if request == nil {
		return nil, errors.New("key derivation request is nil")
	}

	// Get parent key
	parentKey, err := k.GetKey(request.ParentKeyID)
	if err != nil {
		return nil, fmt.Errorf("parent key not found: %v", err)
	}

	// Check if parent key can be used for derivation
	if parentKey.Type != KeyTypeDerivation && parentKey.Purpose != KeyPurposeKDF {
		return nil, errors.New("parent key is not suitable for derivation")
	}

	// Generate derived key ID
	derivedKeyID := k.generateDerivedKeyID(request)

	// Check if derived key already exists
	k.keysMutex.RLock()
	if _, exists := k.keys[derivedKeyID]; exists {
		k.keysMutex.RUnlock()
		return nil, fmt.Errorf("derived key with ID %s already exists", derivedKeyID)
	}
	k.keysMutex.RUnlock()

	// Derive key material
	derivedKeyData, err := k.deriveKeyMaterial(parentKey, request)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key material: %v", err)
	}

	// Create derived key object
	derivedKey := &EnclaveKey{
		ID:             derivedKeyID,
		Type:           KeyTypeSymmetric,
		Purpose:        request.Purpose,
		Algorithm:      request.Algorithm,
		KeyData:        derivedKeyData,
		EnclaveID:      request.EnclaveID,
		CreatedAt:      time.Now(),
		LastUsed:       time.Now(),
		ExpiresAt:      parentKey.ExpiresAt,
		Version:        1,
		DerivedFrom:    parentKey.ID,
		DerivationPath: request.DerivationPath,
		Salt:           request.Salt,
		UsageCount:     0,
		MaxUsage:       parentKey.MaxUsage,
		Status:         KeyStatusActive,
		Revoked:        false,
		Exportable:     parentKey.Exportable,
		Persistent:     parentKey.Persistent,
		AllowedOps:     parentKey.AllowedOps,
		RequiredLevel:  parentKey.RequiredLevel,
	}

	// Store derived key
	k.keysMutex.Lock()
	k.keys[derivedKeyID] = derivedKey
	k.totalKeys++
	k.activeKeys++
	k.derivedKeys++
	k.keysMutex.Unlock()

	// Update parent key usage
	parentKey.mutex.Lock()
	parentKey.UsageCount++
	parentKey.LastUsed = time.Now()
	parentKey.mutex.Unlock()

	return derivedKey, nil
}

// GetKey retrieves a key by ID
func (k *EnclaveKeyManager) GetKey(keyID string) (*EnclaveKey, error) {
	k.keysMutex.RLock()
	key, exists := k.keys[keyID]
	k.keysMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("key with ID %s not found", keyID)
	}

	// Check key status
	if key.Status != KeyStatusActive {
		return nil, fmt.Errorf("key %s is not active (status: %s)", keyID, key.Status)
	}

	// Check expiration
	if !key.ExpiresAt.IsZero() && time.Now().After(key.ExpiresAt) {
		key.Status = KeyStatusExpired
		return nil, fmt.Errorf("key %s has expired", keyID)
	}

	// Update usage
	key.mutex.Lock()
	key.UsageCount++
	key.LastUsed = time.Now()
	key.mutex.Unlock()

	return key, nil
}

// RevokeKey revokes a key
func (k *EnclaveKeyManager) RevokeKey(keyID string) error {
	k.keysMutex.RLock()
	key, exists := k.keys[keyID]
	k.keysMutex.RUnlock()

	if !exists {
		return fmt.Errorf("key with ID %s not found", keyID)
	}

	key.mutex.Lock()
	key.Status = KeyStatusRevoked
	key.Revoked = true
	key.mutex.Unlock()

	k.keysMutex.Lock()
	k.activeKeys--
	k.keysMutex.Unlock()

	return nil
}

// RotateKey rotates a key by generating a new version
func (k *EnclaveKeyManager) RotateKey(keyID string) (*EnclaveKey, error) {
	// Get current key
	currentKey, err := k.GetKey(keyID)
	if err != nil {
		return nil, fmt.Errorf("current key not found: %v", err)
	}

	// Create rotation request
	rotationRequest := &KeyGenerationRequest{
		EnclaveID:      currentKey.EnclaveID,
		KeyType:        currentKey.Type,
		Purpose:        currentKey.Purpose,
		Algorithm:      currentKey.Algorithm,
		KeySize:        len(currentKey.KeyData),
		Exportable:     currentKey.Exportable,
		Persistent:     currentKey.Persistent,
		MaxUsage:       currentKey.MaxUsage,
		ExpiresAt:      time.Now().Add(k.maxKeyAge),
		AllowedOps:     currentKey.AllowedOps,
		RequiredLevel:  currentKey.RequiredLevel,
		DerivationPath: currentKey.DerivationPath,
		Salt:           currentKey.Salt,
	}

	// Generate new key
	newKey, err := k.GenerateKey(rotationRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to generate rotated key: %v", err)
	}

	// Update version
	newKey.Version = currentKey.Version + 1

	// Mark current key as rotating
	currentKey.mutex.Lock()
	currentKey.Status = KeyStatusRotating
	currentKey.mutex.Unlock()

	k.keysMutex.Lock()
	k.rotatedKeys++
	k.keysMutex.Unlock()

	return newKey, nil
}

// DeleteKey deletes a key
func (k *EnclaveKeyManager) DeleteKey(keyID string) error {
	k.keysMutex.Lock()
	defer k.keysMutex.Unlock()

	key, exists := k.keys[keyID]
	if !exists {
		return fmt.Errorf("key with ID %s not found", keyID)
	}

	// Clear key material
	k.clearKeyMaterial(key)

	// Remove from map
	delete(k.keys, keyID)
	k.activeKeys--

	return nil
}

// ListKeys lists all keys for an enclave
func (k *EnclaveKeyManager) ListKeys(enclaveID string) ([]*EnclaveKey, error) {
	k.keysMutex.RLock()
	defer k.keysMutex.RUnlock()

	var keys []*EnclaveKey
	for _, key := range k.keys {
		if key.EnclaveID == enclaveID {
			keys = append(keys, key)
		}
	}

	return keys, nil
}

// GetKeyMetrics returns key management metrics
func (k *EnclaveKeyManager) GetKeyMetrics() map[string]interface{} {
	k.keysMutex.RLock()
	defer k.keysMutex.RUnlock()

	return map[string]interface{}{
		"total_keys":     k.totalKeys,
		"active_keys":    k.activeKeys,
		"rotated_keys":   k.rotatedKeys,
		"derived_keys":   k.derivedKeys,
		"key_types":      k.getKeyTypeDistribution(),
		"key_purposes":   k.getKeyPurposeDistribution(),
		"key_algorithms": k.getKeyAlgorithmDistribution(),
	}
}

// Implementation methods

func (k *EnclaveKeyManager) validateKeyRequest(request *KeyGenerationRequest) error {
	if request.EnclaveID == "" {
		return errors.New("enclave ID is required")
	}

	if request.KeyType == "" {
		return errors.New("key type is required")
	}

	if request.Purpose == "" {
		return errors.New("key purpose is required")
	}

	if request.Algorithm == "" {
		return errors.New("key algorithm is required")
	}

	if request.KeySize <= 0 {
		request.KeySize = k.getDefaultKeySize(request.Algorithm)
	}

	if request.ExpiresAt.IsZero() {
		request.ExpiresAt = time.Now().Add(k.maxKeyAge)
	}

	return nil
}

func (k *EnclaveKeyManager) generateKeyID(request *KeyGenerationRequest) string {
	// Generate deterministic key ID
	data := fmt.Sprintf("%s:%s:%s:%s:%d",
		request.EnclaveID,
		request.KeyType,
		request.Purpose,
		request.Algorithm,
		time.Now().UnixNano())

	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])[:16]
}

func (k *EnclaveKeyManager) generateDerivedKeyID(request *KeyDerivationRequest) string {
	// Generate deterministic derived key ID
	data := fmt.Sprintf("%s:%s:%s:%s:%s",
		request.ParentKeyID,
		request.EnclaveID,
		request.Purpose,
		request.Algorithm,
		request.DerivationPath)

	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])[:16]
}

func (k *EnclaveKeyManager) generateKeyMaterial(request *KeyGenerationRequest) ([]byte, []byte, []byte, error) {
	switch request.KeyType {
	case KeyTypeSymmetric:
		return k.generateSymmetricKey(request.KeySize)
	case KeyTypeAsymmetric:
		return k.generateAsymmetricKey(request.Algorithm)
	case KeyTypeHMAC:
		return k.generateHMACKey(request.KeySize)
	case KeyTypeDerivation:
		return k.generateDerivationKey(request.KeySize)
	default:
		return nil, nil, nil, fmt.Errorf("unsupported key type: %s", request.KeyType)
	}
}

func (k *EnclaveKeyManager) generateSymmetricKey(keySize int) ([]byte, []byte, []byte, error) {
	keyData := make([]byte, keySize)
	_, err := rand.Read(keyData)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate random key: %v", err)
	}

	return keyData, nil, nil, nil
}

func (k *EnclaveKeyManager) generateAsymmetricKey(algorithm KeyAlgorithm) ([]byte, []byte, []byte, error) {
	// Simplified asymmetric key generation
	switch algorithm {
	case KeyAlgorithmECDSAP256:
		privateKey := make([]byte, 32)
		rand.Read(privateKey)

		// Simplified public key generation
		publicKey := make([]byte, 64)
		rand.Read(publicKey)

		return nil, publicKey, privateKey, nil

	case KeyAlgorithmRSA2048:
		privateKey := make([]byte, 256)
		rand.Read(privateKey)

		publicKey := make([]byte, 256)
		rand.Read(publicKey)

		return nil, publicKey, privateKey, nil

	default:
		return nil, nil, nil, fmt.Errorf("unsupported asymmetric algorithm: %s", algorithm)
	}
}

func (k *EnclaveKeyManager) generateHMACKey(keySize int) ([]byte, []byte, []byte, error) {
	keyData := make([]byte, keySize)
	_, err := rand.Read(keyData)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate HMAC key: %v", err)
	}

	return keyData, nil, nil, nil
}

func (k *EnclaveKeyManager) generateDerivationKey(keySize int) ([]byte, []byte, []byte, error) {
	// Generate high-entropy derivation key
	keyData := make([]byte, keySize)
	_, err := rand.Read(keyData)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate derivation key: %v", err)
	}

	// Enhance with master key
	for i := range keyData {
		keyData[i] ^= k.masterKey[i%len(k.masterKey)]
	}

	return keyData, nil, nil, nil
}

func (k *EnclaveKeyManager) deriveKeyMaterial(parentKey *EnclaveKey, request *KeyDerivationRequest) ([]byte, error) {
	// Use HKDF for key derivation
	salt := request.Salt
	if salt == nil {
		salt = make([]byte, k.saltSize)
		rand.Read(salt)
	}

	// Create info string
	info := []byte(fmt.Sprintf("%s:%s:%s", request.EnclaveID, request.Purpose, request.Algorithm))
	if request.Info != nil {
		info = append(info, request.Info...)
	}

	// Perform HKDF
	derivedKey := k.hkdf(parentKey.KeyData, salt, info, request.KeySize)

	return derivedKey, nil
}

func (k *EnclaveKeyManager) hkdf(key, salt, info []byte, keySize int) []byte {
	// Simplified HKDF implementation
	if salt == nil {
		salt = make([]byte, sha256.Size)
	}

	// Extract
	h := sha256.New()
	h.Write(salt)
	h.Write(key)
	prk := h.Sum(nil)

	// Expand
	var okm []byte
	var t []byte
	counter := byte(1)

	for len(okm) < keySize {
		h := sha256.New()
		h.Write(t)
		h.Write(info)
		h.Write([]byte{counter})
		t = h.Sum(nil)
		okm = append(okm, t...)
		counter++
	}

	return okm[:keySize]
}

func (k *EnclaveKeyManager) getDefaultKeySize(algorithm KeyAlgorithm) int {
	switch algorithm {
	case KeyAlgorithmAES128:
		return 16
	case KeyAlgorithmAES256:
		return 32
	case KeyAlgorithmHMACSHA256:
		return 32
	case KeyAlgorithmHMACSHA384:
		return 48
	case KeyAlgorithmHMACSHA512:
		return 64
	default:
		return 32
	}
}

func (k *EnclaveKeyManager) clearKeyMaterial(key *EnclaveKey) {
	// Clear key material
	if key.KeyData != nil {
		for i := range key.KeyData {
			key.KeyData[i] = 0
		}
	}

	if key.PrivateKey != nil {
		for i := range key.PrivateKey {
			key.PrivateKey[i] = 0
		}
	}
}

func (k *EnclaveKeyManager) getKeyTypeDistribution() map[string]int {
	distribution := make(map[string]int)

	for _, key := range k.keys {
		distribution[string(key.Type)]++
	}

	return distribution
}

func (k *EnclaveKeyManager) getKeyPurposeDistribution() map[string]int {
	distribution := make(map[string]int)

	for _, key := range k.keys {
		distribution[string(key.Purpose)]++
	}

	return distribution
}

func (k *EnclaveKeyManager) getKeyAlgorithmDistribution() map[string]int {
	distribution := make(map[string]int)

	for _, key := range k.keys {
		distribution[string(key.Algorithm)]++
	}

	return distribution
}

// Background workers

func (k *EnclaveKeyManager) rotationWorker() {
	if !k.enableRotation {
		return
	}

	ticker := time.NewTicker(k.rotationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			k.performKeyRotation()
		case <-k.stopChan:
			return
		}
	}
}

func (k *EnclaveKeyManager) cleanupWorker() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			k.performCleanup()
		case <-k.stopChan:
			return
		}
	}
}

func (k *EnclaveKeyManager) performKeyRotation() {
	k.keysMutex.RLock()
	keysToRotate := make([]string, 0)

	for keyID, key := range k.keys {
		if k.shouldRotateKey(key) {
			keysToRotate = append(keysToRotate, keyID)
		}
	}
	k.keysMutex.RUnlock()

	// Rotate keys
	for _, keyID := range keysToRotate {
		_, err := k.RotateKey(keyID)
		if err != nil {
			// Log rotation error
			continue
		}
	}
}

func (k *EnclaveKeyManager) performCleanup() {
	k.keysMutex.Lock()
	defer k.keysMutex.Unlock()

	keysToDelete := make([]string, 0)

	for keyID, key := range k.keys {
		if k.shouldDeleteKey(key) {
			keysToDelete = append(keysToDelete, keyID)
		}
	}

	// Delete keys
	for _, keyID := range keysToDelete {
		key := k.keys[keyID]
		k.clearKeyMaterial(key)
		delete(k.keys, keyID)
		k.activeKeys--
	}
}

func (k *EnclaveKeyManager) shouldRotateKey(key *EnclaveKey) bool {
	if key.Status != KeyStatusActive {
		return false
	}

	// Check age
	if time.Since(key.CreatedAt) > k.rotationInterval {
		return true
	}

	// Check usage
	if key.MaxUsage > 0 && key.UsageCount >= key.MaxUsage*8/10 {
		return true
	}

	return false
}

func (k *EnclaveKeyManager) shouldDeleteKey(key *EnclaveKey) bool {
	// Delete revoked keys
	if key.Status == KeyStatusRevoked {
		return true
	}

	// Delete expired keys
	if key.Status == KeyStatusExpired {
		return true
	}

	// Delete old rotating keys
	if key.Status == KeyStatusRotating && time.Since(key.CreatedAt) > 24*time.Hour {
		return true
	}

	return false
}
