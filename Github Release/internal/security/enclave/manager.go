package enclave

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// SecureEnclaveManager manages secure enclaves for sensitive computations
type SecureEnclaveManager struct {
	config        *EnclaveConfig
	enclaves      map[string]*SecureEnclave
	enclavesMutex sync.RWMutex

	// Platform-specific implementations
	sgxManager       *SGXManager
	trustZoneManager *TrustZoneManager

	// Key management
	keyManager  *EnclaveKeyManager
	attestation *EnclaveAttestation

	// Metrics and monitoring
	metrics        *EnclaveMetrics
	lastOperation  time.Time
	operationCount int64

	// Context for shutdown
	ctx    context.Context
	cancel context.CancelFunc
}

// EnclaveConfig holds configuration for secure enclaves
type EnclaveConfig struct {
	EnableSGX            bool
	EnableTrustZone      bool
	EnableAttestation    bool
	EnableSealing        bool
	MaxEnclaves          int
	EnclaveTimeout       time.Duration
	AttestationInterval  time.Duration
	KeyRotationInterval  time.Duration
	SGXDebugMode         bool
	TrustZoneSecureWorld bool
	MemoryQuota          int64
	CPUQuota             float64
	AllowedOperations    []string
	SecurityLevel        SecurityLevel
	AuditLogging         bool
}

// SecurityLevel represents the security level of enclave operations
type SecurityLevel int

const (
	SecurityLevelBasic SecurityLevel = iota
	SecurityLevelStandard
	SecurityLevelHigh
	SecurityLevelMaximum
)

// SecureEnclave represents a secure enclave instance
type SecureEnclave struct {
	ID        string
	Type      EnclaveType
	Platform  Platform
	CreatedAt time.Time
	LastUsed  time.Time
	Status    EnclaveStatus

	// Enclave properties
	BaseAddress uintptr
	Size        int64
	Permissions EnclavePermissions
	ThreadCount int
	MemoryUsage int64
	CPUUsage    float64

	// Security properties
	Sealed         bool
	Attested       bool
	TrustedKeys    []string
	SecurityLevel  SecurityLevel
	IsolationLevel IsolationLevel

	// Operations
	SupportedOps []string
	ActiveOps    int
	CompletedOps int64
	FailedOps    int64

	// Platform-specific data
	SGXData       *SGXEnclaveData
	TrustZoneData *TrustZoneEnclaveData

	// Synchronization
	mutex sync.RWMutex
}

// EnclaveType represents the type of secure enclave
type EnclaveType string

const (
	EnclaveTypeSGX       EnclaveType = "sgx"
	EnclaveTypeTrustZone EnclaveType = "trustzone"
	EnclaveTypeSimulated EnclaveType = "simulated"
)

// Platform represents the hardware platform
type Platform string

const (
	PlatformIntelSGX  Platform = "intel_sgx"
	PlatformARMTZ     Platform = "arm_trustzone"
	PlatformSimulated Platform = "simulated"
)

// EnclaveStatus represents the status of an enclave
type EnclaveStatus string

const (
	EnclaveStatusCreating  EnclaveStatus = "creating"
	EnclaveStatusReady     EnclaveStatus = "ready"
	EnclaveStatusRunning   EnclaveStatus = "running"
	EnclaveStatusSuspended EnclaveStatus = "suspended"
	EnclaveStatusDestroyed EnclaveStatus = "destroyed"
	EnclaveStatusError     EnclaveStatus = "error"
)

// EnclavePermissions represents enclave permissions
type EnclavePermissions struct {
	Read       bool
	Write      bool
	Execute    bool
	Debug      bool
	Production bool
}

// IsolationLevel represents the level of isolation
type IsolationLevel int

const (
	IsolationLevelProcess IsolationLevel = iota
	IsolationLevelThread
	IsolationLevelHardware
	IsolationLevelSecureWorld
)

// SGXEnclaveData contains Intel SGX specific data
type SGXEnclaveData struct {
	MRENCLAVE      [32]byte // Enclave measurement
	MRSIGNER       [32]byte // Signer measurement
	ISVProdID      uint16   // Product ID
	ISVRevision    uint16   // Security version
	Debug          bool     // Debug flag
	Mode64Bit      bool     // 64-bit mode
	ProvisionKey   bool     // Provision key access
	EINITToken     []byte   // EINIT token
	LaunchKey      []byte   // Launch key
	SealingKey     []byte   // Sealing key
	AttestationKey []byte   // Attestation key
}

// TrustZoneEnclaveData contains ARM TrustZone specific data
type TrustZoneEnclaveData struct {
	UUID          [16]byte // Trusted Application UUID
	SessionID     uint32   // Session identifier
	SecureWorldID uint32   // Secure world identifier
	MemoryType    uint32   // Memory type
	Flags         uint32   // Configuration flags
	TEESession    uintptr  // TEE session handle
	SharedMemory  uintptr  // Shared memory address
	SecureStorage []byte   // Secure storage key
	DeviceKey     []byte   // Device-specific key
}

// EnclaveOperation represents an operation to be performed in an enclave
type EnclaveOperation struct {
	ID              string
	Type            OperationType
	EnclaveID       string
	InputData       []byte
	OutputData      []byte
	Parameters      map[string]interface{}
	Timeout         time.Duration
	Priority        int
	CreatedAt       time.Time
	StartedAt       time.Time
	CompletedAt     time.Time
	Status          OperationStatus
	Error           error
	SecurityContext *SecurityContext
}

// OperationType represents the type of operation
type OperationType string

const (
	OperationTypeCompute       OperationType = "compute"
	OperationTypeEncrypt       OperationType = "encrypt"
	OperationTypeDecrypt       OperationType = "decrypt"
	OperationTypeSign          OperationType = "sign"
	OperationTypeVerify        OperationType = "verify"
	OperationTypeKeyGeneration OperationType = "keygen"
	OperationTypeKeyDerivation OperationType = "keyderive"
	OperationTypeAttestation   OperationType = "attestation"
	OperationTypeSealing       OperationType = "sealing"
	OperationTypeUnsealing     OperationType = "unsealing"
)

// OperationStatus represents the status of an operation
type OperationStatus string

const (
	OperationStatusPending   OperationStatus = "pending"
	OperationStatusRunning   OperationStatus = "running"
	OperationStatusCompleted OperationStatus = "completed"
	OperationStatusFailed    OperationStatus = "failed"
	OperationStatusTimeout   OperationStatus = "timeout"
	OperationStatusCancelled OperationStatus = "cancelled"
)

// SecurityContext represents the security context for an operation
type SecurityContext struct {
	UserID        string
	SessionID     string
	Permissions   []string
	TrustLevel    int
	RequiredLevel SecurityLevel
	Authenticated bool
	Authorized    bool
}

// EnclaveMetrics tracks enclave performance and usage metrics
type EnclaveMetrics struct {
	TotalEnclaves     int64
	ActiveEnclaves    int64
	TotalOperations   int64
	SuccessfulOps     int64
	FailedOps         int64
	AverageOpDuration time.Duration
	TotalMemoryUsage  int64
	TotalCPUUsage     float64
	AttestationCount  int64
	SealingOperations int64
	LastMetricsUpdate time.Time
	mutex             sync.RWMutex
}

// NewSecureEnclaveManager creates a new secure enclave manager
func NewSecureEnclaveManager(config *EnclaveConfig) *SecureEnclaveManager {
	if config == nil {
		config = &EnclaveConfig{
			EnableSGX:            true,
			EnableTrustZone:      true,
			EnableAttestation:    true,
			EnableSealing:        true,
			MaxEnclaves:          10,
			EnclaveTimeout:       30 * time.Second,
			AttestationInterval:  time.Hour,
			KeyRotationInterval:  24 * time.Hour,
			SGXDebugMode:         false,
			TrustZoneSecureWorld: true,
			MemoryQuota:          1024 * 1024 * 1024, // 1GB
			CPUQuota:             0.5,                // 50% CPU
			AllowedOperations:    []string{"compute", "encrypt", "decrypt", "sign", "verify"},
			SecurityLevel:        SecurityLevelHigh,
			AuditLogging:         true,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	manager := &SecureEnclaveManager{
		config:   config,
		enclaves: make(map[string]*SecureEnclave),
		metrics:  &EnclaveMetrics{LastMetricsUpdate: time.Now()},
		ctx:      ctx,
		cancel:   cancel,
	}

	// Initialize platform-specific managers
	if config.EnableSGX {
		manager.sgxManager = NewSGXManager()
	}

	if config.EnableTrustZone {
		manager.trustZoneManager = NewTrustZoneManager()
	}

	// Initialize supporting components
	manager.keyManager = NewEnclaveKeyManager()
	manager.attestation = NewEnclaveAttestation()

	return manager
}

// Start starts the secure enclave manager
func (s *SecureEnclaveManager) Start() error {
	// Initialize hardware platforms
	if s.config.EnableSGX && s.sgxManager != nil {
		err := s.sgxManager.Initialize()
		if err != nil {
			return fmt.Errorf("SGX initialization failed: %v", err)
		}
	}

	if s.config.EnableTrustZone && s.trustZoneManager != nil {
		err := s.trustZoneManager.Initialize()
		if err != nil {
			return fmt.Errorf("TrustZone initialization failed: %v", err)
		}
	}

	// Start background workers
	go s.metricsWorker()
	go s.maintenanceWorker()

	if s.config.EnableAttestation {
		go s.attestationWorker()
	}

	return nil
}

// Stop stops the secure enclave manager
func (s *SecureEnclaveManager) Stop() error {
	s.cancel()

	// Destroy all enclaves
	s.enclavesMutex.Lock()
	defer s.enclavesMutex.Unlock()

	for _, enclave := range s.enclaves {
		s.destroyEnclaveUnsafe(enclave)
	}

	return nil
}

// CreateEnclave creates a new secure enclave
func (s *SecureEnclaveManager) CreateEnclave(enclaveType EnclaveType, config *EnclaveCreationConfig) (*SecureEnclave, error) {
	s.enclavesMutex.Lock()
	defer s.enclavesMutex.Unlock()

	// Check limits
	if len(s.enclaves) >= s.config.MaxEnclaves {
		return nil, errors.New("maximum number of enclaves reached")
	}

	// Generate enclave ID
	enclaveID := s.generateEnclaveID()

	// Create enclave based on type
	var enclave *SecureEnclave
	var err error

	switch enclaveType {
	case EnclaveTypeSGX:
		if !s.config.EnableSGX || s.sgxManager == nil {
			return nil, errors.New("SGX not enabled or available")
		}
		enclave, err = s.createSGXEnclave(enclaveID, config)

	case EnclaveTypeTrustZone:
		if !s.config.EnableTrustZone || s.trustZoneManager == nil {
			return nil, errors.New("TrustZone not enabled or available")
		}
		enclave, err = s.createTrustZoneEnclave(enclaveID, config)

	case EnclaveTypeSimulated:
		enclave, err = s.createSimulatedEnclave(enclaveID, config)

	default:
		return nil, fmt.Errorf("unsupported enclave type: %s", enclaveType)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create %s enclave: %v", enclaveType, err)
	}

	// Store enclave
	s.enclaves[enclaveID] = enclave
	s.metrics.TotalEnclaves++
	s.metrics.ActiveEnclaves++

	return enclave, nil
}

// EnclaveCreationConfig holds configuration for creating an enclave
type EnclaveCreationConfig struct {
	Size                int64
	Permissions         EnclavePermissions
	SupportedOps        []string
	SecurityLevel       SecurityLevel
	IsolationLevel      IsolationLevel
	Debug               bool
	AttestationRequired bool
	SealingRequired     bool
	MemoryQuota         int64
	CPUQuota            float64
	Timeout             time.Duration
}

// ExecuteOperation executes an operation in a secure enclave
func (s *SecureEnclaveManager) ExecuteOperation(operation *EnclaveOperation) (*OperationResult, error) {
	// Get enclave
	enclave, err := s.getEnclave(operation.EnclaveID)
	if err != nil {
		return nil, fmt.Errorf("enclave not found: %v", err)
	}

	// Validate operation
	err = s.validateOperation(enclave, operation)
	if err != nil {
		return nil, fmt.Errorf("operation validation failed: %v", err)
	}

	// Update operation status
	operation.Status = OperationStatusRunning
	operation.StartedAt = time.Now()

	// Execute based on enclave type
	var result *OperationResult

	switch enclave.Type {
	case EnclaveTypeSGX:
		result, err = s.executeSGXOperation(enclave, operation)
	case EnclaveTypeTrustZone:
		result, err = s.executeTrustZoneOperation(enclave, operation)
	case EnclaveTypeSimulated:
		result, err = s.executeSimulatedOperation(enclave, operation)
	default:
		err = fmt.Errorf("unsupported enclave type: %s", enclave.Type)
	}

	// Update operation status
	operation.CompletedAt = time.Now()
	if err != nil {
		operation.Status = OperationStatusFailed
		operation.Error = err
		enclave.FailedOps++
	} else {
		operation.Status = OperationStatusCompleted
		enclave.CompletedOps++
	}

	// Update metrics
	s.updateOperationMetrics(operation, result)

	return result, err
}

// OperationResult represents the result of an enclave operation
type OperationResult struct {
	OperationID     string
	Success         bool
	OutputData      []byte
	Metadata        map[string]interface{}
	ExecutionTime   time.Duration
	MemoryUsed      int64
	CPUTime         time.Duration
	SecurityLevel   SecurityLevel
	AttestationData []byte
	Error           error
}

// DestroyEnclave destroys a secure enclave
func (s *SecureEnclaveManager) DestroyEnclave(enclaveID string) error {
	s.enclavesMutex.Lock()
	defer s.enclavesMutex.Unlock()

	enclave, exists := s.enclaves[enclaveID]
	if !exists {
		return errors.New("enclave not found")
	}

	err := s.destroyEnclaveUnsafe(enclave)
	if err != nil {
		return fmt.Errorf("failed to destroy enclave: %v", err)
	}

	delete(s.enclaves, enclaveID)
	s.metrics.ActiveEnclaves--

	return nil
}

// AttestEnclave performs attestation of a secure enclave
func (s *SecureEnclaveManager) AttestEnclave(enclaveID string) (*AttestationResult, error) {
	enclave, err := s.getEnclave(enclaveID)
	if err != nil {
		return nil, err
	}

	if !s.config.EnableAttestation {
		return nil, errors.New("attestation not enabled")
	}

	// Perform attestation based on enclave type
	var result *AttestationResult

	switch enclave.Type {
	case EnclaveTypeSGX:
		result, err = s.attestSGXEnclave(enclave)
	case EnclaveTypeTrustZone:
		result, err = s.attestTrustZoneEnclave(enclave)
	case EnclaveTypeSimulated:
		result, err = s.attestSimulatedEnclave(enclave)
	default:
		err = fmt.Errorf("attestation not supported for enclave type: %s", enclave.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("attestation failed: %v", err)
	}

	// Update enclave status
	enclave.Attested = result.Valid
	enclave.LastUsed = time.Now()

	s.metrics.AttestationCount++

	return result, nil
}

// AttestationResult represents the result of enclave attestation
type AttestationResult struct {
	EnclaveID        string
	Valid            bool
	Measurements     map[string][]byte
	Signature        []byte
	Certificate      []byte
	TrustLevel       SecurityLevel
	Timestamp        time.Time
	AttestationData  []byte
	VerificationKeys [][]byte
	Error            error
}

// SealData seals data to a specific enclave
func (s *SecureEnclaveManager) SealData(enclaveID string, data []byte, policy *SealingPolicy) (*SealedData, error) {
	if !s.config.EnableSealing {
		return nil, errors.New("sealing not enabled")
	}

	enclave, err := s.getEnclave(enclaveID)
	if err != nil {
		return nil, err
	}

	// Perform sealing based on enclave type
	var sealed *SealedData

	switch enclave.Type {
	case EnclaveTypeSGX:
		sealed, err = s.sealSGXData(enclave, data, policy)
	case EnclaveTypeTrustZone:
		sealed, err = s.sealTrustZoneData(enclave, data, policy)
	case EnclaveTypeSimulated:
		sealed, err = s.sealSimulatedData(enclave, data, policy)
	default:
		err = fmt.Errorf("sealing not supported for enclave type: %s", enclave.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("sealing failed: %v", err)
	}

	s.metrics.SealingOperations++

	return sealed, nil
}

// SealingPolicy represents the policy for sealing data
type SealingPolicy struct {
	RequireSignature   bool
	RequireMeasurement bool
	AllowMigration     bool
	ExpirationTime     time.Time
	AccessControl      []string
}

// SealedData represents sealed data
type SealedData struct {
	EnclaveID     string
	SealedBlob    []byte
	Policy        *SealingPolicy
	Timestamp     time.Time
	KeyDerivation string
	Metadata      map[string]interface{}
}

// UnsealData unseals previously sealed data
func (s *SecureEnclaveManager) UnsealData(enclaveID string, sealedData *SealedData) ([]byte, error) {
	if !s.config.EnableSealing {
		return nil, errors.New("sealing not enabled")
	}

	enclave, err := s.getEnclave(enclaveID)
	if err != nil {
		return nil, err
	}

	// Verify sealing policy
	if sealedData.EnclaveID != enclaveID {
		return nil, errors.New("sealed data not bound to this enclave")
	}

	if !sealedData.Policy.ExpirationTime.IsZero() && time.Now().After(sealedData.Policy.ExpirationTime) {
		return nil, errors.New("sealed data has expired")
	}

	// Perform unsealing based on enclave type
	var data []byte

	switch enclave.Type {
	case EnclaveTypeSGX:
		data, err = s.unsealSGXData(enclave, sealedData)
	case EnclaveTypeTrustZone:
		data, err = s.unsealTrustZoneData(enclave, sealedData)
	case EnclaveTypeSimulated:
		data, err = s.unsealSimulatedData(enclave, sealedData)
	default:
		err = fmt.Errorf("unsealing not supported for enclave type: %s", enclave.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("unsealing failed: %v", err)
	}

	return data, nil
}

// Implementation methods

func (s *SecureEnclaveManager) getEnclave(enclaveID string) (*SecureEnclave, error) {
	s.enclavesMutex.RLock()
	defer s.enclavesMutex.RUnlock()

	enclave, exists := s.enclaves[enclaveID]
	if !exists {
		return nil, errors.New("enclave not found")
	}

	if enclave.Status == EnclaveStatusDestroyed || enclave.Status == EnclaveStatusError {
		return nil, errors.New("enclave is not available")
	}

	return enclave, nil
}

func (s *SecureEnclaveManager) generateEnclaveID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (s *SecureEnclaveManager) validateOperation(enclave *SecureEnclave, operation *EnclaveOperation) error {
	// Check if operation is supported
	supported := false
	for _, op := range enclave.SupportedOps {
		if op == string(operation.Type) {
			supported = true
			break
		}
	}

	if !supported {
		return fmt.Errorf("operation %s not supported by enclave", operation.Type)
	}

	// Check security context
	if operation.SecurityContext != nil {
		if operation.SecurityContext.RequiredLevel > enclave.SecurityLevel {
			return errors.New("insufficient security level for operation")
		}

		if !operation.SecurityContext.Authenticated {
			return errors.New("operation requires authentication")
		}
	}

	// Check timeout
	if operation.Timeout <= 0 {
		operation.Timeout = s.config.EnclaveTimeout
	}

	return nil
}

func (s *SecureEnclaveManager) updateOperationMetrics(operation *EnclaveOperation, result *OperationResult) {
	s.metrics.mutex.Lock()
	defer s.metrics.mutex.Unlock()

	s.metrics.TotalOperations++

	if result != nil && result.Success {
		s.metrics.SuccessfulOps++
	} else {
		s.metrics.FailedOps++
	}

	// Update average operation duration
	duration := operation.CompletedAt.Sub(operation.StartedAt)
	if s.metrics.TotalOperations == 1 {
		s.metrics.AverageOpDuration = duration
	} else {
		alpha := 0.1
		s.metrics.AverageOpDuration = time.Duration(
			float64(s.metrics.AverageOpDuration)*(1-alpha) + float64(duration)*alpha)
	}

	if result != nil {
		s.metrics.TotalMemoryUsage += result.MemoryUsed
	}
}

func (s *SecureEnclaveManager) destroyEnclaveUnsafe(enclave *SecureEnclave) error {
	// Platform-specific cleanup
	switch enclave.Type {
	case EnclaveTypeSGX:
		if s.sgxManager != nil {
			return s.sgxManager.DestroyEnclave(enclave)
		}
	case EnclaveTypeTrustZone:
		if s.trustZoneManager != nil {
			return s.trustZoneManager.DestroyEnclave(enclave)
		}
	case EnclaveTypeSimulated:
		// No special cleanup needed for simulated enclaves
	}

	enclave.Status = EnclaveStatusDestroyed
	return nil
}

// Background workers

func (s *SecureEnclaveManager) metricsWorker() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.updateMetrics()
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *SecureEnclaveManager) maintenanceWorker() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.performMaintenance()
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *SecureEnclaveManager) attestationWorker() {
	ticker := time.NewTicker(s.config.AttestationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.performPeriodicAttestation()
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *SecureEnclaveManager) updateMetrics() {
	s.enclavesMutex.RLock()
	defer s.enclavesMutex.RUnlock()

	s.metrics.mutex.Lock()
	defer s.metrics.mutex.Unlock()

	s.metrics.ActiveEnclaves = int64(len(s.enclaves))
	s.metrics.LastMetricsUpdate = time.Now()

	// Update resource usage
	totalMemory := int64(0)
	totalCPU := 0.0

	for _, enclave := range s.enclaves {
		totalMemory += enclave.MemoryUsage
		totalCPU += enclave.CPUUsage
	}

	s.metrics.TotalMemoryUsage = totalMemory
	s.metrics.TotalCPUUsage = totalCPU
}

func (s *SecureEnclaveManager) performMaintenance() {
	// Clean up inactive enclaves
	s.enclavesMutex.Lock()
	defer s.enclavesMutex.Unlock()

	cutoff := time.Now().Add(-time.Hour)

	for id, enclave := range s.enclaves {
		if enclave.LastUsed.Before(cutoff) && enclave.ActiveOps == 0 {
			s.destroyEnclaveUnsafe(enclave)
			delete(s.enclaves, id)
			s.metrics.ActiveEnclaves--
		}
	}
}

func (s *SecureEnclaveManager) performPeriodicAttestation() {
	s.enclavesMutex.RLock()
	enclaveIDs := make([]string, 0, len(s.enclaves))
	for id := range s.enclaves {
		enclaveIDs = append(enclaveIDs, id)
	}
	s.enclavesMutex.RUnlock()

	// Attest each enclave
	for _, id := range enclaveIDs {
		go func(enclaveID string) {
			_, err := s.AttestEnclave(enclaveID)
			if err != nil {
				// Log attestation failure
				fmt.Printf("Attestation failed for enclave %s: %v\n", enclaveID, err)
			}
		}(id)
	}
}

// Public API methods

func (s *SecureEnclaveManager) GetEnclaves() map[string]*SecureEnclave {
	s.enclavesMutex.RLock()
	defer s.enclavesMutex.RUnlock()

	result := make(map[string]*SecureEnclave)
	for id, enclave := range s.enclaves {
		result[id] = enclave
	}

	return result
}

func (s *SecureEnclaveManager) GetMetrics() *EnclaveMetrics {
	s.metrics.mutex.RLock()
	defer s.metrics.mutex.RUnlock()

	return &EnclaveMetrics{
		TotalEnclaves:     s.metrics.TotalEnclaves,
		ActiveEnclaves:    s.metrics.ActiveEnclaves,
		TotalOperations:   s.metrics.TotalOperations,
		SuccessfulOps:     s.metrics.SuccessfulOps,
		FailedOps:         s.metrics.FailedOps,
		AverageOpDuration: s.metrics.AverageOpDuration,
		TotalMemoryUsage:  s.metrics.TotalMemoryUsage,
		TotalCPUUsage:     s.metrics.TotalCPUUsage,
		AttestationCount:  s.metrics.AttestationCount,
		SealingOperations: s.metrics.SealingOperations,
		LastMetricsUpdate: s.metrics.LastMetricsUpdate,
	}
}

func (s *SecureEnclaveManager) GetPlatformInfo() map[string]interface{} {
	info := map[string]interface{}{
		"sgx_enabled":         s.config.EnableSGX,
		"trustzone_enabled":   s.config.EnableTrustZone,
		"attestation_enabled": s.config.EnableAttestation,
		"sealing_enabled":     s.config.EnableSealing,
		"max_enclaves":        s.config.MaxEnclaves,
		"security_level":      s.config.SecurityLevel,
	}

	if s.sgxManager != nil {
		info["sgx_info"] = s.sgxManager.GetPlatformInfo()
	}

	if s.trustZoneManager != nil {
		info["trustzone_info"] = s.trustZoneManager.GetPlatformInfo()
	}

	return info
}

func (s *SecureEnclaveManager) ListSupportedOperations() []string {
	return s.config.AllowedOperations
}

func (s *SecureEnclaveManager) GetEnclaveStatus(enclaveID string) (*EnclaveStatusInfo, error) {
	enclave, err := s.getEnclave(enclaveID)
	if err != nil {
		return nil, err
	}

	return &EnclaveStatusInfo{
		ID:             enclave.ID,
		Type:           enclave.Type,
		Platform:       enclave.Platform,
		Status:         enclave.Status,
		CreatedAt:      enclave.CreatedAt,
		LastUsed:       enclave.LastUsed,
		MemoryUsage:    enclave.MemoryUsage,
		CPUUsage:       enclave.CPUUsage,
		ActiveOps:      enclave.ActiveOps,
		CompletedOps:   enclave.CompletedOps,
		FailedOps:      enclave.FailedOps,
		Sealed:         enclave.Sealed,
		Attested:       enclave.Attested,
		SecurityLevel:  enclave.SecurityLevel,
		IsolationLevel: enclave.IsolationLevel,
	}, nil
}

// EnclaveStatusInfo represents enclave status information
type EnclaveStatusInfo struct {
	ID             string
	Type           EnclaveType
	Platform       Platform
	Status         EnclaveStatus
	CreatedAt      time.Time
	LastUsed       time.Time
	MemoryUsage    int64
	CPUUsage       float64
	ActiveOps      int
	CompletedOps   int64
	FailedOps      int64
	Sealed         bool
	Attested       bool
	SecurityLevel  SecurityLevel
	IsolationLevel IsolationLevel
}
