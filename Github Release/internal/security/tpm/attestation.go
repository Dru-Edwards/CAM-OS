package tpm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// TPM 2.0 constants
const (
	TPMVersion20          = "2.0"
	TPMCommandSize        = 4096
	TPMResponseSize       = 4096
	TPMMaxPCRs            = 24
	TPMPCRValueSize       = 32 // SHA-256
	TPMNonceSize          = 20
	TPMAttestationKeySize = 2048
	TPMQuoteSize          = 1024
)

// TPM Algorithm identifiers
const (
	TPMAlgSHA1   = 0x0004
	TPMAlgSHA256 = 0x000B
	TPMAlgRSA    = 0x0001
	TPMAlgECC    = 0x0023
)

// TPM Handle types
const (
	TPMHandleTypeEndorsement = 0x01
	TPMHandleTypeAttestation = 0x02
	TPMHandleTypeStorage     = 0x03
	TPMHandleTypePlatform    = 0x04
)

// PCR (Platform Configuration Register) indices
const (
	PCRFirmware        = 0  // Core Root of Trust for Measurement
	PCRBootLoader      = 1  // Boot loader
	PCROperatingSystem = 2  // Operating system loader
	PCRSecureBoot      = 7  // Secure Boot Policy
	PCRInitRAMFS       = 8  // Initial RAM file system
	PCRKernel          = 9  // Linux kernel
	PCRUserSpace       = 10 // User space applications
	PCRCustom1         = 16 // Custom measurement 1
	PCRCustom2         = 17 // Custom measurement 2
	PCRCustom3         = 18 // Custom measurement 3
)

// TPMAttestationEngine provides TPM 2.0 attestation capabilities
type TPMAttestationEngine struct {
	config         *TPMConfig
	device         *TPMDevice
	endorsementKey *EndorsementKey
	attestationKey *AttestationKey
	platformKeys   map[string]*PlatformKey
	pcrValues      map[int][]byte
	eventLog       *EventLog
}

// TPMConfig holds TPM configuration
type TPMConfig struct {
	DevicePath          string
	EnableAttestation   bool
	EnableSecureBoot    bool
	EnableMeasuredBoot  bool
	RequireEndorsement  bool
	AttestationKeySize  int
	PCRSelection        []int
	EventLogPath        string
	TrustedRootCerts    [][]byte
	PolicyDigests       map[string][]byte
	AttestationInterval time.Duration
	QuoteSigningAlg     int
	PCRHashAlg          int
}

// TPMDevice represents a TPM 2.0 device
type TPMDevice struct {
	Path         string
	Version      string
	Manufacturer string
	Model        string
	FirmwareVer  string
	Available    bool
	Initialized  bool
	Properties   map[string]interface{}
}

// EndorsementKey represents the TPM Endorsement Key
type EndorsementKey struct {
	Handle      uint32
	PublicKey   *rsa.PublicKey
	Certificate []byte
	Algorithm   int
	KeySize     int
	CreatedAt   time.Time
	Verified    bool
}

// AttestationKey represents the TPM Attestation Identity Key
type AttestationKey struct {
	Handle      uint32
	PublicKey   *rsa.PublicKey
	PrivateKey  *rsa.PrivateKey
	Certificate []byte
	Algorithm   int
	KeySize     int
	CreatedAt   time.Time
	Purpose     string
	Activated   bool
}

// PlatformKey represents platform-specific keys
type PlatformKey struct {
	Handle    uint32
	KeyType   string
	Algorithm int
	Purpose   string
	CreatedAt time.Time
	Active    bool
}

// PCRValue represents a Platform Configuration Register value
type PCRValue struct {
	Index     int
	Value     []byte
	Algorithm int
	Timestamp time.Time
	Source    string
}

// AttestationQuote represents a TPM attestation quote
type AttestationQuote struct {
	PCRSelection map[int][]byte
	QuoteData    []byte
	Signature    []byte
	Nonce        []byte
	Timestamp    time.Time
	AttestorKey  string
	Verified     bool
}

// EventLog represents the measured boot event log
type EventLog struct {
	Events    []MeasurementEvent
	LogPath   string
	LogSize   int64
	UpdatedAt time.Time
}

// MeasurementEvent represents a single measurement event
type MeasurementEvent struct {
	PCRIndex    int
	EventType   int
	Digest      []byte
	EventData   []byte
	Description string
	Timestamp   time.Time
	Component   string
	Valid       bool
}

// SecureBootState represents the secure boot state
type SecureBootState struct {
	Enabled       bool
	SetupMode     bool
	SecureBootDB  [][]byte // Signature Database
	SecureBootDBX [][]byte // Forbidden Signature Database
	PK            []byte   // Platform Key
	KEK           [][]byte // Key Exchange Keys
	Verified      bool
	LastChecked   time.Time
}

// AttestationResult represents the result of attestation
type AttestationResult struct {
	Success          bool
	TrustLevel       TrustLevel
	PCRValues        map[int][]byte
	Quote            *AttestationQuote
	SecureBootState  *SecureBootState
	MeasurementChain []MeasurementEvent
	Violations       []string
	Timestamp        time.Time
	AttestationID    string
	Error            error
}

// TrustLevel represents the trust level of attestation
type TrustLevel int

const (
	TrustLevelUntrusted TrustLevel = iota
	TrustLevelLow
	TrustLevelMedium
	TrustLevelHigh
	TrustLevelUltimate
)

// NewTPMAttestationEngine creates a new TPM attestation engine
func NewTPMAttestationEngine(config *TPMConfig) *TPMAttestationEngine {
	if config == nil {
		config = &TPMConfig{
			DevicePath:          "/dev/tpm0",
			EnableAttestation:   true,
			EnableSecureBoot:    true,
			EnableMeasuredBoot:  true,
			RequireEndorsement:  true,
			AttestationKeySize:  2048,
			PCRSelection:        []int{0, 1, 2, 7, 8, 9, 10},
			EventLogPath:        "/sys/kernel/security/tpm0/binary_bios_measurements",
			TrustedRootCerts:    make([][]byte, 0),
			PolicyDigests:       make(map[string][]byte),
			AttestationInterval: time.Hour,
			QuoteSigningAlg:     TPMAlgRSA,
			PCRHashAlg:          TPMAlgSHA256,
		}
	}

	engine := &TPMAttestationEngine{
		config:       config,
		platformKeys: make(map[string]*PlatformKey),
		pcrValues:    make(map[int][]byte),
		eventLog: &EventLog{
			Events:  make([]MeasurementEvent, 0),
			LogPath: config.EventLogPath,
		},
	}

	return engine
}

// Initialize initializes the TPM attestation engine
func (t *TPMAttestationEngine) Initialize() error {
	// Initialize TPM device
	err := t.initializeTPMDevice()
	if err != nil {
		return fmt.Errorf("failed to initialize TPM device: %v", err)
	}

	// Initialize endorsement key
	if t.config.RequireEndorsement {
		err = t.initializeEndorsementKey()
		if err != nil {
			return fmt.Errorf("failed to initialize endorsement key: %v", err)
		}
	}

	// Initialize attestation key
	if t.config.EnableAttestation {
		err = t.initializeAttestationKey()
		if err != nil {
			return fmt.Errorf("failed to initialize attestation key: %v", err)
		}
	}

	// Read PCR values
	err = t.readPCRValues()
	if err != nil {
		return fmt.Errorf("failed to read PCR values: %v", err)
	}

	// Read event log
	if t.config.EnableMeasuredBoot {
		err = t.readEventLog()
		if err != nil {
			return fmt.Errorf("failed to read event log: %v", err)
		}
	}

	return nil
}

// PerformAttestation performs a complete TPM attestation
func (t *TPMAttestationEngine) PerformAttestation(nonce []byte) (*AttestationResult, error) {
	attestationID := t.generateAttestationID()

	result := &AttestationResult{
		AttestationID: attestationID,
		Timestamp:     time.Now(),
		PCRValues:     make(map[int][]byte),
		Violations:    make([]string, 0),
	}

	// Read current PCR values
	err := t.readPCRValues()
	if err != nil {
		result.Success = false
		result.Error = fmt.Errorf("failed to read PCR values: %v", err)
		return result, err
	}

	// Copy PCR values to result
	for index, value := range t.pcrValues {
		result.PCRValues[index] = make([]byte, len(value))
		copy(result.PCRValues[index], value)
	}

	// Generate attestation quote
	if t.config.EnableAttestation && t.attestationKey != nil {
		quote, err := t.generateQuote(nonce)
		if err != nil {
			result.Violations = append(result.Violations, fmt.Sprintf("Failed to generate quote: %v", err))
		} else {
			result.Quote = quote
		}
	}

	// Check secure boot state
	if t.config.EnableSecureBoot {
		secureBootState, err := t.checkSecureBootState()
		if err != nil {
			result.Violations = append(result.Violations, fmt.Sprintf("Failed to check secure boot: %v", err))
		} else {
			result.SecureBootState = secureBootState
			if !secureBootState.Enabled {
				result.Violations = append(result.Violations, "Secure boot is disabled")
			}
		}
	}

	// Verify measurement chain
	if t.config.EnableMeasuredBoot {
		measurementChain, err := t.verifyMeasurementChain()
		if err != nil {
			result.Violations = append(result.Violations, fmt.Sprintf("Measurement chain verification failed: %v", err))
		} else {
			result.MeasurementChain = measurementChain
		}
	}

	// Calculate trust level
	result.TrustLevel = t.calculateTrustLevel(result)

	// Determine overall success
	result.Success = len(result.Violations) == 0 && result.TrustLevel >= TrustLevelMedium

	return result, nil
}

// GenerateQuote generates a TPM attestation quote
func (t *TPMAttestationEngine) generateQuote(nonce []byte) (*AttestationQuote, error) {
	if t.attestationKey == nil {
		return nil, errors.New("attestation key not available")
	}

	// Prepare PCR selection
	pcrSelection := make(map[int][]byte)
	for _, pcrIndex := range t.config.PCRSelection {
		if value, exists := t.pcrValues[pcrIndex]; exists {
			pcrSelection[pcrIndex] = value
		}
	}

	// Create quote data
	quoteData := t.createQuoteData(pcrSelection, nonce)

	// Sign quote data
	signature, err := t.signQuoteData(quoteData)
	if err != nil {
		return nil, fmt.Errorf("failed to sign quote data: %v", err)
	}

	quote := &AttestationQuote{
		PCRSelection: pcrSelection,
		QuoteData:    quoteData,
		Signature:    signature,
		Nonce:        nonce,
		Timestamp:    time.Now(),
		AttestorKey:  t.getAttestationKeyFingerprint(),
		Verified:     false,
	}

	// Verify quote
	verified, err := t.verifyQuote(quote)
	if err != nil {
		return nil, fmt.Errorf("failed to verify quote: %v", err)
	}

	quote.Verified = verified

	return quote, nil
}

// VerifyAttestation verifies a TPM attestation result
func (t *TPMAttestationEngine) VerifyAttestation(result *AttestationResult, expectedPCRs map[int][]byte) (bool, error) {
	if result == nil {
		return false, errors.New("attestation result is nil")
	}

	// Verify quote if present
	if result.Quote != nil {
		verified, err := t.verifyQuote(result.Quote)
		if err != nil {
			return false, fmt.Errorf("quote verification failed: %v", err)
		}
		if !verified {
			return false, errors.New("quote verification failed")
		}
	}

	// Verify PCR values against expected values
	if expectedPCRs != nil {
		for index, expectedValue := range expectedPCRs {
			if actualValue, exists := result.PCRValues[index]; exists {
				if !t.equalBytes(actualValue, expectedValue) {
					return false, fmt.Errorf("PCR %d mismatch: expected %x, got %x", index, expectedValue, actualValue)
				}
			} else {
				return false, fmt.Errorf("PCR %d not found in attestation", index)
			}
		}
	}

	// Verify secure boot state
	if result.SecureBootState != nil && !result.SecureBootState.Enabled {
		return false, errors.New("secure boot is not enabled")
	}

	// Check trust level
	if result.TrustLevel < TrustLevelMedium {
		return false, fmt.Errorf("trust level too low: %d", result.TrustLevel)
	}

	// Check for violations
	if len(result.Violations) > 0 {
		return false, fmt.Errorf("attestation violations: %v", result.Violations)
	}

	return true, nil
}

// Implementation methods

func (t *TPMAttestationEngine) initializeTPMDevice() error {
	// In a real implementation, this would communicate with the actual TPM device
	// For demonstration, we simulate TPM device initialization

	t.device = &TPMDevice{
		Path:         t.config.DevicePath,
		Version:      TPMVersion20,
		Manufacturer: "Infineon",
		Model:        "SLB9665",
		FirmwareVer:  "7.85",
		Available:    true,
		Initialized:  false,
		Properties: map[string]interface{}{
			"pcr_count":    TPMMaxPCRs,
			"hash_algs":    []int{TPMAlgSHA1, TPMAlgSHA256},
			"signing_algs": []int{TPMAlgRSA, TPMAlgECC},
			"key_sizes":    []int{1024, 2048, 4096},
		},
	}

	// Simulate device initialization
	t.device.Initialized = true

	return nil
}

func (t *TPMAttestationEngine) initializeEndorsementKey() error {
	// In a real implementation, this would read the EK from TPM
	// For demonstration, we simulate EK initialization

	// Generate simulated endorsement key
	privateKey, err := rsa.GenerateKey(rand.Reader, t.config.AttestationKeySize)
	if err != nil {
		return fmt.Errorf("failed to generate endorsement key: %v", err)
	}

	t.endorsementKey = &EndorsementKey{
		Handle:    0x81010001, // Persistent handle for EK
		PublicKey: &privateKey.PublicKey,
		Algorithm: TPMAlgRSA,
		KeySize:   t.config.AttestationKeySize,
		CreatedAt: time.Now(),
		Verified:  true,
	}

	// Generate simulated EK certificate
	cert, err := t.generateSimulatedCertificate(&privateKey.PublicKey, "Endorsement Key")
	if err != nil {
		return fmt.Errorf("failed to generate EK certificate: %v", err)
	}

	t.endorsementKey.Certificate = cert

	return nil
}

func (t *TPMAttestationEngine) initializeAttestationKey() error {
	// In a real implementation, this would create AIK in TPM
	// For demonstration, we simulate AIK creation

	// Generate attestation key
	privateKey, err := rsa.GenerateKey(rand.Reader, t.config.AttestationKeySize)
	if err != nil {
		return fmt.Errorf("failed to generate attestation key: %v", err)
	}

	t.attestationKey = &AttestationKey{
		Handle:     0x81010002, // Persistent handle for AIK
		PublicKey:  &privateKey.PublicKey,
		PrivateKey: privateKey,
		Algorithm:  TPMAlgRSA,
		KeySize:    t.config.AttestationKeySize,
		CreatedAt:  time.Now(),
		Purpose:    "Attestation Identity Key",
		Activated:  true,
	}

	// Generate simulated AIK certificate
	cert, err := t.generateSimulatedCertificate(&privateKey.PublicKey, "Attestation Identity Key")
	if err != nil {
		return fmt.Errorf("failed to generate AIK certificate: %v", err)
	}

	t.attestationKey.Certificate = cert

	return nil
}

func (t *TPMAttestationEngine) readPCRValues() error {
	// In a real implementation, this would read actual PCR values from TPM
	// For demonstration, we simulate PCR values

	for _, pcrIndex := range t.config.PCRSelection {
		// Generate simulated PCR value
		pcrValue := make([]byte, TPMPCRValueSize)

		// Create deterministic but realistic PCR values
		data := fmt.Sprintf("PCR_%d_measurement_data", pcrIndex)
		hash := sha256.Sum256([]byte(data))
		copy(pcrValue, hash[:])

		t.pcrValues[pcrIndex] = pcrValue
	}

	return nil
}

func (t *TPMAttestationEngine) readEventLog() error {
	// In a real implementation, this would read the actual event log
	// For demonstration, we create simulated events

	events := []MeasurementEvent{
		{
			PCRIndex:    PCRFirmware,
			EventType:   1, // EV_POST_CODE
			Digest:      t.generateSimulatedDigest("UEFI_FIRMWARE"),
			EventData:   []byte("UEFI Firmware POST"),
			Description: "UEFI Firmware Power-On Self Test",
			Timestamp:   time.Now().Add(-time.Hour),
			Component:   "UEFI Firmware",
			Valid:       true,
		},
		{
			PCRIndex:    PCRBootLoader,
			EventType:   5, // EV_EFI_BOOT_SERVICES_APPLICATION
			Digest:      t.generateSimulatedDigest("GRUB_BOOTLOADER"),
			EventData:   []byte("GRUB Boot Loader"),
			Description: "GRUB Boot Loader Execution",
			Timestamp:   time.Now().Add(-50 * time.Minute),
			Component:   "GRUB",
			Valid:       true,
		},
		{
			PCRIndex:    PCRSecureBoot,
			EventType:   13, // EV_EFI_VARIABLE_DRIVER_CONFIG
			Digest:      t.generateSimulatedDigest("SECUREBOOT_POLICY"),
			EventData:   []byte("SecureBoot Enabled"),
			Description: "Secure Boot Policy Configuration",
			Timestamp:   time.Now().Add(-45 * time.Minute),
			Component:   "UEFI SecureBoot",
			Valid:       true,
		},
		{
			PCRIndex:    PCRKernel,
			EventType:   9, // EV_EFI_BOOT_SERVICES_DRIVER
			Digest:      t.generateSimulatedDigest("LINUX_KERNEL"),
			EventData:   []byte("Linux Kernel vmlinuz-5.15.0"),
			Description: "Linux Kernel Load",
			Timestamp:   time.Now().Add(-40 * time.Minute),
			Component:   "Linux Kernel",
			Valid:       true,
		},
		{
			PCRIndex:    PCRInitRAMFS,
			EventType:   9, // EV_EFI_BOOT_SERVICES_DRIVER
			Digest:      t.generateSimulatedDigest("INITRAMFS"),
			EventData:   []byte("initramfs.cpio.gz"),
			Description: "Initial RAM File System",
			Timestamp:   time.Now().Add(-35 * time.Minute),
			Component:   "InitRAMFS",
			Valid:       true,
		},
	}

	t.eventLog.Events = events
	t.eventLog.LogSize = int64(len(events) * 256) // Approximate size
	t.eventLog.UpdatedAt = time.Now()

	return nil
}

func (t *TPMAttestationEngine) checkSecureBootState() (*SecureBootState, error) {
	// In a real implementation, this would read UEFI variables
	// For demonstration, we simulate secure boot state

	state := &SecureBootState{
		Enabled:     true,
		SetupMode:   false,
		Verified:    true,
		LastChecked: time.Now(),
	}

	// Simulate signature databases
	state.SecureBootDB = [][]byte{
		t.generateSimulatedCertificate(nil, "Microsoft Corporation UEFI CA 2011"),
		t.generateSimulatedCertificate(nil, "Microsoft Windows Production PCA 2011"),
	}

	state.SecureBootDBX = [][]byte{
		// Simulated revoked certificates
		t.generateSimulatedCertificate(nil, "Revoked Certificate 1"),
	}

	// Simulate platform key
	state.PK = t.generateSimulatedCertificate(nil, "Platform Key")

	// Simulate key exchange keys
	state.KEK = [][]byte{
		t.generateSimulatedCertificate(nil, "Microsoft Corporation KEK CA 2011"),
	}

	return state, nil
}

func (t *TPMAttestationEngine) verifyMeasurementChain() ([]MeasurementEvent, error) {
	// Verify the integrity of the measurement chain
	validEvents := make([]MeasurementEvent, 0)

	for _, event := range t.eventLog.Events {
		// Verify event integrity
		if t.verifyMeasurementEvent(&event) {
			validEvents = append(validEvents, event)
		} else {
			return nil, fmt.Errorf("invalid measurement event at PCR %d", event.PCRIndex)
		}
	}

	return validEvents, nil
}

func (t *TPMAttestationEngine) verifyMeasurementEvent(event *MeasurementEvent) bool {
	// In a real implementation, this would verify the event against known good values
	// For demonstration, we perform basic validation

	if len(event.Digest) != 32 { // SHA-256
		return false
	}

	if event.PCRIndex < 0 || event.PCRIndex >= TPMMaxPCRs {
		return false
	}

	if len(event.EventData) == 0 {
		return false
	}

	// Verify digest matches event data (simplified)
	hash := sha256.Sum256(event.EventData)
	expectedDigest := hash[:]

	return t.equalBytes(event.Digest, expectedDigest)
}

func (t *TPMAttestationEngine) createQuoteData(pcrSelection map[int][]byte, nonce []byte) []byte {
	// Create TPM quote data structure
	quoteData := make([]byte, 0)

	// Add magic value
	quoteData = append(quoteData, []byte("TPM2QUOTE")...)

	// Add nonce
	quoteData = append(quoteData, nonce...)

	// Add PCR selection and values
	for index, value := range pcrSelection {
		quoteData = append(quoteData, byte(index))
		quoteData = append(quoteData, value...)
	}

	// Add timestamp
	timestamp := time.Now().Unix()
	for i := 0; i < 8; i++ {
		quoteData = append(quoteData, byte(timestamp>>(8*i)))
	}

	return quoteData
}

func (t *TPMAttestationEngine) signQuoteData(quoteData []byte) ([]byte, error) {
	if t.attestationKey == nil || t.attestationKey.PrivateKey == nil {
		return nil, errors.New("attestation key not available")
	}

	// Hash the quote data
	hash := sha256.Sum256(quoteData)

	// Sign the hash
	signature, err := rsa.SignPKCS1v15(rand.Reader, t.attestationKey.PrivateKey, 0, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign quote data: %v", err)
	}

	return signature, nil
}

func (t *TPMAttestationEngine) verifyQuote(quote *AttestationQuote) (bool, error) {
	if t.attestationKey == nil {
		return false, errors.New("attestation key not available")
	}

	// Hash the quote data
	hash := sha256.Sum256(quote.QuoteData)

	// Verify signature
	err := rsa.VerifyPKCS1v15(t.attestationKey.PublicKey, 0, hash[:], quote.Signature)
	if err != nil {
		return false, fmt.Errorf("signature verification failed: %v", err)
	}

	return true, nil
}

func (t *TPMAttestationEngine) calculateTrustLevel(result *AttestationResult) TrustLevel {
	trustLevel := TrustLevelUltimate

	// Reduce trust level for each violation
	violationCount := len(result.Violations)

	if violationCount == 0 {
		// Check secure boot
		if result.SecureBootState == nil || !result.SecureBootState.Enabled {
			trustLevel = TrustLevelHigh
		}

		// Check quote verification
		if result.Quote == nil || !result.Quote.Verified {
			if trustLevel > TrustLevelMedium {
				trustLevel = TrustLevelMedium
			}
		}
	} else if violationCount <= 2 {
		trustLevel = TrustLevelMedium
	} else if violationCount <= 5 {
		trustLevel = TrustLevelLow
	} else {
		trustLevel = TrustLevelUntrusted
	}

	return trustLevel
}

// Helper methods

func (t *TPMAttestationEngine) generateAttestationID() string {
	// Generate unique attestation ID
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (t *TPMAttestationEngine) getAttestationKeyFingerprint() string {
	if t.attestationKey == nil {
		return ""
	}

	// Create key fingerprint
	keyData := fmt.Sprintf("%v", t.attestationKey.PublicKey.N)
	hash := sha256.Sum256([]byte(keyData))
	return hex.EncodeToString(hash[:8])
}

func (t *TPMAttestationEngine) generateSimulatedDigest(data string) []byte {
	hash := sha256.Sum256([]byte(data))
	return hash[:]
}

func (t *TPMAttestationEngine) generateSimulatedCertificate(publicKey *rsa.PublicKey, subject string) []byte {
	// Generate a simulated certificate
	if publicKey == nil {
		// Create a dummy key for simulation
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		publicKey = &key.PublicKey
	}

	// Create certificate template
	template := &x509.Certificate{
		Subject: x509.Name{CommonName: subject},
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, nil)
	if err != nil {
		return []byte(fmt.Sprintf("SIMULATED_CERT_%s", subject))
	}

	// Convert to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return certPEM
}

func (t *TPMAttestationEngine) equalBytes(a, b []byte) bool {
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

// Public API methods

func (t *TPMAttestationEngine) GetTPMInfo() map[string]interface{} {
	info := map[string]interface{}{
		"tpm_available": t.device != nil && t.device.Available,
		"tpm_version":   TPMVersion20,
	}

	if t.device != nil {
		info["device_path"] = t.device.Path
		info["manufacturer"] = t.device.Manufacturer
		info["model"] = t.device.Model
		info["firmware_version"] = t.device.FirmwareVer
		info["initialized"] = t.device.Initialized
		info["properties"] = t.device.Properties
	}

	if t.endorsementKey != nil {
		info["endorsement_key"] = map[string]interface{}{
			"available": true,
			"algorithm": t.endorsementKey.Algorithm,
			"key_size":  t.endorsementKey.KeySize,
			"verified":  t.endorsementKey.Verified,
		}
	}

	if t.attestationKey != nil {
		info["attestation_key"] = map[string]interface{}{
			"available": true,
			"algorithm": t.attestationKey.Algorithm,
			"key_size":  t.attestationKey.KeySize,
			"activated": t.attestationKey.Activated,
		}
	}

	return info
}

func (t *TPMAttestationEngine) GetPCRValues() map[int][]byte {
	result := make(map[int][]byte)
	for index, value := range t.pcrValues {
		result[index] = make([]byte, len(value))
		copy(result[index], value)
	}
	return result
}

func (t *TPMAttestationEngine) GetEventLog() *EventLog {
	if t.eventLog == nil {
		return nil
	}

	// Return copy of event log
	eventsCopy := make([]MeasurementEvent, len(t.eventLog.Events))
	copy(eventsCopy, t.eventLog.Events)

	return &EventLog{
		Events:    eventsCopy,
		LogPath:   t.eventLog.LogPath,
		LogSize:   t.eventLog.LogSize,
		UpdatedAt: t.eventLog.UpdatedAt,
	}
}

func (t *TPMAttestationEngine) ExtendPCR(pcrIndex int, data []byte) error {
	if pcrIndex < 0 || pcrIndex >= TPMMaxPCRs {
		return fmt.Errorf("invalid PCR index: %d", pcrIndex)
	}

	// Get current PCR value
	currentValue, exists := t.pcrValues[pcrIndex]
	if !exists {
		currentValue = make([]byte, TPMPCRValueSize)
	}

	// Extend PCR: new_value = SHA256(current_value || data)
	extendData := append(currentValue, data...)
	hash := sha256.Sum256(extendData)

	t.pcrValues[pcrIndex] = hash[:]

	// Add measurement event
	event := MeasurementEvent{
		PCRIndex:    pcrIndex,
		EventType:   14, // EV_IPL
		Digest:      hash[:],
		EventData:   data,
		Description: fmt.Sprintf("PCR %d extension", pcrIndex),
		Timestamp:   time.Now(),
		Component:   "CAM-OS",
		Valid:       true,
	}

	t.eventLog.Events = append(t.eventLog.Events, event)
	t.eventLog.UpdatedAt = time.Now()

	return nil
}
