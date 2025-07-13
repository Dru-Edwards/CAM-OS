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
	"strings"
	"time"
)

// Secure Boot constants
const (
	SecureBootEnabled  = "enabled"
	SecureBootDisabled = "disabled"
	SetupModeEnabled   = "setup_mode"
	SetupModeDisabled  = "user_mode"
	
	// UEFI Variable names
	UEFIVarSecureBoot = "SecureBoot"
	UEFIVarSetupMode  = "SetupMode"
	UEFIVarPK         = "PK"
	UEFIVarKEK        = "KEK"
	UEFIVarDB         = "db"
	UEFIVarDBX        = "dbx"
	UEFIVarMOK        = "MokList"
	
	// Certificate types
	CertTypePlatformKey    = "PK"
	CertTypeKeyExchange    = "KEK"
	CertTypeSignatureDB    = "db"
	CertTypeForbiddenDB    = "dbx"
	CertTypeMachineOwner   = "MOK"
	
	// Signature algorithms
	SigAlgRSA2048SHA256 = "rsa2048-sha256"
	SigAlgRSA4096SHA256 = "rsa4096-sha256"
	SigAlgECCP256SHA256 = "ecp256-sha256"
	SigAlgECCP384SHA256 = "ecp384-sha256"
)

// SecureBootManager manages secure boot verification and chain of trust
type SecureBootManager struct {
	config        *SecureBootConfig
	variables     map[string]*UEFIVariable
	certificates  map[string]*SecureBootCertificate
	chainOfTrust  *ChainOfTrust
	bootPath      *BootPath
	verifiedBoot  bool
	lastVerified  time.Time
}

// SecureBootConfig holds secure boot configuration
type SecureBootConfig struct {
	RequireSecureBoot     bool
	RequirePlatformKey    bool
	AllowSetupMode        bool
	VerifyBootPath        bool
	CheckRevocation       bool
	TrustedRootCerts      [][]byte
	TrustedVendors        []string
	AllowedSigners        []string
	ForbiddenSigners      []string
	BootPathWhitelist     []string
	VerificationLevel     VerificationLevel
	MaxChainDepth         int
	CertValidityPeriod    time.Duration
}

// VerificationLevel represents the level of verification required
type VerificationLevel int

const (
	VerificationLevelBasic VerificationLevel = iota
	VerificationLevelStandard
	VerificationLevelStrict
	VerificationLevelMaximum
)

// UEFIVariable represents a UEFI variable
type UEFIVariable struct {
	Name       string
	GUID       string
	Attributes uint32
	Data       []byte
	Size       uint32
	Timestamp  time.Time
	Valid      bool
}

// SecureBootCertificate represents a secure boot certificate
type SecureBootCertificate struct {
	Type           string
	Subject        string
	Issuer         string
	SerialNumber   string
	Fingerprint    string
	PublicKey      interface{}
	Certificate    *x509.Certificate
	RawData        []byte
	Algorithm      string
	KeySize        int
	ValidFrom      time.Time
	ValidTo        time.Time
	Trusted        bool
	Revoked        bool
	Purpose        string
}

// ChainOfTrust represents the complete chain of trust
type ChainOfTrust struct {
	PlatformKey     *SecureBootCertificate
	KeyExchangeKeys []*SecureBootCertificate
	SignatureDB     []*SecureBootCertificate
	ForbiddenDB     []*SecureBootCertificate
	MachineOwnerDB  []*SecureBootCertificate
	TrustLevel      TrustLevel
	Verified        bool
	LastVerified    time.Time
	Violations      []string
}

// BootPath represents the secure boot path
type BootPath struct {
	Bootloader    *BootComponent
	Kernel        *BootComponent
	InitRAMFS     *BootComponent
	Drivers       []*BootComponent
	Applications  []*BootComponent
	Verified      bool
	TrustLevel    TrustLevel
	Violations    []string
	LastVerified  time.Time
}

// BootComponent represents a component in the boot path
type BootComponent struct {
	Name         string
	Path         string
	Hash         []byte
	Signature    []byte
	Signer       string
	Certificate  *SecureBootCertificate
	LoadOrder    int
	Verified     bool
	TrustLevel   TrustLevel
	LoadTime     time.Time
	Size         int64
	Attributes   map[string]string
}

// SecureBootVerificationResult represents the result of secure boot verification
type SecureBootVerificationResult struct {
	SecureBootEnabled   bool
	SetupMode          bool
	ChainOfTrust       *ChainOfTrust
	BootPath           *BootPath
	OverallTrustLevel  TrustLevel
	Verified           bool
	Violations         []string
	Recommendations    []string
	Timestamp          time.Time
	VerificationID     string
}

// NewSecureBootManager creates a new secure boot manager
func NewSecureBootManager(config *SecureBootConfig) *SecureBootManager {
	if config == nil {
		config = &SecureBootConfig{
			RequireSecureBoot:     true,
			RequirePlatformKey:    true,
			AllowSetupMode:        false,
			VerifyBootPath:        true,
			CheckRevocation:       true,
			TrustedRootCerts:      make([][]byte, 0),
			TrustedVendors:        []string{"Microsoft Corporation", "Canonical Ltd.", "Red Hat, Inc."},
			AllowedSigners:        make([]string, 0),
			ForbiddenSigners:      make([]string, 0),
			BootPathWhitelist:     []string{"/boot/", "/efi/"},
			VerificationLevel:     VerificationLevelStandard,
			MaxChainDepth:         5,
			CertValidityPeriod:    10 * 365 * 24 * time.Hour, // 10 years
		}
	}
	
	manager := &SecureBootManager{
		config:       config,
		variables:    make(map[string]*UEFIVariable),
		certificates: make(map[string]*SecureBootCertificate),
		chainOfTrust: &ChainOfTrust{
			KeyExchangeKeys: make([]*SecureBootCertificate, 0),
			SignatureDB:     make([]*SecureBootCertificate, 0),
			ForbiddenDB:     make([]*SecureBootCertificate, 0),
			MachineOwnerDB:  make([]*SecureBootCertificate, 0),
			Violations:      make([]string, 0),
		},
		bootPath: &BootPath{
			Drivers:      make([]*BootComponent, 0),
			Applications: make([]*BootComponent, 0),
			Violations:   make([]string, 0),
		},
	}
	
	return manager
}

// Initialize initializes the secure boot manager
func (s *SecureBootManager) Initialize() error {
	// Read UEFI variables
	err := s.readUEFIVariables()
	if err != nil {
		return fmt.Errorf("failed to read UEFI variables: %v", err)
	}
	
	// Parse certificates
	err = s.parseCertificates()
	if err != nil {
		return fmt.Errorf("failed to parse certificates: %v", err)
	}
	
	// Build chain of trust
	err = s.buildChainOfTrust()
	if err != nil {
		return fmt.Errorf("failed to build chain of trust: %v", err)
	}
	
	// Analyze boot path
	if s.config.VerifyBootPath {
		err = s.analyzeBootPath()
		if err != nil {
			return fmt.Errorf("failed to analyze boot path: %v", err)
		}
	}
	
	return nil
}

// VerifySecureBoot performs comprehensive secure boot verification
func (s *SecureBootManager) VerifySecureBoot() (*SecureBootVerificationResult, error) {
	verificationID := s.generateVerificationID()
	
	result := &SecureBootVerificationResult{
		VerificationID:  verificationID,
		Timestamp:       time.Now(),
		Violations:      make([]string, 0),
		Recommendations: make([]string, 0),
	}
	
	// Check secure boot status
	secureBootEnabled, err := s.isSecureBootEnabled()
	if err != nil {
		result.Violations = append(result.Violations, fmt.Sprintf("Failed to check secure boot status: %v", err))
	} else {
		result.SecureBootEnabled = secureBootEnabled
		if !secureBootEnabled && s.config.RequireSecureBoot {
			result.Violations = append(result.Violations, "Secure boot is disabled but required")
		}
	}
	
	// Check setup mode
	setupMode, err := s.isSetupMode()
	if err != nil {
		result.Violations = append(result.Violations, fmt.Sprintf("Failed to check setup mode: %v", err))
	} else {
		result.SetupMode = setupMode
		if setupMode && !s.config.AllowSetupMode {
			result.Violations = append(result.Violations, "System is in setup mode")
		}
	}
	
	// Verify chain of trust
	err = s.verifyChainOfTrust()
	if err != nil {
		result.Violations = append(result.Violations, fmt.Sprintf("Chain of trust verification failed: %v", err))
	} else {
		result.ChainOfTrust = s.chainOfTrust
		if !s.chainOfTrust.Verified {
			result.Violations = append(result.Violations, "Chain of trust is not verified")
		}
		result.Violations = append(result.Violations, s.chainOfTrust.Violations...)
	}
	
	// Verify boot path
	if s.config.VerifyBootPath {
		err = s.verifyBootPath()
		if err != nil {
			result.Violations = append(result.Violations, fmt.Sprintf("Boot path verification failed: %v", err))
		} else {
			result.BootPath = s.bootPath
			if !s.bootPath.Verified {
				result.Violations = append(result.Violations, "Boot path is not verified")
			}
			result.Violations = append(result.Violations, s.bootPath.Violations...)
		}
	}
	
	// Calculate overall trust level
	result.OverallTrustLevel = s.calculateOverallTrustLevel(result)
	
	// Determine overall verification status
	result.Verified = len(result.Violations) == 0 && result.OverallTrustLevel >= TrustLevelMedium
	
	// Generate recommendations
	result.Recommendations = s.generateRecommendations(result)
	
	s.verifiedBoot = result.Verified
	s.lastVerified = time.Now()
	
	return result, nil
}

// Implementation methods

func (s *SecureBootManager) readUEFIVariables() error {
	// In a real implementation, this would read actual UEFI variables
	// For demonstration, we simulate UEFI variable reading
	
	// Simulate SecureBoot variable
	s.variables[UEFIVarSecureBoot] = &UEFIVariable{
		Name:       UEFIVarSecureBoot,
		GUID:       "8be4df61-93ca-11d2-aa0d-00e098032b8c",
		Attributes: 0x07, // NV+BS+RT
		Data:       []byte{0x01}, // Enabled
		Size:       1,
		Timestamp:  time.Now(),
		Valid:      true,
	}
	
	// Simulate SetupMode variable
	s.variables[UEFIVarSetupMode] = &UEFIVariable{
		Name:       UEFIVarSetupMode,
		GUID:       "8be4df61-93ca-11d2-aa0d-00e098032b8c",
		Attributes: 0x07, // NV+BS+RT
		Data:       []byte{0x00}, // User mode
		Size:       1,
		Timestamp:  time.Now(),
		Valid:      true,
	}
	
	// Simulate Platform Key (PK)
	pkData := s.generateSimulatedCertificateData("Microsoft Corporation UEFI CA 2011", CertTypePlatformKey)
	s.variables[UEFIVarPK] = &UEFIVariable{
		Name:       UEFIVarPK,
		GUID:       "8be4df61-93ca-11d2-aa0d-00e098032b8c",
		Attributes: 0x07, // NV+BS+RT
		Data:       pkData,
		Size:       uint32(len(pkData)),
		Timestamp:  time.Now(),
		Valid:      true,
	}
	
	// Simulate Key Exchange Key (KEK)
	kekData := s.generateSimulatedCertificateData("Microsoft Corporation KEK CA 2011", CertTypeKeyExchange)
	s.variables[UEFIVarKEK] = &UEFIVariable{
		Name:       UEFIVarKEK,
		GUID:       "8be4df61-93ca-11d2-aa0d-00e098032b8c",
		Attributes: 0x07, // NV+BS+RT
		Data:       kekData,
		Size:       uint32(len(kekData)),
		Timestamp:  time.Now(),
		Valid:      true,
	}
	
	// Simulate Signature Database (db)
	dbData := s.generateSimulatedCertificateData("Microsoft Windows Production PCA 2011", CertTypeSignatureDB)
	s.variables[UEFIVarDB] = &UEFIVariable{
		Name:       UEFIVarDB,
		GUID:       "d719b2cb-3d3a-4596-a3bc-dad00e67656f",
		Attributes: 0x07, // NV+BS+RT
		Data:       dbData,
		Size:       uint32(len(dbData)),
		Timestamp:  time.Now(),
		Valid:      true,
	}
	
	// Simulate Forbidden Signature Database (dbx)
	dbxData := s.generateSimulatedCertificateData("Revoked Certificate", CertTypeForbiddenDB)
	s.variables[UEFIVarDBX] = &UEFIVariable{
		Name:       UEFIVarDBX,
		GUID:       "d719b2cb-3d3a-4596-a3bc-dad00e67656f",
		Attributes: 0x07, // NV+BS+RT
		Data:       dbxData,
		Size:       uint32(len(dbxData)),
		Timestamp:  time.Now(),
		Valid:      true,
	}
	
	return nil
}

func (s *SecureBootManager) parseCertificates() error {
	for varName, variable := range s.variables {
		if varName == UEFIVarSecureBoot || varName == UEFIVarSetupMode {
			continue // Skip non-certificate variables
		}
		
		cert, err := s.parseCertificateFromData(variable.Data, varName)
		if err != nil {
			return fmt.Errorf("failed to parse certificate from %s: %v", varName, err)
		}
		
		if cert != nil {
			s.certificates[cert.Fingerprint] = cert
		}
	}
	
	return nil
}

func (s *SecureBootManager) parseCertificateFromData(data []byte, certType string) (*SecureBootCertificate, error) {
	// In a real implementation, this would parse actual certificate data
	// For demonstration, we create simulated certificates
	
	// Generate a simulated certificate
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %v", err)
	}
	
	// Create certificate subject based on type
	var subject string
	switch certType {
	case UEFIVarPK:
		subject = "Microsoft Corporation UEFI CA 2011"
	case UEFIVarKEK:
		subject = "Microsoft Corporation KEK CA 2011"
	case UEFIVarDB:
		subject = "Microsoft Windows Production PCA 2011"
	case UEFIVarDBX:
		subject = "Revoked Certificate"
	default:
		subject = fmt.Sprintf("Unknown Certificate (%s)", certType)
	}
	
	// Create certificate template
	template := &x509.Certificate{
		Subject:    x509.Name{CommonName: subject},
		NotBefore:  time.Now().Add(-365 * 24 * time.Hour),
		NotAfter:   time.Now().Add(s.config.CertValidityPeriod),
	}
	
	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}
	
	// Parse certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}
	
	// Create fingerprint
	hash := sha256.Sum256(certDER)
	fingerprint := hex.EncodeToString(hash[:])
	
	// Determine if certificate is trusted
	trusted := s.isTrustedCertificate(subject)
	
	secureBootCert := &SecureBootCertificate{
		Type:         s.getCertificateType(certType),
		Subject:      subject,
		Issuer:       cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.String(),
		Fingerprint:  fingerprint,
		PublicKey:    cert.PublicKey,
		Certificate:  cert,
		RawData:      certDER,
		Algorithm:    SigAlgRSA2048SHA256,
		KeySize:      2048,
		ValidFrom:    cert.NotBefore,
		ValidTo:      cert.NotAfter,
		Trusted:      trusted,
		Revoked:      s.isRevokedCertificate(subject),
		Purpose:      s.getCertificatePurpose(certType),
	}
	
	return secureBootCert, nil
}

func (s *SecureBootManager) buildChainOfTrust() error {
	// Build the chain of trust from parsed certificates
	for _, cert := range s.certificates {
		switch cert.Type {
		case CertTypePlatformKey:
			s.chainOfTrust.PlatformKey = cert
		case CertTypeKeyExchange:
			s.chainOfTrust.KeyExchangeKeys = append(s.chainOfTrust.KeyExchangeKeys, cert)
		case CertTypeSignatureDB:
			s.chainOfTrust.SignatureDB = append(s.chainOfTrust.SignatureDB, cert)
		case CertTypeForbiddenDB:
			s.chainOfTrust.ForbiddenDB = append(s.chainOfTrust.ForbiddenDB, cert)
		case CertTypeMachineOwner:
			s.chainOfTrust.MachineOwnerDB = append(s.chainOfTrust.MachineOwnerDB, cert)
		}
	}
	
	return nil
}

func (s *SecureBootManager) analyzeBootPath() error {
	// Analyze the boot path components
	// In a real implementation, this would analyze actual boot components
	
	// Simulate bootloader
	s.bootPath.Bootloader = &BootComponent{
		Name:       "GRUB",
		Path:       "/boot/efi/EFI/ubuntu/grubx64.efi",
		Hash:       s.generateComponentHash("GRUB_BOOTLOADER"),
		Signature:  s.generateComponentSignature("GRUB_BOOTLOADER"),
		Signer:     "Canonical Ltd.",
		LoadOrder:  1,
		Verified:   true,
		TrustLevel: TrustLevelHigh,
		LoadTime:   time.Now().Add(-time.Hour),
		Size:       1048576, // 1MB
		Attributes: map[string]string{
			"version": "2.06",
			"signed":  "true",
		},
	}
	
	// Simulate kernel
	s.bootPath.Kernel = &BootComponent{
		Name:       "Linux Kernel",
		Path:       "/boot/vmlinuz-5.15.0-generic",
		Hash:       s.generateComponentHash("LINUX_KERNEL"),
		Signature:  s.generateComponentSignature("LINUX_KERNEL"),
		Signer:     "Canonical Ltd.",
		LoadOrder:  2,
		Verified:   true,
		TrustLevel: TrustLevelHigh,
		LoadTime:   time.Now().Add(-50 * time.Minute),
		Size:       11534336, // ~11MB
		Attributes: map[string]string{
			"version": "5.15.0-generic",
			"signed":  "true",
		},
	}
	
	// Simulate InitRAMFS
	s.bootPath.InitRAMFS = &BootComponent{
		Name:       "InitRAMFS",
		Path:       "/boot/initrd.img-5.15.0-generic",
		Hash:       s.generateComponentHash("INITRAMFS"),
		Signature:  s.generateComponentSignature("INITRAMFS"),
		Signer:     "Canonical Ltd.",
		LoadOrder:  3,
		Verified:   true,
		TrustLevel: TrustLevelMedium,
		LoadTime:   time.Now().Add(-45 * time.Minute),
		Size:       33554432, // 32MB
		Attributes: map[string]string{
			"compressed": "true",
			"signed":     "true",
		},
	}
	
	// Simulate drivers
	driver := &BootComponent{
		Name:       "TPM Driver",
		Path:       "/lib/modules/5.15.0-generic/kernel/drivers/char/tpm/tpm.ko",
		Hash:       s.generateComponentHash("TPM_DRIVER"),
		Signature:  s.generateComponentSignature("TPM_DRIVER"),
		Signer:     "Canonical Ltd.",
		LoadOrder:  4,
		Verified:   true,
		TrustLevel: TrustLevelMedium,
		LoadTime:   time.Now().Add(-40 * time.Minute),
		Size:       65536, // 64KB
		Attributes: map[string]string{
			"module_type": "kernel_driver",
			"signed":      "true",
		},
	}
	
	s.bootPath.Drivers = append(s.bootPath.Drivers, driver)
	
	return nil
}

func (s *SecureBootManager) verifyChainOfTrust() error {
	violations := make([]string, 0)
	
	// Verify Platform Key
	if s.config.RequirePlatformKey && s.chainOfTrust.PlatformKey == nil {
		violations = append(violations, "Platform Key (PK) is missing")
	}
	
	if s.chainOfTrust.PlatformKey != nil {
		if !s.chainOfTrust.PlatformKey.Trusted {
			violations = append(violations, "Platform Key is not trusted")
		}
		if s.chainOfTrust.PlatformKey.Revoked {
			violations = append(violations, "Platform Key is revoked")
		}
		if time.Now().After(s.chainOfTrust.PlatformKey.ValidTo) {
			violations = append(violations, "Platform Key has expired")
		}
	}
	
	// Verify Key Exchange Keys
	if len(s.chainOfTrust.KeyExchangeKeys) == 0 {
		violations = append(violations, "No Key Exchange Keys (KEK) found")
	}
	
	for _, kek := range s.chainOfTrust.KeyExchangeKeys {
		if !kek.Trusted {
			violations = append(violations, fmt.Sprintf("KEK %s is not trusted", kek.Subject))
		}
		if kek.Revoked {
			violations = append(violations, fmt.Sprintf("KEK %s is revoked", kek.Subject))
		}
		if time.Now().After(kek.ValidTo) {
			violations = append(violations, fmt.Sprintf("KEK %s has expired", kek.Subject))
		}
	}
	
	// Verify Signature Database
	if len(s.chainOfTrust.SignatureDB) == 0 {
		violations = append(violations, "Signature Database (db) is empty")
	}
	
	for _, cert := range s.chainOfTrust.SignatureDB {
		if !cert.Trusted {
			violations = append(violations, fmt.Sprintf("Signature DB cert %s is not trusted", cert.Subject))
		}
		if cert.Revoked {
			violations = append(violations, fmt.Sprintf("Signature DB cert %s is revoked", cert.Subject))
		}
	}
	
	// Check forbidden certificates
	for _, cert := range s.chainOfTrust.ForbiddenDB {
		if cert.Trusted {
			violations = append(violations, fmt.Sprintf("Forbidden cert %s is incorrectly trusted", cert.Subject))
		}
	}
	
	// Set chain of trust status
	s.chainOfTrust.Violations = violations
	s.chainOfTrust.Verified = len(violations) == 0
	s.chainOfTrust.TrustLevel = s.calculateChainTrustLevel(violations)
	s.chainOfTrust.LastVerified = time.Now()
	
	if len(violations) > 0 {
		return fmt.Errorf("chain of trust violations: %v", violations)
	}
	
	return nil
}

func (s *SecureBootManager) verifyBootPath() error {
	violations := make([]string, 0)
	
	// Verify bootloader
	if s.bootPath.Bootloader != nil {
		if !s.bootPath.Bootloader.Verified {
			violations = append(violations, "Bootloader signature verification failed")
		}
		if !s.isPathWhitelisted(s.bootPath.Bootloader.Path) {
			violations = append(violations, fmt.Sprintf("Bootloader path not whitelisted: %s", s.bootPath.Bootloader.Path))
		}
	} else {
		violations = append(violations, "Bootloader component missing")
	}
	
	// Verify kernel
	if s.bootPath.Kernel != nil {
		if !s.bootPath.Kernel.Verified {
			violations = append(violations, "Kernel signature verification failed")
		}
		if !s.isPathWhitelisted(s.bootPath.Kernel.Path) {
			violations = append(violations, fmt.Sprintf("Kernel path not whitelisted: %s", s.bootPath.Kernel.Path))
		}
	} else {
		violations = append(violations, "Kernel component missing")
	}
	
	// Verify InitRAMFS
	if s.bootPath.InitRAMFS != nil {
		if !s.bootPath.InitRAMFS.Verified {
			violations = append(violations, "InitRAMFS signature verification failed")
		}
	}
	
	// Verify drivers
	for _, driver := range s.bootPath.Drivers {
		if !driver.Verified {
			violations = append(violations, fmt.Sprintf("Driver %s signature verification failed", driver.Name))
		}
	}
	
	// Set boot path status
	s.bootPath.Violations = violations
	s.bootPath.Verified = len(violations) == 0
	s.bootPath.TrustLevel = s.calculateBootPathTrustLevel(violations)
	s.bootPath.LastVerified = time.Now()
	
	if len(violations) > 0 {
		return fmt.Errorf("boot path violations: %v", violations)
	}
	
	return nil
}

func (s *SecureBootManager) isSecureBootEnabled() (bool, error) {
	variable, exists := s.variables[UEFIVarSecureBoot]
	if !exists {
		return false, errors.New("SecureBoot variable not found")
	}
	
	if !variable.Valid {
		return false, errors.New("SecureBoot variable is invalid")
	}
	
	if len(variable.Data) == 0 {
		return false, errors.New("SecureBoot variable data is empty")
	}
	
	return variable.Data[0] == 0x01, nil
}

func (s *SecureBootManager) isSetupMode() (bool, error) {
	variable, exists := s.variables[UEFIVarSetupMode]
	if !exists {
		return false, errors.New("SetupMode variable not found")
	}
	
	if !variable.Valid {
		return false, errors.New("SetupMode variable is invalid")
	}
	
	if len(variable.Data) == 0 {
		return false, errors.New("SetupMode variable data is empty")
	}
	
	return variable.Data[0] == 0x01, nil
}

// Helper methods

func (s *SecureBootManager) generateVerificationID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (s *SecureBootManager) generateSimulatedCertificateData(subject, certType string) []byte {
	// Generate simulated certificate data
	data := fmt.Sprintf("CERT_%s_%s_%d", certType, subject, time.Now().Unix())
	hash := sha256.Sum256([]byte(data))
	return hash[:]
}

func (s *SecureBootManager) generateComponentHash(component string) []byte {
	data := fmt.Sprintf("COMPONENT_%s_%d", component, time.Now().Unix())
	hash := sha256.Sum256([]byte(data))
	return hash[:]
}

func (s *SecureBootManager) generateComponentSignature(component string) []byte {
	data := fmt.Sprintf("SIGNATURE_%s_%d", component, time.Now().Unix())
	hash := sha256.Sum256([]byte(data))
	return hash[:]
}

func (s *SecureBootManager) isTrustedCertificate(subject string) bool {
	for _, vendor := range s.config.TrustedVendors {
		if strings.Contains(subject, vendor) {
			return true
		}
	}
	
	for _, signer := range s.config.AllowedSigners {
		if strings.Contains(subject, signer) {
			return true
		}
	}
	
	return false
}

func (s *SecureBootManager) isRevokedCertificate(subject string) bool {
	for _, signer := range s.config.ForbiddenSigners {
		if strings.Contains(subject, signer) {
			return true
		}
	}
	
	return strings.Contains(subject, "Revoked")
}

func (s *SecureBootManager) getCertificateType(varName string) string {
	switch varName {
	case UEFIVarPK:
		return CertTypePlatformKey
	case UEFIVarKEK:
		return CertTypeKeyExchange
	case UEFIVarDB:
		return CertTypeSignatureDB
	case UEFIVarDBX:
		return CertTypeForbiddenDB
	case UEFIVarMOK:
		return CertTypeMachineOwner
	default:
		return "unknown"
	}
}

func (s *SecureBootManager) getCertificatePurpose(varName string) string {
	switch varName {
	case UEFIVarPK:
		return "Platform ownership and control"
	case UEFIVarKEK:
		return "Key exchange and delegation"
	case UEFIVarDB:
		return "Code signing and verification"
	case UEFIVarDBX:
		return "Revocation and blacklisting"
	case UEFIVarMOK:
		return "Machine owner control"
	default:
		return "Unknown purpose"
	}
}

func (s *SecureBootManager) isPathWhitelisted(path string) bool {
	for _, whitelistedPath := range s.config.BootPathWhitelist {
		if strings.HasPrefix(path, whitelistedPath) {
			return true
		}
	}
	return false
}

func (s *SecureBootManager) calculateChainTrustLevel(violations []string) TrustLevel {
	if len(violations) == 0 {
		return TrustLevelUltimate
	} else if len(violations) <= 2 {
		return TrustLevelHigh
	} else if len(violations) <= 5 {
		return TrustLevelMedium
	} else if len(violations) <= 10 {
		return TrustLevelLow
	} else {
		return TrustLevelUntrusted
	}
}

func (s *SecureBootManager) calculateBootPathTrustLevel(violations []string) TrustLevel {
	if len(violations) == 0 {
		return TrustLevelUltimate
	} else if len(violations) <= 1 {
		return TrustLevelHigh
	} else if len(violations) <= 3 {
		return TrustLevelMedium
	} else if len(violations) <= 6 {
		return TrustLevelLow
	} else {
		return TrustLevelUntrusted
	}
}

func (s *SecureBootManager) calculateOverallTrustLevel(result *SecureBootVerificationResult) TrustLevel {
	minLevel := TrustLevelUltimate
	
	if result.ChainOfTrust != nil && result.ChainOfTrust.TrustLevel < minLevel {
		minLevel = result.ChainOfTrust.TrustLevel
	}
	
	if result.BootPath != nil && result.BootPath.TrustLevel < minLevel {
		minLevel = result.BootPath.TrustLevel
	}
	
	// Reduce trust level if secure boot is disabled
	if !result.SecureBootEnabled && minLevel > TrustLevelMedium {
		minLevel = TrustLevelMedium
	}
	
	// Reduce trust level if in setup mode
	if result.SetupMode && minLevel > TrustLevelLow {
		minLevel = TrustLevelLow
	}
	
	return minLevel
}

func (s *SecureBootManager) generateRecommendations(result *SecureBootVerificationResult) []string {
	recommendations := make([]string, 0)
	
	if !result.SecureBootEnabled {
		recommendations = append(recommendations, "Enable Secure Boot in UEFI firmware settings")
	}
	
	if result.SetupMode {
		recommendations = append(recommendations, "Exit Setup Mode and enroll Platform Key")
	}
	
	if result.ChainOfTrust != nil && !result.ChainOfTrust.Verified {
		recommendations = append(recommendations, "Review and update certificate trust chains")
	}
	
	if result.BootPath != nil && !result.BootPath.Verified {
		recommendations = append(recommendations, "Verify digital signatures of boot components")
	}
	
	if result.OverallTrustLevel < TrustLevelMedium {
		recommendations = append(recommendations, "Immediate security review required")
	}
	
	return recommendations
}

// Public API methods

func (s *SecureBootManager) GetSecureBootStatus() map[string]interface{} {
	status := map[string]interface{}{
		"verified_boot":   s.verifiedBoot,
		"last_verified":   s.lastVerified,
	}
	
	if secureBootEnabled, err := s.isSecureBootEnabled(); err == nil {
		status["secure_boot_enabled"] = secureBootEnabled
	}
	
	if setupMode, err := s.isSetupMode(); err == nil {
		status["setup_mode"] = setupMode
	}
	
	if s.chainOfTrust != nil {
		status["chain_of_trust"] = map[string]interface{}{
			"verified":     s.chainOfTrust.Verified,
			"trust_level":  s.chainOfTrust.TrustLevel,
			"violations":   len(s.chainOfTrust.Violations),
		}
	}
	
	if s.bootPath != nil {
		status["boot_path"] = map[string]interface{}{
			"verified":    s.bootPath.Verified,
			"trust_level": s.bootPath.TrustLevel,
			"violations":  len(s.bootPath.Violations),
		}
	}
	
	return status
}

func (s *SecureBootManager) GetCertificates() map[string]*SecureBootCertificate {
	// Return copy of certificates
	certificates := make(map[string]*SecureBootCertificate)
	for fingerprint, cert := range s.certificates {
		certificates[fingerprint] = cert
	}
	return certificates
}

func (s *SecureBootManager) GetBootPath() *BootPath {
	return s.bootPath
}

func (s *SecureBootManager) IsSecureBootCompliant() bool {
	if !s.verifiedBoot {
		return false
	}
	
	secureBootEnabled, err := s.isSecureBootEnabled()
	if err != nil || !secureBootEnabled {
		return false
	}
	
	setupMode, err := s.isSetupMode()
	if err != nil || setupMode {
		return false
	}
	
	if s.chainOfTrust == nil || !s.chainOfTrust.Verified {
		return false
	}
	
	if s.config.VerifyBootPath && (s.bootPath == nil || !s.bootPath.Verified) {
		return false
	}
	
	return true
} 