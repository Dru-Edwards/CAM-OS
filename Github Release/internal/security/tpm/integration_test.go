package tpm

import (
	"testing"
	"time"
)

func TestTPMAttestationEngine_Initialize(t *testing.T) {
	config := createTestTPMConfig()
	engine := NewTPMAttestationEngine(config)

	err := engine.Initialize()
	if err != nil {
		t.Fatalf("Expected no error initializing TPM engine: %v", err)
	}

	if engine.device == nil {
		t.Error("Expected TPM device to be initialized")
	}

	if !engine.device.Available {
		t.Error("Expected TPM device to be available")
	}

	if !engine.device.Initialized {
		t.Error("Expected TPM device to be initialized")
	}

	if engine.endorsementKey == nil {
		t.Error("Expected endorsement key to be initialized")
	}

	if engine.attestationKey == nil {
		t.Error("Expected attestation key to be initialized")
	}

	if len(engine.pcrValues) == 0 {
		t.Error("Expected PCR values to be read")
	}

	if len(engine.eventLog.Events) == 0 {
		t.Error("Expected event log to be populated")
	}
}

func TestTPMAttestationEngine_PerformAttestation(t *testing.T) {
	config := createTestTPMConfig()
	engine := NewTPMAttestationEngine(config)

	err := engine.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize TPM engine: %v", err)
	}

	nonce := []byte("test_nonce_12345")

	result, err := engine.PerformAttestation(nonce)
	if err != nil {
		t.Fatalf("Expected no error performing attestation: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil attestation result")
	}

	if result.AttestationID == "" {
		t.Error("Expected attestation ID to be generated")
	}

	if len(result.PCRValues) == 0 {
		t.Error("Expected PCR values in result")
	}

	if result.Quote == nil {
		t.Error("Expected attestation quote to be generated")
	}

	if result.SecureBootState == nil {
		t.Error("Expected secure boot state to be checked")
	}

	if len(result.MeasurementChain) == 0 {
		t.Error("Expected measurement chain to be verified")
	}

	if result.TrustLevel < TrustLevelMedium {
		t.Error("Expected at least medium trust level")
	}

	if !result.Success {
		t.Errorf("Expected successful attestation, violations: %v", result.Violations)
	}
}

func TestTPMAttestationEngine_GenerateQuote(t *testing.T) {
	config := createTestTPMConfig()
	engine := NewTPMAttestationEngine(config)

	err := engine.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize TPM engine: %v", err)
	}

	nonce := []byte("test_nonce_67890")

	quote, err := engine.generateQuote(nonce)
	if err != nil {
		t.Fatalf("Expected no error generating quote: %v", err)
	}

	if quote == nil {
		t.Fatal("Expected non-nil quote")
	}

	if len(quote.PCRSelection) == 0 {
		t.Error("Expected PCR selection in quote")
	}

	if len(quote.QuoteData) == 0 {
		t.Error("Expected quote data")
	}

	if len(quote.Signature) == 0 {
		t.Error("Expected quote signature")
	}

	if !quote.Verified {
		t.Error("Expected quote to be verified")
	}

	if string(quote.Nonce) != string(nonce) {
		t.Error("Expected nonce to match")
	}

	if quote.AttestorKey == "" {
		t.Error("Expected attestor key fingerprint")
	}
}

func TestTPMAttestationEngine_VerifyAttestation(t *testing.T) {
	config := createTestTPMConfig()
	engine := NewTPMAttestationEngine(config)

	err := engine.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize TPM engine: %v", err)
	}

	nonce := []byte("verification_nonce")

	// Perform attestation
	result, err := engine.PerformAttestation(nonce)
	if err != nil {
		t.Fatalf("Failed to perform attestation: %v", err)
	}

	// Verify attestation with correct PCR values
	expectedPCRs := result.PCRValues
	verified, err := engine.VerifyAttestation(result, expectedPCRs)
	if err != nil {
		t.Fatalf("Expected no error verifying attestation: %v", err)
	}

	if !verified {
		t.Error("Expected attestation to be verified")
	}

	// Test verification with wrong PCR values
	wrongPCRs := make(map[int][]byte)
	wrongPCRs[0] = []byte("wrong_pcr_value")

	verified, err = engine.VerifyAttestation(result, wrongPCRs)
	if err == nil {
		t.Error("Expected error for wrong PCR values")
	}

	if verified {
		t.Error("Expected verification to fail for wrong PCR values")
	}
}

func TestTPMAttestationEngine_ExtendPCR(t *testing.T) {
	config := createTestTPMConfig()
	engine := NewTPMAttestationEngine(config)

	err := engine.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize TPM engine: %v", err)
	}

	// Get initial PCR value
	initialValue := make([]byte, len(engine.pcrValues[PCRCustom1]))
	copy(initialValue, engine.pcrValues[PCRCustom1])

	// Extend PCR
	extensionData := []byte("test_extension_data")
	err = engine.ExtendPCR(PCRCustom1, extensionData)
	if err != nil {
		t.Fatalf("Expected no error extending PCR: %v", err)
	}

	// Verify PCR value changed
	newValue := engine.pcrValues[PCRCustom1]
	if equalBytes(initialValue, newValue) {
		t.Error("Expected PCR value to change after extension")
	}

	// Verify event was logged
	found := false
	for _, event := range engine.eventLog.Events {
		if event.PCRIndex == PCRCustom1 && string(event.EventData) == string(extensionData) {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected measurement event to be logged")
	}

	// Test invalid PCR index
	err = engine.ExtendPCR(-1, extensionData)
	if err == nil {
		t.Error("Expected error for invalid PCR index")
	}

	err = engine.ExtendPCR(TPMMaxPCRs, extensionData)
	if err == nil {
		t.Error("Expected error for PCR index out of range")
	}
}

func TestSecureBootManager_Initialize(t *testing.T) {
	config := createTestSecureBootConfig()
	manager := NewSecureBootManager(config)

	err := manager.Initialize()
	if err != nil {
		t.Fatalf("Expected no error initializing secure boot manager: %v", err)
	}

	if len(manager.variables) == 0 {
		t.Error("Expected UEFI variables to be read")
	}

	if len(manager.certificates) == 0 {
		t.Error("Expected certificates to be parsed")
	}

	if manager.chainOfTrust == nil {
		t.Error("Expected chain of trust to be built")
	}

	if manager.bootPath == nil {
		t.Error("Expected boot path to be analyzed")
	}
}

func TestSecureBootManager_VerifySecureBoot(t *testing.T) {
	config := createTestSecureBootConfig()
	manager := NewSecureBootManager(config)

	err := manager.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize secure boot manager: %v", err)
	}

	result, err := manager.VerifySecureBoot()
	if err != nil {
		t.Fatalf("Expected no error verifying secure boot: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil verification result")
	}

	if result.VerificationID == "" {
		t.Error("Expected verification ID to be generated")
	}

	if !result.SecureBootEnabled {
		t.Error("Expected secure boot to be enabled")
	}

	if result.SetupMode {
		t.Error("Expected system to not be in setup mode")
	}

	if result.ChainOfTrust == nil {
		t.Error("Expected chain of trust in result")
	}

	if result.BootPath == nil {
		t.Error("Expected boot path in result")
	}

	if result.OverallTrustLevel < TrustLevelMedium {
		t.Error("Expected at least medium overall trust level")
	}

	if !result.Verified {
		t.Errorf("Expected successful verification, violations: %v", result.Violations)
	}

	if len(result.Recommendations) > 0 {
		t.Logf("Recommendations: %v", result.Recommendations)
	}
}

func TestSecureBootManager_ChainOfTrust(t *testing.T) {
	config := createTestSecureBootConfig()
	manager := NewSecureBootManager(config)

	err := manager.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize secure boot manager: %v", err)
	}

	// Verify chain of trust
	err = manager.verifyChainOfTrust()
	if err != nil {
		t.Fatalf("Expected no error verifying chain of trust: %v", err)
	}

	if manager.chainOfTrust.PlatformKey == nil {
		t.Error("Expected Platform Key to be present")
	}

	if len(manager.chainOfTrust.KeyExchangeKeys) == 0 {
		t.Error("Expected Key Exchange Keys to be present")
	}

	if len(manager.chainOfTrust.SignatureDB) == 0 {
		t.Error("Expected Signature Database to be present")
	}

	if !manager.chainOfTrust.Verified {
		t.Errorf("Expected chain of trust to be verified, violations: %v", manager.chainOfTrust.Violations)
	}

	if manager.chainOfTrust.TrustLevel < TrustLevelMedium {
		t.Error("Expected at least medium trust level for chain of trust")
	}
}

func TestSecureBootManager_BootPath(t *testing.T) {
	config := createTestSecureBootConfig()
	manager := NewSecureBootManager(config)

	err := manager.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize secure boot manager: %v", err)
	}

	// Verify boot path
	err = manager.verifyBootPath()
	if err != nil {
		t.Fatalf("Expected no error verifying boot path: %v", err)
	}

	if manager.bootPath.Bootloader == nil {
		t.Error("Expected bootloader component to be present")
	}

	if manager.bootPath.Kernel == nil {
		t.Error("Expected kernel component to be present")
	}

	if manager.bootPath.InitRAMFS == nil {
		t.Error("Expected InitRAMFS component to be present")
	}

	if len(manager.bootPath.Drivers) == 0 {
		t.Error("Expected driver components to be present")
	}

	if !manager.bootPath.Verified {
		t.Errorf("Expected boot path to be verified, violations: %v", manager.bootPath.Violations)
	}

	if manager.bootPath.TrustLevel < TrustLevelMedium {
		t.Error("Expected at least medium trust level for boot path")
	}
}

func TestSecureBootManager_UEFIVariables(t *testing.T) {
	config := createTestSecureBootConfig()
	manager := NewSecureBootManager(config)

	err := manager.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize secure boot manager: %v", err)
	}

	// Test SecureBoot variable
	secureBootEnabled, err := manager.isSecureBootEnabled()
	if err != nil {
		t.Fatalf("Expected no error checking secure boot status: %v", err)
	}

	if !secureBootEnabled {
		t.Error("Expected secure boot to be enabled")
	}

	// Test SetupMode variable
	setupMode, err := manager.isSetupMode()
	if err != nil {
		t.Fatalf("Expected no error checking setup mode: %v", err)
	}

	if setupMode {
		t.Error("Expected system to not be in setup mode")
	}

	// Verify specific variables
	requiredVars := []string{UEFIVarSecureBoot, UEFIVarSetupMode, UEFIVarPK, UEFIVarKEK, UEFIVarDB, UEFIVarDBX}

	for _, varName := range requiredVars {
		if variable, exists := manager.variables[varName]; !exists {
			t.Errorf("Expected UEFI variable %s to be present", varName)
		} else if !variable.Valid {
			t.Errorf("Expected UEFI variable %s to be valid", varName)
		}
	}
}

func TestIntegratedTPMSecureBootAttestation(t *testing.T) {
	// Test integration of TPM attestation and secure boot verification

	// Initialize TPM engine
	tpmConfig := createTestTPMConfig()
	tpmEngine := NewTPMAttestationEngine(tpmConfig)

	err := tpmEngine.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize TPM engine: %v", err)
	}

	// Initialize secure boot manager
	sbConfig := createTestSecureBootConfig()
	sbManager := NewSecureBootManager(sbConfig)

	err = sbManager.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize secure boot manager: %v", err)
	}

	// Perform TPM attestation
	nonce := []byte("integrated_test_nonce")
	tpmResult, err := tpmEngine.PerformAttestation(nonce)
	if err != nil {
		t.Fatalf("Failed to perform TPM attestation: %v", err)
	}

	// Perform secure boot verification
	sbResult, err := sbManager.VerifySecureBoot()
	if err != nil {
		t.Fatalf("Failed to perform secure boot verification: %v", err)
	}

	// Verify both results are successful
	if !tpmResult.Success {
		t.Errorf("TPM attestation failed, violations: %v", tpmResult.Violations)
	}

	if !sbResult.Verified {
		t.Errorf("Secure boot verification failed, violations: %v", sbResult.Violations)
	}

	// Verify trust levels are adequate
	if tpmResult.TrustLevel < TrustLevelMedium {
		t.Error("TPM attestation trust level too low")
	}

	if sbResult.OverallTrustLevel < TrustLevelMedium {
		t.Error("Secure boot trust level too low")
	}

	// Verify secure boot state matches TPM measurement
	if tpmResult.SecureBootState != nil && sbResult.SecureBootEnabled {
		if tpmResult.SecureBootState.Enabled != sbResult.SecureBootEnabled {
			t.Error("Secure boot state mismatch between TPM and UEFI")
		}
	}

	// Create combined trust assessment
	combinedTrustLevel := TrustLevelUltimate
	if tpmResult.TrustLevel < combinedTrustLevel {
		combinedTrustLevel = tpmResult.TrustLevel
	}
	if sbResult.OverallTrustLevel < combinedTrustLevel {
		combinedTrustLevel = sbResult.OverallTrustLevel
	}

	if combinedTrustLevel < TrustLevelMedium {
		t.Errorf("Combined trust level too low: %d", combinedTrustLevel)
	}

	// Log integration results
	t.Logf("TPM Attestation: Success=%v, TrustLevel=%d, Violations=%d",
		tpmResult.Success, tpmResult.TrustLevel, len(tpmResult.Violations))
	t.Logf("Secure Boot: Verified=%v, TrustLevel=%d, Violations=%d",
		sbResult.Verified, sbResult.OverallTrustLevel, len(sbResult.Violations))
	t.Logf("Combined Trust Level: %d", combinedTrustLevel)
}

func TestTPMAttestationEngine_GetInfo(t *testing.T) {
	config := createTestTPMConfig()
	engine := NewTPMAttestationEngine(config)

	err := engine.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize TPM engine: %v", err)
	}

	info := engine.GetTPMInfo()

	if info["tpm_available"] != true {
		t.Error("Expected TPM to be available")
	}

	if info["tpm_version"] != TPMVersion20 {
		t.Error("Expected TPM version 2.0")
	}

	if info["device_path"] == nil {
		t.Error("Expected device path in info")
	}

	if info["endorsement_key"] == nil {
		t.Error("Expected endorsement key info")
	}

	if info["attestation_key"] == nil {
		t.Error("Expected attestation key info")
	}
}

func TestSecureBootManager_GetStatus(t *testing.T) {
	config := createTestSecureBootConfig()
	manager := NewSecureBootManager(config)

	err := manager.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize secure boot manager: %v", err)
	}

	status := manager.GetSecureBootStatus()

	if status["secure_boot_enabled"] != true {
		t.Error("Expected secure boot to be enabled")
	}

	if status["setup_mode"] != false {
		t.Error("Expected setup mode to be false")
	}

	if status["chain_of_trust"] == nil {
		t.Error("Expected chain of trust status")
	}

	if status["boot_path"] == nil {
		t.Error("Expected boot path status")
	}
}

func BenchmarkTPMAttestation(b *testing.B) {
	config := createTestTPMConfig()
	engine := NewTPMAttestationEngine(config)

	err := engine.Initialize()
	if err != nil {
		b.Fatalf("Failed to initialize TPM engine: %v", err)
	}

	nonce := []byte("benchmark_nonce")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := engine.PerformAttestation(nonce)
			if err != nil {
				b.Fatalf("Attestation failed: %v", err)
			}
		}
	})
}

func BenchmarkSecureBootVerification(b *testing.B) {
	config := createTestSecureBootConfig()
	manager := NewSecureBootManager(config)

	err := manager.Initialize()
	if err != nil {
		b.Fatalf("Failed to initialize secure boot manager: %v", err)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := manager.VerifySecureBoot()
			if err != nil {
				b.Fatalf("Secure boot verification failed: %v", err)
			}
		}
	})
}

// Helper functions

func createTestTPMConfig() *TPMConfig {
	return &TPMConfig{
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

func createTestSecureBootConfig() *SecureBootConfig {
	return &SecureBootConfig{
		RequireSecureBoot:  true,
		RequirePlatformKey: true,
		AllowSetupMode:     false,
		VerifyBootPath:     true,
		CheckRevocation:    true,
		TrustedRootCerts:   make([][]byte, 0),
		TrustedVendors:     []string{"Microsoft Corporation", "Canonical Ltd.", "Red Hat, Inc."},
		AllowedSigners:     make([]string, 0),
		ForbiddenSigners:   make([]string, 0),
		BootPathWhitelist:  []string{"/boot/", "/efi/"},
		VerificationLevel:  VerificationLevelStandard,
		MaxChainDepth:      5,
		CertValidityPeriod: 10 * 365 * 24 * time.Hour,
	}
}

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
