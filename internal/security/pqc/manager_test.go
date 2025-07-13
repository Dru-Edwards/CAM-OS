package pqc

import (
	"fmt"
	"testing"
	"time"
)

func TestPQCManager_NewManager(t *testing.T) {
	config := &PQCConfig{
		EnableKyber768:      true,
		EnableDilithium3:    true,
		EnableKeyRotation:   true,
		KeyRotationInterval: time.Hour,
		KeyValidityPeriod:   24 * time.Hour,
		MaxKeyAge:           72 * time.Hour,
		KeyStoreEnabled:     true,
		KeyStoreCapacity:    1000,
		MetricsEnabled:      true,
		PerformanceMode:     false,
		SecurityLevel:       "NIST-Level-3",
		PreHashMode:         false,
		ContextSeparation:   true,
	}

	manager := NewPostQuantumCryptoManager(config)

	if manager == nil {
		t.Fatal("Expected non-nil manager")
	}

	if manager.kyberEngine == nil {
		t.Error("Expected Kyber768 engine to be initialized")
	}

	if manager.dilithiumEngine == nil {
		t.Error("Expected Dilithium3 engine to be initialized")
	}

	if manager.keyStore == nil {
		t.Error("Expected key store to be initialized")
	}

	if manager.config != config {
		t.Error("Expected config to be set")
	}
}

func TestPQCManager_GenerateHybridKeyPair(t *testing.T) {
	config := createTestPQCConfig()
	manager := NewPostQuantumCryptoManager(config)

	keyPair, err := manager.GenerateHybridKeyPair("test", "user123")
	if err != nil {
		t.Fatalf("Expected no error generating key pair: %v", err)
	}

	if keyPair == nil {
		t.Fatal("Expected non-nil key pair")
	}

	if keyPair.KeyID == "" {
		t.Error("Expected key ID to be generated")
	}

	if keyPair.KyberKeyPair == nil {
		t.Error("Expected Kyber768 key pair to be generated")
	}

	if keyPair.DilithiumKeyPair == nil {
		t.Error("Expected Dilithium3 key pair to be generated")
	}

	if keyPair.Purpose != "test" {
		t.Error("Expected purpose to be set")
	}

	if keyPair.Owner != "user123" {
		t.Error("Expected owner to be set")
	}

	// Verify key sizes
	if len(keyPair.KyberKeyPair.PublicKey) != Kyber768PublicKeySize {
		t.Errorf("Expected Kyber768 public key size %d, got %d", Kyber768PublicKeySize, len(keyPair.KyberKeyPair.PublicKey))
	}

	if len(keyPair.KyberKeyPair.PrivateKey) != Kyber768PrivateKeySize {
		t.Errorf("Expected Kyber768 private key size %d, got %d", Kyber768PrivateKeySize, len(keyPair.KyberKeyPair.PrivateKey))
	}

	if len(keyPair.DilithiumKeyPair.PublicKey) != Dilithium3PublicKeySize {
		t.Errorf("Expected Dilithium3 public key size %d, got %d", Dilithium3PublicKeySize, len(keyPair.DilithiumKeyPair.PublicKey))
	}

	if len(keyPair.DilithiumKeyPair.PrivateKey) != Dilithium3PrivateKeySize {
		t.Errorf("Expected Dilithium3 private key size %d, got %d", Dilithium3PrivateKeySize, len(keyPair.DilithiumKeyPair.PrivateKey))
	}
}

func TestPQCManager_KeyEncapsulation(t *testing.T) {
	config := createTestPQCConfig()
	manager := NewPostQuantumCryptoManager(config)

	// Generate key pair
	keyPair, err := manager.GenerateHybridKeyPair("test", "user123")
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Test encapsulation
	encResult, err := manager.EncapsulateKey(keyPair.KeyID, keyPair.KyberKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("Expected no error during encapsulation: %v", err)
	}

	if !encResult.Success {
		t.Error("Expected successful encapsulation")
	}

	if len(encResult.EncapsulatedKey) != Kyber768CiphertextSize {
		t.Errorf("Expected ciphertext size %d, got %d", Kyber768CiphertextSize, len(encResult.EncapsulatedKey))
	}

	if len(encResult.SharedSecret) != Kyber768SharedKeySize {
		t.Errorf("Expected shared secret size %d, got %d", Kyber768SharedKeySize, len(encResult.SharedSecret))
	}

	if encResult.Algorithm != "Kyber768" {
		t.Error("Expected algorithm to be Kyber768")
	}

	// Test decapsulation
	decResult, err := manager.DecapsulateKey(keyPair.KeyID, keyPair.KyberKeyPair.PrivateKey, encResult.EncapsulatedKey)
	if err != nil {
		t.Fatalf("Expected no error during decapsulation: %v", err)
	}

	if !decResult.Success {
		t.Error("Expected successful decapsulation")
	}

	if len(decResult.SharedSecret) != Kyber768SharedKeySize {
		t.Errorf("Expected shared secret size %d, got %d", Kyber768SharedKeySize, len(decResult.SharedSecret))
	}

	// Verify shared secrets match
	if !equalBytes(encResult.SharedSecret, decResult.SharedSecret) {
		t.Error("Expected shared secrets to match")
	}
}

func TestPQCManager_DigitalSignature(t *testing.T) {
	config := createTestPQCConfig()
	manager := NewPostQuantumCryptoManager(config)

	// Generate key pair
	keyPair, err := manager.GenerateHybridKeyPair("test", "user123")
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	message := []byte("Hello, post-quantum world!")

	// Test signing
	signResult, err := manager.SignMessage(keyPair.KeyID, keyPair.DilithiumKeyPair.PrivateKey, message)
	if err != nil {
		t.Fatalf("Expected no error during signing: %v", err)
	}

	if !signResult.Success {
		t.Error("Expected successful signing")
	}

	if len(signResult.Signature) != Dilithium3SignatureSize {
		t.Errorf("Expected signature size %d, got %d", Dilithium3SignatureSize, len(signResult.Signature))
	}

	if signResult.Algorithm != "Dilithium3" {
		t.Error("Expected algorithm to be Dilithium3")
	}

	// Test verification
	verifyResult, err := manager.VerifySignature(keyPair.KeyID, keyPair.DilithiumKeyPair.PublicKey, message, signResult.Signature)
	if err != nil {
		t.Fatalf("Expected no error during verification: %v", err)
	}

	if !verifyResult.Success {
		t.Error("Expected successful verification")
	}

	if verifyResult.Algorithm != "Dilithium3" {
		t.Error("Expected algorithm to be Dilithium3")
	}

	// Test verification with wrong message
	wrongMessage := []byte("Wrong message")
	wrongVerifyResult, err := manager.VerifySignature(keyPair.KeyID, keyPair.DilithiumKeyPair.PublicKey, wrongMessage, signResult.Signature)
	if err != nil {
		t.Fatalf("Expected no error during wrong verification: %v", err)
	}

	if wrongVerifyResult.Success {
		t.Error("Expected verification to fail for wrong message")
	}
}

func TestPQCManager_KeyStore(t *testing.T) {
	config := createTestPQCConfig()
	manager := NewPostQuantumCryptoManager(config)

	// Generate key pair
	keyPair, err := manager.GenerateHybridKeyPair("test", "user123")
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Retrieve key pair from store
	retrievedKeyPair, err := manager.GetKeyPair(keyPair.KeyID)
	if err != nil {
		t.Fatalf("Expected no error retrieving key pair: %v", err)
	}

	if retrievedKeyPair.KeyID != keyPair.KeyID {
		t.Error("Expected key IDs to match")
	}

	if retrievedKeyPair.Purpose != keyPair.Purpose {
		t.Error("Expected purposes to match")
	}

	if retrievedKeyPair.Owner != keyPair.Owner {
		t.Error("Expected owners to match")
	}

	// Test non-existent key
	_, err = manager.GetKeyPair("non-existent-key")
	if err == nil {
		t.Error("Expected error for non-existent key")
	}
}

func TestPQCManager_KeyValidation(t *testing.T) {
	config := createTestPQCConfig()
	manager := NewPostQuantumCryptoManager(config)

	// Generate key pair
	keyPair, err := manager.GenerateHybridKeyPair("test", "user123")
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Validate key pair
	err = manager.ValidateKeyPair(keyPair)
	if err != nil {
		t.Fatalf("Expected no error validating key pair: %v", err)
	}

	// Test with nil key pair
	err = manager.ValidateKeyPair(nil)
	if err == nil {
		t.Error("Expected error for nil key pair")
	}

	// Test with expired key pair
	expiredKeyPair := &HybridKeyPair{
		KeyID:            "expired",
		KyberKeyPair:     keyPair.KyberKeyPair,
		DilithiumKeyPair: keyPair.DilithiumKeyPair,
		CreatedAt:        time.Now().Add(-48 * time.Hour),
		ExpiresAt:        time.Now().Add(-24 * time.Hour),
		Purpose:          "test",
		Owner:            "user123",
	}

	err = manager.ValidateKeyPair(expiredKeyPair)
	if err == nil {
		t.Error("Expected error for expired key pair")
	}
}

func TestPQCManager_StartStop(t *testing.T) {
	config := createTestPQCConfig()
	manager := NewPostQuantumCryptoManager(config)

	err := manager.Start()
	if err != nil {
		t.Fatalf("Expected no error starting manager: %v", err)
	}

	// Give background workers time to start
	time.Sleep(100 * time.Millisecond)

	err = manager.Stop()
	if err != nil {
		t.Fatalf("Expected no error stopping manager: %v", err)
	}
}

func TestPQCManager_Metrics(t *testing.T) {
	config := createTestPQCConfig()
	manager := NewPostQuantumCryptoManager(config)

	// Initial metrics should be zero
	metrics := manager.GetMetrics()
	if metrics.KeyPairsGenerated != 0 {
		t.Error("Expected initial key pairs generated to be 0")
	}

	// Generate key pair
	keyPair, err := manager.GenerateHybridKeyPair("test", "user123")
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Check metrics after key generation
	metrics = manager.GetMetrics()
	if metrics.KeyPairsGenerated != 1 {
		t.Error("Expected key pairs generated to be 1")
	}

	if metrics.ActiveKeys != 1 {
		t.Error("Expected active keys to be 1")
	}

	// Perform operations
	_, err = manager.EncapsulateKey(keyPair.KeyID, keyPair.KyberKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("Failed encapsulation: %v", err)
	}

	message := []byte("test message")
	_, err = manager.SignMessage(keyPair.KeyID, keyPair.DilithiumKeyPair.PrivateKey, message)
	if err != nil {
		t.Fatalf("Failed signing: %v", err)
	}

	// Check updated metrics
	metrics = manager.GetMetrics()
	if metrics.EncapsulationOps != 1 {
		t.Error("Expected encapsulation ops to be 1")
	}

	if metrics.SignatureOps != 1 {
		t.Error("Expected signature ops to be 1")
	}

	// Check performance metrics
	if len(metrics.PerformanceMetrics) == 0 {
		t.Error("Expected performance metrics to be recorded")
	}
}

func TestPQCManager_AlgorithmInfo(t *testing.T) {
	config := createTestPQCConfig()
	manager := NewPostQuantumCryptoManager(config)

	info := manager.GetAlgorithmInfo()

	if info["manager_version"] != "1.0.0" {
		t.Error("Expected manager version to be set")
	}

	if info["security_level"] != "NIST-Level-3" {
		t.Error("Expected security level to be NIST-Level-3")
	}

	enabledAlgorithms, ok := info["enabled_algorithms"].(map[string]bool)
	if !ok {
		t.Error("Expected enabled algorithms to be present")
	}

	if !enabledAlgorithms["Kyber768"] {
		t.Error("Expected Kyber768 to be enabled")
	}

	if !enabledAlgorithms["Dilithium3"] {
		t.Error("Expected Dilithium3 to be enabled")
	}

	// Check algorithm-specific info
	if info["kyber768"] == nil {
		t.Error("Expected Kyber768 info to be present")
	}

	if info["dilithium3"] == nil {
		t.Error("Expected Dilithium3 info to be present")
	}
}

func TestPQCManager_KeyRotation(t *testing.T) {
	config := createTestPQCConfig()
	config.KeyValidityPeriod = 100 * time.Millisecond // Very short for testing
	config.MaxKeyAge = 200 * time.Millisecond
	manager := NewPostQuantumCryptoManager(config)

	// Generate key pair
	keyPair, err := manager.GenerateHybridKeyPair("test", "user123")
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Wait for key to expire
	time.Sleep(300 * time.Millisecond)

	// Perform key rotation
	err = manager.RotateKeys()
	if err != nil {
		t.Fatalf("Expected no error during key rotation: %v", err)
	}

	// Check metrics
	metrics := manager.GetMetrics()
	if metrics.KeyRotations == 0 {
		t.Error("Expected key rotations to be recorded")
	}

	if !metrics.LastRotation.IsZero() {
		// Check that last rotation time is recent
		if time.Since(metrics.LastRotation) > time.Second {
			t.Error("Expected recent last rotation time")
		}
	}
}

func TestPQCManager_ErrorHandling(t *testing.T) {
	// Test with disabled algorithms
	config := &PQCConfig{
		EnableKyber768:   false,
		EnableDilithium3: false,
		KeyStoreEnabled:  true,
		MetricsEnabled:   true,
	}

	manager := NewPostQuantumCryptoManager(config)

	// Test encapsulation with disabled Kyber768
	_, err := manager.EncapsulateKey("test", make([]byte, Kyber768PublicKeySize))
	if err == nil {
		t.Error("Expected error for encapsulation with disabled Kyber768")
	}

	// Test signing with disabled Dilithium3
	_, err = manager.SignMessage("test", make([]byte, Dilithium3PrivateKeySize), []byte("message"))
	if err == nil {
		t.Error("Expected error for signing with disabled Dilithium3")
	}

	// Test with invalid key sizes
	config.EnableKyber768 = true
	config.EnableDilithium3 = true
	manager = NewPostQuantumCryptoManager(config)

	// Test encapsulation with wrong public key size
	_, err = manager.EncapsulateKey("test", make([]byte, 100))
	if err == nil {
		t.Error("Expected error for wrong public key size")
	}

	// Test signing with wrong private key size
	_, err = manager.SignMessage("test", make([]byte, 100), []byte("message"))
	if err == nil {
		t.Error("Expected error for wrong private key size")
	}
}

func TestPQCManager_ConcurrentOperations(t *testing.T) {
	config := createTestPQCConfig()
	manager := NewPostQuantumCryptoManager(config)

	// Generate key pair
	keyPair, err := manager.GenerateHybridKeyPair("test", "user123")
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Test concurrent operations
	const numOperations = 10

	// Concurrent encapsulations
	encResults := make(chan *HybridOperationResult, numOperations)
	for i := 0; i < numOperations; i++ {
		go func() {
			result, err := manager.EncapsulateKey(keyPair.KeyID, keyPair.KyberKeyPair.PublicKey)
			if err != nil {
				t.Errorf("Concurrent encapsulation failed: %v", err)
			}
			encResults <- result
		}()
	}

	// Collect results
	for i := 0; i < numOperations; i++ {
		result := <-encResults
		if !result.Success {
			t.Error("Expected successful concurrent encapsulation")
		}
	}

	// Concurrent signings
	message := []byte("test message")
	signResults := make(chan *HybridOperationResult, numOperations)
	for i := 0; i < numOperations; i++ {
		go func() {
			result, err := manager.SignMessage(keyPair.KeyID, keyPair.DilithiumKeyPair.PrivateKey, message)
			if err != nil {
				t.Errorf("Concurrent signing failed: %v", err)
			}
			signResults <- result
		}()
	}

	// Collect results
	for i := 0; i < numOperations; i++ {
		result := <-signResults
		if !result.Success {
			t.Error("Expected successful concurrent signing")
		}
	}
}

func BenchmarkPQCManager_GenerateKeyPair(b *testing.B) {
	config := createTestPQCConfig()
	manager := NewPostQuantumCryptoManager(config)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_, err := manager.GenerateHybridKeyPair("benchmark", fmt.Sprintf("user%d", i))
			if err != nil {
				b.Fatalf("Key generation failed: %v", err)
			}
			i++
		}
	})
}

func BenchmarkPQCManager_Encapsulation(b *testing.B) {
	config := createTestPQCConfig()
	manager := NewPostQuantumCryptoManager(config)

	keyPair, err := manager.GenerateHybridKeyPair("benchmark", "user")
	if err != nil {
		b.Fatalf("Failed to generate key pair: %v", err)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := manager.EncapsulateKey(keyPair.KeyID, keyPair.KyberKeyPair.PublicKey)
			if err != nil {
				b.Fatalf("Encapsulation failed: %v", err)
			}
		}
	})
}

func BenchmarkPQCManager_Signing(b *testing.B) {
	config := createTestPQCConfig()
	manager := NewPostQuantumCryptoManager(config)

	keyPair, err := manager.GenerateHybridKeyPair("benchmark", "user")
	if err != nil {
		b.Fatalf("Failed to generate key pair: %v", err)
	}

	message := []byte("benchmark message")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := manager.SignMessage(keyPair.KeyID, keyPair.DilithiumKeyPair.PrivateKey, message)
			if err != nil {
				b.Fatalf("Signing failed: %v", err)
			}
		}
	})
}

func BenchmarkPQCManager_Verification(b *testing.B) {
	config := createTestPQCConfig()
	manager := NewPostQuantumCryptoManager(config)

	keyPair, err := manager.GenerateHybridKeyPair("benchmark", "user")
	if err != nil {
		b.Fatalf("Failed to generate key pair: %v", err)
	}

	message := []byte("benchmark message")
	signResult, err := manager.SignMessage(keyPair.KeyID, keyPair.DilithiumKeyPair.PrivateKey, message)
	if err != nil {
		b.Fatalf("Failed to sign message: %v", err)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := manager.VerifySignature(keyPair.KeyID, keyPair.DilithiumKeyPair.PublicKey, message, signResult.Signature)
			if err != nil {
				b.Fatalf("Verification failed: %v", err)
			}
		}
	})
}

// Helper functions

func createTestPQCConfig() *PQCConfig {
	return &PQCConfig{
		EnableKyber768:      true,
		EnableDilithium3:    true,
		EnableKeyRotation:   true,
		KeyRotationInterval: time.Hour,
		KeyValidityPeriod:   24 * time.Hour,
		MaxKeyAge:           72 * time.Hour,
		KeyStoreEnabled:     true,
		KeyStoreCapacity:    1000,
		MetricsEnabled:      true,
		PerformanceMode:     true, // Use performance mode for testing
		SecurityLevel:       "NIST-Level-3",
		PreHashMode:         false,
		ContextSeparation:   true,
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
