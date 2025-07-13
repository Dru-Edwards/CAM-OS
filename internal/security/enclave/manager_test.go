package enclave

import (
	"fmt"
	"testing"
	"time"
)

func TestSecureEnclaveManager_CreateEnclave(t *testing.T) {
	// Test creating enclaves of different types
	testCases := []struct {
		name        string
		enclaveType EnclaveType
		expectedErr bool
	}{
		{"SGX Enclave", EnclaveTypeSGX, false},
		{"TrustZone Enclave", EnclaveTypeTrustZone, false},
		{"Simulated Enclave", EnclaveTypeSimulated, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			manager := NewSecureEnclaveManager(nil)
			err := manager.Start()
			if err != nil {
				t.Fatalf("Failed to start manager: %v", err)
			}
			defer manager.Stop()

			config := &EnclaveCreationConfig{
				Size:                1024 * 1024, // 1MB
				Permissions:         EnclavePermissions{Read: true, Write: true, Execute: true},
				SupportedOps:        []string{"compute", "encrypt", "decrypt"},
				SecurityLevel:       SecurityLevelHigh,
				IsolationLevel:      IsolationLevelHardware,
				AttestationRequired: true,
				SealingRequired:     true,
			}

			enclave, err := manager.CreateEnclave(tc.enclaveType, config)

			if tc.expectedErr {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}

				if enclave == nil {
					t.Errorf("Expected enclave but got nil")
				}

				if enclave.Type != tc.enclaveType {
					t.Errorf("Expected enclave type %s, got %s", tc.enclaveType, enclave.Type)
				}

				if enclave.Status != EnclaveStatusReady {
					t.Errorf("Expected enclave status %s, got %s", EnclaveStatusReady, enclave.Status)
				}
			}
		})
	}
}

func TestSecureEnclaveManager_ExecuteOperation(t *testing.T) {
	manager := NewSecureEnclaveManager(nil)
	err := manager.Start()
	if err != nil {
		t.Fatalf("Failed to start manager: %v", err)
	}
	defer manager.Stop()

	// Create a simulated enclave for testing
	config := &EnclaveCreationConfig{
		Size:                1024 * 1024,
		Permissions:         EnclavePermissions{Read: true, Write: true, Execute: true},
		SupportedOps:        []string{"compute", "encrypt", "decrypt", "sign", "verify"},
		SecurityLevel:       SecurityLevelHigh,
		IsolationLevel:      IsolationLevelHardware,
		AttestationRequired: true,
		SealingRequired:     true,
	}

	enclave, err := manager.CreateEnclave(EnclaveTypeSimulated, config)
	if err != nil {
		t.Fatalf("Failed to create enclave: %v", err)
	}

	// Test different operations
	testCases := []struct {
		name      string
		operation *EnclaveOperation
		expectErr bool
	}{
		{
			"Compute Operation",
			&EnclaveOperation{
				ID:        "op1",
				Type:      OperationTypeCompute,
				EnclaveID: enclave.ID,
				InputData: []byte("test data for computation"),
				Timeout:   30 * time.Second,
				SecurityContext: &SecurityContext{
					UserID:        "test-user",
					RequiredLevel: SecurityLevelStandard,
					Authenticated: true,
				},
			},
			false,
		},
		{
			"Encrypt Operation",
			&EnclaveOperation{
				ID:        "op2",
				Type:      OperationTypeEncrypt,
				EnclaveID: enclave.ID,
				InputData: []byte("sensitive data to encrypt"),
				Timeout:   30 * time.Second,
				SecurityContext: &SecurityContext{
					UserID:        "test-user",
					RequiredLevel: SecurityLevelStandard,
					Authenticated: true,
				},
			},
			false,
		},
		{
			"Decrypt Operation",
			&EnclaveOperation{
				ID:        "op3",
				Type:      OperationTypeDecrypt,
				EnclaveID: enclave.ID,
				InputData: []byte("encrypted data to decrypt"),
				Timeout:   30 * time.Second,
				SecurityContext: &SecurityContext{
					UserID:        "test-user",
					RequiredLevel: SecurityLevelStandard,
					Authenticated: true,
				},
			},
			false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := manager.ExecuteOperation(tc.operation)

			if tc.expectErr {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}

				if result == nil {
					t.Errorf("Expected result but got nil")
				}

				if !result.Success {
					t.Errorf("Expected successful operation")
				}

				if len(result.OutputData) == 0 {
					t.Errorf("Expected output data but got none")
				}
			}
		})
	}
}

func TestSecureEnclaveManager_AttestEnclave(t *testing.T) {
	manager := NewSecureEnclaveManager(nil)
	err := manager.Start()
	if err != nil {
		t.Fatalf("Failed to start manager: %v", err)
	}
	defer manager.Stop()

	// Test attestation for different enclave types
	testCases := []struct {
		name        string
		enclaveType EnclaveType
		expectedErr bool
	}{
		{"SGX Attestation", EnclaveTypeSGX, false},
		{"TrustZone Attestation", EnclaveTypeTrustZone, false},
		{"Simulated Attestation", EnclaveTypeSimulated, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &EnclaveCreationConfig{
				Size:                1024 * 1024,
				Permissions:         EnclavePermissions{Read: true, Write: true, Execute: true},
				SupportedOps:        []string{"attestation"},
				SecurityLevel:       SecurityLevelHigh,
				IsolationLevel:      IsolationLevelHardware,
				AttestationRequired: true,
			}

			enclave, err := manager.CreateEnclave(tc.enclaveType, config)
			if err != nil {
				t.Fatalf("Failed to create enclave: %v", err)
			}

			result, err := manager.AttestEnclave(enclave.ID)

			if tc.expectedErr {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}

				if result == nil {
					t.Errorf("Expected attestation result but got nil")
				}

				if result.EnclaveID != enclave.ID {
					t.Errorf("Expected enclave ID %s, got %s", enclave.ID, result.EnclaveID)
				}

				if len(result.Measurements) == 0 {
					t.Errorf("Expected measurements but got none")
				}
			}
		})
	}
}

func TestSecureEnclaveManager_SealUnsealData(t *testing.T) {
	manager := NewSecureEnclaveManager(nil)
	err := manager.Start()
	if err != nil {
		t.Fatalf("Failed to start manager: %v", err)
	}
	defer manager.Stop()

	// Create enclave
	config := &EnclaveCreationConfig{
		Size:            1024 * 1024,
		Permissions:     EnclavePermissions{Read: true, Write: true, Execute: true},
		SupportedOps:    []string{"sealing"},
		SecurityLevel:   SecurityLevelHigh,
		IsolationLevel:  IsolationLevelHardware,
		SealingRequired: true,
	}

	enclave, err := manager.CreateEnclave(EnclaveTypeSimulated, config)
	if err != nil {
		t.Fatalf("Failed to create enclave: %v", err)
	}

	// Test data to seal
	testData := []byte("This is sensitive data that needs to be sealed")

	// Create sealing policy
	policy := &SealingPolicy{
		RequireSignature:   true,
		RequireMeasurement: true,
		AllowMigration:     false,
		ExpirationTime:     time.Now().Add(24 * time.Hour),
	}

	// Seal data
	sealedData, err := manager.SealData(enclave.ID, testData, policy)
	if err != nil {
		t.Fatalf("Failed to seal data: %v", err)
	}

	if sealedData == nil {
		t.Fatalf("Expected sealed data but got nil")
	}

	if len(sealedData.SealedBlob) == 0 {
		t.Errorf("Expected sealed blob but got none")
	}

	// Unseal data
	unsealedData, err := manager.UnsealData(enclave.ID, sealedData)
	if err != nil {
		t.Fatalf("Failed to unseal data: %v", err)
	}

	if len(unsealedData) == 0 {
		t.Errorf("Expected unsealed data but got none")
	}

	// Verify data integrity
	if string(unsealedData) != string(testData) {
		t.Errorf("Unsealed data doesn't match original data")
	}
}

func TestSecureEnclaveManager_Metrics(t *testing.T) {
	manager := NewSecureEnclaveManager(nil)
	err := manager.Start()
	if err != nil {
		t.Fatalf("Failed to start manager: %v", err)
	}
	defer manager.Stop()

	// Get initial metrics
	metrics := manager.GetMetrics()
	if metrics == nil {
		t.Errorf("Expected metrics but got nil")
	}

	// Create some enclaves
	config := &EnclaveCreationConfig{
		Size:           1024 * 1024,
		Permissions:    EnclavePermissions{Read: true, Write: true, Execute: true},
		SupportedOps:   []string{"compute"},
		SecurityLevel:  SecurityLevelHigh,
		IsolationLevel: IsolationLevelHardware,
	}

	enclave1, err := manager.CreateEnclave(EnclaveTypeSimulated, config)
	if err != nil {
		t.Fatalf("Failed to create enclave 1: %v", err)
	}

	enclave2, err := manager.CreateEnclave(EnclaveTypeSimulated, config)
	if err != nil {
		t.Fatalf("Failed to create enclave 2: %v", err)
	}

	// Execute some operations
	operation := &EnclaveOperation{
		ID:        "test-op",
		Type:      OperationTypeCompute,
		EnclaveID: enclave1.ID,
		InputData: []byte("test data"),
		Timeout:   30 * time.Second,
		SecurityContext: &SecurityContext{
			UserID:        "test-user",
			RequiredLevel: SecurityLevelStandard,
			Authenticated: true,
		},
	}

	_, err = manager.ExecuteOperation(operation)
	if err != nil {
		t.Fatalf("Failed to execute operation: %v", err)
	}

	// Get updated metrics
	updatedMetrics := manager.GetMetrics()
	if updatedMetrics == nil {
		t.Errorf("Expected updated metrics but got nil")
	}

	// Check metric values
	if activeEnclaves, ok := updatedMetrics.ActiveEnclaves.(int64); !ok || activeEnclaves != 2 {
		t.Errorf("Expected 2 active enclaves, got %v", updatedMetrics.ActiveEnclaves)
	}

	if totalOps, ok := updatedMetrics.TotalOperations.(int64); !ok || totalOps != 1 {
		t.Errorf("Expected 1 total operation, got %v", updatedMetrics.TotalOperations)
	}

	// Test destroying enclave
	err = manager.DestroyEnclave(enclave2.ID)
	if err != nil {
		t.Fatalf("Failed to destroy enclave: %v", err)
	}

	// Check metrics after destruction
	finalMetrics := manager.GetMetrics()
	if activeEnclaves, ok := finalMetrics.ActiveEnclaves.(int64); !ok || activeEnclaves != 1 {
		t.Errorf("Expected 1 active enclave after destruction, got %v", finalMetrics.ActiveEnclaves)
	}
}

func TestSecureEnclaveManager_PlatformInfo(t *testing.T) {
	manager := NewSecureEnclaveManager(nil)
	err := manager.Start()
	if err != nil {
		t.Fatalf("Failed to start manager: %v", err)
	}
	defer manager.Stop()

	platformInfo := manager.GetPlatformInfo()
	if platformInfo == nil {
		t.Errorf("Expected platform info but got nil")
	}

	// Check for expected fields
	expectedFields := []string{
		"sgx_enabled",
		"trustzone_enabled",
		"attestation_enabled",
		"sealing_enabled",
		"max_enclaves",
		"security_level",
	}

	for _, field := range expectedFields {
		if _, exists := platformInfo[field]; !exists {
			t.Errorf("Expected field %s in platform info", field)
		}
	}
}

func TestSecureEnclaveManager_ConcurrentOperations(t *testing.T) {
	manager := NewSecureEnclaveManager(nil)
	err := manager.Start()
	if err != nil {
		t.Fatalf("Failed to start manager: %v", err)
	}
	defer manager.Stop()

	// Create enclave
	config := &EnclaveCreationConfig{
		Size:           1024 * 1024,
		Permissions:    EnclavePermissions{Read: true, Write: true, Execute: true},
		SupportedOps:   []string{"compute", "encrypt", "decrypt"},
		SecurityLevel:  SecurityLevelHigh,
		IsolationLevel: IsolationLevelHardware,
	}

	enclave, err := manager.CreateEnclave(EnclaveTypeSimulated, config)
	if err != nil {
		t.Fatalf("Failed to create enclave: %v", err)
	}

	// Run concurrent operations
	numOperations := 10
	results := make(chan *OperationResult, numOperations)
	errors := make(chan error, numOperations)

	for i := 0; i < numOperations; i++ {
		go func(opID int) {
			operation := &EnclaveOperation{
				ID:        fmt.Sprintf("concurrent-op-%d", opID),
				Type:      OperationTypeCompute,
				EnclaveID: enclave.ID,
				InputData: []byte(fmt.Sprintf("concurrent test data %d", opID)),
				Timeout:   30 * time.Second,
				SecurityContext: &SecurityContext{
					UserID:        "test-user",
					RequiredLevel: SecurityLevelStandard,
					Authenticated: true,
				},
			}

			result, err := manager.ExecuteOperation(operation)
			if err != nil {
				errors <- err
				return
			}

			results <- result
		}(i)
	}

	// Collect results
	successCount := 0
	errorCount := 0

	for i := 0; i < numOperations; i++ {
		select {
		case result := <-results:
			if result.Success {
				successCount++
			}
		case err := <-errors:
			t.Logf("Operation error: %v", err)
			errorCount++
		case <-time.After(60 * time.Second):
			t.Errorf("Timeout waiting for operation results")
			break
		}
	}

	if successCount != numOperations {
		t.Errorf("Expected %d successful operations, got %d", numOperations, successCount)
	}

	if errorCount > 0 {
		t.Errorf("Expected 0 errors, got %d", errorCount)
	}
}

func BenchmarkSecureEnclaveManager_ExecuteOperation(b *testing.B) {
	manager := NewSecureEnclaveManager(nil)
	err := manager.Start()
	if err != nil {
		b.Fatalf("Failed to start manager: %v", err)
	}
	defer manager.Stop()

	// Create enclave
	config := &EnclaveCreationConfig{
		Size:           1024 * 1024,
		Permissions:    EnclavePermissions{Read: true, Write: true, Execute: true},
		SupportedOps:   []string{"compute"},
		SecurityLevel:  SecurityLevelHigh,
		IsolationLevel: IsolationLevelHardware,
	}

	enclave, err := manager.CreateEnclave(EnclaveTypeSimulated, config)
	if err != nil {
		b.Fatalf("Failed to create enclave: %v", err)
	}

	// Benchmark operation execution
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		operation := &EnclaveOperation{
			ID:        fmt.Sprintf("bench-op-%d", i),
			Type:      OperationTypeCompute,
			EnclaveID: enclave.ID,
			InputData: []byte("benchmark test data"),
			Timeout:   30 * time.Second,
			SecurityContext: &SecurityContext{
				UserID:        "test-user",
				RequiredLevel: SecurityLevelStandard,
				Authenticated: true,
			},
		}

		_, err := manager.ExecuteOperation(operation)
		if err != nil {
			b.Fatalf("Failed to execute operation: %v", err)
		}
	}
}
