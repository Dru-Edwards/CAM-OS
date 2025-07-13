package unit

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	pb "github.com/cam-os/kernel/proto/generated"
)

// TestTPMCertificateChainValidation tests TPM certificate chain validation (H-10)
func TestTPMCertificateChainValidation(t *testing.T) {
	// Create a trusted root CA for testing
	rootCert, rootKey := createTestRootCA(t)
	trustedRoots := x509.NewCertPool()
	trustedRoots.AddCert(rootCert)

	validator := tmp.NewTPMValidator(trustedRoots)

	t.Run("Valid TPM certificate chain", func(t *testing.T) {
		// Create valid certificate chain
		leafCert := createValidLeafCert(t, rootCert, rootKey)
		chain := &pb.TmpCertificateChain{
			KeyId:            "TEST0001", // Generic test TPM key handle
			CertificateChain: [][]byte{leafCert.Raw},
			AttestationData:  createValidAttestationData(t, "81000001"),
			Algorithm:        "RSA-PSS",
			CreatedAt:        time.Now().Add(-time.Hour).Unix(),
			ExpiresAt:        time.Now().Add(time.Hour * 24).Unix(),
		}

		err := validator.ValidateTmpCertificateChain(chain)
		if err != nil {
			t.Errorf("Valid chain should pass validation, got error: %v", err)
		}
	})

	// H-10 NEGATIVE TESTS: Invalid chains should be rejected
	negativeTests := []struct {
		name          string
		chain         *pb.TmpCertificateChain
		expectedError string
	}{
		{
			name:          "Nil certificate chain",
			chain:         nil,
			expectedError: "certificate chain is nil",
		},
		{
			name: "Empty certificate chain",
			chain: &pb.TmpCertificateChain{
				KeyId:            "TEST0001",
				CertificateChain: [][]byte{},
				AttestationData:  createValidAttestationData(t, "81000001"),
				Algorithm:        "RSA-PSS",
				CreatedAt:        time.Now().Add(-time.Hour).Unix(),
				ExpiresAt:        time.Now().Add(time.Hour * 24).Unix(),
			},
			expectedError: "certificate chain is empty",
		},
		{
			name: "Invalid key ID - empty",
			chain: &pb.TmpCertificateChain{
				KeyId:            "", // Invalid: empty key ID
				CertificateChain: [][]byte{createValidLeafCert(t, rootCert, rootKey).Raw},
				AttestationData:  createValidAttestationData(t, "81000001"),
				Algorithm:        "RSA-PSS",
				CreatedAt:        time.Now().Add(-time.Hour).Unix(),
				ExpiresAt:        time.Now().Add(time.Hour * 24).Unix(),
			},
			expectedError: "key ID is empty",
		},
		{
			name: "Invalid key ID - wrong format",
			chain: &pb.TmpCertificateChain{
				KeyId:            "invalid-key-id", // Invalid: not hex
				CertificateChain: [][]byte{createValidLeafCert(t, rootCert, rootKey).Raw},
				AttestationData:  createValidAttestationData(t, "81000001"),
				Algorithm:        "RSA-PSS",
				CreatedAt:        time.Now().Add(-time.Hour).Unix(),
				ExpiresAt:        time.Now().Add(time.Hour * 24).Unix(),
			},
			expectedError: "key ID must be hex-encoded",
		},
		{
			name: "Invalid algorithm",
			chain: &pb.TmpCertificateChain{
				KeyId:            "TEST0001",
				CertificateChain: [][]byte{createValidLeafCert(t, rootCert, rootKey).Raw},
				AttestationData:  createValidAttestationData(t, "81000001"),
				Algorithm:        "INVALID-ALGORITHM", // Invalid algorithm
				CreatedAt:        time.Now().Add(-time.Hour).Unix(),
				ExpiresAt:        time.Now().Add(time.Hour * 24).Unix(),
			},
			expectedError: "unsupported algorithm: INVALID-ALGORITHM",
		},
		{
			name: "Expired certificate",
			chain: &pb.TmpCertificateChain{
				KeyId:            "TEST0001",
				CertificateChain: [][]byte{createExpiredCert(t, rootCert, rootKey).Raw},
				AttestationData:  createValidAttestationData(t, "81000001"),
				Algorithm:        "RSA-PSS",
				CreatedAt:        time.Now().Add(-time.Hour).Unix(),
				ExpiresAt:        time.Now().Add(time.Hour * 24).Unix(),
			},
			expectedError: "certificate expired",
		},
		{
			name: "Invalid certificate data",
			chain: &pb.TmpCertificateChain{
				KeyId:            "TEST0001",
				CertificateChain: [][]byte{[]byte("invalid-cert-data")}, // Invalid cert data
				AttestationData:  createValidAttestationData(t, "81000001"),
				Algorithm:        "RSA-PSS",
				CreatedAt:        time.Now().Add(-time.Hour).Unix(),
				ExpiresAt:        time.Now().Add(time.Hour * 24).Unix(),
			},
			expectedError: "failed to parse certificate chain",
		},
		{
			name: "Missing attestation data",
			chain: &pb.TmpCertificateChain{
				KeyId:            "TEST0001",
				CertificateChain: [][]byte{createValidLeafCert(t, rootCert, rootKey).Raw},
				AttestationData:  []byte{}, // Empty attestation data
				Algorithm:        "RSA-PSS",
				CreatedAt:        time.Now().Add(-time.Hour).Unix(),
				ExpiresAt:        time.Now().Add(time.Hour * 24).Unix(),
			},
			expectedError: "attestation data is empty",
		},
		{
			name: "Invalid timestamps - expiration before creation",
			chain: &pb.TmpCertificateChain{
				KeyId:            "TEST0001",
				CertificateChain: [][]byte{createValidLeafCert(t, rootCert, rootKey).Raw},
				AttestationData:  createValidAttestationData(t, "81000001"),
				Algorithm:        "RSA-PSS",
				CreatedAt:        time.Now().Unix(),
				ExpiresAt:        time.Now().Add(-time.Hour).Unix(), // Expires before creation
			},
			expectedError: "expiration timestamp before creation timestamp",
		},
		{
			name: "Expired TPM key",
			chain: &pb.TmpCertificateChain{
				KeyId:            "TEST0001",
				CertificateChain: [][]byte{createValidLeafCert(t, rootCert, rootKey).Raw},
				AttestationData:  createValidAttestationData(t, "81000001"),
				Algorithm:        "RSA-PSS",
				CreatedAt:        time.Now().Add(-time.Hour * 2).Unix(),
				ExpiresAt:        time.Now().Add(-time.Hour).Unix(), // Expired
			},
			expectedError: "TPM key expired",
		},
		{
			name: "Certificate chain too long",
			chain: &pb.TmpCertificateChain{
				KeyId: "TEST0001",
				CertificateChain: [][]byte{
					createValidLeafCert(t, rootCert, rootKey).Raw,
					rootCert.Raw,
					rootCert.Raw, // Duplicate to make chain too long
					rootCert.Raw,
					rootCert.Raw,
					rootCert.Raw, // 6 certs, exceeds limit of 5
				},
				AttestationData: createValidAttestationData(t, "81000001"),
				Algorithm:       "RSA-PSS",
				CreatedAt:       time.Now().Add(-time.Hour).Unix(),
				ExpiresAt:       time.Now().Add(time.Hour * 24).Unix(),
			},
			expectedError: "certificate chain too long",
		},
		{
			name: "Invalid certificate key usage",
			chain: &pb.TmpCertificateChain{
				KeyId:            "TEST0001",
				CertificateChain: [][]byte{createInvalidKeyUsageCert(t, rootCert, rootKey).Raw},
				AttestationData:  createValidAttestationData(t, "81000001"),
				Algorithm:        "RSA-PSS",
				CreatedAt:        time.Now().Add(-time.Hour).Unix(),
				ExpiresAt:        time.Now().Add(time.Hour * 24).Unix(),
			},
			expectedError: "certificate key usage not valid for TPM authentication",
		},
	}

	for _, tt := range negativeTests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateTmpCertificateChain(tt.chain)

			// H-10 REQUIREMENT: Invalid chains MUST be rejected
			if err == nil {
				t.Errorf("Expected validation to fail for %s, but it passed", tt.name)
				return
			}

			// Check error message contains expected content
			if !strings.Contains(err.Error(), tt.expectedError) {
				t.Errorf("Expected error containing '%s', got: %v", tt.expectedError, err)
			}

			// Log the validation failure (as expected)
			t.Logf("✅ Correctly rejected invalid chain '%s': %v", tt.name, err)
		})
	}
}

// TestTPMValidationWithUntrustedRoot tests validation against untrusted roots
func TestTPMValidationWithUntrustedRoot(t *testing.T) {
	// Create a different root CA (untrusted)
	untrustedRootCert, untrustedRootKey := createTestRootCA(t)

	// Create trusted roots pool (empty - no trusted roots)
	trustedRoots := x509.NewCertPool()

	validator := tmp.NewTPMValidator(trustedRoots)

	// Create certificate signed by untrusted root
	leafCert := createValidLeafCert(t, untrustedRootCert, untrustedRootKey)

	chain := &pb.TmpCertificateChain{
		KeyId:            "TEST0001",
		CertificateChain: [][]byte{leafCert.Raw, untrustedRootCert.Raw},
		AttestationData:  createValidAttestationData(t, "81000001"),
		Algorithm:        "RSA-PSS",
		CreatedAt:        time.Now().Add(-time.Hour).Unix(),
		ExpiresAt:        time.Now().Add(time.Hour * 24).Unix(),
	}

	err := validator.ValidateTmpCertificateChain(chain)

	// Should pass basic validation if no trusted roots configured
	if err != nil {
		t.Errorf("Expected validation to pass with no trusted roots, got error: %v", err)
	}
}

// Helper functions for creating test certificates

func createTestRootCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test TPM CA"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert, key
}

func createValidLeafCert(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization:  []string{"Test TPM Client"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

func createExpiredCert(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Organization: []string{"Test TPM Client"},
		},
		NotBefore:   time.Now().Add(-time.Hour * 48), // Expired 2 hours ago
		NotAfter:    time.Now().Add(-time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

func createInvalidKeyUsageCert(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject: pkix.Name{
			Organization: []string{"Test TPM Client"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Hour * 24),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, // Invalid usage
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

func createValidAttestationData(t *testing.T, keyID string) []byte {
	t.Helper()

	// Create minimal valid TPM attestation data
	data := make([]byte, 64)

	// TPM_GENERATED_VALUE magic (0xFF544347)
	data[0] = 0xFF
	data[1] = 0x54
	data[2] = 0x43
	data[3] = 0x47

	// Type: TPM_ST_ATTEST_QUOTE
	data[4] = 0x00
	data[5] = 0x00
	data[6] = 0x00
	data[7] = 0x01

	// Add some dummy data for qualified signer and extra data
	copy(data[16:32], []byte("dummy-extra-data"))

	return data
}
