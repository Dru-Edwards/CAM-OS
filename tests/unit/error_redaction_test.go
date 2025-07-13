package unit

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cam-os/kernel/internal/errors"
	"github.com/cam-os/kernel/internal/syscall/handlers"
	"google.golang.org/grpc/status"
)

// TestErrorRedactionLeakage verifies that file paths and IPs are not leaked (H-5)
func TestErrorRedactionLeakage(t *testing.T) {
	// Create error redactor with H-5 compliant configuration
	config := &errors.ErrorRedactionConfig{
		RedactAllErrors:       true,
		LogDetailedErrors:     true,
		GenerateCorrelationID: true,
		RedactionPatterns: []string{
			// H-5 requirement: redact file paths and IPs
			`[A-Za-z]:[\\\/][^\\\/\s]+`,         // Windows file paths
			`\/[^\\\/\s]+(?:\/[^\\\/\s]+)*`,     // Unix file paths
			`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`, // IP addresses
			`:[0-9]{1,5}\b`,                     // Port numbers
			`[a-zA-Z]+://[^\s]+`,                // Connection strings
		},
	}

	redactor := errors.NewErrorRedactor(config)
	ctx := context.Background()

	testCases := []struct {
		name          string
		inputError    error
		sensitiveData []string // Data that MUST NOT appear in redacted error
		operation     string
		userID        string
	}{
		{
			name:       "File path leakage - Windows paths",
			inputError: errors.New("failed to read config from C:\\Windows\\System32\\config\\secrets.ini"),
			sensitiveData: []string{
				"C:\\Windows\\System32\\config\\secrets.ini",
				"C:\\Windows",
				"secrets.ini",
				"System32",
			},
			operation: "file_read",
			userID:    "test-user",
		},
		{
			name:       "File path leakage - Unix paths",
			inputError: errors.New("permission denied accessing /etc/shadow"),
			sensitiveData: []string{
				"/etc/shadow",
				"/etc",
				"shadow",
			},
			operation: "file_access",
			userID:    "test-user",
		},
		{
			name:       "IP address leakage - private IPs",
			inputError: errors.New("connection failed to database server 192.168.1.100"),
			sensitiveData: []string{
				"192.168.1.100",
				"192.168",
			},
			operation: "db_connect",
			userID:    "test-user",
		},
		{
			name:       "IP address leakage - public IPs",
			inputError: errors.New("timeout connecting to API server 203.0.113.45"),
			sensitiveData: []string{
				"203.0.113.45",
			},
			operation: "api_connect",
			userID:    "test-user",
		},
		{
			name:       "Port number leakage",
			inputError: errors.New("failed to bind to port :8080"),
			sensitiveData: []string{
				":8080",
				"8080",
			},
			operation: "port_bind",
			userID:    "test-user",
		},
		{
			name:       "Connection string leakage",
			inputError: errors.New("database connection failed: postgres://admin:secret@192.168.1.50:5432/production"),
			sensitiveData: []string{
				"postgres://admin:secret@192.168.1.50:5432/production",
				"admin:secret",
				"192.168.1.50",
				":5432",
				"production",
			},
			operation: "db_connect",
			userID:    "test-user",
		},
		{
			name:       "Stack trace leakage",
			inputError: errors.New("panic: runtime error\n\tat main.processRequest(/app/src/handlers/secret_handler.go:42)"),
			sensitiveData: []string{
				"/app/src/handlers/secret_handler.go",
				"secret_handler.go",
				"main.processRequest",
			},
			operation: "request_process",
			userID:    "test-user",
		},
		{
			name:       "Complex path with credentials",
			inputError: errors.New("backup failed: cannot access /home/admin/.ssh/id_rsa"),
			sensitiveData: []string{
				"/home/admin/.ssh/id_rsa",
				"/home/admin",
				".ssh",
				"id_rsa",
			},
			operation: "backup",
			userID:    "admin",
		},
		{
			name:       "Network error with internal details",
			inputError: errors.New("network error: failed to connect to internal service at 10.0.0.15:9090"),
			sensitiveData: []string{
				"10.0.0.15",
				":9090",
				"9090",
			},
			operation: "service_connect",
			userID:    "service-user",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Redact the error
			redactedErr := redactor.RedactError(ctx, tc.inputError, tc.operation, tc.userID)

			// Verify error was redacted (not nil)
			if redactedErr == nil {
				t.Fatal("Expected redacted error, got nil")
			}

			// Get the redacted error message
			redactedMessage := redactedErr.Error()

			// Verify it's a gRPC status error
			_, ok := status.FromError(redactedErr)
			if !ok {
				t.Errorf("Expected gRPC status error, got: %T", redactedErr)
			}

			// H-5 CRITICAL CHECK: Verify sensitive data is NOT leaked
			for _, sensitive := range tc.sensitiveData {
				if strings.Contains(redactedMessage, sensitive) {
					t.Errorf("SECURITY VIOLATION: Sensitive data '%s' leaked in redacted error: %s",
						sensitive, redactedMessage)
				}
			}

			// Verify the message contains safe, generic content
			if !strings.Contains(redactedMessage, "correlation_id:") &&
				!strings.Contains(redactedMessage, "Internal server error") &&
				!strings.Contains(redactedMessage, "Authentication required") &&
				!strings.Contains(redactedMessage, "Access denied") {
				t.Errorf("Redacted error doesn't contain expected safe message format: %s", redactedMessage)
			}

			// Verify original error details are not present
			originalMessage := tc.inputError.Error()
			if redactedMessage == originalMessage {
				t.Errorf("Error was not redacted - original message still present: %s", redactedMessage)
			}

			t.Logf("✅ Original: %s", originalMessage)
			t.Logf("✅ Redacted: %s", redactedMessage)
		})
	}
}

// TestHandlerErrorRedaction tests that handlers properly redact errors (H-5)
func TestHandlerErrorRedaction(t *testing.T) {
	// Create handler with error redaction enabled
	config := &handlers.Config{
		SyscallTimeout:     500 * 1000000, // 500ms in nanoseconds
		RedactErrorDetails: true,
	}

	// Create mock handler for testing
	redactor := handlers.NewErrorRedactor(config)

	testCases := []struct {
		name          string
		operation     string
		userID        string
		internalError error
		sensitiveData []string
	}{
		{
			name:          "Database connection error",
			operation:     "context_read",
			userID:        "test-user",
			internalError: errors.New("connection failed to postgres://user:pass@10.0.1.50:5432/cam_production"),
			sensitiveData: []string{"postgres://user:pass@10.0.1.50:5432/cam_production", "10.0.1.50", "user:pass"},
		},
		{
			name:          "File system error",
			operation:     "context_write",
			userID:        "admin",
			internalError: errors.New("permission denied: /var/lib/cam-os/secrets/encryption.key"),
			sensitiveData: []string{"/var/lib/cam-os/secrets/encryption.key", "encryption.key"},
		},
		{
			name:          "Memory allocation error",
			operation:     "arbitrate",
			userID:        "service-account",
			internalError: errors.New("out of memory at 0x7fff8a2e4000, heap dump: /tmp/cam-heap-12345.dump"),
			sensitiveData: []string{"0x7fff8a2e4000", "/tmp/cam-heap-12345.dump"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			// Use handler's error redaction
			redactedErr := redactor.RedactError(ctx, tc.internalError, tc.operation, tc.userID)

			if redactedErr == nil {
				t.Fatal("Expected redacted error, got nil")
			}

			redactedMessage := redactedErr.Error()

			// Verify sensitive data is not leaked
			for _, sensitive := range tc.sensitiveData {
				if strings.Contains(redactedMessage, sensitive) {
					t.Errorf("Handler leaked sensitive data '%s' in error: %s",
						sensitive, redactedMessage)
				}
			}

			// Verify correlation ID is present for tracking
			if !strings.Contains(redactedMessage, "correlation_id:") {
				t.Errorf("Missing correlation ID in redacted error: %s", redactedMessage)
			}
		})
	}
}

// TestFastPathRedaction tests redaction for fast-path methods (H-5 requirement)
func TestFastPathRedaction(t *testing.T) {
	// Note: fastPathRead and fastPathRoute don't exist yet, but H-5 requires them
	// This test documents the requirement for when they are implemented

	t.Run("fastPathRead error redaction", func(t *testing.T) {
		// This test will need to be implemented when fastPathRead is created
		// Requirements:
		// 1. Must use RedactError() for all errors
		// 2. Must not leak file paths, IPs, or sensitive data
		// 3. Must include correlation IDs

		t.Skip("fastPathRead method not yet implemented - required by H-5")
	})

	t.Run("fastPathRoute error redaction", func(t *testing.T) {
		// This test will need to be implemented when fastPathRoute is created
		// Requirements:
		// 1. Must use RedactError() for all errors
		// 2. Must not leak file paths, IPs, or sensitive data
		// 3. Must include correlation IDs

		t.Skip("fastPathRoute method not yet implemented - required by H-5")
	})
}

// TestErrorRedactionPatterns tests specific redaction patterns
func TestErrorRedactionPatterns(t *testing.T) {
	config := &errors.ErrorRedactionConfig{
		RedactAllErrors:       false, // Enable pattern-based redaction for testing
		LogDetailedErrors:     false,
		GenerateCorrelationID: false,
		RedactionPatterns: []string{
			`[A-Za-z]:[\\\/][^\\\/\s]+`,         // Windows paths
			`\/[^\\\/\s]+(?:\/[^\\\/\s]+)*`,     // Unix paths
			`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`, // IP addresses
			`:[0-9]{1,5}\b`,                     // Ports
		},
	}

	redactor := errors.NewErrorRedactor(config)

	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Windows path redaction",
			input:    "Error reading C:\\Program Files\\CAM-OS\\config.yaml",
			expected: "Error reading [REDACTED]",
		},
		{
			name:     "Unix path redaction",
			input:    "Cannot access /etc/cam-os/secrets.conf",
			expected: "Cannot access [REDACTED]",
		},
		{
			name:     "IP address redaction",
			input:    "Connection timeout to 192.168.1.100",
			expected: "Connection timeout to [REDACTED]",
		},
		{
			name:     "Port redaction",
			input:    "Failed to bind to port :8080",
			expected: "Failed to bind to port [REDACTED]",
		},
		{
			name:     "Multiple patterns",
			input:    "DB error: cannot connect to 10.0.0.1:5432, check /etc/postgresql/postgresql.conf",
			expected: "DB error: cannot connect to [REDACTED][REDACTED], check [REDACTED]",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Access private method for testing
			redacted := redactor.(*errors.ErrorRedactor).applyRedactionPatterns(tc.input)

			if redacted != tc.expected {
				t.Errorf("Pattern redaction failed:\nInput:    %s\nExpected: %s\nGot:      %s",
					tc.input, tc.expected, redacted)
			}
		})
	}
}

// Helper function to access private method for testing
func (r *errors.ErrorRedactor) applyRedactionPatterns(message string) string {
	// This would need to be made public or use reflection for testing
	// For now, we'll test through the public interface
	return message
}
