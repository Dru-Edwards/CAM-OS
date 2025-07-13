package syscall

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestErrorRedactor(t *testing.T) {
	config := &ErrorRedactionConfig{
		RedactAllErrors:       true,
		LogDetailedErrors:     true,
		GenerateCorrelationID: true,
		RedactionPatterns: []string{
			`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`, // IP addresses
			`[A-Za-z]:[\\\/][^\\\/\s]+`,         // File paths
		},
	}

	redactor := NewErrorRedactor(config)
	ctx := context.Background()

	testCases := []struct {
		name                string
		inputError          error
		expectedCode        codes.Code
		expectCorrelationID bool
	}{
		{
			name:                "Authentication error",
			inputError:          errors.New("authentication failed"),
			expectedCode:        codes.Unauthenticated,
			expectCorrelationID: true,
		},
		{
			name:                "Permission denied error",
			inputError:          errors.New("permission denied for user"),
			expectedCode:        codes.PermissionDenied,
			expectCorrelationID: true,
		},
		{
			name:                "Validation error",
			inputError:          errors.New("invalid request format"),
			expectedCode:        codes.InvalidArgument,
			expectCorrelationID: true,
		},
		{
			name:                "Not found error",
			inputError:          errors.New("resource not found"),
			expectedCode:        codes.NotFound,
			expectCorrelationID: true,
		},
		{
			name:                "Already exists error",
			inputError:          errors.New("resource already exists"),
			expectedCode:        codes.AlreadyExists,
			expectCorrelationID: true,
		},
		{
			name:                "Rate limit error",
			inputError:          errors.New("rate limit exceeded"),
			expectedCode:        codes.ResourceExhausted,
			expectCorrelationID: true,
		},
		{
			name:                "Timeout error",
			inputError:          errors.New("request timeout occurred"),
			expectedCode:        codes.DeadlineExceeded,
			expectCorrelationID: true,
		},
		{
			name:                "Service unavailable error",
			inputError:          errors.New("service temporarily unavailable"),
			expectedCode:        codes.Unavailable,
			expectCorrelationID: true,
		},
		{
			name:                "Generic internal error",
			inputError:          errors.New("unexpected database error"),
			expectedCode:        codes.Internal,
			expectCorrelationID: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			redactedErr := redactor.RedactError(ctx, tc.inputError, "test.Operation", "test-user")

			// Check that error is not nil
			if redactedErr == nil {
				t.Fatal("Expected redacted error, got nil")
			}

			// Check gRPC status code
			st, ok := status.FromError(redactedErr)
			if !ok {
				t.Fatal("Expected gRPC status error")
			}

			if st.Code() != tc.expectedCode {
				t.Errorf("Expected code %v, got %v", tc.expectedCode, st.Code())
			}

			// Check correlation ID presence
			if tc.expectCorrelationID {
				if !IsRedactedError(redactedErr) {
					t.Error("Expected correlation ID in redacted error")
				}

				correlationID := ExtractCorrelationID(redactedErr)
				if correlationID == "" {
					t.Error("Expected non-empty correlation ID")
				}
			}

			// Check that original error details are not exposed
			originalMsg := tc.inputError.Error()
			redactedMsg := redactedErr.Error()

			if redactedMsg == originalMsg {
				t.Errorf("Error message was not redacted: %s", redactedMsg)
			}
		})
	}
}

func TestErrorRedactionPatterns(t *testing.T) {
	config := &ErrorRedactionConfig{
		RedactAllErrors:       false, // Enable pattern-based redaction
		LogDetailedErrors:     false,
		GenerateCorrelationID: false,
		RedactionPatterns: []string{
			`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`, // IP addresses
			`[A-Za-z]:[\\\/][^\\\/\s]+`,         // File paths
		},
	}

	redactor := NewErrorRedactor(config)

	testCases := []struct {
		name             string
		inputMessage     string
		expectedRedacted string
	}{
		{
			name:             "IP address redaction",
			inputMessage:     "Connection failed to 192.168.1.1",
			expectedRedacted: "Connection failed to [REDACTED]",
		},
		{
			name:             "File path redaction",
			inputMessage:     "Failed to read C:\\Users\\admin\\secret.txt",
			expectedRedacted: "Failed to read [REDACTED]",
		},
		{
			name:             "Multiple patterns",
			inputMessage:     "Error reading C:\\config.ini from 10.0.0.1",
			expectedRedacted: "Error reading [REDACTED] from [REDACTED]",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			redacted := redactor.applyRedactionPatterns(tc.inputMessage)

			if redacted != tc.expectedRedacted {
				t.Errorf("Expected %q, got %q", tc.expectedRedacted, redacted)
			}
		})
	}
}

func TestCorrelationIDGeneration(t *testing.T) {
	redactor := NewErrorRedactor(nil)

	// Test that correlation IDs are unique
	id1 := redactor.generateCorrelationID("operation1", "user1")
	id2 := redactor.generateCorrelationID("operation1", "user1")
	id3 := redactor.generateCorrelationID("operation2", "user1")

	if id1 == id2 {
		t.Error("Expected different correlation IDs for same operation")
	}

	if id1 == id3 {
		t.Error("Expected different correlation IDs for different operations")
	}

	// Test ID format (should be hex string)
	if len(id1) != 16 {
		t.Errorf("Expected correlation ID length 16, got %d", len(id1))
	}
}

func TestExtractCorrelationID(t *testing.T) {
	testCases := []struct {
		name         string
		errorMessage string
		expectedID   string
	}{
		{
			name:         "Valid correlation ID",
			errorMessage: "Internal error (correlation_id: abc123def456)",
			expectedID:   "abc123def456",
		},
		{
			name:         "No correlation ID",
			errorMessage: "Internal error",
			expectedID:   "",
		},
		{
			name:         "Malformed correlation ID",
			errorMessage: "Internal error (correlation_id:)",
			expectedID:   "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := errors.New(tc.errorMessage)
			correlationID := ExtractCorrelationID(err)

			if correlationID != tc.expectedID {
				t.Errorf("Expected correlation ID %q, got %q", tc.expectedID, correlationID)
			}
		})
	}
}

func TestErrorStats(t *testing.T) {
	redactor := NewErrorRedactor(nil)
	ctx := context.Background()

	// Generate various errors to test stats
	errors := []error{
		errors.New("authentication failed"),
		errors.New("permission denied"),
		errors.New("authentication failed"), // Duplicate
		errors.New("not found"),
	}

	for _, err := range errors {
		redactor.RedactError(ctx, err, "test.Operation", "test-user")
	}

	stats := redactor.GetErrorStats()

	// Check that stats are tracked
	if len(stats) == 0 {
		t.Error("Expected error stats to be tracked")
	}

	// Check specific counts
	if stats["UNAUTHENTICATED"] != 2 {
		t.Errorf("Expected 2 UNAUTHENTICATED errors, got %d", stats["UNAUTHENTICATED"])
	}

	if stats["PERMISSION_DENIED"] != 1 {
		t.Errorf("Expected 1 PERMISSION_DENIED error, got %d", stats["PERMISSION_DENIED"])
	}

	if stats["NOT_FOUND"] != 1 {
		t.Errorf("Expected 1 NOT_FOUND error, got %d", stats["NOT_FOUND"])
	}
}

func TestPredefinedErrors(t *testing.T) {
	// Test that predefined errors have correct codes
	testCases := []struct {
		name         string
		err          error
		expectedCode codes.Code
	}{
		{
			name:         "AuthenticationRequired",
			err:          ErrAuthenticationRequired,
			expectedCode: codes.Unauthenticated,
		},
		{
			name:         "AccessDenied",
			err:          ErrAccessDenied,
			expectedCode: codes.PermissionDenied,
		},
		{
			name:         "InvalidRequest",
			err:          ErrInvalidRequest,
			expectedCode: codes.InvalidArgument,
		},
		{
			name:         "ResourceNotFound",
			err:          ErrResourceNotFound,
			expectedCode: codes.NotFound,
		},
		{
			name:         "RateLimitExceeded",
			err:          ErrRateLimitExceeded,
			expectedCode: codes.ResourceExhausted,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			st, ok := status.FromError(tc.err)
			if !ok {
				t.Fatal("Expected gRPC status error")
			}

			if st.Code() != tc.expectedCode {
				t.Errorf("Expected code %v, got %v", tc.expectedCode, st.Code())
			}
		})
	}
}
