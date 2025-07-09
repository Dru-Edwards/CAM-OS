package syscall

import (
	"fmt"
	"log"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ValidationError represents input validation errors
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}

// NewValidationError creates a new validation error
func NewValidationError(format string, args ...interface{}) *ValidationError {
	return &ValidationError{
		Message: fmt.Sprintf(format, args...),
	}
}

// ErrorSanitizer handles secure error responses
type ErrorSanitizer struct {
	redactDetails bool
	auditLogger   *log.Logger
}

// NewErrorSanitizer creates a new error sanitizer
func NewErrorSanitizer(redactDetails bool, auditLogger *log.Logger) *ErrorSanitizer {
	return &ErrorSanitizer{
		redactDetails: redactDetails,
		auditLogger:   auditLogger,
	}
}

// SanitizeError converts internal errors to safe public errors
func (es *ErrorSanitizer) SanitizeError(err error, operation string, callerID string) (codes.Code, string) {
	if err == nil {
		return codes.OK, ""
	}

	// Log full error details for internal debugging
	if es.auditLogger != nil {
		es.auditLogger.Printf("[ERROR] Operation=%s CallerID=%s Error=%v", operation, callerID, err)
	}

	// Handle specific error types
	switch e := err.(type) {
	case *ValidationError:
		return codes.InvalidArgument, e.Message

	default:
		// For unknown errors, check if it's a known safe pattern
		errMsg := err.Error()
		
		// Safe error patterns that can be returned as-is
		safePatterns := []string{
			"not found",
			"already exists",
			"permission denied",
			"invalid format",
			"timeout exceeded",
			"quota exceeded",
			"service unavailable",
		}
		
		for _, pattern := range safePatterns {
			if strings.Contains(strings.ToLower(errMsg), pattern) {
				return codes.Internal, errMsg
			}
		}
		
		// If redaction is enabled, return generic error
		if es.redactDetails {
			return codes.Internal, "internal server error"
		}
		
		// Otherwise return the original error (for development)
		return codes.Internal, errMsg
	}
}

// MapToGRPCStatus converts an error to a gRPC status
func (es *ErrorSanitizer) MapToGRPCStatus(err error, operation string, callerID string) error {
	if err == nil {
		return nil
	}

	code, message := es.SanitizeError(err, operation, callerID)
	return status.Error(code, message)
}

// Common error constructors for consistent error handling
func NewTimeoutError(operation string) error {
	return fmt.Errorf("timeout exceeded for operation: %s", operation)
}

func NewNotFoundError(resource string, id string) error {
	return fmt.Errorf("%s not found: %s", resource, id)
}

func NewAlreadyExistsError(resource string, id string) error {
	return fmt.Errorf("%s already exists: %s", resource, id)
}

func NewQuotaExceededError(resource string, limit interface{}) error {
	return fmt.Errorf("quota exceeded for %s: limit %v", resource, limit)
}

func NewPermissionDeniedError(operation string, resource string) error {
	return fmt.Errorf("permission denied for %s on %s", operation, resource)
}

func NewInvalidFormatError(field string, expected string) error {
	return fmt.Errorf("invalid format for %s: expected %s", field, expected)
}

func NewServiceUnavailableError(service string) error {
	return fmt.Errorf("service unavailable: %s", service)
} 