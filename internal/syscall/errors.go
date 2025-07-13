package syscall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrorRedactionConfig configures how errors are redacted
type ErrorRedactionConfig struct {
	// Enable complete error redaction (production mode)
	RedactAllErrors bool
	
	// Enable detailed error logging for debugging
	LogDetailedErrors bool
	
	// Error correlation ID generation
	GenerateCorrelationID bool
	
	// Patterns to redact from error messages
	RedactionPatterns []string
	
	// Audit logger for security events
	AuditLogger *log.Logger
}

// DefaultErrorRedactionConfig returns a secure default configuration
func DefaultErrorRedactionConfig() *ErrorRedactionConfig {
	return &ErrorRedactionConfig{
		RedactAllErrors:       true,
		LogDetailedErrors:     true,
		GenerateCorrelationID: true,
		RedactionPatterns: []string{
			// Redact file paths
			`[A-Za-z]:[\\\/][^\\\/\s]+`,
			// Redact IP addresses
			`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`,
			// Redact ports
			`:[0-9]{1,5}\b`,
			// Redact connection strings
			`[a-zA-Z]+://[^\s]+`,
			// Redact stack traces
			`at\s+[a-zA-Z0-9_.]+\([^)]+\)`,
			// Redact SQL queries
			`SELECT\s+.+\s+FROM\s+.+`,
			`INSERT\s+INTO\s+.+`,
			`UPDATE\s+.+\s+SET\s+.+`,
			`DELETE\s+FROM\s+.+`,
		},
		AuditLogger: log.New(os.Stdout, "[ERROR_AUDIT] ", log.LstdFlags|log.Lmicroseconds),
	}
}

// ErrorRedactor handles error redaction and mapping
type ErrorRedactor struct {
	config            *ErrorRedactionConfig
	redactionPatterns []*regexp.Regexp
	errorCounter      map[string]int
	auditLogger       *log.Logger
}

// NewErrorRedactor creates a new error redactor
func NewErrorRedactor(config *ErrorRedactionConfig) *ErrorRedactor {
	if config == nil {
		config = DefaultErrorRedactionConfig()
	}
	
	// Compile redaction patterns
	patterns := make([]*regexp.Regexp, len(config.RedactionPatterns))
	for i, pattern := range config.RedactionPatterns {
		patterns[i] = regexp.MustCompile(pattern)
	}
	
	return &ErrorRedactor{
		config:            config,
		redactionPatterns: patterns,
		errorCounter:      make(map[string]int),
		auditLogger:       config.AuditLogger,
	}
}

// RedactError redacts an error and returns a safe external message with gRPC status
func (r *ErrorRedactor) RedactError(ctx context.Context, err error, operation string, userID string) error {
	if err == nil {
		return nil
	}
	
	// Generate correlation ID for tracking
	correlationID := ""
	if r.config.GenerateCorrelationID {
		correlationID = r.generateCorrelationID(operation, userID)
	}
	
	// Get original error details
	originalError := err.Error()
	
	// Map internal error to gRPC status code
	grpcCode := r.mapErrorToGRPCCode(err)
	
	// Generate safe external message
	externalMessage := r.generateSafeMessage(grpcCode, correlationID)
	
	// Log detailed error for debugging (internal only)
	if r.config.LogDetailedErrors {
		r.auditLogger.Printf("Error redacted - correlation_id: %s, operation: %s, user_id: %s, grpc_code: %s, internal_error: %s", 
			correlationID, operation, userID, grpcCode.String(), originalError)
	}
	
	// Track error frequency
	r.trackErrorFrequency(grpcCode.String())
	
	// Apply additional redaction patterns
	if !r.config.RedactAllErrors {
		externalMessage = r.applyRedactionPatterns(originalError)
	}
	
	// Create gRPC status error
	return status.Error(grpcCode, externalMessage)
}

// mapErrorToGRPCCode maps internal errors to appropriate gRPC status codes
func (r *ErrorRedactor) mapErrorToGRPCCode(err error) codes.Code {
	errorStr := strings.ToLower(err.Error())
	
	switch {
	// Authentication errors
	case strings.Contains(errorStr, "unauthorized") || strings.Contains(errorStr, "authentication"):
		return codes.Unauthenticated
	
	// Authorization errors
	case strings.Contains(errorStr, "forbidden") || strings.Contains(errorStr, "permission denied"):
		return codes.PermissionDenied
	
	// Validation errors
	case strings.Contains(errorStr, "invalid") || strings.Contains(errorStr, "validation"):
		return codes.InvalidArgument
	
	// Not found errors
	case strings.Contains(errorStr, "not found") || strings.Contains(errorStr, "does not exist"):
		return codes.NotFound
	
	// Already exists errors
	case strings.Contains(errorStr, "already exists") || strings.Contains(errorStr, "duplicate"):
		return codes.AlreadyExists
	
	// Resource exhaustion
	case strings.Contains(errorStr, "rate limit") || strings.Contains(errorStr, "quota"):
		return codes.ResourceExhausted
	
	// Timeout errors
	case strings.Contains(errorStr, "timeout") || strings.Contains(errorStr, "deadline"):
		return codes.DeadlineExceeded
	
	// Service unavailable
	case strings.Contains(errorStr, "unavailable") || strings.Contains(errorStr, "connection"):
		return codes.Unavailable
	
	// Precondition failures
	case strings.Contains(errorStr, "precondition") || strings.Contains(errorStr, "conflict"):
		return codes.FailedPrecondition
	
	// Out of range errors
	case strings.Contains(errorStr, "out of range") || strings.Contains(errorStr, "bounds"):
		return codes.OutOfRange
	
	// Unimplemented features
	case strings.Contains(errorStr, "not implemented") || strings.Contains(errorStr, "unsupported"):
		return codes.Unimplemented
	
	// Data corruption
	case strings.Contains(errorStr, "corrupted") || strings.Contains(errorStr, "checksum"):
		return codes.DataLoss
	
	// Default to internal error
	default:
		return codes.Internal
	}
}

// generateSafeMessage generates a safe external error message
func (r *ErrorRedactor) generateSafeMessage(code codes.Code, correlationID string) string {
	base := ""
	
	switch code {
	case codes.Unauthenticated:
		base = "Authentication required"
	case codes.PermissionDenied:
		base = "Access denied"
	case codes.InvalidArgument:
		base = "Invalid request parameters"
	case codes.NotFound:
		base = "Resource not found"
	case codes.AlreadyExists:
		base = "Resource already exists"
	case codes.ResourceExhausted:
		base = "Rate limit exceeded"
	case codes.DeadlineExceeded:
		base = "Request timeout"
	case codes.Unavailable:
		base = "Service temporarily unavailable"
	case codes.FailedPrecondition:
		base = "Precondition failed"
	case codes.OutOfRange:
		base = "Value out of range"
	case codes.Unimplemented:
		base = "Feature not implemented"
	case codes.DataLoss:
		base = "Data integrity error"
	default:
		base = "Internal server error"
	}
	
	if correlationID != "" {
		return fmt.Sprintf("%s (correlation_id: %s)", base, correlationID)
	}
	
	return base
}

// applyRedactionPatterns applies redaction patterns to error message
func (r *ErrorRedactor) applyRedactionPatterns(message string) string {
	redacted := message
	
	for _, pattern := range r.redactionPatterns {
		redacted = pattern.ReplaceAllString(redacted, "[REDACTED]")
	}
	
	return redacted
}

// generateCorrelationID generates a unique correlation ID for error tracking
func (r *ErrorRedactor) generateCorrelationID(operation, userID string) string {
	timestamp := time.Now().UnixNano()
	data := fmt.Sprintf("%s:%s:%d", operation, userID, timestamp)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])[:16] // First 16 characters
}

// trackErrorFrequency tracks error frequency for monitoring
func (r *ErrorRedactor) trackErrorFrequency(errorType string) {
	if r.errorCounter == nil {
		r.errorCounter = make(map[string]int)
	}
	r.errorCounter[errorType]++
}

// GetErrorStats returns error statistics
func (r *ErrorRedactor) GetErrorStats() map[string]int {
	return r.errorCounter
}

// SecurityAuditError logs security-related errors
func (r *ErrorRedactor) SecurityAuditError(ctx context.Context, operation, userID, clientIP, reason string) {
	if r.auditLogger != nil {
		r.auditLogger.Printf("SECURITY_VIOLATION - operation: %s, user_id: %s, client_ip: %s, reason: %s", 
			operation, userID, clientIP, reason)
	}
}

// IsRedactedError checks if an error has been redacted
func IsRedactedError(err error) bool {
	if err == nil {
		return false
	}
	
	return strings.Contains(err.Error(), "correlation_id:")
}

// ExtractCorrelationID extracts correlation ID from a redacted error
func ExtractCorrelationID(err error) string {
	if err == nil {
		return ""
	}
	
	message := err.Error()
	pattern := regexp.MustCompile(`correlation_id:\s*([a-f0-9]+)`)
	matches := pattern.FindStringSubmatch(message)
	
	if len(matches) > 1 {
		return matches[1]
	}
	
	return ""
}

// Predefined error types for common scenarios
var (
	ErrAuthenticationRequired = status.Error(codes.Unauthenticated, "Authentication required")
	ErrAccessDenied          = status.Error(codes.PermissionDenied, "Access denied")
	ErrInvalidRequest        = status.Error(codes.InvalidArgument, "Invalid request parameters")
	ErrResourceNotFound      = status.Error(codes.NotFound, "Resource not found")
	ErrResourceExists        = status.Error(codes.AlreadyExists, "Resource already exists")
	ErrRateLimitExceeded     = status.Error(codes.ResourceExhausted, "Rate limit exceeded")
	ErrRequestTimeout        = status.Error(codes.DeadlineExceeded, "Request timeout")
	ErrServiceUnavailable    = status.Error(codes.Unavailable, "Service temporarily unavailable")
	ErrPreconditionFailed    = status.Error(codes.FailedPrecondition, "Precondition failed")
	ErrValueOutOfRange       = status.Error(codes.OutOfRange, "Value out of range")
	ErrNotImplemented        = status.Error(codes.Unimplemented, "Feature not implemented")
	ErrDataIntegrity         = status.Error(codes.DataLoss, "Data integrity error")
	ErrInternalServer        = status.Error(codes.Internal, "Internal server error")
)

// ErrorRedactionMiddleware provides gRPC middleware for error redaction
func ErrorRedactionMiddleware(redactor *ErrorRedactor) func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Extract user ID from context (if available)
		userID := ExtractUserIDFromContext(ctx)
		
		// Call the handler
		resp, err := handler(ctx, req)
		
		// Redact error if present
		if err != nil {
			err = redactor.RedactError(ctx, err, info.FullMethod, userID)
		}
		
		return resp, err
	}
}

// ExtractUserIDFromContext extracts user ID from gRPC context
func ExtractUserIDFromContext(ctx context.Context) string {
	// This would typically extract from JWT claims or metadata
	// For now, return empty string if not available
	return ""
} 
} 