package validation

import (
	"fmt"
	"regexp"
	"strings"
)

// Validation patterns for namespace and key format
var (
	// NamespacePattern validates namespace strings: alphanumeric, underscore, hyphen, 1-64 chars
	NamespacePattern = regexp.MustCompile(`^[a-z0-9_\-]{1,64}$`)
	
	// KeyPattern validates key strings: alphanumeric, underscore, hyphen, dot, slash, 1-256 chars
	KeyPattern = regexp.MustCompile(`^[a-zA-Z0-9_\-\./]{1,256}$`)
	
	// AgentIDPattern validates agent IDs: alphanumeric, underscore, hyphen, 1-128 chars
	AgentIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_\-]{1,128}$`)
)

// ValidationError represents a validation error
type ValidationError struct {
	message string
}

func (e *ValidationError) Error() string {
	return e.message
}

// NewValidationError creates a new validation error
func NewValidationError(format string, args ...interface{}) error {
	return &ValidationError{
		message: fmt.Sprintf(format, args...),
	}
}

// ValidateNamespace validates a namespace string to prevent directory traversal attacks
func ValidateNamespace(namespace string) error {
	if len(namespace) == 0 {
		return NewValidationError("namespace cannot be empty")
	}
	if len(namespace) > 64 {
		return NewValidationError("namespace too long (max 64 chars)")
	}
	
	// Check regex pattern
	if !NamespacePattern.MatchString(namespace) {
		return NewValidationError("namespace contains invalid characters (allowed: a-z, 0-9, _, -)")
	}
	
	// Additional security checks for directory traversal
	if strings.Contains(namespace, "..") {
		return NewValidationError("directory traversal detected in namespace")
	}
	
	if strings.Contains(namespace, "/") || strings.HasPrefix(namespace, ".") {
		return NewValidationError("namespace contains invalid path characters")
	}
	
	// Check for null bytes or control characters
	for _, char := range namespace {
		if char < 32 || char == 127 {
			return NewValidationError("namespace contains control characters")
		}
	}
	
	return nil
}

// ValidateKey validates a key string to prevent directory traversal attacks
func ValidateKey(key string) error {
	if len(key) == 0 {
		return NewValidationError("key cannot be empty")
	}
	if len(key) > 256 {
		return NewValidationError("key too long (max 256 chars)")
	}
	
	// Check regex pattern
	if !KeyPattern.MatchString(key) {
		return NewValidationError("key contains invalid characters (allowed: a-z, A-Z, 0-9, _, -, ., /)")
	}
	
	// Additional security checks for directory traversal
	if strings.Contains(key, "..") {
		return NewValidationError("directory traversal detected in key")
	}
	
	// Check for null bytes or control characters
	for _, char := range key {
		if char < 32 || char == 127 {
			return NewValidationError("key contains control characters")
		}
	}
	
	return nil
}

// ValidateAgentID validates an agent ID string
func ValidateAgentID(agentID string) error {
	if len(agentID) == 0 {
		return NewValidationError("agent_id cannot be empty")
	}
	if len(agentID) > 128 {
		return NewValidationError("agent_id too long (max 128 chars)")
	}
	if !AgentIDPattern.MatchString(agentID) {
		return NewValidationError("agent_id contains invalid characters (allowed: a-z, A-Z, 0-9, _, -)")
	}
	return nil
}

// ValidateNamespaceAndKey validates both namespace and key format
func ValidateNamespaceAndKey(namespace, key string) error {
	if err := ValidateNamespace(namespace); err != nil {
		return fmt.Errorf("invalid namespace: %v", err)
	}
	
	if err := ValidateKey(key); err != nil {
		return fmt.Errorf("invalid key: %v", err)
	}
	
	return nil
} 