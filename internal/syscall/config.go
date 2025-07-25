package syscall

import (
	"regexp"
	"time"

	"github.com/cam-os/kernel/internal/validation"
)

// Config holds the syscall dispatcher configuration with security and performance settings
type Config struct {
	// Component dependencies
	ArbitrationEngine    interface{}
	MemoryManager        interface{}
	PolicyEngine         interface{}
	SecurityManager      interface{}
	ExplainabilityEngine interface{}

	// Timeout settings
	SyscallTimeout        time.Duration `yaml:"syscall_timeout" default:"500ms"`
	ArbitrationTimeout    time.Duration `yaml:"arbitration_timeout" default:"100ms"`
	MemoryTimeout         time.Duration `yaml:"memory_timeout" default:"50ms"`
	SecurityTimeout       time.Duration `yaml:"security_timeout" default:"200ms"`
	ExplainabilityTimeout time.Duration `yaml:"explainability_timeout" default:"75ms"`

	// Rate limiting
	MaxRequestsPerSecond int `yaml:"max_requests_per_second" default:"1000"`
	BurstSize            int `yaml:"burst_size" default:"100"`

	// Validation settings
	MaxNamespaceLength int `yaml:"max_namespace_length" default:"64"`
	MaxKeyLength       int `yaml:"max_key_length" default:"256"`
	MaxPayloadSize     int `yaml:"max_payload_size" default:"1048576"` // 1MB

	// Security settings
	RequireMTLS        bool `yaml:"require_mtls" default:"true"`
	EnableAuditLogging bool `yaml:"enable_audit_logging" default:"true"`
	RedactErrorDetails bool `yaml:"redact_error_details" default:"true"`
}

// DefaultConfig returns a configuration with secure defaults
func DefaultConfig() *Config {
	return &Config{
		SyscallTimeout:        500 * time.Millisecond,
		ArbitrationTimeout:    100 * time.Millisecond,
		MemoryTimeout:         50 * time.Millisecond,
		SecurityTimeout:       200 * time.Millisecond,
		ExplainabilityTimeout: 75 * time.Millisecond,
		MaxRequestsPerSecond:  1000,
		BurstSize:             100,
		MaxNamespaceLength:    64,
		MaxKeyLength:          256,
		MaxPayloadSize:        1048576, // 1MB
		RequireMTLS:           true,
		EnableAuditLogging:    true,
		RedactErrorDetails:    true,
	}
}

// Validation patterns
var (
	// NamespacePattern validates namespace strings: alphanumeric, underscore, hyphen, 1-64 chars
	NamespacePattern = regexp.MustCompile(`^[a-z0-9_\-]{1,64}$`)

	// KeyPattern validates key strings: alphanumeric, underscore, hyphen, dot, slash, 1-256 chars
	KeyPattern = regexp.MustCompile(`^[a-zA-Z0-9_\-\./]{1,256}$`)

	// AgentIDPattern validates agent IDs: alphanumeric, underscore, hyphen, 1-128 chars
	AgentIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_\-]{1,128}$`)
)

// ValidateNamespace validates a namespace string
func (c *Config) ValidateNamespace(namespace string) error {
	return validation.ValidateNamespace(namespace)
}

// ValidateKey validates a key string
func (c *Config) ValidateKey(key string) error {
	return validation.ValidateKey(key)
}

// ValidateAgentID validates an agent ID string
func (c *Config) ValidateAgentID(agentID string) error {
	return validation.ValidateAgentID(agentID)
}

// ValidatePayloadSize validates payload size
func (c *Config) ValidatePayloadSize(size int) error {
	if size > c.MaxPayloadSize {
		return NewValidationError("payload too large (max %d bytes)", c.MaxPayloadSize)
	}
	return nil
}
