package backends

import (
	"context"
	"fmt"
	"time"
)

// ContextData represents data stored in the context backend
type ContextData struct {
	Data      []byte
	Version   int64
	Hash      string
	Timestamp time.Time
	Metadata  map[string]string
}

// WriteResult represents the result of a write operation
type WriteResult struct {
	Version int64
	Hash    string
}

// Backend defines the interface for pluggable context storage backends
type Backend interface {
	// Core operations
	Initialize(ctx context.Context) error
	Shutdown(ctx context.Context) error
	
	// Data operations
	Read(ctx context.Context, namespace, key string, version int64) (*ContextData, error)
	Write(ctx context.Context, namespace, key string, data []byte, metadata map[string]string) (*WriteResult, error)
	Delete(ctx context.Context, namespace, key string, version int64) error
	
	// Namespace operations
	CreateNamespace(ctx context.Context, namespace string) error
	DeleteNamespace(ctx context.Context, namespace string) error
	ListNamespaces(ctx context.Context) ([]string, error)
	
	// Versioning operations
	ListVersions(ctx context.Context, namespace, key string) ([]int64, error)
	GetVersion(ctx context.Context, namespace, key string, version int64) (*ContextData, error)
	
	// Snapshot operations
	CreateSnapshot(ctx context.Context, namespace, description string) (string, error)
	RestoreSnapshot(ctx context.Context, snapshotID string, force bool) error
	ListSnapshots(ctx context.Context, namespace string) ([]SnapshotInfo, error)
	DeleteSnapshot(ctx context.Context, snapshotID string) error
	
	// Bulk operations
	BatchWrite(ctx context.Context, operations []WriteOperation) ([]WriteResult, error)
	BatchRead(ctx context.Context, operations []ReadOperation) ([]ReadResult, error)
	
	// Health and metrics
	HealthCheck(ctx context.Context) error
	GetMetrics(ctx context.Context) (*BackendMetrics, error)
}

// WriteOperation represents a batch write operation
type WriteOperation struct {
	Namespace string
	Key       string
	Data      []byte
	Metadata  map[string]string
}

// ReadOperation represents a batch read operation
type ReadOperation struct {
	Namespace string
	Key       string
	Version   int64
}

// ReadResult represents the result of a read operation
type ReadResult struct {
	Data  *ContextData
	Error error
}

// SnapshotInfo represents information about a snapshot
type SnapshotInfo struct {
	ID          string
	Namespace   string
	Description string
	Timestamp   time.Time
	Size        int64
	Hash        string
	Compressed  bool
}

// BackendMetrics represents backend performance metrics
type BackendMetrics struct {
	TotalReads       int64
	TotalWrites      int64
	TotalSnapshots   int64
	CacheHits        int64
	CacheMisses      int64
	ErrorCount       int64
	AvgLatency       time.Duration
	CompressionRatio float64
	StorageUsed      int64
	ConnectionCount  int64
}

// BackendConfig represents configuration for a backend
type BackendConfig struct {
	Type            string            // "redis", "foundationdb", "scylla", "memory"
	ConnectionString string           // Backend-specific connection string
	Options         map[string]string // Backend-specific options
	
	// Common options
	MaxConnections   int
	ConnectionTimeout time.Duration
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration
	
	// Performance options
	CompressionEnabled bool
	EncryptionEnabled  bool
	BatchSize         int
	
	// Retention options
	TTL               time.Duration
	SnapshotRetention time.Duration
	VersionRetention  int
}

// BackendFactory creates backend instances
type BackendFactory interface {
	CreateBackend(config *BackendConfig) (Backend, error)
	SupportedTypes() []string
}

// Registry holds all registered backend factories
type Registry struct {
	factories map[string]BackendFactory
}

// NewRegistry creates a new backend registry
func NewRegistry() *Registry {
	return &Registry{
		factories: make(map[string]BackendFactory),
	}
}

// Register registers a backend factory
func (r *Registry) Register(backendType string, factory BackendFactory) {
	r.factories[backendType] = factory
}

// CreateBackend creates a backend instance
func (r *Registry) CreateBackend(config *BackendConfig) (Backend, error) {
	factory, exists := r.factories[config.Type]
	if !exists {
		return nil, fmt.Errorf("unsupported backend type: %s", config.Type)
	}
	
	return factory.CreateBackend(config)
}

// GetSupportedTypes returns all supported backend types
func (r *Registry) GetSupportedTypes() []string {
	var types []string
	for backendType := range r.factories {
		types = append(types, backendType)
	}
	return types
}

// Default registry instance
var DefaultRegistry = NewRegistry() 