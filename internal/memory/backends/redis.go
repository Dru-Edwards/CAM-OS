package backends

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/pierrec/lz4/v4"
)

// RedisBackend implements the Backend interface using Redis
type RedisBackend struct {
	client *redis.Client
	config *BackendConfig

	// Metrics
	metrics *BackendMetrics
}

// RedisFactory creates Redis backend instances
type RedisFactory struct{}

// CreateBackend creates a new Redis backend
func (f *RedisFactory) CreateBackend(config *BackendConfig) (Backend, error) {
	// Parse Redis connection string
	opts, err := redis.ParseURL(config.ConnectionString)
	if err != nil {
		return nil, fmt.Errorf("invalid Redis connection string: %v", err)
	}

	// Apply configuration overrides
	if config.ConnectionTimeout > 0 {
		opts.DialTimeout = config.ConnectionTimeout
	}
	if config.ReadTimeout > 0 {
		opts.ReadTimeout = config.ReadTimeout
	}
	if config.WriteTimeout > 0 {
		opts.WriteTimeout = config.WriteTimeout
	}
	if config.MaxConnections > 0 {
		opts.PoolSize = config.MaxConnections
	}

	client := redis.NewClient(opts)

	return &RedisBackend{
		client:  client,
		config:  config,
		metrics: &BackendMetrics{},
	}, nil
}

// SupportedTypes returns the supported backend types
func (f *RedisFactory) SupportedTypes() []string {
	return []string{"redis"}
}

// Initialize initializes the Redis backend
func (r *RedisBackend) Initialize(ctx context.Context) error {
	// Test connection
	if err := r.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("failed to connect to Redis: %v", err)
	}

	return nil
}

// Shutdown shuts down the Redis backend
func (r *RedisBackend) Shutdown(ctx context.Context) error {
	return r.client.Close()
}

// Read reads data from Redis
func (r *RedisBackend) Read(ctx context.Context, namespace, key string, version int64) (*ContextData, error) {
	start := time.Now()
	defer func() {
		r.metrics.AvgLatency = time.Since(start)
		r.metrics.TotalReads++
	}()

	// Construct Redis key
	var redisKey string
	if version == 0 {
		redisKey = fmt.Sprintf("ctx:%s:%s:latest", namespace, key)
	} else {
		redisKey = fmt.Sprintf("ctx:%s:%s:%d", namespace, key, version)
	}

	// Get from Redis
	data, err := r.client.Get(ctx, redisKey).Bytes()
	if err != nil {
		if err == redis.Nil {
			r.metrics.CacheMisses++
			return nil, fmt.Errorf("key not found: %s", key)
		}
		r.metrics.ErrorCount++
		return nil, fmt.Errorf("failed to read from Redis: %v", err)
	}

	r.metrics.CacheHits++

	// Deserialize data
	var contextData ContextData
	if err := json.Unmarshal(data, &contextData); err != nil {
		r.metrics.ErrorCount++
		return nil, fmt.Errorf("failed to deserialize data: %v", err)
	}

	// Decompress if needed
	if r.config.CompressionEnabled && len(contextData.Data) > 0 {
		decompressed, err := r.decompress(contextData.Data)
		if err != nil {
			r.metrics.ErrorCount++
			return nil, fmt.Errorf("failed to decompress data: %v", err)
		}
		contextData.Data = decompressed
	}

	return &contextData, nil
}

// Write writes data to Redis
func (r *RedisBackend) Write(ctx context.Context, namespace, key string, data []byte, metadata map[string]string) (*WriteResult, error) {
	start := time.Now()
	defer func() {
		r.metrics.AvgLatency = time.Since(start)
		r.metrics.TotalWrites++
	}()

	// Generate version (timestamp-based)
	version := time.Now().UnixNano()

	// Calculate hash
	hash := sha256.Sum256(data)
	hashStr := hex.EncodeToString(hash[:])

	// Compress data if enabled
	dataToStore := data
	if r.config.CompressionEnabled {
		compressed, err := r.compress(data)
		if err != nil {
			r.metrics.ErrorCount++
			return nil, fmt.Errorf("failed to compress data: %v", err)
		}
		dataToStore = compressed
		r.metrics.CompressionRatio = float64(len(compressed)) / float64(len(data))
	}

	// Create context data
	contextData := ContextData{
		Data:      dataToStore,
		Version:   version,
		Hash:      hashStr,
		Timestamp: time.Now(),
		Metadata:  metadata,
	}

	// Serialize data
	serialized, err := json.Marshal(contextData)
	if err != nil {
		r.metrics.ErrorCount++
		return nil, fmt.Errorf("failed to serialize data: %v", err)
	}

	// Store in Redis with TTL
	redisKey := fmt.Sprintf("ctx:%s:%s:%d", namespace, key, version)
	if err := r.client.Set(ctx, redisKey, serialized, r.config.TTL).Err(); err != nil {
		r.metrics.ErrorCount++
		return nil, fmt.Errorf("failed to write to Redis: %v", err)
	}

	// Update latest pointer
	latestKey := fmt.Sprintf("ctx:%s:%s:latest", namespace, key)
	if err := r.client.Set(ctx, latestKey, serialized, r.config.TTL).Err(); err != nil {
		r.metrics.ErrorCount++
		return nil, fmt.Errorf("failed to update latest pointer: %v", err)
	}

	// Store version metadata
	versionKey := fmt.Sprintf("ctx:%s:%s:versions", namespace, key)
	versionInfo := map[string]interface{}{
		"version":   version,
		"hash":      hashStr,
		"timestamp": time.Now().Unix(),
		"size":      len(data),
	}
	versionData, _ := json.Marshal(versionInfo)
	if err := r.client.LPush(ctx, versionKey, versionData).Err(); err != nil {
		r.metrics.ErrorCount++
		return nil, fmt.Errorf("failed to store version metadata: %v", err)
	}

	// Limit version history
	if r.config.VersionRetention > 0 {
		r.client.LTrim(ctx, versionKey, 0, int64(r.config.VersionRetention-1))
	}

	return &WriteResult{
		Version: version,
		Hash:    hashStr,
	}, nil
}

// Delete deletes data from Redis
func (r *RedisBackend) Delete(ctx context.Context, namespace, key string, version int64) error {
	var redisKey string
	if version == 0 {
		// Delete all versions
		pattern := fmt.Sprintf("ctx:%s:%s:*", namespace, key)
		keys, err := r.client.Keys(ctx, pattern).Result()
		if err != nil {
			return fmt.Errorf("failed to get keys for deletion: %v", err)
		}

		if len(keys) > 0 {
			return r.client.Del(ctx, keys...).Err()
		}
		return nil
	} else {
		redisKey = fmt.Sprintf("ctx:%s:%s:%d", namespace, key, version)
		return r.client.Del(ctx, redisKey).Err()
	}
}

// CreateNamespace creates a namespace (Redis doesn't need explicit namespace creation)
func (r *RedisBackend) CreateNamespace(ctx context.Context, namespace string) error {
	// Redis doesn't require explicit namespace creation
	// Just store namespace metadata
	namespaceKey := fmt.Sprintf("ns:%s:metadata", namespace)
	metadata := map[string]interface{}{
		"created_at": time.Now().Unix(),
		"name":       namespace,
	}

	data, _ := json.Marshal(metadata)
	return r.client.Set(ctx, namespaceKey, data, 0).Err() // No TTL for namespace metadata
}

// DeleteNamespace deletes a namespace and all its data
func (r *RedisBackend) DeleteNamespace(ctx context.Context, namespace string) error {
	// Get all keys in namespace
	pattern := fmt.Sprintf("ctx:%s:*", namespace)
	keys, err := r.client.Keys(ctx, pattern).Result()
	if err != nil {
		return fmt.Errorf("failed to get namespace keys: %v", err)
	}

	// Add namespace metadata key
	keys = append(keys, fmt.Sprintf("ns:%s:metadata", namespace))

	if len(keys) > 0 {
		return r.client.Del(ctx, keys...).Err()
	}

	return nil
}

// ListNamespaces lists all namespaces
func (r *RedisBackend) ListNamespaces(ctx context.Context) ([]string, error) {
	pattern := "ns:*:metadata"
	keys, err := r.client.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get namespace keys: %v", err)
	}

	var namespaces []string
	for _, key := range keys {
		// Extract namespace from key: ns:namespace:metadata
		parts := strings.Split(key, ":")
		if len(parts) >= 2 {
			namespaces = append(namespaces, parts[1])
		}
	}

	return namespaces, nil
}

// ListVersions lists all versions for a key
func (r *RedisBackend) ListVersions(ctx context.Context, namespace, key string) ([]int64, error) {
	versionKey := fmt.Sprintf("ctx:%s:%s:versions", namespace, key)
	versionData, err := r.client.LRange(ctx, versionKey, 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get versions: %v", err)
	}

	var versions []int64
	for _, data := range versionData {
		var versionInfo map[string]interface{}
		if err := json.Unmarshal([]byte(data), &versionInfo); err != nil {
			continue
		}

		if versionFloat, ok := versionInfo["version"].(float64); ok {
			versions = append(versions, int64(versionFloat))
		}
	}

	return versions, nil
}

// GetVersion gets a specific version
func (r *RedisBackend) GetVersion(ctx context.Context, namespace, key string, version int64) (*ContextData, error) {
	return r.Read(ctx, namespace, key, version)
}

// CreateSnapshot creates a snapshot of a namespace
func (r *RedisBackend) CreateSnapshot(ctx context.Context, namespace, description string) (string, error) {
	defer func() {
		r.metrics.TotalSnapshots++
	}()

	// Generate snapshot ID
	snapshotID := fmt.Sprintf("snap_%s_%d", namespace, time.Now().UnixNano())

	// Get all keys in namespace
	pattern := fmt.Sprintf("ctx:%s:*", namespace)
	keys, err := r.client.Keys(ctx, pattern).Result()
	if err != nil {
		return "", fmt.Errorf("failed to get keys: %v", err)
	}

	// Create snapshot data
	snapshotData := make(map[string]interface{})
	totalSize := int64(0)

	for _, key := range keys {
		// Skip version metadata and latest pointers for now
		if strings.Contains(key, ":versions") || strings.Contains(key, ":latest") {
			continue
		}

		data, err := r.client.Get(ctx, key).Bytes()
		if err != nil {
			continue // Skip failed keys
		}

		snapshotData[key] = data
		totalSize += int64(len(data))
	}

	// Serialize snapshot
	serialized, err := json.Marshal(snapshotData)
	if err != nil {
		return "", fmt.Errorf("failed to serialize snapshot: %v", err)
	}

	// Compress snapshot
	compressed, err := r.compress(serialized)
	if err != nil {
		return "", fmt.Errorf("failed to compress snapshot: %v", err)
	}

	// Calculate hash
	hash := sha256.Sum256(compressed)
	hashStr := hex.EncodeToString(hash[:])

	// Store snapshot
	snapshotKey := fmt.Sprintf("snapshot:%s", snapshotID)
	if err := r.client.Set(ctx, snapshotKey, compressed, r.config.SnapshotRetention).Err(); err != nil {
		return "", fmt.Errorf("failed to store snapshot: %v", err)
	}

	// Store snapshot metadata
	snapshotInfo := SnapshotInfo{
		ID:          snapshotID,
		Namespace:   namespace,
		Description: description,
		Timestamp:   time.Now(),
		Size:        totalSize,
		Hash:        hashStr,
		Compressed:  true,
	}

	metadataKey := fmt.Sprintf("snapshot:%s:metadata", snapshotID)
	metadataData, _ := json.Marshal(snapshotInfo)
	if err := r.client.Set(ctx, metadataKey, metadataData, r.config.SnapshotRetention).Err(); err != nil {
		return "", fmt.Errorf("failed to store snapshot metadata: %v", err)
	}

	return snapshotID, nil
}

// RestoreSnapshot restores a snapshot
func (r *RedisBackend) RestoreSnapshot(ctx context.Context, snapshotID string, force bool) error {
	// Get snapshot data
	snapshotKey := fmt.Sprintf("snapshot:%s", snapshotID)
	compressed, err := r.client.Get(ctx, snapshotKey).Bytes()
	if err != nil {
		if err == redis.Nil {
			return fmt.Errorf("snapshot not found: %s", snapshotID)
		}
		return fmt.Errorf("failed to get snapshot: %v", err)
	}

	// Get snapshot metadata
	metadataKey := fmt.Sprintf("snapshot:%s:metadata", snapshotID)
	metadataData, err := r.client.Get(ctx, metadataKey).Bytes()
	if err != nil {
		return fmt.Errorf("failed to get snapshot metadata: %v", err)
	}

	var snapshotInfo SnapshotInfo
	if err := json.Unmarshal(metadataData, &snapshotInfo); err != nil {
		return fmt.Errorf("failed to deserialize snapshot metadata: %v", err)
	}

	// Decompress snapshot
	decompressed, err := r.decompress(compressed)
	if err != nil {
		return fmt.Errorf("failed to decompress snapshot: %v", err)
	}

	// Deserialize snapshot data
	var snapshotData map[string]interface{}
	if err := json.Unmarshal(decompressed, &snapshotData); err != nil {
		return fmt.Errorf("failed to deserialize snapshot data: %v", err)
	}

	// Clear existing namespace data if force is true
	if force {
		if err := r.DeleteNamespace(ctx, snapshotInfo.Namespace); err != nil {
			return fmt.Errorf("failed to clear namespace: %v", err)
		}
	}

	// Restore data
	for key, data := range snapshotData {
		dataBytes, ok := data.([]byte)
		if !ok {
			// Try to convert from interface{}
			if dataStr, ok := data.(string); ok {
				dataBytes = []byte(dataStr)
			} else {
				continue // Skip invalid data
			}
		}

		if err := r.client.Set(ctx, key, dataBytes, r.config.TTL).Err(); err != nil {
			continue // Skip failed keys
		}
	}

	return nil
}

// ListSnapshots lists snapshots for a namespace
func (r *RedisBackend) ListSnapshots(ctx context.Context, namespace string) ([]SnapshotInfo, error) {
	pattern := fmt.Sprintf("snapshot:snap_%s_*:metadata", namespace)
	keys, err := r.client.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get snapshot keys: %v", err)
	}

	var snapshots []SnapshotInfo
	for _, key := range keys {
		data, err := r.client.Get(ctx, key).Bytes()
		if err != nil {
			continue
		}

		var snapshotInfo SnapshotInfo
		if err := json.Unmarshal(data, &snapshotInfo); err != nil {
			continue
		}

		snapshots = append(snapshots, snapshotInfo)
	}

	return snapshots, nil
}

// DeleteSnapshot deletes a snapshot
func (r *RedisBackend) DeleteSnapshot(ctx context.Context, snapshotID string) error {
	snapshotKey := fmt.Sprintf("snapshot:%s", snapshotID)
	metadataKey := fmt.Sprintf("snapshot:%s:metadata", snapshotID)

	return r.client.Del(ctx, snapshotKey, metadataKey).Err()
}

// BatchWrite performs batch write operations
func (r *RedisBackend) BatchWrite(ctx context.Context, operations []WriteOperation) ([]WriteResult, error) {
	results := make([]WriteResult, len(operations))

	for i, op := range operations {
		result, err := r.Write(ctx, op.Namespace, op.Key, op.Data, op.Metadata)
		if err != nil {
			results[i] = WriteResult{Version: -1, Hash: ""} // Error marker
		} else {
			results[i] = *result
		}
	}

	return results, nil
}

// BatchRead performs batch read operations
func (r *RedisBackend) BatchRead(ctx context.Context, operations []ReadOperation) ([]ReadResult, error) {
	results := make([]ReadResult, len(operations))

	for i, op := range operations {
		data, err := r.Read(ctx, op.Namespace, op.Key, op.Version)
		results[i] = ReadResult{
			Data:  data,
			Error: err,
		}
	}

	return results, nil
}

// HealthCheck checks the health of the Redis backend
func (r *RedisBackend) HealthCheck(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

// GetMetrics returns backend metrics
func (r *RedisBackend) GetMetrics(ctx context.Context) (*BackendMetrics, error) {
	// Get Redis info
	info, err := r.client.Info(ctx, "memory").Result()
	if err == nil {
		// Parse memory usage from info
		lines := strings.Split(info, "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "used_memory:") {
				if memStr := strings.TrimPrefix(line, "used_memory:"); memStr != "" {
					if mem, err := strconv.ParseInt(strings.TrimSpace(memStr), 10, 64); err == nil {
						r.metrics.StorageUsed = mem
					}
				}
			}
		}
	}

	return r.metrics, nil
}

// Helper methods for compression
func (r *RedisBackend) compress(data []byte) ([]byte, error) {
	if !r.config.CompressionEnabled {
		return data, nil
	}

	var compressed []byte
	if _, err := lz4.CompressBlock(data, compressed, nil); err != nil {
		return nil, err
	}

	return compressed, nil
}

func (r *RedisBackend) decompress(data []byte) ([]byte, error) {
	if !r.config.CompressionEnabled {
		return data, nil
	}

	var decompressed []byte
	if _, err := lz4.UncompressBlock(data, decompressed); err != nil {
		return nil, err
	}

	return decompressed, nil
}

// Register Redis backend factory
func init() {
	DefaultRegistry.Register("redis", &RedisFactory{})
}
