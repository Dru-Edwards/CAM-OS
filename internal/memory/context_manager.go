package memory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/pierrec/lz4/v4"
)

// ContextData represents data stored in the context manager
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

// RestoreResult represents the result of a restore operation
type RestoreResult struct {
	Namespace     string
	RestoredItems int64
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

// VersionInfo represents version metadata - Enhanced for fork expansion
type VersionInfo struct {
	Version     int64
	Timestamp   time.Time
	Author      string
	Description string
	Hash        string
	Size        int64
	Tags        map[string]string
}

// Config holds the context manager configuration - Enhanced for CAM-OS Fork
type Config struct {
	RedisAddr           string
	RedisPassword       string
	RedisDB             int
	MaxNamespaces       int
	MaxContextSize      int64
	TTL                 time.Duration
	CompressionEnabled  bool
	SnapshotRetention   time.Duration
	EncryptionEnabled   bool
	EncryptionKey       []byte
	SchemaValidation    bool
	VersionRetention    int
	AutoCompaction      bool
	MetricsEnabled      bool
}

// ContextManager manages context data with Redis backend - Enhanced for CAM-OS Fork
type ContextManager struct {
	config      *Config
	redisClient *redis.Client
	mutex       sync.RWMutex
	
	// Namespace tracking
	namespaces map[string]*NamespaceInfo
	
	// Metrics
	totalReads       int64
	totalWrites      int64
	totalSnapshots   int64
	cacheHits        int64
	cacheMisses      int64
	compressionRatio float64
	
	// Fork expansion features
	schemas          map[string]interface{}
	encryptionCache  map[string][]byte
	compactionTicker *time.Ticker
}

// NamespaceInfo tracks information about a namespace - Enhanced for fork expansion
type NamespaceInfo struct {
	Name           string
	CreatedAt      time.Time
	LastAccessed   time.Time
	ItemCount      int64
	TotalSize      int64
	Quota          int64
	EncryptionKey  []byte
	Schema         string
	Retention      time.Duration
	AccessPattern  string // "read-heavy", "write-heavy", "balanced"
}

// NewContextManager creates a new enhanced context manager
func NewContextManager(config *Config) *ContextManager {
	// Set defaults
	if config.TTL == 0 {
		config.TTL = 7 * 24 * time.Hour // 7 days
	}
	if config.SnapshotRetention == 0 {
		config.SnapshotRetention = 30 * 24 * time.Hour // 30 days
	}
	if config.VersionRetention == 0 {
		config.VersionRetention = 10 // Keep 10 versions by default
	}
	
	return &ContextManager{
		config:          config,
		namespaces:      make(map[string]*NamespaceInfo),
		schemas:         make(map[string]interface{}),
		encryptionCache: make(map[string][]byte),
	}
}

// Initialize initializes the context manager
func (cm *ContextManager) Initialize(ctx context.Context) error {
	// Initialize Redis client
	cm.redisClient = redis.NewClient(&redis.Options{
		Addr:     cm.config.RedisAddr,
		Password: cm.config.RedisPassword,
		DB:       cm.config.RedisDB,
	})
	
	// Test connection
	if err := cm.redisClient.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("failed to connect to Redis: %v", err)
	}
	
	// Load existing namespaces
	if err := cm.loadNamespaces(ctx); err != nil {
		return fmt.Errorf("failed to load namespaces: %v", err)
	}
	
	// Start background cleanup
	go cm.cleanupLoop(ctx)
	
	return nil
}

// Shutdown shuts down the context manager
func (cm *ContextManager) Shutdown(ctx context.Context) error {
	if cm.redisClient != nil {
		return cm.redisClient.Close()
	}
	return nil
}

// Read reads context data from a namespace
func (cm *ContextManager) Read(ctx context.Context, namespace, key string, version int64) (*ContextData, error) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	
	// Check namespace exists
	if _, exists := cm.namespaces[namespace]; !exists {
		return nil, fmt.Errorf("namespace not found: %s", namespace)
	}
	
	// Construct Redis key
	var redisKey string
	if version == 0 {
		// Get latest version
		redisKey = fmt.Sprintf("ctx:%s:%s:latest", namespace, key)
	} else {
		redisKey = fmt.Sprintf("ctx:%s:%s:%d", namespace, key, version)
	}
	
	// Get from Redis
	data, err := cm.redisClient.Get(ctx, redisKey).Bytes()
	if err != nil {
		if err == redis.Nil {
			cm.cacheMisses++
			return nil, fmt.Errorf("key not found: %s", key)
		}
		return nil, fmt.Errorf("failed to read from Redis: %v", err)
	}
	
	cm.cacheHits++
	cm.totalReads++
	
	// Deserialize data
	var contextData ContextData
	if err := json.Unmarshal(data, &contextData); err != nil {
		return nil, fmt.Errorf("failed to deserialize data: %v", err)
	}
	
	// Decompress if needed
	if cm.config.CompressionEnabled && len(contextData.Data) > 0 {
		decompressed, err := cm.decompress(contextData.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to decompress data: %v", err)
		}
		contextData.Data = decompressed
	}
	
	// Update namespace access time
	cm.updateNamespaceAccess(namespace)
	
	return &contextData, nil
}

// Write writes context data to a namespace
func (cm *ContextManager) Write(ctx context.Context, namespace, key string, data []byte, metadata map[string]string) (*WriteResult, error) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	
	// Check namespace quota
	if err := cm.checkNamespaceQuota(namespace, int64(len(data))); err != nil {
		return nil, err
	}
	
	// Ensure namespace exists
	if err := cm.ensureNamespace(namespace); err != nil {
		return nil, err
	}
	
	// Generate version (timestamp-based)
	version := time.Now().UnixNano()
	
	// Calculate hash
	hash := sha256.Sum256(data)
	hashStr := hex.EncodeToString(hash[:])
	
	// Compress data if enabled
	dataToStore := data
	if cm.config.CompressionEnabled {
		compressed, err := cm.compress(data)
		if err != nil {
			return nil, fmt.Errorf("failed to compress data: %v", err)
		}
		dataToStore = compressed
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
		return nil, fmt.Errorf("failed to serialize data: %v", err)
	}
	
	// Store in Redis with TTL
	redisKey := fmt.Sprintf("ctx:%s:%s:%d", namespace, key, version)
	if err := cm.redisClient.Set(ctx, redisKey, serialized, cm.config.TTL).Err(); err != nil {
		return nil, fmt.Errorf("failed to write to Redis: %v", err)
	}
	
	// Update latest pointer
	latestKey := fmt.Sprintf("ctx:%s:%s:latest", namespace, key)
	if err := cm.redisClient.Set(ctx, latestKey, serialized, cm.config.TTL).Err(); err != nil {
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
	if err := cm.redisClient.LPush(ctx, versionKey, versionData).Err(); err != nil {
		return nil, fmt.Errorf("failed to store version metadata: %v", err)
	}
	
	// Limit version history (keep last 10 versions)
	cm.redisClient.LTrim(ctx, versionKey, 0, 9)
	
	// Update namespace statistics
	cm.updateNamespaceStats(namespace, int64(len(data)))
	
	cm.totalWrites++
	
	return &WriteResult{
		Version: version,
		Hash:    hashStr,
	}, nil
}

// Snapshot creates a snapshot of a namespace
func (cm *ContextManager) Snapshot(ctx context.Context, namespace, description string) (string, error) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	
	// Check namespace exists
	if _, exists := cm.namespaces[namespace]; !exists {
		return "", fmt.Errorf("namespace not found: %s", namespace)
	}
	
	// Generate snapshot ID
	snapshotID := fmt.Sprintf("snap_%s_%d", namespace, time.Now().UnixNano())
	
	// Get all keys in namespace
	pattern := fmt.Sprintf("ctx:%s:*", namespace)
	keys, err := cm.redisClient.Keys(ctx, pattern).Result()
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
		
		data, err := cm.redisClient.Get(ctx, key).Bytes()
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
	compressed, err := cm.compress(serialized)
	if err != nil {
		return "", fmt.Errorf("failed to compress snapshot: %v", err)
	}
	
	// Calculate hash
	hash := sha256.Sum256(compressed)
	hashStr := hex.EncodeToString(hash[:])
	
	// Store snapshot
	snapshotKey := fmt.Sprintf("snapshot:%s", snapshotID)
	if err := cm.redisClient.Set(ctx, snapshotKey, compressed, cm.config.SnapshotRetention).Err(); err != nil {
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
	if err := cm.redisClient.Set(ctx, metadataKey, metadataData, cm.config.SnapshotRetention).Err(); err != nil {
		return "", fmt.Errorf("failed to store snapshot metadata: %v", err)
	}
	
	cm.totalSnapshots++
	
	return snapshotID, nil
}

// Restore restores a namespace from a snapshot
func (cm *ContextManager) Restore(ctx context.Context, snapshotID string, force bool) (*RestoreResult, error) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	
	// Get snapshot data
	snapshotKey := fmt.Sprintf("snapshot:%s", snapshotID)
	compressed, err := cm.redisClient.Get(ctx, snapshotKey).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("snapshot not found: %s", snapshotID)
		}
		return nil, fmt.Errorf("failed to get snapshot: %v", err)
	}
	
	// Get snapshot metadata
	metadataKey := fmt.Sprintf("snapshot:%s:metadata", snapshotID)
	metadataData, err := cm.redisClient.Get(ctx, metadataKey).Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to get snapshot metadata: %v", err)
	}
	
	var snapshotInfo SnapshotInfo
	if err := json.Unmarshal(metadataData, &snapshotInfo); err != nil {
		return nil, fmt.Errorf("failed to deserialize snapshot metadata: %v", err)
	}
	
	// Decompress snapshot
	decompressed, err := cm.decompress(compressed)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress snapshot: %v", err)
	}
	
	// Deserialize snapshot data
	var snapshotData map[string]interface{}
	if err := json.Unmarshal(decompressed, &snapshotData); err != nil {
		return nil, fmt.Errorf("failed to deserialize snapshot data: %v", err)
	}
	
	// Clear existing namespace data if force is true
	if force {
		pattern := fmt.Sprintf("ctx:%s:*", snapshotInfo.Namespace)
		keys, err := cm.redisClient.Keys(ctx, pattern).Result()
		if err == nil {
			if len(keys) > 0 {
				cm.redisClient.Del(ctx, keys...)
			}
		}
	}
	
	// Restore data
	restoredItems := int64(0)
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
		
		if err := cm.redisClient.Set(ctx, key, dataBytes, cm.config.TTL).Err(); err != nil {
			continue // Skip failed keys
		}
		
		restoredItems++
	}
	
	// Ensure namespace exists
	cm.ensureNamespace(snapshotInfo.Namespace)
	
	return &RestoreResult{
		Namespace:     snapshotInfo.Namespace,
		RestoredItems: restoredItems,
	}, nil
}

// ListSnapshots lists all snapshots for a namespace
func (cm *ContextManager) ListSnapshots(ctx context.Context, namespace string) ([]SnapshotInfo, error) {
	pattern := fmt.Sprintf("snapshot:snap_%s_*:metadata", namespace)
	keys, err := cm.redisClient.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get snapshot keys: %v", err)
	}
	
	var snapshots []SnapshotInfo
	for _, key := range keys {
		data, err := cm.redisClient.Get(ctx, key).Bytes()
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

// GetNamespaceInfo returns information about a namespace
func (cm *ContextManager) GetNamespaceInfo(namespace string) (*NamespaceInfo, error) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	
	info, exists := cm.namespaces[namespace]
	if !exists {
		return nil, fmt.Errorf("namespace not found: %s", namespace)
	}
	
	return info, nil
}

// GetMetrics returns context manager metrics
func (cm *ContextManager) GetMetrics() map[string]interface{} {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	
	return map[string]interface{}{
		"total_reads":      cm.totalReads,
		"total_writes":     cm.totalWrites,
		"total_snapshots":  cm.totalSnapshots,
		"cache_hits":       cm.cacheHits,
		"cache_misses":     cm.cacheMisses,
		"hit_ratio":        float64(cm.cacheHits) / float64(cm.cacheHits+cm.cacheMisses),
		"namespace_count":  len(cm.namespaces),
	}
}

// HealthCheck performs a health check
func (cm *ContextManager) HealthCheck(ctx context.Context) error {
	if cm.redisClient == nil {
		return fmt.Errorf("Redis client not initialized")
	}
	
	if err := cm.redisClient.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("Redis health check failed: %v", err)
	}
	
	return nil
}

// ListVersions lists versions for a specific key - New method for fork expansion
func (cm *ContextManager) ListVersions(ctx context.Context, namespace, key string, limit int32, sinceVersion int64) ([]*VersionInfo, bool, string, error) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	
	// Check namespace exists
	if _, exists := cm.namespaces[namespace]; !exists {
		return nil, false, "", fmt.Errorf("namespace not found: %s", namespace)
	}
	
	// Get version metadata
	versionKey := fmt.Sprintf("ctx:%s:%s:versions", namespace, key)
	versionData, err := cm.redisClient.LRange(ctx, versionKey, 0, -1).Result()
	if err != nil {
		return nil, false, "", fmt.Errorf("failed to get versions: %v", err)
	}
	
	var versions []*VersionInfo
	for _, data := range versionData {
		var versionInfo map[string]interface{}
		if err := json.Unmarshal([]byte(data), &versionInfo); err != nil {
			continue
		}
		
		version := int64(versionInfo["version"].(float64))
		if sinceVersion > 0 && version <= sinceVersion {
			continue
		}
		
		timestamp := time.Unix(int64(versionInfo["timestamp"].(float64)), 0)
		
		vi := &VersionInfo{
			Version:   version,
			Timestamp: timestamp,
			Hash:      versionInfo["hash"].(string),
			Size:      int64(versionInfo["size"].(float64)),
		}
		
		// Add optional fields
		if author, ok := versionInfo["author"]; ok {
			vi.Author = author.(string)
		}
		if description, ok := versionInfo["description"]; ok {
			vi.Description = description.(string)
		}
		if tags, ok := versionInfo["tags"]; ok {
			if tagMap, ok := tags.(map[string]interface{}); ok {
				vi.Tags = make(map[string]string)
				for k, v := range tagMap {
					vi.Tags[k] = v.(string)
				}
			}
		}
		
		versions = append(versions, vi)
		
		if limit > 0 && len(versions) >= int(limit) {
			break
		}
	}
	
	// Determine if there are more versions
	hasMore := limit > 0 && len(versionData) > int(limit)
	nextToken := ""
	if hasMore && len(versions) > 0 {
		nextToken = fmt.Sprintf("%d", versions[len(versions)-1].Version)
	}
	
	return versions, hasMore, nextToken, nil
}

// UpdateConfig updates the context manager configuration - New method for fork expansion
func (cm *ContextManager) UpdateConfig(ctx context.Context, updates map[string]interface{}) error {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	
	for key, value := range updates {
		switch key {
		case "compression_enabled":
			if enabled, ok := value.(bool); ok {
				cm.config.CompressionEnabled = enabled
			}
		case "encryption_enabled":
			if enabled, ok := value.(bool); ok {
				cm.config.EncryptionEnabled = enabled
			}
		case "schema_validation":
			if enabled, ok := value.(bool); ok {
				cm.config.SchemaValidation = enabled
			}
		case "version_retention":
			if retention, ok := value.(int); ok {
				cm.config.VersionRetention = retention
			}
		case "auto_compaction":
			if enabled, ok := value.(bool); ok {
				cm.config.AutoCompaction = enabled
				if enabled && cm.compactionTicker == nil {
					cm.startAutoCompaction(ctx)
				} else if !enabled && cm.compactionTicker != nil {
					cm.stopAutoCompaction()
				}
			}
		case "gc_target":
			// Handle garbage collection target for memory optimization
			if target, ok := value.(string); ok {
				cm.adjustGCTarget(target)
			}
		default:
			return fmt.Errorf("unknown configuration key: %s", key)
		}
	}
	
	return nil
}

// RegisterSchema registers a schema for validation - New method for fork expansion
func (cm *ContextManager) RegisterSchema(namespace, schemaType string, schema interface{}) error {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	
	schemaKey := fmt.Sprintf("%s:%s", namespace, schemaType)
	cm.schemas[schemaKey] = schema
	
	// Update namespace info
	if nsInfo, exists := cm.namespaces[namespace]; exists {
		nsInfo.Schema = schemaType
	}
	
	return nil
}

// ValidateSchema validates data against a registered schema - New method for fork expansion
func (cm *ContextManager) ValidateSchema(namespace, schemaType string, data []byte) error {
	if !cm.config.SchemaValidation {
		return nil
	}
	
	cm.mutex.RLock()
	schemaKey := fmt.Sprintf("%s:%s", namespace, schemaType)
	schema, exists := cm.schemas[schemaKey]
	cm.mutex.RUnlock()
	
	if !exists {
		return fmt.Errorf("schema not found: %s", schemaKey)
	}
	
	// Mock schema validation - in real implementation, use JSON Schema or similar
	var dataObj interface{}
	if err := json.Unmarshal(data, &dataObj); err != nil {
		return fmt.Errorf("data is not valid JSON")
	}
	
	// Perform basic validation based on schema
	// This is a simplified implementation - real schema validation would be more robust
	_ = schema // Use schema for validation logic
	
	return nil
}

// Encrypt encrypts data using namespace-specific key - New method for fork expansion
func (cm *ContextManager) Encrypt(namespace string, data []byte) ([]byte, error) {
	if !cm.config.EncryptionEnabled {
		return data, nil
	}
	
	// Get or create namespace encryption key
	key := cm.getOrCreateEncryptionKey(namespace)
	
	// Mock encryption - in real implementation, use AES-GCM or similar
	encrypted := make([]byte, len(data))
	for i, b := range data {
		encrypted[i] = b ^ key[i%len(key)]
	}
	
	return encrypted, nil
}

// Decrypt decrypts data using namespace-specific key - New method for fork expansion
func (cm *ContextManager) Decrypt(namespace string, encrypted []byte) ([]byte, error) {
	if !cm.config.EncryptionEnabled {
		return encrypted, nil
	}
	
	// Get namespace encryption key
	key := cm.getOrCreateEncryptionKey(namespace)
	
	// Mock decryption - in real implementation, use AES-GCM or similar
	decrypted := make([]byte, len(encrypted))
	for i, b := range encrypted {
		decrypted[i] = b ^ key[i%len(key)]
	}
	
	return decrypted, nil
}

// CompactNamespace compacts a namespace by removing old versions - New method for fork expansion
func (cm *ContextManager) CompactNamespace(ctx context.Context, namespace string, keepVersions int) (int64, error) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	
	if _, exists := cm.namespaces[namespace]; !exists {
		return 0, fmt.Errorf("namespace not found: %s", namespace)
	}
	
	// Get all version keys in namespace
	pattern := fmt.Sprintf("ctx:%s:*:versions", namespace)
	versionKeys, err := cm.redisClient.Keys(ctx, pattern).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to get version keys: %v", err)
	}
	
	removedVersions := int64(0)
	
	for _, versionKey := range versionKeys {
		// Get version count
		count, err := cm.redisClient.LLen(ctx, versionKey).Result()
		if err != nil {
			continue
		}
		
		if count > int64(keepVersions) {
			// Get versions to remove
			versionsToRemove, err := cm.redisClient.LRange(ctx, versionKey, int64(keepVersions), -1).Result()
			if err != nil {
				continue
			}
			
			// Remove version data
			for _, versionData := range versionsToRemove {
				var versionInfo map[string]interface{}
				if err := json.Unmarshal([]byte(versionData), &versionInfo); err != nil {
					continue
				}
				
				version := int64(versionInfo["version"].(float64))
				
				// Extract key from version key pattern
				parts := strings.Split(versionKey, ":")
				if len(parts) >= 3 {
					key := parts[2]
					dataKey := fmt.Sprintf("ctx:%s:%s:%d", namespace, key, version)
					cm.redisClient.Del(ctx, dataKey)
					removedVersions++
				}
			}
			
			// Trim version list
			cm.redisClient.LTrim(ctx, versionKey, 0, int64(keepVersions)-1)
		}
	}
	
	return removedVersions, nil
}

// GetNamespaceMetrics returns detailed metrics for a namespace - Enhanced method
func (cm *ContextManager) GetNamespaceMetrics(namespace string) (map[string]interface{}, error) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	
	nsInfo, exists := cm.namespaces[namespace]
	if !exists {
		return nil, fmt.Errorf("namespace not found: %s", namespace)
	}
	
	metrics := map[string]interface{}{
		"name":            nsInfo.Name,
		"created_at":      nsInfo.CreatedAt.Unix(),
		"last_accessed":   nsInfo.LastAccessed.Unix(),
		"item_count":      nsInfo.ItemCount,
		"total_size":      nsInfo.TotalSize,
		"quota":           nsInfo.Quota,
		"quota_usage":     float64(nsInfo.TotalSize) / float64(nsInfo.Quota),
		"encryption_enabled": len(nsInfo.EncryptionKey) > 0,
		"schema":          nsInfo.Schema,
		"access_pattern":  nsInfo.AccessPattern,
		"retention":       nsInfo.Retention.String(),
	}
	
	return metrics, nil
}

// SetNamespaceQuota sets quota for a namespace - New method for fork expansion
func (cm *ContextManager) SetNamespaceQuota(namespace string, quota int64) error {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	
	if nsInfo, exists := cm.namespaces[namespace]; exists {
		nsInfo.Quota = quota
		return nil
	}
	
	return fmt.Errorf("namespace not found: %s", namespace)
}

// GetGlobalMetrics returns enhanced global metrics - Enhanced method
func (cm *ContextManager) GetGlobalMetrics() map[string]interface{} {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	
	totalQuota := int64(0)
	totalUsed := int64(0)
	encryptedNamespaces := 0
	schemasRegistered := len(cm.schemas)
	
	for _, nsInfo := range cm.namespaces {
		totalQuota += nsInfo.Quota
		totalUsed += nsInfo.TotalSize
		if len(nsInfo.EncryptionKey) > 0 {
			encryptedNamespaces++
		}
	}
	
	hitRatio := float64(0)
	if cm.cacheHits+cm.cacheMisses > 0 {
		hitRatio = float64(cm.cacheHits) / float64(cm.cacheHits+cm.cacheMisses)
	}
	
	return map[string]interface{}{
		"total_reads":           cm.totalReads,
		"total_writes":          cm.totalWrites,
		"total_snapshots":       cm.totalSnapshots,
		"cache_hits":            cm.cacheHits,
		"cache_misses":          cm.cacheMisses,
		"hit_ratio":             hitRatio,
		"namespace_count":       len(cm.namespaces),
		"total_quota":           totalQuota,
		"total_used":            totalUsed,
		"quota_utilization":     float64(totalUsed) / float64(totalQuota),
		"compression_ratio":     cm.compressionRatio,
		"encrypted_namespaces":  encryptedNamespaces,
		"schemas_registered":    schemasRegistered,
		"compression_enabled":   cm.config.CompressionEnabled,
		"encryption_enabled":    cm.config.EncryptionEnabled,
		"schema_validation":     cm.config.SchemaValidation,
		"auto_compaction":       cm.config.AutoCompaction,
	}
}

// Private methods

// loadNamespaces loads existing namespaces from Redis
func (cm *ContextManager) loadNamespaces(ctx context.Context) error {
	// Get all context keys to discover namespaces
	keys, err := cm.redisClient.Keys(ctx, "ctx:*").Result()
	if err != nil {
		return err
	}
	
	namespaceMap := make(map[string]bool)
	for _, key := range keys {
		parts := strings.Split(key, ":")
		if len(parts) >= 2 {
			namespace := parts[1]
			namespaceMap[namespace] = true
		}
	}
	
	// Initialize namespace info
	for namespace := range namespaceMap {
		cm.namespaces[namespace] = &NamespaceInfo{
			Name:         namespace,
			CreatedAt:    time.Now(), // Approximation
			LastAccessed: time.Now(),
			ItemCount:    0,
			TotalSize:    0,
			Quota:        cm.config.MaxContextSize,
		}
	}
	
	return nil
}

// ensureNamespace ensures a namespace exists
func (cm *ContextManager) ensureNamespace(namespace string) error {
	if _, exists := cm.namespaces[namespace]; !exists {
		if len(cm.namespaces) >= cm.config.MaxNamespaces {
			return fmt.Errorf("maximum number of namespaces reached: %d", cm.config.MaxNamespaces)
		}
		
		cm.namespaces[namespace] = &NamespaceInfo{
			Name:         namespace,
			CreatedAt:    time.Now(),
			LastAccessed: time.Now(),
			ItemCount:    0,
			TotalSize:    0,
			Quota:        cm.config.MaxContextSize,
		}
	}
	
	return nil
}

// checkNamespaceQuota checks if a namespace has enough quota
func (cm *ContextManager) checkNamespaceQuota(namespace string, dataSize int64) error {
	if info, exists := cm.namespaces[namespace]; exists {
		if info.TotalSize+dataSize > info.Quota {
			return fmt.Errorf("namespace quota exceeded: %s", namespace)
		}
	}
	return nil
}

// updateNamespaceAccess updates namespace access time
func (cm *ContextManager) updateNamespaceAccess(namespace string) {
	if info, exists := cm.namespaces[namespace]; exists {
		info.LastAccessed = time.Now()
	}
}

// updateNamespaceStats updates namespace statistics
func (cm *ContextManager) updateNamespaceStats(namespace string, dataSize int64) {
	if info, exists := cm.namespaces[namespace]; exists {
		info.ItemCount++
		info.TotalSize += dataSize
		info.LastAccessed = time.Now()
	}
}

// compress compresses data using LZ4
func (cm *ContextManager) compress(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}
	
	compressed := make([]byte, lz4.CompressBlockBound(len(data)))
	n, err := lz4.CompressBlock(data, compressed, nil)
	if err != nil {
		return nil, err
	}
	
	return compressed[:n], nil
}

// decompress decompresses data using LZ4
func (cm *ContextManager) decompress(compressed []byte) ([]byte, error) {
	if len(compressed) == 0 {
		return compressed, nil
	}
	
	// Estimate decompressed size (this is a simple heuristic)
	decompressed := make([]byte, len(compressed)*4)
	n, err := lz4.UncompressBlock(compressed, decompressed)
	if err != nil {
		return nil, err
	}
	
	return decompressed[:n], nil
}

// cleanupLoop runs periodic cleanup tasks
func (cm *ContextManager) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cm.performCleanup(ctx)
		}
	}
}

// performCleanup performs cleanup tasks
func (cm *ContextManager) performCleanup(ctx context.Context) {
	// Clean up expired snapshots
	pattern := "snapshot:*:metadata"
	keys, err := cm.redisClient.Keys(ctx, pattern).Result()
	if err != nil {
		return
	}
	
	now := time.Now()
	for _, key := range keys {
		data, err := cm.redisClient.Get(ctx, key).Bytes()
		if err != nil {
			continue
		}
		
		var snapshotInfo SnapshotInfo
		if err := json.Unmarshal(data, &snapshotInfo); err != nil {
			continue
		}
		
		// Check if snapshot is expired
		if now.Sub(snapshotInfo.Timestamp) > cm.config.SnapshotRetention {
			// Delete snapshot and metadata
			snapshotKey := fmt.Sprintf("snapshot:%s", snapshotInfo.ID)
			cm.redisClient.Del(ctx, snapshotKey, key)
		}
	}
}

// Private helper methods for fork expansion

func (cm *ContextManager) getOrCreateEncryptionKey(namespace string) []byte {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	
	if key, exists := cm.encryptionCache[namespace]; exists {
		return key
	}
	
	// Generate namespace-specific key from global key and namespace
	if len(cm.config.EncryptionKey) == 0 {
		// Use a default key for demo purposes
		cm.config.EncryptionKey = []byte("cam-os-default-encryption-key-32b")
	}
	
	// Derive namespace key
	hash := sha256.Sum256(append(cm.config.EncryptionKey, []byte(namespace)...))
	key := hash[:]
	
	cm.encryptionCache[namespace] = key
	
	// Store in namespace info
	if nsInfo, exists := cm.namespaces[namespace]; exists {
		nsInfo.EncryptionKey = key
	}
	
	return key
}

func (cm *ContextManager) adjustGCTarget(target string) {
	// Mock GC adjustment - in real implementation, adjust Go GC parameters
	switch target {
	case "50":
		// Aggressive GC for performance
	case "75":
		// Balanced GC
	case "100":
		// Conservative GC for memory efficiency
	}
}

func (cm *ContextManager) startAutoCompaction(ctx context.Context) {
	cm.compactionTicker = time.NewTicker(1 * time.Hour)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-cm.compactionTicker.C:
				cm.performAutoCompaction(ctx)
			}
		}
	}()
}

func (cm *ContextManager) stopAutoCompaction() {
	if cm.compactionTicker != nil {
		cm.compactionTicker.Stop()
		cm.compactionTicker = nil
	}
}

func (cm *ContextManager) performAutoCompaction(ctx context.Context) {
	// Compact namespaces that exceed version retention
	for namespace := range cm.namespaces {
		cm.CompactNamespace(ctx, namespace, cm.config.VersionRetention)
	}
}

// Enhanced Write method with fork expansion features
func (cm *ContextManager) WriteEnhanced(ctx context.Context, namespace, key string, data []byte, metadata map[string]string, options map[string]interface{}) (*WriteResult, error) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	
	// Schema validation
	if schemaType, ok := options["schema_type"]; ok {
		if err := cm.ValidateSchema(namespace, schemaType.(string), data); err != nil {
			return nil, fmt.Errorf("schema validation failed: %v", err)
		}
	}
	
	// Encryption
	dataToStore := data
	if cm.config.EncryptionEnabled || (options["encrypt"] != nil && options["encrypt"].(bool)) {
		encrypted, err := cm.Encrypt(namespace, data)
		if err != nil {
			return nil, fmt.Errorf("encryption failed: %v", err)
		}
		dataToStore = encrypted
		if metadata == nil {
			metadata = make(map[string]string)
		}
		metadata["encrypted"] = "true"
	}
	
	// Use existing Write method
	return cm.Write(ctx, namespace, key, dataToStore, metadata)
}

// Enhanced Read method with fork expansion features
func (cm *ContextManager) ReadEnhanced(ctx context.Context, namespace, key string, version int64, options map[string]interface{}) (*ContextData, error) {
	// Use existing Read method
	data, err := cm.Read(ctx, namespace, key, version)
	if err != nil {
		return nil, err
	}
	
	// Decryption
	if data.Metadata["encrypted"] == "true" {
		decrypted, err := cm.Decrypt(namespace, data.Data)
		if err != nil {
			return nil, fmt.Errorf("decryption failed: %v", err)
		}
		data.Data = decrypted
	}
	
	// Integrity validation
	if options["validate_integrity"] != nil && options["validate_integrity"].(bool) {
		if expectedHash, ok := options["expected_hash"]; ok {
			actualHash := sha256.Sum256(data.Data)
			if hex.EncodeToString(actualHash[:]) != expectedHash.(string) {
				return nil, fmt.Errorf("integrity validation failed")
			}
		}
	}
	
	return data, nil
} 