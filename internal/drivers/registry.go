package drivers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cam-os/kernel/internal/drivers/wasm"
	"github.com/cam-os/kernel/internal/security"
)

// DriverRegistry manages driver registration, discovery, and lifecycle
type DriverRegistry struct {
	drivers     map[string]*DriverInfo
	marketplace *DriverMarketplace
	wasmRuntime *wasm.WASMRuntime
	security    *security.Manager
	config      *RegistryConfig
	mutex       sync.RWMutex

	// Metrics
	metrics *RegistryMetrics
}

// RegistryConfig configures the driver registry
type RegistryConfig struct {
	// Storage
	DriverStorePath   string
	ManifestStorePath string

	// Security
	RequireSignature     bool
	TrustedPublishers    []string
	AllowUnsignedDrivers bool

	// Marketplace
	MarketplaceURL      string
	EnableMarketplace   bool
	UpdateCheckInterval time.Duration

	// Runtime
	MaxDrivers            int
	DefaultResourceLimits *ResourceLimits

	// Hot loading
	EnableHotLoading bool
	WatchDirectories []string
}

// DriverInfo represents information about a driver
type DriverInfo struct {
	Manifest   *DriverManifest
	Binary     []byte
	State      DriverState
	Instance   interface{} // gRPC client or WASM module instance
	LoadedAt   time.Time
	LastUsed   time.Time
	UsageCount int64

	// Resource usage
	ResourceUsage *ResourceUsage

	// Health
	HealthStatus    HealthStatus
	LastHealthCheck time.Time
}

// DriverManifest defines driver metadata and capabilities
type DriverManifest struct {
	// Basic info
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Author      string `json:"author"`
	License     string `json:"license"`

	// Runtime info
	Runtime      string   `json:"runtime"` // "grpc", "wasm"
	Entrypoint   string   `json:"entrypoint"`
	Capabilities []string `json:"capabilities"`

	// Dependencies
	Dependencies []string `json:"dependencies"`
	Syscalls     []string `json:"syscalls"`

	// Security
	Signature    string   `json:"signature"`
	ManifestHash string   `json:"manifest_hash"`
	PublisherKey string   `json:"publisher_key"`
	Permissions  []string `json:"permissions"`

	// Resources
	ResourceLimits *ResourceLimits `json:"resource_limits"`

	// Metadata
	Tags       []string `json:"tags"`
	Category   string   `json:"category"`
	Homepage   string   `json:"homepage"`
	Repository string   `json:"repository"`

	// Marketplace
	MarketplaceID string  `json:"marketplace_id"`
	Price         float64 `json:"price"`
	Rating        float64 `json:"rating"`
	Downloads     int64   `json:"downloads"`
}

// ResourceLimits defines resource constraints for a driver
type ResourceLimits struct {
	MaxMemory      int64         `json:"max_memory"`
	MaxCPU         time.Duration `json:"max_cpu"`
	MaxDisk        int64         `json:"max_disk"`
	MaxNetwork     int64         `json:"max_network"`
	MaxFileHandles int           `json:"max_file_handles"`
}

// ResourceUsage tracks actual resource usage
type ResourceUsage struct {
	MemoryUsed  int64
	CPUUsed     time.Duration
	DiskUsed    int64
	NetworkUsed int64
	FileHandles int
	LastUpdated time.Time
}

// DriverState represents the state of a driver
type DriverState int

const (
	DriverStateUnloaded DriverState = iota
	DriverStateLoading
	DriverStateRunning
	DriverStateStopped
	DriverStateError
	DriverStateUpdating
)

// HealthStatus represents driver health
type HealthStatus int

const (
	HealthStatusUnknown HealthStatus = iota
	HealthStatusHealthy
	HealthStatusUnhealthy
	HealthStatusDegraded
)

// RegistryMetrics tracks registry performance
type RegistryMetrics struct {
	DriversLoaded     int64
	DriversRunning    int64
	DriversError      int64
	TotalLoads        int64
	TotalUnloads      int64
	AverageLoadTime   time.Duration
	TotalResourceUsed *ResourceUsage
}

// DriverMarketplace handles driver discovery and updates
type DriverMarketplace struct {
	config     *RegistryConfig
	httpClient *http.Client
	cache      map[string]*MarketplaceEntry
	mutex      sync.RWMutex
}

// MarketplaceEntry represents a driver in the marketplace
type MarketplaceEntry struct {
	Manifest    *DriverManifest
	DownloadURL string
	Verified    bool
	LastUpdated time.Time
	Popularity  int64

	// Reviews and ratings
	Reviews       []Review
	AverageRating float64
}

// Review represents a driver review
type Review struct {
	Author    string
	Rating    int
	Comment   string
	Timestamp time.Time
}

// NewDriverRegistry creates a new driver registry
func NewDriverRegistry(config *RegistryConfig, wasmRuntime *wasm.WASMRuntime, securityManager *security.Manager) *DriverRegistry {
	if config == nil {
		config = DefaultRegistryConfig()
	}

	marketplace := &DriverMarketplace{
		config:     config,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		cache:      make(map[string]*MarketplaceEntry),
	}

	return &DriverRegistry{
		drivers:     make(map[string]*DriverInfo),
		marketplace: marketplace,
		wasmRuntime: wasmRuntime,
		security:    securityManager,
		config:      config,
		metrics:     &RegistryMetrics{},
	}
}

// DefaultRegistryConfig returns default registry configuration
func DefaultRegistryConfig() *RegistryConfig {
	return &RegistryConfig{
		DriverStorePath:      "./drivers",
		ManifestStorePath:    "./manifests",
		RequireSignature:     true,
		AllowUnsignedDrivers: false,
		MarketplaceURL:       "https://marketplace.cam-os.dev",
		EnableMarketplace:    true,
		UpdateCheckInterval:  24 * time.Hour,
		MaxDrivers:           100,
		DefaultResourceLimits: &ResourceLimits{
			MaxMemory:      50 * 1024 * 1024, // 50MB
			MaxCPU:         100 * time.Millisecond,
			MaxDisk:        100 * 1024 * 1024, // 100MB
			MaxNetwork:     10 * 1024 * 1024,  // 10MB
			MaxFileHandles: 100,
		},
		EnableHotLoading: true,
		WatchDirectories: []string{"./drivers"},
	}
}

// Initialize initializes the driver registry
func (r *DriverRegistry) Initialize(ctx context.Context) error {
	// Create storage directories
	if err := os.MkdirAll(r.config.DriverStorePath, 0755); err != nil {
		return fmt.Errorf("failed to create driver storage path: %v", err)
	}

	if err := os.MkdirAll(r.config.ManifestStorePath, 0755); err != nil {
		return fmt.Errorf("failed to create manifest storage path: %v", err)
	}

	// Load existing drivers
	if err := r.loadExistingDrivers(ctx); err != nil {
		return fmt.Errorf("failed to load existing drivers: %v", err)
	}

	// Initialize marketplace
	if r.config.EnableMarketplace {
		if err := r.marketplace.Initialize(ctx); err != nil {
			return fmt.Errorf("failed to initialize marketplace: %v", err)
		}
	}

	// Start background tasks
	go r.backgroundTasks(ctx)

	return nil
}

// RegisterDriver registers a new driver
func (r *DriverRegistry) RegisterDriver(ctx context.Context, manifest *DriverManifest, binary []byte) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Validate manifest
	if err := r.validateManifest(manifest); err != nil {
		return fmt.Errorf("invalid manifest: %v", err)
	}

	// Verify signature if required
	if r.config.RequireSignature && !r.config.AllowUnsignedDrivers {
		if err := r.verifySignature(manifest, binary); err != nil {
			return fmt.Errorf("signature verification failed: %v", err)
		}
	}

	// Check resource limits
	if err := r.checkResourceLimits(manifest.ResourceLimits); err != nil {
		return fmt.Errorf("resource limits exceeded: %v", err)
	}

	// Store driver files
	if err := r.storeDriverFiles(manifest, binary); err != nil {
		return fmt.Errorf("failed to store driver files: %v", err)
	}

	// Create driver info
	driverInfo := &DriverInfo{
		Manifest:      manifest,
		Binary:        binary,
		State:         DriverStateUnloaded,
		LoadedAt:      time.Now(),
		ResourceUsage: &ResourceUsage{},
		HealthStatus:  HealthStatusUnknown,
	}

	// Store in registry
	r.drivers[manifest.Name] = driverInfo
	r.metrics.DriversLoaded++

	return nil
}

// LoadDriver loads a driver for execution
func (r *DriverRegistry) LoadDriver(ctx context.Context, driverName string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	driverInfo, exists := r.drivers[driverName]
	if !exists {
		return fmt.Errorf("driver not found: %s", driverName)
	}

	if driverInfo.State == DriverStateRunning {
		return nil // Already loaded
	}

	startTime := time.Now()
	driverInfo.State = DriverStateLoading

	// Load based on runtime type
	switch driverInfo.Manifest.Runtime {
	case "wasm":
		if err := r.loadWASMDriver(ctx, driverInfo); err != nil {
			driverInfo.State = DriverStateError
			return fmt.Errorf("failed to load WASM driver: %v", err)
		}
	case "grpc":
		if err := r.loadGRPCDriver(ctx, driverInfo); err != nil {
			driverInfo.State = DriverStateError
			return fmt.Errorf("failed to load gRPC driver: %v", err)
		}
	default:
		driverInfo.State = DriverStateError
		return fmt.Errorf("unsupported runtime: %s", driverInfo.Manifest.Runtime)
	}

	driverInfo.State = DriverStateRunning
	driverInfo.LoadedAt = time.Now()

	// Update metrics
	r.metrics.DriversRunning++
	r.metrics.TotalLoads++
	r.metrics.AverageLoadTime = time.Since(startTime)

	return nil
}

// UnloadDriver unloads a driver
func (r *DriverRegistry) UnloadDriver(ctx context.Context, driverName string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	driverInfo, exists := r.drivers[driverName]
	if !exists {
		return fmt.Errorf("driver not found: %s", driverName)
	}

	if driverInfo.State != DriverStateRunning {
		return nil // Already unloaded
	}

	// Unload based on runtime type
	switch driverInfo.Manifest.Runtime {
	case "wasm":
		if err := r.unloadWASMDriver(ctx, driverInfo); err != nil {
			return fmt.Errorf("failed to unload WASM driver: %v", err)
		}
	case "grpc":
		if err := r.unloadGRPCDriver(ctx, driverInfo); err != nil {
			return fmt.Errorf("failed to unload gRPC driver: %v", err)
		}
	}

	driverInfo.State = DriverStateStopped
	driverInfo.Instance = nil

	// Update metrics
	r.metrics.DriversRunning--
	r.metrics.TotalUnloads++

	return nil
}

// GetDriver returns driver information
func (r *DriverRegistry) GetDriver(driverName string) (*DriverInfo, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	driverInfo, exists := r.drivers[driverName]
	if !exists {
		return nil, fmt.Errorf("driver not found: %s", driverName)
	}

	return driverInfo, nil
}

// ListDrivers returns all registered drivers
func (r *DriverRegistry) ListDrivers() []*DriverInfo {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	drivers := make([]*DriverInfo, 0, len(r.drivers))
	for _, driverInfo := range r.drivers {
		drivers = append(drivers, driverInfo)
	}

	return drivers
}

// SearchMarketplace searches for drivers in the marketplace
func (r *DriverRegistry) SearchMarketplace(ctx context.Context, query string, category string) ([]*MarketplaceEntry, error) {
	if !r.config.EnableMarketplace {
		return nil, fmt.Errorf("marketplace is disabled")
	}

	return r.marketplace.Search(ctx, query, category)
}

// InstallFromMarketplace installs a driver from the marketplace
func (r *DriverRegistry) InstallFromMarketplace(ctx context.Context, driverID string) error {
	if !r.config.EnableMarketplace {
		return fmt.Errorf("marketplace is disabled")
	}

	entry, err := r.marketplace.GetDriver(ctx, driverID)
	if err != nil {
		return fmt.Errorf("failed to get driver from marketplace: %v", err)
	}

	// Download driver binary
	binary, err := r.marketplace.DownloadDriver(ctx, entry.DownloadURL)
	if err != nil {
		return fmt.Errorf("failed to download driver: %v", err)
	}

	// Register driver
	return r.RegisterDriver(ctx, entry.Manifest, binary)
}

// GetMetrics returns registry metrics
func (r *DriverRegistry) GetMetrics() *RegistryMetrics {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	// Update current metrics
	r.metrics.DriversLoaded = int64(len(r.drivers))

	runningCount := int64(0)
	errorCount := int64(0)
	totalResourceUsage := &ResourceUsage{}

	for _, driverInfo := range r.drivers {
		if driverInfo.State == DriverStateRunning {
			runningCount++
		}
		if driverInfo.State == DriverStateError {
			errorCount++
		}

		// Aggregate resource usage
		totalResourceUsage.MemoryUsed += driverInfo.ResourceUsage.MemoryUsed
		totalResourceUsage.CPUUsed += driverInfo.ResourceUsage.CPUUsed
		totalResourceUsage.DiskUsed += driverInfo.ResourceUsage.DiskUsed
		totalResourceUsage.NetworkUsed += driverInfo.ResourceUsage.NetworkUsed
		totalResourceUsage.FileHandles += driverInfo.ResourceUsage.FileHandles
	}

	r.metrics.DriversRunning = runningCount
	r.metrics.DriversError = errorCount
	r.metrics.TotalResourceUsed = totalResourceUsage

	return r.metrics
}

// Private methods

func (r *DriverRegistry) validateManifest(manifest *DriverManifest) error {
	if manifest.Name == "" {
		return fmt.Errorf("driver name is required")
	}

	if manifest.Version == "" {
		return fmt.Errorf("driver version is required")
	}

	if manifest.Runtime != "wasm" && manifest.Runtime != "grpc" {
		return fmt.Errorf("unsupported runtime: %s", manifest.Runtime)
	}

	// Check for duplicate names
	if _, exists := r.drivers[manifest.Name]; exists {
		return fmt.Errorf("driver with name %s already exists", manifest.Name)
	}

	return nil
}

func (r *DriverRegistry) verifySignature(manifest *DriverManifest, binary []byte) error {
	// Calculate manifest hash
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %v", err)
	}

	hash := sha256.Sum256(manifestJSON)
	manifestHash := hex.EncodeToString(hash[:])

	if manifest.ManifestHash != manifestHash {
		return fmt.Errorf("manifest hash mismatch")
	}

	// Verify signature using security manager
	return r.security.VerifyDriverSignature([]byte(manifest.Signature), binary, manifest.PublisherKey)
}

func (r *DriverRegistry) checkResourceLimits(limits *ResourceLimits) error {
	if limits == nil {
		return nil
	}

	defaults := r.config.DefaultResourceLimits

	if limits.MaxMemory > defaults.MaxMemory {
		return fmt.Errorf("memory limit exceeds maximum: %d > %d", limits.MaxMemory, defaults.MaxMemory)
	}

	if limits.MaxCPU > defaults.MaxCPU {
		return fmt.Errorf("CPU limit exceeds maximum: %v > %v", limits.MaxCPU, defaults.MaxCPU)
	}

	return nil
}

func (r *DriverRegistry) storeDriverFiles(manifest *DriverManifest, binary []byte) error {
	// Store manifest
	manifestPath := filepath.Join(r.config.ManifestStorePath, manifest.Name+".json")
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %v", err)
	}

	if err := os.WriteFile(manifestPath, manifestJSON, 0644); err != nil {
		return fmt.Errorf("failed to write manifest file: %v", err)
	}

	// Store binary
	binaryPath := filepath.Join(r.config.DriverStorePath, manifest.Name)
	if err := os.WriteFile(binaryPath, binary, 0755); err != nil {
		return fmt.Errorf("failed to write binary file: %v", err)
	}

	return nil
}

func (r *DriverRegistry) loadExistingDrivers(ctx context.Context) error {
	// Load manifests from storage
	manifestFiles, err := filepath.Glob(filepath.Join(r.config.ManifestStorePath, "*.json"))
	if err != nil {
		return fmt.Errorf("failed to glob manifest files: %v", err)
	}

	for _, manifestFile := range manifestFiles {
		manifestData, err := os.ReadFile(manifestFile)
		if err != nil {
			continue // Skip failed files
		}

		var manifest DriverManifest
		if err := json.Unmarshal(manifestData, &manifest); err != nil {
			continue // Skip invalid manifests
		}

		// Load binary
		binaryPath := filepath.Join(r.config.DriverStorePath, manifest.Name)
		binary, err := os.ReadFile(binaryPath)
		if err != nil {
			continue // Skip if binary not found
		}

		// Create driver info
		driverInfo := &DriverInfo{
			Manifest:      &manifest,
			Binary:        binary,
			State:         DriverStateUnloaded,
			LoadedAt:      time.Now(),
			ResourceUsage: &ResourceUsage{},
			HealthStatus:  HealthStatusUnknown,
		}

		r.drivers[manifest.Name] = driverInfo
	}

	return nil
}

func (r *DriverRegistry) loadWASMDriver(ctx context.Context, driverInfo *DriverInfo) error {
	// Create WASM module config
	moduleConfig := &wasm.ModuleConfig{
		Name:         driverInfo.Manifest.Name,
		Binary:       driverInfo.Binary,
		Capabilities: driverInfo.Manifest.Capabilities,
		Environment:  make(map[string]string),
		Arguments:    []string{},
	}

	// Set resource limits
	if driverInfo.Manifest.ResourceLimits != nil {
		moduleConfig.MaxMemory = driverInfo.Manifest.ResourceLimits.MaxMemory
		moduleConfig.MaxCPU = driverInfo.Manifest.ResourceLimits.MaxCPU
	}

	// Load module
	instance, err := r.wasmRuntime.LoadModule(ctx, moduleConfig)
	if err != nil {
		return fmt.Errorf("failed to load WASM module: %v", err)
	}

	driverInfo.Instance = instance
	return nil
}

func (r *DriverRegistry) unloadWASMDriver(ctx context.Context, driverInfo *DriverInfo) error {
	return r.wasmRuntime.UnloadModule(ctx, driverInfo.Manifest.Name)
}

func (r *DriverRegistry) loadGRPCDriver(ctx context.Context, driverInfo *DriverInfo) error {
	// TODO: Implement gRPC driver loading
	return fmt.Errorf("gRPC driver loading not implemented")
}

func (r *DriverRegistry) unloadGRPCDriver(ctx context.Context, driverInfo *DriverInfo) error {
	// TODO: Implement gRPC driver unloading
	return fmt.Errorf("gRPC driver unloading not implemented")
}

func (r *DriverRegistry) backgroundTasks(ctx context.Context) {
	ticker := time.NewTicker(r.config.UpdateCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Health checks
			r.performHealthChecks(ctx)

			// Update checks
			if r.config.EnableMarketplace {
				r.marketplace.CheckUpdates(ctx)
			}
		}
	}
}

func (r *DriverRegistry) performHealthChecks(ctx context.Context) {
	r.mutex.RLock()
	drivers := make([]*DriverInfo, 0, len(r.drivers))
	for _, driverInfo := range r.drivers {
		if driverInfo.State == DriverStateRunning {
			drivers = append(drivers, driverInfo)
		}
	}
	r.mutex.RUnlock()

	for _, driverInfo := range drivers {
		// TODO: Implement health check logic
		driverInfo.LastHealthCheck = time.Now()
		driverInfo.HealthStatus = HealthStatusHealthy
	}
}

// Marketplace methods

func (m *DriverMarketplace) Initialize(ctx context.Context) error {
	// TODO: Initialize marketplace connection
	return nil
}

func (m *DriverMarketplace) Search(ctx context.Context, query string, category string) ([]*MarketplaceEntry, error) {
	// TODO: Implement marketplace search
	return nil, fmt.Errorf("marketplace search not implemented")
}

func (m *DriverMarketplace) GetDriver(ctx context.Context, driverID string) (*MarketplaceEntry, error) {
	// TODO: Implement driver retrieval
	return nil, fmt.Errorf("driver retrieval not implemented")
}

func (m *DriverMarketplace) DownloadDriver(ctx context.Context, downloadURL string) ([]byte, error) {
	resp, err := m.httpClient.Get(downloadURL)
	if err != nil {
		return nil, fmt.Errorf("failed to download driver: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download failed with status: %d", resp.StatusCode)
	}

	binary, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	return binary, nil
}

func (m *DriverMarketplace) CheckUpdates(ctx context.Context) error {
	// TODO: Implement update checking
	return nil
}

// String methods for debugging
func (s DriverState) String() string {
	switch s {
	case DriverStateUnloaded:
		return "unloaded"
	case DriverStateLoading:
		return "loading"
	case DriverStateRunning:
		return "running"
	case DriverStateStopped:
		return "stopped"
	case DriverStateError:
		return "error"
	case DriverStateUpdating:
		return "updating"
	default:
		return "unknown"
	}
}

func (s HealthStatus) String() string {
	switch s {
	case HealthStatusUnknown:
		return "unknown"
	case HealthStatusHealthy:
		return "healthy"
	case HealthStatusUnhealthy:
		return "unhealthy"
	case HealthStatusDegraded:
		return "degraded"
	default:
		return "unknown"
	}
}
