package wasm

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// WASMRuntime manages WebAssembly driver execution with WASI support
type WASMRuntime struct {
	runtime wazero.Runtime
	config  *RuntimeConfig
	modules map[string]*ModuleInstance
	mutex   sync.RWMutex
	
	// Resource management
	resourceLimiter *ResourceLimiter
	
	// Capability management
	capabilities map[string]*CapabilitySet
	
	// Metrics
	metrics *RuntimeMetrics
}

// RuntimeConfig configures the WASM runtime
type RuntimeConfig struct {
	// WASI configuration
	WASIVersion        string        // "preview1", "preview2"
	EnableWASI         bool
	
	// Resource limits
	MaxMemoryPerModule int64         // Maximum memory per module in bytes
	MaxCPUPerModule    time.Duration // Maximum CPU time per module
	StartupTimeout     time.Duration // Maximum startup time
	
	// Security
	EnableSandboxing   bool
	AllowedSyscalls    []string
	DeniedSyscalls     []string
	
	// Performance
	EnableJIT          bool
	CompilationCache   bool
	
	// Debugging
	EnableDebugInfo    bool
	EnableProfiling    bool
}

// ModuleInstance represents a running WASM module
type ModuleInstance struct {
	ID          string
	Module      api.Module
	Config      *ModuleConfig
	StartedAt   time.Time
	LastUsed    time.Time
	
	// Resource usage
	MemoryUsage int64
	CPUUsage    time.Duration
	
	// State
	State       ModuleState
	Error       error
	
	// Capabilities
	Capabilities *CapabilitySet
}

// ModuleConfig configures a WASM module
type ModuleConfig struct {
	Name         string
	Binary       []byte
	Capabilities []string
	Environment  map[string]string
	Arguments    []string
	
	// Resource limits (overrides runtime defaults)
	MaxMemory    int64
	MaxCPU       time.Duration
	
	// Filesystem access
	AllowedPaths []string
	ReadOnlyPaths []string
}

// ModuleState represents the state of a WASM module
type ModuleState int

const (
	ModuleStateInitializing ModuleState = iota
	ModuleStateRunning
	ModuleStateSuspended
	ModuleStateTerminated
	ModuleStateError
)

// CapabilitySet defines what a module can access
type CapabilitySet struct {
	// Syscall capabilities
	AllowedSyscalls map[string]bool
	
	// Network capabilities
	AllowNetworkAccess bool
	AllowedHosts       []string
	AllowedPorts       []int
	
	// Filesystem capabilities
	AllowFilesystemAccess bool
	AllowedPaths          []string
	ReadOnlyPaths         []string
	
	// Context capabilities
	AllowedNamespaces []string
	AllowContextRead  bool
	AllowContextWrite bool
	
	// Driver capabilities
	AllowDriverCalls bool
	AllowedDrivers   []string
}

// ResourceLimiter manages resource usage across modules
type ResourceLimiter struct {
	maxTotalMemory int64
	maxTotalCPU    time.Duration
	
	currentMemory int64
	currentCPU    time.Duration
	
	mutex sync.RWMutex
}

// RuntimeMetrics tracks runtime performance
type RuntimeMetrics struct {
	ModulesLoaded     int64
	ModulesRunning    int64
	ModulesTerminated int64
	ModulesError      int64
	
	TotalMemoryUsed   int64
	TotalCPUUsed      time.Duration
	
	AverageStartupTime time.Duration
	AverageExecutionTime time.Duration
	
	CompilationCacheHits   int64
	CompilationCacheMisses int64
}

// NewWASMRuntime creates a new WASM runtime
func NewWASMRuntime(config *RuntimeConfig) *WASMRuntime {
	if config == nil {
		config = DefaultRuntimeConfig()
	}
	
	// Create wazero runtime with configuration
	runtimeConfig := wazero.NewRuntimeConfig()
	
	if config.EnableJIT {
		runtimeConfig = runtimeConfig.WithCompilationCache(wazero.NewCompilationCache())
	}
	
	if config.EnableDebugInfo {
		runtimeConfig = runtimeConfig.WithDebugInfoEnabled(true)
	}
	
	runtime := wazero.NewRuntimeWithConfig(context.Background(), runtimeConfig)
	
	// Initialize resource limiter
	resourceLimiter := &ResourceLimiter{
		maxTotalMemory: config.MaxMemoryPerModule * 10, // Allow 10 modules by default
		maxTotalCPU:    config.MaxCPUPerModule * 10,
	}
	
	return &WASMRuntime{
		runtime:         runtime,
		config:          config,
		modules:         make(map[string]*ModuleInstance),
		resourceLimiter: resourceLimiter,
		capabilities:    make(map[string]*CapabilitySet),
		metrics:         &RuntimeMetrics{},
	}
}

// DefaultRuntimeConfig returns default runtime configuration
func DefaultRuntimeConfig() *RuntimeConfig {
	return &RuntimeConfig{
		WASIVersion:        "preview1",
		EnableWASI:         true,
		MaxMemoryPerModule: 50 * 1024 * 1024, // 50MB
		MaxCPUPerModule:    100 * time.Millisecond,
		StartupTimeout:     5 * time.Millisecond,
		EnableSandboxing:   true,
		EnableJIT:          true,
		CompilationCache:   true,
		EnableDebugInfo:    false,
		EnableProfiling:    false,
	}
}

// Initialize initializes the WASM runtime
func (r *WASMRuntime) Initialize(ctx context.Context) error {
	// Initialize WASI if enabled
	if r.config.EnableWASI {
		if r.config.WASIVersion == "preview1" {
			_, err := wasi_snapshot_preview1.Instantiate(ctx, r.runtime)
			if err != nil {
				return fmt.Errorf("failed to initialize WASI preview1: %v", err)
			}
		}
		// TODO: Add preview2 support when available
	}
	
	return nil
}

// Shutdown shuts down the WASM runtime
func (r *WASMRuntime) Shutdown(ctx context.Context) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	
	// Terminate all running modules
	for _, module := range r.modules {
		if module.State == ModuleStateRunning {
			module.Module.Close(ctx)
		}
	}
	
	// Close runtime
	return r.runtime.Close(ctx)
}

// LoadModule loads a WASM module
func (r *WASMRuntime) LoadModule(ctx context.Context, config *ModuleConfig) (*ModuleInstance, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	
	startTime := time.Now()
	
	// Check if module already exists
	if _, exists := r.modules[config.Name]; exists {
		return nil, fmt.Errorf("module already loaded: %s", config.Name)
	}
	
	// Check resource limits
	if !r.resourceLimiter.CanAllocate(config.MaxMemory, config.MaxCPU) {
		return nil, fmt.Errorf("insufficient resources to load module: %s", config.Name)
	}
	
	// Create module configuration
	moduleConfig := wazero.NewModuleConfig().
		WithName(config.Name).
		WithArgs(config.Arguments...)
	
	// Add environment variables
	for key, value := range config.Environment {
		moduleConfig = moduleConfig.WithEnv(key, value)
	}
	
	// Set up filesystem access if allowed
	capabilities := r.getCapabilities(config.Name)
	if capabilities.AllowFilesystemAccess {
		fsConfig := wazero.NewFSConfig()
		for _, path := range config.AllowedPaths {
			fsConfig = fsConfig.WithDirMount(path, path)
		}
		for _, path := range config.ReadOnlyPaths {
			fsConfig = fsConfig.WithDirMount(path, path)
		}
		moduleConfig = moduleConfig.WithFSConfig(fsConfig)
	}
	
	// Create timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, r.config.StartupTimeout)
	defer cancel()
	
	// Instantiate module
	module, err := r.runtime.InstantiateWithConfig(timeoutCtx, config.Binary, moduleConfig)
	if err != nil {
		r.metrics.ModulesError++
		return nil, fmt.Errorf("failed to instantiate module %s: %v", config.Name, err)
	}
	
	// Create module instance
	instance := &ModuleInstance{
		ID:           config.Name,
		Module:       module,
		Config:       config,
		StartedAt:    time.Now(),
		LastUsed:     time.Now(),
		State:        ModuleStateRunning,
		Capabilities: capabilities,
	}
	
	// Update resource usage
	r.resourceLimiter.Allocate(config.MaxMemory, config.MaxCPU)
	
	// Store module
	r.modules[config.Name] = instance
	
	// Update metrics
	r.metrics.ModulesLoaded++
	r.metrics.ModulesRunning++
	r.metrics.AverageStartupTime = time.Since(startTime)
	
	return instance, nil
}

// UnloadModule unloads a WASM module
func (r *WASMRuntime) UnloadModule(ctx context.Context, moduleID string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	
	instance, exists := r.modules[moduleID]
	if !exists {
		return fmt.Errorf("module not found: %s", moduleID)
	}
	
	// Close module
	if err := instance.Module.Close(ctx); err != nil {
		return fmt.Errorf("failed to close module %s: %v", moduleID, err)
	}
	
	// Update resource usage
	r.resourceLimiter.Release(instance.Config.MaxMemory, instance.Config.MaxCPU)
	
	// Update state
	instance.State = ModuleStateTerminated
	
	// Remove from active modules
	delete(r.modules, moduleID)
	
	// Update metrics
	r.metrics.ModulesRunning--
	r.metrics.ModulesTerminated++
	
	return nil
}

// CallFunction calls a function in a WASM module
func (r *WASMRuntime) CallFunction(ctx context.Context, moduleID, functionName string, args ...uint64) ([]uint64, error) {
	r.mutex.RLock()
	instance, exists := r.modules[moduleID]
	r.mutex.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("module not found: %s", moduleID)
	}
	
	if instance.State != ModuleStateRunning {
		return nil, fmt.Errorf("module not running: %s", moduleID)
	}
	
	// Update last used time
	instance.LastUsed = time.Now()
	
	// Get function
	fn := instance.Module.ExportedFunction(functionName)
	if fn == nil {
		return nil, fmt.Errorf("function not found: %s in module %s", functionName, moduleID)
	}
	
	// Create execution context with timeout
	execCtx, cancel := context.WithTimeout(ctx, instance.Config.MaxCPU)
	defer cancel()
	
	// Call function
	startTime := time.Now()
	results, err := fn.Call(execCtx, args...)
	executionTime := time.Since(startTime)
	
	// Update metrics
	instance.CPUUsage += executionTime
	r.metrics.AverageExecutionTime = executionTime
	
	if err != nil {
		// Check if it's a timeout or resource limit error
		if ctx.Err() == context.DeadlineExceeded {
			instance.State = ModuleStateError
			instance.Error = fmt.Errorf("function execution timeout: %s", functionName)
		}
		return nil, fmt.Errorf("function call failed: %v", err)
	}
	
	return results, nil
}

// GetModule returns a module instance
func (r *WASMRuntime) GetModule(moduleID string) (*ModuleInstance, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	
	instance, exists := r.modules[moduleID]
	if !exists {
		return nil, fmt.Errorf("module not found: %s", moduleID)
	}
	
	return instance, nil
}

// ListModules returns all loaded modules
func (r *WASMRuntime) ListModules() []*ModuleInstance {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	
	modules := make([]*ModuleInstance, 0, len(r.modules))
	for _, instance := range r.modules {
		modules = append(modules, instance)
	}
	
	return modules
}

// GetMetrics returns runtime metrics
func (r *WASMRuntime) GetMetrics() *RuntimeMetrics {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	
	// Update current metrics
	r.metrics.ModulesRunning = int64(len(r.modules))
	r.metrics.TotalMemoryUsed = r.resourceLimiter.currentMemory
	r.metrics.TotalCPUUsed = r.resourceLimiter.currentCPU
	
	return r.metrics
}

// SetCapabilities sets capabilities for a module
func (r *WASMRuntime) SetCapabilities(moduleID string, capabilities *CapabilitySet) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	
	r.capabilities[moduleID] = capabilities
}

// getCapabilities returns capabilities for a module
func (r *WASMRuntime) getCapabilities(moduleID string) *CapabilitySet {
	if capabilities, exists := r.capabilities[moduleID]; exists {
		return capabilities
	}
	
	// Return default restricted capabilities
	return &CapabilitySet{
		AllowedSyscalls:       make(map[string]bool),
		AllowNetworkAccess:    false,
		AllowFilesystemAccess: false,
		AllowContextRead:      false,
		AllowContextWrite:     false,
		AllowDriverCalls:      false,
	}
}

// Resource limiter methods
func (rl *ResourceLimiter) CanAllocate(memory int64, cpu time.Duration) bool {
	rl.mutex.RLock()
	defer rl.mutex.RUnlock()
	
	return (rl.currentMemory+memory <= rl.maxTotalMemory) &&
		   (rl.currentCPU+cpu <= rl.maxTotalCPU)
}

func (rl *ResourceLimiter) Allocate(memory int64, cpu time.Duration) {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()
	
	rl.currentMemory += memory
	rl.currentCPU += cpu
}

func (rl *ResourceLimiter) Release(memory int64, cpu time.Duration) {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()
	
	rl.currentMemory -= memory
	rl.currentCPU -= cpu
	
	if rl.currentMemory < 0 {
		rl.currentMemory = 0
	}
	if rl.currentCPU < 0 {
		rl.currentCPU = 0
	}
}

// String methods for debugging
func (s ModuleState) String() string {
	switch s {
	case ModuleStateInitializing:
		return "initializing"
	case ModuleStateRunning:
		return "running"
	case ModuleStateSuspended:
		return "suspended"
	case ModuleStateTerminated:
		return "terminated"
	case ModuleStateError:
		return "error"
	default:
		return "unknown"
	}
} 