package performance

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/cam-os/kernel/internal/arbitration"
	"github.com/cam-os/kernel/internal/scheduler"
)

// OptimizationEngine provides performance optimization and tuning capabilities
type OptimizationEngine struct {
	mu     sync.RWMutex
	config *OptimizationConfig

	// Performance metrics
	metrics           *PerformanceMetrics
	latencyHistory    []time.Duration
	throughputHistory []float64

	// Caching systems
	decisionCache *DecisionCache
	agentCache    *AgentCache

	// Parallel processing
	workerPool     *WorkerPool
	batchProcessor *BatchProcessor

	// Auto-tuning
	autoTuner         *AutoTuner
	priorityOptimizer *PriorityOptimizer
}

// OptimizationConfig holds performance optimization configuration
type OptimizationConfig struct {
	// Cache settings
	DecisionCacheSize int
	AgentCacheSize    int
	CacheTTL          time.Duration

	// Parallel processing
	WorkerPoolSize int
	BatchSize      int
	MaxConcurrency int

	// Performance targets
	TargetLatency     time.Duration // Sub-millisecond target
	TargetThroughput  float64       // Requests per second
	LatencyPercentile float64       // P99 latency target

	// Auto-tuning
	EnableAutoTuning   bool
	TuningInterval     time.Duration
	AdaptivePriorities bool
}

// PerformanceMetrics tracks comprehensive performance data
type PerformanceMetrics struct {
	mu sync.RWMutex

	// Latency metrics
	AverageLatency time.Duration
	P50Latency     time.Duration
	P95Latency     time.Duration
	P99Latency     time.Duration

	// Throughput metrics
	RequestsPerSecond float64
	PeakThroughput    float64

	// Cache metrics
	CacheHitRate   float64
	CacheMissCount int64

	// Resource utilization
	CPUUtilization    float64
	MemoryUtilization float64
	GoroutineCount    int

	// Quality metrics
	DecisionAccuracy float64
	SuccessRate      float64

	lastUpdateTime time.Time
}

// DecisionCache provides fast lookup for recent arbitration decisions
type DecisionCache struct {
	mu        sync.RWMutex
	cache     map[string]*CachedDecision
	keyOrder  []string
	maxSize   int
	ttl       time.Duration
	hitCount  int64
	missCount int64
}

// CachedDecision represents a cached arbitration decision
type CachedDecision struct {
	Result    *arbitration.Result
	Timestamp time.Time
	Hash      string
}

// AgentCache provides fast agent capability and status lookup
type AgentCache struct {
	mu            sync.RWMutex
	agentStatus   map[string]*AgentStatus
	capabilityMap map[string][]string // capability -> agent IDs
	lastUpdate    time.Time
	ttl           time.Duration
}

// AgentStatus represents cached agent status information
type AgentStatus struct {
	AgentID          string
	Available        bool
	CurrentLoad      float64
	PerformanceScore float64
	LastSeen         time.Time
	Capabilities     map[string]float64
}

// WorkerPool manages parallel processing of arbitration requests
type WorkerPool struct {
	workers    int
	taskQueue  chan *ArbitrationTask
	resultChan chan *ArbitrationResult
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
}

// ArbitrationTask represents a task to be processed by the worker pool
type ArbitrationTask struct {
	ID       string
	Task     *arbitration.Task
	PolicyID string
	Callback func(*arbitration.Result, error)
}

// ArbitrationResult represents the result from worker pool processing
type ArbitrationResult struct {
	TaskID string
	Result *arbitration.Result
	Error  error
}

// BatchProcessor processes multiple arbitration requests in batches
type BatchProcessor struct {
	mu           sync.Mutex
	batchSize    int
	currentBatch []*ArbitrationTask
	flushTimer   *time.Timer
	flushDelay   time.Duration
}

// AutoTuner automatically adjusts system parameters for optimal performance
type AutoTuner struct {
	mu       sync.RWMutex
	enabled  bool
	interval time.Duration

	// Tuning parameters
	priorityWeights *scheduler.PriorityDimensions
	workerCount     int
	batchSize       int

	// Performance tracking
	currentMetrics *PerformanceMetrics
	bestMetrics    *PerformanceMetrics
	bestConfig     *TuningConfig

	// Tuning state
	tuningHistory  []*TuningAttempt
	currentAttempt *TuningAttempt
}

// TuningConfig represents a set of tuning parameters
type TuningConfig struct {
	PriorityWeights *scheduler.PriorityDimensions
	WorkerCount     int
	BatchSize       int
	CacheSize       int
}

// TuningAttempt tracks a tuning attempt and its results
type TuningAttempt struct {
	Config      *TuningConfig
	StartTime   time.Time
	EndTime     time.Time
	Metrics     *PerformanceMetrics
	Improvement float64
}

// PriorityOptimizer optimizes the 5-dimensional priority system
type PriorityOptimizer struct {
	mu      sync.RWMutex
	enabled bool

	// Priority dimensions tracking
	dimensionWeights     *scheduler.PriorityDimensions
	dimensionPerformance map[string]*DimensionPerformance

	// Optimization state
	optimizationHistory []*OptimizationRun
	currentRun          *OptimizationRun
}

// DimensionPerformance tracks performance for each priority dimension
type DimensionPerformance struct {
	Dimension     string
	Weight        float64
	Accuracy      float64
	Throughput    float64
	LatencyImpact time.Duration
	LastOptimized time.Time
}

// OptimizationRun represents a priority optimization run
type OptimizationRun struct {
	StartTime      time.Time
	EndTime        time.Time
	InitialWeights *scheduler.PriorityDimensions
	FinalWeights   *scheduler.PriorityDimensions
	Improvement    float64
	TestCount      int
}

// NewOptimizationEngine creates a new performance optimization engine
func NewOptimizationEngine(config *OptimizationConfig) *OptimizationEngine {
	ctx, cancel := context.WithCancel(context.Background())

	engine := &OptimizationEngine{
		config:            config,
		metrics:           NewPerformanceMetrics(),
		latencyHistory:    make([]time.Duration, 0, 1000),
		throughputHistory: make([]float64, 0, 1000),
		decisionCache:     NewDecisionCache(config.DecisionCacheSize, config.CacheTTL),
		agentCache:        NewAgentCache(config.AgentCacheSize, config.CacheTTL),
		workerPool:        NewWorkerPool(config.WorkerPoolSize, ctx, cancel),
		batchProcessor:    NewBatchProcessor(config.BatchSize),
		autoTuner:         NewAutoTuner(config),
		priorityOptimizer: NewPriorityOptimizer(),
	}

	// Start background optimization if enabled
	if config.EnableAutoTuning {
		go engine.autoTuner.Start(ctx, engine)
	}

	return engine
}

// OptimizeArbitration performs optimized arbitration with caching and parallel processing
func (oe *OptimizationEngine) OptimizeArbitration(ctx context.Context, task *arbitration.Task, policyID string, engine *arbitration.Engine) (*arbitration.Result, error) {
	startTime := time.Now()

	// Step 1: Check decision cache
	if cachedResult := oe.decisionCache.Get(task, policyID); cachedResult != nil {
		oe.updateLatencyMetrics(time.Since(startTime))
		return cachedResult.Result, nil
	}

	// Step 2: Optimize agent selection using cache
	if err := oe.optimizeAgentSelection(ctx, task); err != nil {
		return nil, fmt.Errorf("agent optimization failed: %v", err)
	}

	// Step 3: Perform arbitration with optimizations
	result, err := oe.performOptimizedArbitration(ctx, task, policyID, engine)
	if err != nil {
		return nil, err
	}

	// Step 4: Cache the result
	oe.decisionCache.Set(task, policyID, result)

	// Step 5: Update performance metrics
	latency := time.Since(startTime)
	oe.updateLatencyMetrics(latency)

	// Step 6: Trigger auto-tuning if performance degrades
	if latency > oe.config.TargetLatency {
		oe.autoTuner.TriggerTuning()
	}

	return result, nil
}

// performOptimizedArbitration executes arbitration with performance optimizations
func (oe *OptimizationEngine) performOptimizedArbitration(ctx context.Context, task *arbitration.Task, policyID string, engine *arbitration.Engine) (*arbitration.Result, error) {
	// Use worker pool for parallel processing if available
	if oe.workerPool != nil && oe.workerPool.AvailableWorkers() > 0 {
		return oe.processWithWorkerPool(ctx, task, policyID, engine)
	}

	// Fallback to direct processing with optimizations
	return oe.processDirectly(ctx, task, policyID, engine)
}

// processWithWorkerPool processes arbitration using the worker pool
func (oe *OptimizationEngine) processWithWorkerPool(ctx context.Context, task *arbitration.Task, policyID string, engine *arbitration.Engine) (*arbitration.Result, error) {
	resultChan := make(chan *ArbitrationResult, 1)

	arbitrationTask := &ArbitrationTask{
		ID:       task.ID,
		Task:     task,
		PolicyID: policyID,
		Callback: func(result *arbitration.Result, err error) {
			resultChan <- &ArbitrationResult{
				TaskID: task.ID,
				Result: result,
				Error:  err,
			}
		},
	}

	// Submit to worker pool
	select {
	case oe.workerPool.taskQueue <- arbitrationTask:
		// Wait for result
		select {
		case result := <-resultChan:
			return result.Result, result.Error
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(oe.config.TargetLatency * 10): // Timeout
			return nil, fmt.Errorf("arbitration timeout")
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		// Worker pool full, fallback to direct processing
		return oe.processDirectly(ctx, task, policyID, engine)
	}
}

// processDirectly processes arbitration directly with optimizations
func (oe *OptimizationEngine) processDirectly(ctx context.Context, task *arbitration.Task, policyID string, engine *arbitration.Engine) (*arbitration.Result, error) {
	// Apply priority optimization
	if oe.priorityOptimizer.enabled {
		oe.optimizeTaskPriority(task)
	}

	// Execute arbitration
	return engine.Arbitrate(ctx, task, policyID)
}

// optimizeAgentSelection optimizes agent selection using cached data
func (oe *OptimizationEngine) optimizeAgentSelection(ctx context.Context, task *arbitration.Task) error {
	// Get cached agent information
	availableAgents := oe.agentCache.GetAvailableAgents(task.Requirements)

	if len(availableAgents) == 0 {
		// No cached agents available, force cache refresh
		return oe.agentCache.Refresh(ctx)
	}

	// Sort agents by performance score for optimal selection
	oe.sortAgentsByPerformance(availableAgents)

	return nil
}

// optimizeTaskPriority applies priority optimization to tasks
func (oe *OptimizationEngine) optimizeTaskPriority(task *arbitration.Task) {
	oe.priorityOptimizer.mu.RLock()
	defer oe.priorityOptimizer.mu.RUnlock()

	if !oe.priorityOptimizer.enabled {
		return
	}

	// Apply learned priority weights
	// This would adjust the task priority based on optimization learnings
	baseScore := float64(task.Priority)

	// Apply dimension-specific optimizations
	for dimension, performance := range oe.priorityOptimizer.dimensionPerformance {
		if performance.Accuracy > 0.8 { // High-performing dimension
			multiplier := 1.0 + (performance.Accuracy-0.8)*0.5 // Up to 10% bonus
			baseScore *= multiplier

			// Log optimization application
			fmt.Printf("Applied %s optimization: %.2f multiplier\n", dimension, multiplier)
		}
	}

	task.Priority = int64(baseScore)
}

// sortAgentsByPerformance sorts agents by their performance scores
func (oe *OptimizationEngine) sortAgentsByPerformance(agents []*AgentStatus) {
	// Simple sort by performance score (highest first)
	for i := 0; i < len(agents); i++ {
		for j := i + 1; j < len(agents); j++ {
			if agents[i].PerformanceScore < agents[j].PerformanceScore {
				agents[i], agents[j] = agents[j], agents[i]
			}
		}
	}
}

// updateLatencyMetrics updates performance metrics with new latency data
func (oe *OptimizationEngine) updateLatencyMetrics(latency time.Duration) {
	oe.mu.Lock()
	defer oe.mu.Unlock()

	// Add to latency history
	oe.latencyHistory = append(oe.latencyHistory, latency)

	// Keep only last 1000 entries
	if len(oe.latencyHistory) > 1000 {
		oe.latencyHistory = oe.latencyHistory[1:]
	}

	// Update metrics
	oe.metrics.UpdateLatency(oe.latencyHistory)
}

// GetMetrics returns current performance metrics
func (oe *OptimizationEngine) GetMetrics() *PerformanceMetrics {
	oe.metrics.mu.RLock()
	defer oe.metrics.mu.RUnlock()

	// Create a copy to avoid race conditions
	metrics := *oe.metrics
	return &metrics
}

// GetOptimizationReport generates a comprehensive optimization report
func (oe *OptimizationEngine) GetOptimizationReport() map[string]interface{} {
	oe.mu.RLock()
	defer oe.mu.RUnlock()

	metrics := oe.GetMetrics()

	report := map[string]interface{}{
		"performance": map[string]interface{}{
			"average_latency":    metrics.AverageLatency.String(),
			"p99_latency":        metrics.P99Latency.String(),
			"throughput":         metrics.RequestsPerSecond,
			"cache_hit_rate":     metrics.CacheHitRate,
			"cpu_utilization":    metrics.CPUUtilization,
			"memory_utilization": metrics.MemoryUtilization,
		},
		"optimization": map[string]interface{}{
			"auto_tuning_enabled": oe.config.EnableAutoTuning,
			"target_latency":      oe.config.TargetLatency.String(),
			"target_throughput":   oe.config.TargetThroughput,
			"worker_pool_size":    oe.config.WorkerPoolSize,
			"batch_size":          oe.config.BatchSize,
		},
		"cache": map[string]interface{}{
			"decision_cache_size": oe.config.DecisionCacheSize,
			"agent_cache_size":    oe.config.AgentCacheSize,
			"cache_ttl":           oe.config.CacheTTL.String(),
		},
	}

	// Add auto-tuning report if enabled
	if oe.autoTuner.enabled {
		report["auto_tuning"] = oe.autoTuner.GetReport()
	}

	// Add priority optimization report
	if oe.priorityOptimizer.enabled {
		report["priority_optimization"] = oe.priorityOptimizer.GetReport()
	}

	return report
}

// Helper constructors and utility functions

func NewPerformanceMetrics() *PerformanceMetrics {
	return &PerformanceMetrics{
		lastUpdateTime: time.Now(),
	}
}

func (pm *PerformanceMetrics) UpdateLatency(latencyHistory []time.Duration) {
	if len(latencyHistory) == 0 {
		return
	}

	// Calculate percentiles
	sorted := make([]time.Duration, len(latencyHistory))
	copy(sorted, latencyHistory)

	// Simple sort
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[i] > sorted[j] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	pm.P50Latency = sorted[len(sorted)/2]
	pm.P95Latency = sorted[int(float64(len(sorted))*0.95)]
	pm.P99Latency = sorted[int(float64(len(sorted))*0.99)]

	// Calculate average
	var total time.Duration
	for _, latency := range latencyHistory {
		total += latency
	}
	pm.AverageLatency = total / time.Duration(len(latencyHistory))

	pm.lastUpdateTime = time.Now()
}

func NewDecisionCache(size int, ttl time.Duration) *DecisionCache {
	return &DecisionCache{
		cache:    make(map[string]*CachedDecision),
		keyOrder: make([]string, 0, size),
		maxSize:  size,
		ttl:      ttl,
	}
}

func (dc *DecisionCache) Get(task *arbitration.Task, policyID string) *CachedDecision {
	dc.mu.RLock()
	defer dc.mu.RUnlock()

	key := dc.generateKey(task, policyID)

	if decision, exists := dc.cache[key]; exists {
		// Check TTL
		if time.Since(decision.Timestamp) < dc.ttl {
			dc.hitCount++
			return decision
		}
		// Expired, remove
		delete(dc.cache, key)
	}

	dc.missCount++
	return nil
}

func (dc *DecisionCache) Set(task *arbitration.Task, policyID string, result *arbitration.Result) {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	key := dc.generateKey(task, policyID)

	// Remove oldest if at capacity
	if len(dc.cache) >= dc.maxSize && len(dc.keyOrder) > 0 {
		oldestKey := dc.keyOrder[0]
		delete(dc.cache, oldestKey)
		dc.keyOrder = dc.keyOrder[1:]
	}

	dc.cache[key] = &CachedDecision{
		Result:    result,
		Timestamp: time.Now(),
		Hash:      key,
	}
	dc.keyOrder = append(dc.keyOrder, key)
}

func (dc *DecisionCache) generateKey(task *arbitration.Task, policyID string) string {
	// Simple key generation - in production, use a more sophisticated hash
	return fmt.Sprintf("%s_%s_%d_%s", task.ID, policyID, task.Priority, task.Type)
}

func NewAgentCache(size int, ttl time.Duration) *AgentCache {
	return &AgentCache{
		agentStatus:   make(map[string]*AgentStatus),
		capabilityMap: make(map[string][]string),
		ttl:           ttl,
	}
}

func (ac *AgentCache) GetAvailableAgents(requirements []string) []*AgentStatus {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	var availableAgents []*AgentStatus

	// Find agents with required capabilities
	agentCandidates := make(map[string]bool)
	for _, requirement := range requirements {
		if agentIDs, exists := ac.capabilityMap[requirement]; exists {
			for _, agentID := range agentIDs {
				agentCandidates[agentID] = true
			}
		}
	}

	// Filter by availability
	for agentID := range agentCandidates {
		if status, exists := ac.agentStatus[agentID]; exists && status.Available {
			availableAgents = append(availableAgents, status)
		}
	}

	return availableAgents
}

func (ac *AgentCache) Refresh(ctx context.Context) error {
	// In a real implementation, this would fetch fresh agent data
	// For now, just simulate a refresh
	ac.mu.Lock()
	defer ac.mu.Unlock()

	ac.lastUpdate = time.Now()
	return nil
}

func NewWorkerPool(size int, ctx context.Context, cancel context.CancelFunc) *WorkerPool {
	return &WorkerPool{
		workers:    size,
		taskQueue:  make(chan *ArbitrationTask, size*2),
		resultChan: make(chan *ArbitrationResult, size*2),
		ctx:        ctx,
		cancel:     cancel,
	}
}

func (wp *WorkerPool) AvailableWorkers() int {
	// Simple availability check
	return wp.workers - len(wp.taskQueue)
}

func NewBatchProcessor(batchSize int) *BatchProcessor {
	return &BatchProcessor{
		batchSize:    batchSize,
		currentBatch: make([]*ArbitrationTask, 0, batchSize),
		flushDelay:   10 * time.Millisecond,
	}
}

func NewAutoTuner(config *OptimizationConfig) *AutoTuner {
	return &AutoTuner{
		enabled:  config.EnableAutoTuning,
		interval: config.TuningInterval,
		priorityWeights: &scheduler.PriorityDimensions{
			Urgency:    0.4,
			Importance: 0.3,
			Efficiency: 0.2,
			Energy:     0.05,
			Trust:      0.05,
		},
		tuningHistory: make([]*TuningAttempt, 0, 100),
	}
}

func (at *AutoTuner) Start(ctx context.Context, engine *OptimizationEngine) {
	ticker := time.NewTicker(at.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			at.performTuning(engine)
		}
	}
}

func (at *AutoTuner) TriggerTuning() {
	// Trigger immediate tuning if performance degrades
	go func() {
		// In a real implementation, this would trigger immediate optimization
		fmt.Println("Performance degradation detected, triggering optimization")
	}()
}

func (at *AutoTuner) performTuning(engine *OptimizationEngine) {
	at.mu.Lock()
	defer at.mu.Unlock()

	// Get current metrics
	currentMetrics := engine.GetMetrics()

	// Simple tuning: adjust worker pool size based on CPU utilization
	if currentMetrics.CPUUtilization > 0.8 {
		// Reduce workers if CPU is high
		at.workerCount = max(1, at.workerCount-1)
	} else if currentMetrics.CPUUtilization < 0.5 {
		// Increase workers if CPU is low
		at.workerCount = min(runtime.NumCPU()*2, at.workerCount+1)
	}

	fmt.Printf("Auto-tuning: adjusted worker count to %d based on CPU %.2f%%\n",
		at.workerCount, currentMetrics.CPUUtilization*100)
}

func (at *AutoTuner) GetReport() map[string]interface{} {
	at.mu.RLock()
	defer at.mu.RUnlock()

	return map[string]interface{}{
		"enabled":        at.enabled,
		"interval":       at.interval.String(),
		"worker_count":   at.workerCount,
		"batch_size":     at.batchSize,
		"tuning_history": len(at.tuningHistory),
	}
}

func NewPriorityOptimizer() *PriorityOptimizer {
	return &PriorityOptimizer{
		enabled: true,
		dimensionWeights: &scheduler.PriorityDimensions{
			Urgency:    0.4,
			Importance: 0.3,
			Efficiency: 0.2,
			Energy:     0.05,
			Trust:      0.05,
		},
		dimensionPerformance: make(map[string]*DimensionPerformance),
		optimizationHistory:  make([]*OptimizationRun, 0, 50),
	}
}

func (po *PriorityOptimizer) GetReport() map[string]interface{} {
	po.mu.RLock()
	defer po.mu.RUnlock()

	return map[string]interface{}{
		"enabled":               po.enabled,
		"dimension_weights":     po.dimensionWeights,
		"optimization_runs":     len(po.optimizationHistory),
		"dimension_performance": po.dimensionPerformance,
	}
}

// Utility functions
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
