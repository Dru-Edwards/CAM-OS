package arbitration

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cam-os/kernel/internal/policy"
	"github.com/cam-os/kernel/internal/scheduler"
	"github.com/cam-os/kernel/internal/security"
)

// DataIntegrator interface to avoid import cycles
type DataIntegrator interface {
	GetCachedAgents() []*CognitiveAgent
	GetCachedTasks() []*Task
	GetMetrics() map[string]interface{}
}

// TaskType represents different types of tasks
type TaskType int

const (
	TaskTypeArbitration TaskType = iota
	TaskTypeCollaboration
	TaskTypeRouting
	TaskTypeAnalysis
)

// Task represents a task to be arbitrated
type Task struct {
	ID           string
	Description  string
	Requirements []string
	Metadata     map[string]string
	Priority     int64
	Deadline     time.Time
	Type         TaskType
	AgentID      string
}

// Config holds the arbitration engine configuration
type Config struct {
	Scheduler               *scheduler.TripleHelixScheduler
	PolicyEngine            *policy.Engine
	SecurityManager         *security.Manager
	DataIntegrator          DataIntegrator
	EnableCognitiveArbitration bool
	PerformanceLearningEnabled bool
	DefaultConfidenceThreshold float64
}

// Engine handles task arbitration with cognitive capabilities
type Engine struct {
	config          *Config
	scheduler       *scheduler.TripleHelixScheduler
	policyEngine    *policy.Engine
	securityManager *security.Manager
	dataIntegrator  DataIntegrator
	cognitiveEngine    *CognitiveEngine

	// Task and agent tracking
	mu              sync.RWMutex
	activeTasks     map[string]*Task
	taskHistory     map[string]*Task
	rollbacks       map[string]*TaskRollback
	agents          map[string]*Agent
	capabilityIndex map[string][]string // capability -> []agentID
	
	// Performance metrics
	totalArbitrations    int64
	successfulArbitrations int64
	averageDecisionTime  time.Duration
	confidenceHistory    []float64
	
	// Learning system
	outcomeTracker    map[string]*ArbitrationOutcome
	performanceTrends map[string]*PerformanceTrend
}

// ArbitrationOutcome tracks the outcome of arbitration decisions
type ArbitrationOutcome struct {
	TaskID           string
	DecisionTime     time.Time
	PredictedSuccess float64
	ActualSuccess    bool
	PredictedDuration time.Duration
	ActualDuration   time.Duration
	QualityScore     float64
	AgentFeedback    map[string]interface{}
}

// PerformanceTrend tracks performance trends for continuous improvement
type PerformanceTrend struct {
	TimeWindow       time.Duration
	AverageAccuracy  float64
	DecisionLatency  time.Duration
	ConfidenceScore  float64
	ImprovementRate  float64
}

// NewEngine creates a new enhanced arbitration engine
func NewEngine(config *Config) *Engine {
	engine := &Engine{
		config:          config,
		scheduler:       config.Scheduler,
		policyEngine:    config.PolicyEngine,
		securityManager: config.SecurityManager,
		dataIntegrator:  config.DataIntegrator,
		activeTasks:     make(map[string]*Task),
		taskHistory:     make(map[string]*Task),
		rollbacks:       make(map[string]*TaskRollback),
		agents:          make(map[string]*Agent),
		capabilityIndex: make(map[string][]string),
		outcomeTracker:  make(map[string]*ArbitrationOutcome),
		performanceTrends: make(map[string]*PerformanceTrend),
		confidenceHistory: make([]float64, 0, 1000),
	}
	
	// Initialize cognitive engine if enabled
	if config.EnableCognitiveArbitration {
		engine.cognitiveEngine = NewCognitiveEngine()
	}
	
	return engine
}

// Initialize initializes the arbitration engine
func (e *Engine) Initialize(ctx context.Context) error {
	// Initialize cognitive engine
	if e.cognitiveEngine != nil && e.dataIntegrator != nil {
		// Load existing agents from integration sources
		agents := e.dataIntegrator.GetCachedAgents()
		for _, agent := range agents {
			if err := e.cognitiveEngine.RegisterCognitiveAgent(agent); err != nil {
				return fmt.Errorf("failed to register cognitive agent %s: %v", agent.ID, err)
			}
		}
	}
	
	// Start performance learning if enabled
	if e.config.PerformanceLearningEnabled {
		go e.performanceLearningLoop(ctx)
	}
	
	return nil
}

// Shutdown shuts down the arbitration engine
func (e *Engine) Shutdown(ctx context.Context) error {
	// Save performance data and learning outcomes
	e.persistLearningData(ctx)
	return nil
}

// Arbitrate performs enhanced task arbitration using cognitive algorithms
func (e *Engine) Arbitrate(ctx context.Context, task *Task, policyID string) (*Result, error) {
	startTime := time.Now()
	e.mu.Lock()
	e.totalArbitrations++
	arbitrationID := e.totalArbitrations
	e.mu.Unlock()
	
	// Generate trace ID for explainability
	traceID := fmt.Sprintf("trace_%d_%d", arbitrationID, time.Now().UnixNano())
	
	// Step 1: Check policy constraints
	if policyID != "" {
		allowed, err := e.checkPolicyConstraints(ctx, task, policyID)
		if err != nil {
			return nil, fmt.Errorf("policy check failed: %v", err)
		}
		if !allowed {
			return nil, fmt.Errorf("task %s not allowed by policy %s", task.ID, policyID)
		}
	}
	
	// Step 2: Use cognitive arbitration if enabled
	if e.cognitiveEngine != nil {
		return e.cognitiveArbitrate(ctx, task, traceID, startTime)
	}
	
	// Step 3: Fallback to basic arbitration
	return e.basicArbitrate(ctx, task, traceID, startTime)
}

// cognitiveArbitrate performs intelligent cognitive arbitration
func (e *Engine) cognitiveArbitrate(ctx context.Context, task *Task, traceID string, startTime time.Time) (*Result, error) {
	// Prepare constraints from scheduler and policy
	constraints := map[string]interface{}{
		"max_load":        0.9,
		"min_trust":       0.5,
		"energy_priority": true,
	}
	
	// Get cognitive decision
	decision, err := e.cognitiveEngine.CognitiveArbitrate(ctx, task, constraints)
	if err != nil {
		return nil, fmt.Errorf("cognitive arbitration failed: %v", err)
	}
	
	// Convert to scheduler task if decision confidence is acceptable
	if decision.Confidence >= e.config.DefaultConfidenceThreshold {
		scheduledTask := &scheduler.ScheduledTask{
			ID:              task.ID,
			Type:            convertTaskType(task.Type),
			UrgencyScore:    e.calculateUrgencyScore(task),
			ImportanceScore: e.calculateImportanceScore(task),
			EfficiencyScore: decision.DecisionFactors["energy_efficiency"],
			EnergyScore:     decision.DecisionFactors["energy_efficiency"],
			TrustScore:      decision.DecisionFactors["trust_level"],
			AgentID:         decision.SelectedAgent.ID,
			Metadata:        task.Metadata,
			Deadline:        task.Deadline,
			MaxRetries:      3,
		}
		
		// Schedule the task
		if err := e.scheduler.ScheduleTask(scheduledTask); err != nil {
			return nil, fmt.Errorf("failed to schedule task: %v", err)
		}
	}
	
	// Record decision metrics
	decisionTime := time.Since(startTime)
	e.recordDecisionMetrics(decision.Confidence, decisionTime)
	
	// Create outcome tracker for learning
	outcome := &ArbitrationOutcome{
		TaskID:           task.ID,
		DecisionTime:     startTime,
		PredictedSuccess: decision.PredictedOutcome.SuccessProbability,
		PredictedDuration: decision.PredictedOutcome.EstimatedDuration,
	}
	e.mu.Lock()
	e.outcomeTracker[task.ID] = outcome
	e.mu.Unlock()
	
	// Build comprehensive result
	result := &Result{
		TaskID:        task.ID,
		AssignedAgent: decision.SelectedAgent.ID,
		Provider:      "cognitive-arbitration",
		Confidence:    decision.Confidence,
		Reasoning:     fmt.Sprintf("Cognitive decision: %s", decision.Reasoning),
		Metadata:      make(map[string]string),
		TraceID:       traceID,
		Timestamp:     time.Now(),
	}
	
	// Add decision factors to metadata
	result.Metadata["capability_match"] = fmt.Sprintf("%.2f", decision.DecisionFactors["capability_match"])
	result.Metadata["performance_history"] = fmt.Sprintf("%.2f", decision.DecisionFactors["performance_history"])
	result.Metadata["availability"] = fmt.Sprintf("%.2f", decision.DecisionFactors["current_availability"])
	result.Metadata["estimated_duration"] = decision.PredictedOutcome.EstimatedDuration.String()
	result.Metadata["success_probability"] = fmt.Sprintf("%.2f", decision.PredictedOutcome.SuccessProbability)
	
	return result, nil
}

// basicArbitrate performs traditional arbitration for fallback scenarios
func (e *Engine) basicArbitrate(ctx context.Context, task *Task, traceID string, startTime time.Time) (*Result, error) {
	// Find suitable agent using traditional methods
	agentID := e.findBestAgent(task)
	if agentID == "" {
		agentID = task.AgentID // Use provided agent as fallback
	}
	
	// Convert to scheduler task
	scheduledTask := &scheduler.ScheduledTask{
		ID:              task.ID,
		Type:            convertTaskType(task.Type),
		UrgencyScore:    e.calculateUrgencyScore(task),
		ImportanceScore: e.calculateImportanceScore(task),
		EfficiencyScore: 0.6,
		EnergyScore:     0.5,
		TrustScore:      0.8,
		AgentID:         agentID,
		Metadata:        task.Metadata,
		Deadline:        task.Deadline,
		MaxRetries:      3,
	}
	
	// Schedule the task
	if err := e.scheduler.ScheduleTask(scheduledTask); err != nil {
		return nil, fmt.Errorf("failed to schedule task: %v", err)
	}
	
	// Record decision metrics
	decisionTime := time.Since(startTime)
	confidence := 0.7 // Default confidence for basic arbitration
	e.recordDecisionMetrics(confidence, decisionTime)
	
	// Create result
	result := &Result{
		TaskID:        task.ID,
		AssignedAgent: agentID,
		Provider:      "basic-arbitration",
		Confidence:    confidence,
		Reasoning:     "Basic arbitration based on agent capabilities and system load",
		Metadata:      make(map[string]string),
		TraceID:       traceID,
		Timestamp:     time.Now(),
	}
	
	return result, nil
}

// checkPolicyConstraints validates task against policy constraints
func (e *Engine) checkPolicyConstraints(ctx context.Context, task *Task, policyID string) (bool, error) {
	if e.policyEngine == nil {
		return true, nil // No policy engine, allow all
	}
	
	// Create policy context from task
	policyContext := map[string]string{
		"task_type":    fmt.Sprintf("%d", task.Type),
		"priority":     fmt.Sprintf("%d", task.Priority),
		"agent_id":     task.AgentID,
		"deadline":     task.Deadline.Format(time.RFC3339),
	}
	
	// Add task metadata to policy context
	for key, value := range task.Metadata {
		policyContext["meta_"+key] = value
	}
	
	// Query policy engine
	result, err := e.policyEngine.Query(ctx, policyID, "arbitration_request", policyContext)
	if err != nil {
		return false, err
	}
	
	return result.Allowed, nil
}

// calculateUrgencyScore calculates urgency based on deadline proximity
func (e *Engine) calculateUrgencyScore(task *Task) float64 {
	timeToDeadline := time.Until(task.Deadline)
	if timeToDeadline <= 0 {
		return 1.0 // Past deadline, maximum urgency
	}
	
	// Urgency increases exponentially as deadline approaches
	hours := timeToDeadline.Hours()
	if hours <= 1 {
		return 1.0
	} else if hours <= 6 {
		return 0.9
	} else if hours <= 24 {
		return 0.7
	} else {
		return 0.4
	}
}

// calculateImportanceScore calculates importance based on priority and task type
func (e *Engine) calculateImportanceScore(task *Task) float64 {
	// Normalize priority (assuming 0-100 scale)
	priorityScore := float64(task.Priority) / 100.0
	
	// Adjust based on task type
	typeMultiplier := 1.0
	switch task.Type {
	case TaskTypeArbitration:
		typeMultiplier = 1.2 // Arbitration tasks are slightly more important
	case TaskTypeCollaboration:
		typeMultiplier = 1.1
	case TaskTypeRouting:
		typeMultiplier = 0.9
	case TaskTypeAnalysis:
		typeMultiplier = 0.8
	}
	
	return priorityScore * typeMultiplier
}

// findBestAgent finds the best agent using traditional methods
func (e *Engine) findBestAgent(task *Task) string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	// Simple capability matching
	for _, requirement := range task.Requirements {
		if agentIDs, exists := e.capabilityIndex[requirement]; exists && len(agentIDs) > 0 {
			return agentIDs[0] // Return first capable agent
		}
	}
	
	// Return any available agent
	for agentID := range e.agents {
		return agentID
	}
	
	return ""
}

// recordDecisionMetrics records metrics for decision quality tracking
func (e *Engine) recordDecisionMetrics(confidence float64, decisionTime time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	
	// Update average decision time
	if e.averageDecisionTime == 0 {
		e.averageDecisionTime = decisionTime
	} else {
		e.averageDecisionTime = (e.averageDecisionTime + decisionTime) / 2
	}
	
	// Track confidence history (keep last 1000 decisions)
	e.confidenceHistory = append(e.confidenceHistory, confidence)
	if len(e.confidenceHistory) > 1000 {
		e.confidenceHistory = e.confidenceHistory[1:]
	}
}

// performanceLearningLoop continuously learns from arbitration outcomes
func (e *Engine) performanceLearningLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute) // Check every 5 minutes
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.analyzePerformanceOutcomes(ctx)
		}
	}
}

// analyzePerformanceOutcomes analyzes arbitration outcomes for learning
func (e *Engine) analyzePerformanceOutcomes(ctx context.Context) {
	e.mu.Lock()
	outcomes := make([]*ArbitrationOutcome, 0, len(e.outcomeTracker))
	for _, outcome := range e.outcomeTracker {
		outcomes = append(outcomes, outcome)
	}
	e.mu.Unlock()
	
	// Analyze prediction accuracy
	var totalAccuracy float64
	var validPredictions int
	
	for _, outcome := range outcomes {
		if outcome.ActualSuccess {
			accuracy := 1.0 - abs(outcome.PredictedSuccess-1.0)
			totalAccuracy += accuracy
			validPredictions++
		}
	}
	
	if validPredictions > 0 {
		avgAccuracy := totalAccuracy / float64(validPredictions)
		
		// Update performance trends
		trend := &PerformanceTrend{
			TimeWindow:      time.Hour,
			AverageAccuracy: avgAccuracy,
			DecisionLatency: e.averageDecisionTime,
		}
		
		e.mu.Lock()
		e.performanceTrends["overall"] = trend
		e.mu.Unlock()
		
		// Feed learning back to cognitive engine
		if e.cognitiveEngine != nil && avgAccuracy < 0.8 {
			// Adjust learning rate if accuracy is low
			fmt.Printf("Adjusting cognitive engine parameters due to accuracy: %.2f\n", avgAccuracy)
		}
	}
}

// persistLearningData saves learning data for future use
func (e *Engine) persistLearningData(ctx context.Context) {
	// In a real implementation, this would save to persistent storage
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	fmt.Printf("Persisting learning data: %d outcomes, %d trends\n", 
		len(e.outcomeTracker), len(e.performanceTrends))
}

// CommitTask commits a task to an agent with enhanced tracking
func (e *Engine) CommitTask(ctx context.Context, task *Task, agentID string) (string, error) {
	commitID := fmt.Sprintf("commit_%s_%d", agentID, time.Now().UnixNano())
	
	// Update task with agent assignment
	task.AgentID = agentID
	
	// Track in active tasks
	e.mu.Lock()
	e.activeTasks[task.ID] = task
	e.mu.Unlock()
	
	// In a real implementation, this would:
	// 1. Validate agent capabilities against task requirements
	// 2. Reserve agent resources
	// 3. Create execution context
	// 4. Start task monitoring
	
	return commitID, nil
}

// RollbackTask rolls back a previously committed task
func (e *Engine) RollbackTask(ctx context.Context, taskID string, reason string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	
	// Record rollback
	rollback := &TaskRollback{
		TaskID:    taskID,
		Reason:    reason,
		Timestamp: time.Now(),
	}
	e.rollbacks[taskID] = rollback
	
	// Remove from active tasks
	delete(e.activeTasks, taskID)
	
	// In a real implementation, this would:
	// 1. Cancel task execution
	// 2. Release agent resources
	// 3. Notify stakeholders
	// 4. Update performance metrics
	
	return nil
}

// RegisterAgent registers a new agent with enhanced capability tracking
func (e *Engine) RegisterAgent(ctx context.Context, agentID string, capabilities []string, metadata map[string]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	
	// Create agent
	agent := &Agent{
		ID:           agentID,
		Capabilities: capabilities,
		Metadata:     metadata,
		RegisteredAt: time.Now(),
		Status:       "active",
	}
	e.agents[agentID] = agent
	
	// Update capability index
	for _, capability := range capabilities {
		if e.capabilityIndex[capability] == nil {
			e.capabilityIndex[capability] = make([]string, 0)
		}
		e.capabilityIndex[capability] = append(e.capabilityIndex[capability], agentID)
	}
	
	// Register with cognitive engine if available
	if e.cognitiveEngine != nil {
		cognitiveAgent := &CognitiveAgent{
			ID:              agentID,
			Capabilities:    make(map[string]float64),
			CurrentLoad:     0.0,
			PerformanceScore: 0.8, // Default starting score
			TrustLevel:      0.8,
			EnergyEfficiency: 0.7,
			LastUpdate:      time.Now(),
			Metadata:        metadata,
		}
		
		// Convert string capabilities to competency scores
		for _, capability := range capabilities {
			cognitiveAgent.Capabilities[capability] = 0.8 // Default competency
		}
		
		if err := e.cognitiveEngine.RegisterCognitiveAgent(cognitiveAgent); err != nil {
			return fmt.Errorf("failed to register cognitive agent: %v", err)
		}
	}
	
	return nil
}

// HealthCheck performs health check on the arbitration engine
func (e *Engine) HealthCheck(ctx context.Context) error {
	if e.scheduler == nil {
		return fmt.Errorf("scheduler not initialized")
	}
	
	// Check scheduler health
	if err := e.scheduler.HealthCheck(ctx); err != nil {
		return fmt.Errorf("scheduler health check failed: %v", err)
	}
	
	// Check data integrator if available
	if e.dataIntegrator != nil {
		// Data integrator would have its own health check
		// For now, just check if we have data sources
		metrics := e.dataIntegrator.GetMetrics()
		if sourceCount, ok := metrics["data_sources_count"].(int); ok && sourceCount == 0 {
			fmt.Printf("Warning: No data sources registered in data integrator\n")
		}
	}
	
	return nil
}

// GetMetrics returns comprehensive arbitration metrics
func (e *Engine) GetMetrics() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	// Calculate average confidence
	var avgConfidence float64
	if len(e.confidenceHistory) > 0 {
		var total float64
		for _, conf := range e.confidenceHistory {
			total += conf
		}
		avgConfidence = total / float64(len(e.confidenceHistory))
	}
	
	metrics := map[string]interface{}{
		"total_arbitrations":      e.totalArbitrations,
		"successful_arbitrations": e.successfulArbitrations,
		"average_decision_time":   e.averageDecisionTime.String(),
		"average_confidence":      avgConfidence,
		"active_tasks":           len(e.activeTasks),
		"registered_agents":      len(e.agents),
		"rollbacks":              len(e.rollbacks),
		"cognitive_enabled":      e.cognitiveEngine != nil,
		"learning_enabled":       e.config.PerformanceLearningEnabled,
	}
	
	// Add integration metrics if available
	if e.dataIntegrator != nil {
		integrationMetrics := e.dataIntegrator.GetMetrics()
		metrics["integration"] = integrationMetrics
	}
	
	return metrics
}

// Helper functions

func convertTaskType(taskType TaskType) scheduler.TaskType {
	switch taskType {
	case TaskTypeArbitration:
		return scheduler.TaskTypeArbitration
	case TaskTypeCollaboration:
		return scheduler.TaskTypeCollaboration
	case TaskTypeRouting:
		return scheduler.TaskTypeRouting
	case TaskTypeAnalysis:
		return scheduler.TaskTypeAnalysis
	default:
		return scheduler.TaskTypeArbitration
	}
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
