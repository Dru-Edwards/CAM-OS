package arbitration

import (
	"context"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// CognitiveEngine implements intelligent arbitration using multi-criteria decision analysis
type CognitiveEngine struct {
	mu                  sync.RWMutex
	agents              map[string]*CognitiveAgent
	capabilityMatrix    map[string]map[string]float64 // capability -> agentID -> competency
	performanceHistory  map[string]*PerformanceMetrics
	learningRate        float64
	confidenceThreshold float64
}

// CognitiveAgent represents an agent with cognitive capabilities
type CognitiveAgent struct {
	ID               string
	Capabilities     map[string]float64 // capability -> competency score (0-1)
	CurrentLoad      float64            // current workload (0-1)
	PerformanceScore float64            // historical performance (0-1)
	TrustLevel       float64            // trust score (0-1)
	EnergyEfficiency float64            // energy efficiency rating (0-1)
	LastUpdate       time.Time
	Metadata         map[string]string
}

// PerformanceMetrics tracks agent performance over time
type PerformanceMetrics struct {
	TasksCompleted   int64
	TasksFailed      int64
	AverageLatency   time.Duration
	QualityScore     float64
	ReliabilityScore float64
	LastTaskTime     time.Time
	TrendDirection   float64 // -1 (declining) to 1 (improving)
}

// ArbitrationDecision represents a cognitive arbitration decision
type ArbitrationDecision struct {
	TaskID            string
	SelectedAgent     *CognitiveAgent
	Confidence        float64
	Reasoning         []string
	AlternativeAgents []*CognitiveAgent
	DecisionFactors   map[string]float64
	PredictedOutcome  *OutcomePrediction
}

// OutcomePrediction predicts task execution outcomes
type OutcomePrediction struct {
	EstimatedDuration  time.Duration
	SuccessProbability float64
	QualityScore       float64
	ResourceUsage      map[string]float64
}

// NewCognitiveEngine creates a new cognitive arbitration engine
func NewCognitiveEngine() *CognitiveEngine {
	return &CognitiveEngine{
		agents:              make(map[string]*CognitiveAgent),
		capabilityMatrix:    make(map[string]map[string]float64),
		performanceHistory:  make(map[string]*PerformanceMetrics),
		learningRate:        0.1,
		confidenceThreshold: 0.7,
	}
}

// RegisterCognitiveAgent registers a new cognitive agent
func (ce *CognitiveEngine) RegisterCognitiveAgent(agent *CognitiveAgent) error {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	ce.agents[agent.ID] = agent

	// Update capability matrix
	for capability, competency := range agent.Capabilities {
		if ce.capabilityMatrix[capability] == nil {
			ce.capabilityMatrix[capability] = make(map[string]float64)
		}
		ce.capabilityMatrix[capability][agent.ID] = competency
	}

	// Initialize performance metrics if not exists
	if ce.performanceHistory[agent.ID] == nil {
		ce.performanceHistory[agent.ID] = &PerformanceMetrics{
			QualityScore:     0.8, // Start with reasonable defaults
			ReliabilityScore: 0.8,
			TrendDirection:   0.0,
		}
	}

	return nil
}

// CognitiveArbitrate performs intelligent task arbitration using cognitive algorithms
func (ce *CognitiveEngine) CognitiveArbitrate(ctx context.Context, task *Task, constraints map[string]interface{}) (*ArbitrationDecision, error) {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	// Step 1: Find candidate agents based on capabilities
	candidates := ce.findCandidateAgents(task)
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no suitable agents found for task %s", task.ID)
	}

	// Step 2: Score candidates using multi-criteria decision analysis
	scoredCandidates := ce.scoreAgents(task, candidates, constraints)

	// Step 3: Select best agent using cognitive decision-making
	decision := ce.makeCognitiveDecision(task, scoredCandidates)

	// Step 4: Generate outcome prediction
	decision.PredictedOutcome = ce.predictOutcome(task, decision.SelectedAgent)

	return decision, nil
}

// findCandidateAgents identifies agents with required capabilities
func (ce *CognitiveEngine) findCandidateAgents(task *Task) []*CognitiveAgent {
	var candidates []*CognitiveAgent

	for _, agent := range ce.agents {
		if ce.agentCanHandleTask(agent, task) {
			candidates = append(candidates, agent)
		}
	}

	return candidates
}

// agentCanHandleTask checks if an agent can handle a specific task
func (ce *CognitiveEngine) agentCanHandleTask(agent *CognitiveAgent, task *Task) bool {
	// Check if agent has required capabilities
	for _, requirement := range task.Requirements {
		competency, hasCapability := agent.Capabilities[requirement]
		if !hasCapability || competency < 0.3 { // Minimum competency threshold
			return false
		}
	}

	// Check current load capacity
	if agent.CurrentLoad > 0.9 { // Agent is overloaded
		return false
	}

	return true
}

// scoreAgents scores candidate agents using multi-criteria analysis
func (ce *CognitiveEngine) scoreAgents(task *Task, candidates []*CognitiveAgent, constraints map[string]interface{}) []AgentScore {
	var scores []AgentScore

	for _, agent := range candidates {
		score := ce.calculateAgentScore(task, agent, constraints)
		scores = append(scores, AgentScore{
			Agent: agent,
			Score: score,
		})
	}

	// Sort by score (highest first)
	sort.Slice(scores, func(i, j int) bool {
		return scores[i].Score > scores[j].Score
	})

	return scores
}

// AgentScore represents an agent's suitability score for a task
type AgentScore struct {
	Agent *CognitiveAgent
	Score float64
}

// calculateAgentScore calculates comprehensive agent suitability score
func (ce *CognitiveEngine) calculateAgentScore(task *Task, agent *CognitiveAgent, constraints map[string]interface{}) float64 {
	weights := map[string]float64{
		"capability":   0.35,
		"performance":  0.25,
		"availability": 0.20,
		"trust":        0.10,
		"efficiency":   0.10,
	}

	// Calculate capability score
	capabilityScore := ce.calculateCapabilityScore(task, agent)

	// Calculate performance score
	performanceScore := ce.calculatePerformanceScore(agent)

	// Calculate availability score
	availabilityScore := 1.0 - agent.CurrentLoad

	// Calculate trust score
	trustScore := agent.TrustLevel

	// Calculate efficiency score
	efficiencyScore := agent.EnergyEfficiency

	// Weighted combination
	totalScore := (capabilityScore * weights["capability"]) +
		(performanceScore * weights["performance"]) +
		(availabilityScore * weights["availability"]) +
		(trustScore * weights["trust"]) +
		(efficiencyScore * weights["efficiency"])

	// Apply time penalty for urgent tasks
	if task.Priority > 80 {
		urgencyPenalty := math.Min(0.1, float64(time.Until(task.Deadline).Seconds())/3600.0)
		totalScore += urgencyPenalty
	}

	return math.Min(1.0, totalScore)
}

// calculateCapabilityScore calculates how well agent capabilities match task requirements
func (ce *CognitiveEngine) calculateCapabilityScore(task *Task, agent *CognitiveAgent) float64 {
	if len(task.Requirements) == 0 {
		return 0.8 // Default score for tasks with no specific requirements
	}

	var totalScore float64
	for _, requirement := range task.Requirements {
		competency, exists := agent.Capabilities[requirement]
		if exists {
			totalScore += competency
		}
	}

	return totalScore / float64(len(task.Requirements))
}

// calculatePerformanceScore calculates agent's historical performance score
func (ce *CognitiveEngine) calculatePerformanceScore(agent *CognitiveAgent) float64 {
	metrics, exists := ce.performanceHistory[agent.ID]
	if !exists {
		return 0.5 // Default score for new agents
	}

	// Combine multiple performance factors
	reliabilityWeight := 0.4
	qualityWeight := 0.3
	trendWeight := 0.3

	reliabilityScore := metrics.ReliabilityScore
	qualityScore := metrics.QualityScore
	trendBonus := (metrics.TrendDirection + 1.0) / 2.0 // Convert -1,1 to 0,1

	return (reliabilityScore * reliabilityWeight) +
		(qualityScore * qualityWeight) +
		(trendBonus * trendWeight)
}

// makeCognitiveDecision makes the final arbitration decision
func (ce *CognitiveEngine) makeCognitiveDecision(task *Task, scoredCandidates []AgentScore) *ArbitrationDecision {
	if len(scoredCandidates) == 0 {
		return nil
	}

	best := scoredCandidates[0]

	// Generate reasoning
	reasoning := ce.generateReasoning(task, best.Agent, scoredCandidates)

	// Calculate confidence based on score gap and absolute score
	confidence := ce.calculateConfidence(scoredCandidates)

	// Prepare alternative agents
	var alternatives []*CognitiveAgent
	for i := 1; i < len(scoredCandidates) && i < 3; i++ {
		alternatives = append(alternatives, scoredCandidates[i].Agent)
	}

	return &ArbitrationDecision{
		TaskID:            task.ID,
		SelectedAgent:     best.Agent,
		Confidence:        confidence,
		Reasoning:         reasoning,
		AlternativeAgents: alternatives,
		DecisionFactors:   ce.extractDecisionFactors(task, best.Agent),
	}
}

// generateReasoning generates human-readable reasoning for the decision
func (ce *CognitiveEngine) generateReasoning(task *Task, selectedAgent *CognitiveAgent, candidates []AgentScore) []string {
	var reasoning []string

	reasoning = append(reasoning, fmt.Sprintf("Selected agent %s with score %.2f", selectedAgent.ID, candidates[0].Score))

	// Capability reasoning
	capScore := ce.calculateCapabilityScore(task, selectedAgent)
	reasoning = append(reasoning, fmt.Sprintf("Agent has %.1f%% capability match for required skills", capScore*100))

	// Performance reasoning
	perfScore := ce.calculatePerformanceScore(selectedAgent)
	reasoning = append(reasoning, fmt.Sprintf("Agent has %.1f%% performance rating based on history", perfScore*100))

	// Load reasoning
	loadLevel := selectedAgent.CurrentLoad * 100
	reasoning = append(reasoning, fmt.Sprintf("Agent current workload is %.1f%%, within acceptable limits", loadLevel))

	// Comparison with alternatives
	if len(candidates) > 1 {
		scoreDiff := candidates[0].Score - candidates[1].Score
		reasoning = append(reasoning, fmt.Sprintf("Selected agent outperforms next best by %.2f points", scoreDiff))
	}

	return reasoning
}

// calculateConfidence calculates decision confidence based on various factors
func (ce *CognitiveEngine) calculateConfidence(candidates []AgentScore) float64 {
	if len(candidates) == 0 {
		return 0.0
	}

	bestScore := candidates[0].Score

	// Base confidence from absolute score
	baseConfidence := bestScore

	// Confidence boost from clear winner
	if len(candidates) > 1 {
		scoreDiff := bestScore - candidates[1].Score
		confidenceBoost := math.Min(0.3, scoreDiff*2) // Up to 30% boost
		baseConfidence += confidenceBoost
	}

	return math.Min(1.0, baseConfidence)
}

// extractDecisionFactors extracts key decision factors for explainability
func (ce *CognitiveEngine) extractDecisionFactors(task *Task, agent *CognitiveAgent) map[string]float64 {
	return map[string]float64{
		"capability_match":     ce.calculateCapabilityScore(task, agent),
		"performance_history":  ce.calculatePerformanceScore(agent),
		"current_availability": 1.0 - agent.CurrentLoad,
		"trust_level":          agent.TrustLevel,
		"energy_efficiency":    agent.EnergyEfficiency,
	}
}

// predictOutcome predicts the likely outcome of assigning the task to the agent
func (ce *CognitiveEngine) predictOutcome(task *Task, agent *CognitiveAgent) *OutcomePrediction {
	metrics := ce.performanceHistory[agent.ID]

	// Estimate duration based on task complexity and agent performance
	baseEstimate := time.Duration(len(task.Requirements)) * time.Minute * 5
	performanceMultiplier := 2.0 - agent.PerformanceScore // Better agents are faster
	estimatedDuration := time.Duration(float64(baseEstimate) * performanceMultiplier)

	// Calculate success probability
	successProb := 0.9 * agent.PerformanceScore // Base on historical performance
	if metrics != nil {
		reliabilityFactor := metrics.ReliabilityScore
		successProb = (successProb + reliabilityFactor) / 2.0
	}

	// Predict quality score
	qualityScore := agent.PerformanceScore
	if metrics != nil {
		qualityScore = (qualityScore + metrics.QualityScore) / 2.0
	}

	// Estimate resource usage
	resourceUsage := map[string]float64{
		"cpu":    0.3 + (1.0-agent.EnergyEfficiency)*0.4,
		"memory": 0.2 + float64(len(task.Requirements))*0.1,
		"time":   estimatedDuration.Seconds(),
	}

	return &OutcomePrediction{
		EstimatedDuration:  estimatedDuration,
		SuccessProbability: successProb,
		QualityScore:       qualityScore,
		ResourceUsage:      resourceUsage,
	}
}

// UpdateAgentPerformance updates agent performance metrics based on task outcomes
func (ce *CognitiveEngine) UpdateAgentPerformance(agentID string, outcome *TaskOutcome) error {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	metrics, exists := ce.performanceHistory[agentID]
	if !exists {
		metrics = &PerformanceMetrics{}
		ce.performanceHistory[agentID] = metrics
	}

	// Update metrics based on outcome
	if outcome.Success {
		metrics.TasksCompleted++
	} else {
		metrics.TasksFailed++
	}

	// Update quality and reliability using exponential moving average
	alpha := ce.learningRate
	metrics.QualityScore = (1-alpha)*metrics.QualityScore + alpha*outcome.QualityScore

	reliability := 1.0
	if !outcome.Success {
		reliability = 0.0
	}
	metrics.ReliabilityScore = (1-alpha)*metrics.ReliabilityScore + alpha*reliability

	// Update trend direction based on recent performance
	if outcome.Success && outcome.QualityScore > 0.8 {
		metrics.TrendDirection = math.Min(1.0, metrics.TrendDirection+0.1)
	} else if !outcome.Success {
		metrics.TrendDirection = math.Max(-1.0, metrics.TrendDirection-0.2)
	}

	metrics.LastTaskTime = outcome.CompletionTime

	return nil
}

// TaskOutcome represents the outcome of a completed task
type TaskOutcome struct {
	TaskID         string
	AgentID        string
	Success        bool
	QualityScore   float64
	Duration       time.Duration
	CompletionTime time.Time
	ErrorDetails   string
}
