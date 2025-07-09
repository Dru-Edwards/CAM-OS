package scheduler

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// TaskType represents the type of task for scheduling
type TaskType int

const (
	TaskTypeArbitration TaskType = iota
	TaskTypeCollaboration
	TaskTypeRouting
	TaskTypeAnalysis
)

// PriorityDimensions defines the weights for priority calculation
type PriorityDimensions struct {
	Urgency     float64 // Time-sensitive tasks
	Importance  float64 // Business-critical tasks
	Efficiency  float64 // Resource-optimized tasks
	Energy      float64 // Power-efficient tasks (optional)
	Trust       float64 // Tasks from trusted sources (optional)
}

// DefaultPriorityWeights provides the default priority calculation weights
var DefaultPriorityWeights = PriorityDimensions{
	Urgency:    0.4,
	Importance: 0.3,
	Efficiency: 0.2,
	Energy:     0.05,
	Trust:      0.05,
}

// ScheduledTask represents a task in the scheduler
type ScheduledTask struct {
	ID               string
	Type             TaskType
	Priority         float64
	SubmissionTime   time.Time
	Deadline         time.Time
	EstimatedRuntime time.Duration
	ResourceRequirements map[string]interface{}
	
	// Priority dimensions
	UrgencyScore    float64
	ImportanceScore float64
	EfficiencyScore float64
	EnergyScore     float64
	TrustScore      float64
	
	// Metadata
	AgentID    string
	CallerID   string
	Metadata   map[string]string
	
	// Execution tracking
	StartTime     time.Time
	EndTime       time.Time
	Status        TaskStatus
	RetryCount    int
	MaxRetries    int
}

// TaskStatus represents the current status of a task
type TaskStatus int

const (
	TaskStatusPending TaskStatus = iota
	TaskStatusRunning
	TaskStatusCompleted
	TaskStatusFailed
	TaskStatusCancelled
	TaskStatusRetrying
)

// Config holds the scheduler configuration
type Config struct {
	MaxConcurrentTasks int
	PriorityDimensions []string
	PreemptionEnabled  bool
	MaxRetries         int
	RetryDelay         time.Duration
	TaskTimeout        time.Duration
}

// TripleHelixScheduler implements the Triple-Helix priority queue scheduler
type TripleHelixScheduler struct {
	config           *Config
	priorityWeights  PriorityDimensions
	
	// Task queues organized by priority
	highPriorityQueue   []*ScheduledTask
	mediumPriorityQueue []*ScheduledTask
	lowPriorityQueue    []*ScheduledTask
	
	// Running tasks
	runningTasks map[string]*ScheduledTask
	
	// Scheduler state
	mutex           sync.RWMutex
	running         bool
	shutdownChan    chan struct{}
	
	// Metrics
	totalTasksScheduled   int64
	totalTasksCompleted   int64
	totalTasksFailed      int64
	averageWaitTime       time.Duration
	averageExecutionTime  time.Duration
	
	// Preemption support
	preemptionEnabled bool
	preemptionThreshold float64
}

// NewTripleHelixScheduler creates a new Triple-Helix scheduler
func NewTripleHelixScheduler(config *Config) *TripleHelixScheduler {
	return &TripleHelixScheduler{
		config:              config,
		priorityWeights:     DefaultPriorityWeights,
		runningTasks:        make(map[string]*ScheduledTask),
		shutdownChan:        make(chan struct{}),
		preemptionEnabled:   config.PreemptionEnabled,
		preemptionThreshold: 2.0, // Tasks with 2x higher priority can preempt
	}
}

// Initialize initializes the scheduler
func (s *TripleHelixScheduler) Initialize(ctx context.Context) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	if s.running {
		return fmt.Errorf("scheduler already running")
	}
	
	s.running = true
	
	// Start the scheduler loop
	go s.schedulerLoop()
	
	return nil
}

// Shutdown gracefully shuts down the scheduler
func (s *TripleHelixScheduler) Shutdown(ctx context.Context) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	if !s.running {
		return nil
	}
	
	s.running = false
	close(s.shutdownChan)
	
	// Wait for running tasks to complete or timeout
	timeout := time.NewTimer(30 * time.Second)
	defer timeout.Stop()
	
	for len(s.runningTasks) > 0 {
		select {
		case <-timeout.C:
			// Force shutdown after timeout
			return fmt.Errorf("scheduler shutdown timeout with %d running tasks", len(s.runningTasks))
		case <-time.After(100 * time.Millisecond):
			// Check again
		}
	}
	
	return nil
}

// ScheduleTask schedules a new task
func (s *TripleHelixScheduler) ScheduleTask(task *ScheduledTask) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	if !s.running {
		return fmt.Errorf("scheduler not running")
	}
	
	// Calculate priority score
	task.Priority = s.calculatePriority(task)
	task.SubmissionTime = time.Now()
	task.Status = TaskStatusPending
	
	// Add to appropriate queue based on priority
	if task.Priority >= 0.8 {
		s.highPriorityQueue = append(s.highPriorityQueue, task)
		s.sortQueue(s.highPriorityQueue)
	} else if task.Priority >= 0.5 {
		s.mediumPriorityQueue = append(s.mediumPriorityQueue, task)
		s.sortQueue(s.mediumPriorityQueue)
	} else {
		s.lowPriorityQueue = append(s.lowPriorityQueue, task)
		s.sortQueue(s.lowPriorityQueue)
	}
	
	s.totalTasksScheduled++
	
	return nil
}

// GetTaskStatus returns the status of a task
func (s *TripleHelixScheduler) GetTaskStatus(taskID string) (*ScheduledTask, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	// Check running tasks first
	if task, exists := s.runningTasks[taskID]; exists {
		return task, nil
	}
	
	// Check queues
	for _, queue := range [][]*ScheduledTask{s.highPriorityQueue, s.mediumPriorityQueue, s.lowPriorityQueue} {
		for _, task := range queue {
			if task.ID == taskID {
				return task, nil
			}
		}
	}
	
	return nil, fmt.Errorf("task not found: %s", taskID)
}

// CancelTask cancels a pending or running task
func (s *TripleHelixScheduler) CancelTask(taskID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	// Check running tasks
	if task, exists := s.runningTasks[taskID]; exists {
		task.Status = TaskStatusCancelled
		task.EndTime = time.Now()
		delete(s.runningTasks, taskID)
		return nil
	}
	
	// Check and remove from queues
	for _, queue := range [][]*ScheduledTask{s.highPriorityQueue, s.mediumPriorityQueue, s.lowPriorityQueue} {
		for i, task := range queue {
			if task.ID == taskID {
				task.Status = TaskStatusCancelled
				// Remove from queue
				copy(queue[i:], queue[i+1:])
				queue = queue[:len(queue)-1]
				return nil
			}
		}
	}
	
	return fmt.Errorf("task not found: %s", taskID)
}

// GetSchedulerMetrics returns current scheduler metrics
func (s *TripleHelixScheduler) GetSchedulerMetrics() map[string]interface{} {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	return map[string]interface{}{
		"total_tasks_scheduled":    s.totalTasksScheduled,
		"total_tasks_completed":    s.totalTasksCompleted,
		"total_tasks_failed":       s.totalTasksFailed,
		"running_tasks":            len(s.runningTasks),
		"high_priority_queue":      len(s.highPriorityQueue),
		"medium_priority_queue":    len(s.mediumPriorityQueue),
		"low_priority_queue":       len(s.lowPriorityQueue),
		"average_wait_time":        s.averageWaitTime.Seconds(),
		"average_execution_time":   s.averageExecutionTime.Seconds(),
		"preemption_enabled":       s.preemptionEnabled,
	}
}

// HealthCheck performs a health check on the scheduler
func (s *TripleHelixScheduler) HealthCheck(ctx context.Context) error {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	if !s.running {
		return fmt.Errorf("scheduler not running")
	}
	
	// Check for deadlocks or stuck tasks
	now := time.Now()
	stuckTasks := 0
	
	for _, task := range s.runningTasks {
		if task.Status == TaskStatusRunning && now.Sub(task.StartTime) > s.config.TaskTimeout {
			stuckTasks++
		}
	}
	
	if stuckTasks > 0 {
		return fmt.Errorf("detected %d stuck tasks", stuckTasks)
	}
	
	return nil
}

// Private methods

// schedulerLoop is the main scheduler loop
func (s *TripleHelixScheduler) schedulerLoop() {
	ticker := time.NewTicker(10 * time.Millisecond) // 100Hz scheduling
	defer ticker.Stop()
	
	for {
		select {
		case <-s.shutdownChan:
			return
		case <-ticker.C:
			s.processSchedulingCycle()
		}
	}
}

// processSchedulingCycle processes one scheduling cycle
func (s *TripleHelixScheduler) processSchedulingCycle() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	// Check for completed tasks
	s.checkCompletedTasks()
	
	// Check for task timeouts
	s.checkTaskTimeouts()
	
	// Schedule new tasks if capacity available
	if len(s.runningTasks) < s.config.MaxConcurrentTasks {
		s.scheduleNextTask()
	}
	
	// Handle preemption if enabled
	if s.preemptionEnabled {
		s.handlePreemption()
	}
}

// scheduleNextTask schedules the next highest priority task
func (s *TripleHelixScheduler) scheduleNextTask() {
	var nextTask *ScheduledTask
	var sourceQueue *[]*ScheduledTask
	
	// Check high priority queue first
	if len(s.highPriorityQueue) > 0 {
		nextTask = s.highPriorityQueue[0]
		sourceQueue = &s.highPriorityQueue
	} else if len(s.mediumPriorityQueue) > 0 {
		nextTask = s.mediumPriorityQueue[0]
		sourceQueue = &s.mediumPriorityQueue
	} else if len(s.lowPriorityQueue) > 0 {
		nextTask = s.lowPriorityQueue[0]
		sourceQueue = &s.lowPriorityQueue
	}
	
	if nextTask != nil {
		// Remove from queue
		*sourceQueue = (*sourceQueue)[1:]
		
		// Start execution
		nextTask.Status = TaskStatusRunning
		nextTask.StartTime = time.Now()
		s.runningTasks[nextTask.ID] = nextTask
		
		// Start task execution in goroutine
		go s.executeTask(nextTask)
	}
}

// executeTask executes a task (placeholder implementation)
func (s *TripleHelixScheduler) executeTask(task *ScheduledTask) {
	// Simulate task execution
	// In a real implementation, this would delegate to the appropriate engine
	
	// Simulate variable execution time based on task type
	var executionTime time.Duration
	switch task.Type {
	case TaskTypeArbitration:
		executionTime = time.Duration(50+task.Priority*50) * time.Millisecond
	case TaskTypeCollaboration:
		executionTime = time.Duration(100+task.Priority*100) * time.Millisecond
	case TaskTypeRouting:
		executionTime = time.Duration(20+task.Priority*20) * time.Millisecond
	case TaskTypeAnalysis:
		executionTime = time.Duration(200+task.Priority*200) * time.Millisecond
	}
	
	// Sleep to simulate work
	time.Sleep(executionTime)
	
	// Mark task as completed
	s.mutex.Lock()
	task.Status = TaskStatusCompleted
	task.EndTime = time.Now()
	delete(s.runningTasks, task.ID)
	s.totalTasksCompleted++
	
	// Update metrics
	waitTime := task.StartTime.Sub(task.SubmissionTime)
	execTime := task.EndTime.Sub(task.StartTime)
	s.updateMetrics(waitTime, execTime)
	
	s.mutex.Unlock()
}

// checkCompletedTasks checks for completed tasks and updates metrics
func (s *TripleHelixScheduler) checkCompletedTasks() {
	// Tasks are marked as completed in executeTask
	// This method can be used for additional cleanup if needed
}

// checkTaskTimeouts checks for tasks that have exceeded their timeout
func (s *TripleHelixScheduler) checkTaskTimeouts() {
	now := time.Now()
	
	for taskID, task := range s.runningTasks {
		if task.Status == TaskStatusRunning && now.Sub(task.StartTime) > s.config.TaskTimeout {
			// Task has timed out
			if task.RetryCount < task.MaxRetries {
				// Retry the task
				task.Status = TaskStatusRetrying
				task.RetryCount++
				// Re-queue the task
				s.ScheduleTask(task)
			} else {
				// Mark as failed
				task.Status = TaskStatusFailed
				task.EndTime = now
				s.totalTasksFailed++
			}
			
			delete(s.runningTasks, taskID)
		}
	}
}

// handlePreemption handles task preemption for higher priority tasks
func (s *TripleHelixScheduler) handlePreemption() {
	if len(s.highPriorityQueue) == 0 {
		return
	}
	
	highestPriorityWaiting := s.highPriorityQueue[0]
	
	// Find the lowest priority running task
	var lowestPriorityRunning *ScheduledTask
	for _, task := range s.runningTasks {
		if lowestPriorityRunning == nil || task.Priority < lowestPriorityRunning.Priority {
			lowestPriorityRunning = task
		}
	}
	
	// Check if preemption is justified
	if lowestPriorityRunning != nil && 
		highestPriorityWaiting.Priority >= lowestPriorityRunning.Priority*s.preemptionThreshold {
		
		// Preempt the running task
		lowestPriorityRunning.Status = TaskStatusPending
		delete(s.runningTasks, lowestPriorityRunning.ID)
		
		// Re-queue the preempted task
		s.ScheduleTask(lowestPriorityRunning)
		
		// Schedule the higher priority task
		s.scheduleNextTask()
	}
}

// calculatePriority calculates the priority score for a task
func (s *TripleHelixScheduler) calculatePriority(task *ScheduledTask) float64 {
	return (task.UrgencyScore * s.priorityWeights.Urgency) +
		(task.ImportanceScore * s.priorityWeights.Importance) +
		(task.EfficiencyScore * s.priorityWeights.Efficiency) +
		(task.EnergyScore * s.priorityWeights.Energy) +
		(task.TrustScore * s.priorityWeights.Trust)
}

// sortQueue sorts a queue by priority (highest first)
func (s *TripleHelixScheduler) sortQueue(queue []*ScheduledTask) {
	// Simple bubble sort for now - could be optimized with heap
	for i := 0; i < len(queue); i++ {
		for j := i + 1; j < len(queue); j++ {
			if queue[i].Priority < queue[j].Priority {
				queue[i], queue[j] = queue[j], queue[i]
			}
		}
	}
}

// updateMetrics updates scheduler performance metrics
func (s *TripleHelixScheduler) updateMetrics(waitTime, execTime time.Duration) {
	// Simple moving average - could be improved with exponential moving average
	totalCompleted := s.totalTasksCompleted
	if totalCompleted == 1 {
		s.averageWaitTime = waitTime
		s.averageExecutionTime = execTime
	} else {
		s.averageWaitTime = time.Duration(
			(int64(s.averageWaitTime)*(totalCompleted-1) + int64(waitTime)) / totalCompleted,
		)
		s.averageExecutionTime = time.Duration(
			(int64(s.averageExecutionTime)*(totalCompleted-1) + int64(execTime)) / totalCompleted,
		)
	}
}

// SetPriorityWeights updates the priority calculation weights
func (s *TripleHelixScheduler) SetPriorityWeights(weights PriorityDimensions) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	s.priorityWeights = weights
}

// GetPriorityWeights returns the current priority weights
func (s *TripleHelixScheduler) GetPriorityWeights() PriorityDimensions {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	return s.priorityWeights
} 