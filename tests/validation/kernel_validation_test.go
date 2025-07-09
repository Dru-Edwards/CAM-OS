package validation

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cam-os/kernel/internal/arbitration"
	"github.com/cam-os/kernel/internal/explainability"
	"github.com/cam-os/kernel/internal/memory"
	"github.com/cam-os/kernel/internal/policy"
	"github.com/cam-os/kernel/internal/scheduler"
	"github.com/cam-os/kernel/internal/security"
	syscallpkg "github.com/cam-os/kernel/internal/syscall"
	pb "github.com/cam-os/kernel/proto/generated"
)

// TestKernelComponentsInitialization tests that all kernel components can be initialized
func TestKernelComponentsInitialization(t *testing.T) {
	ctx := context.Background()
	
	// Test Security Manager
	t.Run("SecurityManager", func(t *testing.T) {
		config := &security.Config{
			PostQuantumEnabled: true,
			TLSEnabled:         true,
		}
		securityManager := security.NewManager(config)
		
		if err := securityManager.Initialize(ctx); err != nil {
			t.Errorf("Failed to initialize security manager: %v", err)
		}
		
		if err := securityManager.HealthCheck(ctx); err != nil {
			t.Errorf("Security manager health check failed: %v", err)
		}
		
		if err := securityManager.Shutdown(ctx); err != nil {
			t.Errorf("Failed to shutdown security manager: %v", err)
		}
	})
	
	// Test Policy Engine
	t.Run("PolicyEngine", func(t *testing.T) {
		config := &policy.Config{
			DefaultPolicy: "allow",
			AuditEnabled:  true,
		}
		policyEngine := policy.NewEngine(config)
		
		if err := policyEngine.Initialize(ctx); err != nil {
			t.Errorf("Failed to initialize policy engine: %v", err)
		}
		
		if err := policyEngine.HealthCheck(ctx); err != nil {
			t.Errorf("Policy engine health check failed: %v", err)
		}
		
		// Test policy query
		result, err := policyEngine.Query(ctx, "allow", "test query", map[string]string{})
		if err != nil {
			t.Errorf("Policy query failed: %v", err)
		}
		if !result.Allowed {
			t.Errorf("Expected policy to allow, got: %v", result)
		}
		
		if err := policyEngine.Shutdown(ctx); err != nil {
			t.Errorf("Failed to shutdown policy engine: %v", err)
		}
	})
	
	// Test Scheduler
	t.Run("TripleHelixScheduler", func(t *testing.T) {
		config := &scheduler.Config{
			MaxConcurrentTasks: 100,
			PriorityDimensions: []string{"urgency", "importance", "efficiency", "energy", "trust"},
			PreemptionEnabled:  true,
			MaxRetries:         3,
			RetryDelay:         time.Second,
			TaskTimeout:        30 * time.Second,
		}
		scheduler := scheduler.NewTripleHelixScheduler(config)
		
		if err := scheduler.Initialize(ctx); err != nil {
			t.Errorf("Failed to initialize scheduler: %v", err)
		}
		
		if err := scheduler.HealthCheck(ctx); err != nil {
			t.Errorf("Scheduler health check failed: %v", err)
		}
		
		// Test task scheduling
		task := &scheduler.ScheduledTask{
			ID:               "test-task-1",
			Type:             scheduler.TaskTypeArbitration,
			UrgencyScore:     0.8,
			ImportanceScore:  0.7,
			EfficiencyScore:  0.6,
			EnergyScore:      0.5,
			TrustScore:       0.9,
			AgentID:          "test-agent",
			Deadline:         time.Now().Add(time.Minute),
			MaxRetries:       3,
		}
		
		if err := scheduler.ScheduleTask(task); err != nil {
			t.Errorf("Failed to schedule task: %v", err)
		}
		
		// Wait a bit for task to be processed
		time.Sleep(100 * time.Millisecond)
		
		// Get scheduler metrics
		metrics := scheduler.GetSchedulerMetrics()
		if metrics["total_tasks_scheduled"].(int64) != 1 {
			t.Errorf("Expected 1 scheduled task, got: %v", metrics["total_tasks_scheduled"])
		}
		
		if err := scheduler.Shutdown(ctx); err != nil {
			t.Errorf("Failed to shutdown scheduler: %v", err)
		}
	})
	
	// Test Explainability Engine
	t.Run("ExplainabilityEngine", func(t *testing.T) {
		config := &explainability.Config{
			AuditRetention: 24 * time.Hour,
			TraceEnabled:   true,
		}
		explainabilityEngine := explainability.NewEngine(config)
		
		if err := explainabilityEngine.Initialize(ctx); err != nil {
			t.Errorf("Failed to initialize explainability engine: %v", err)
		}
		
		if err := explainabilityEngine.HealthCheck(ctx); err != nil {
			t.Errorf("Explainability engine health check failed: %v", err)
		}
		
		// Test decision recording
		decision := &explainability.Decision{
			TraceID:     "trace-123",
			TaskID:      "task-123",
			AgentID:     "agent-123",
			Decision:    "Task assigned to agent",
			Reasoning:   "Agent has required capabilities",
			Confidence:  0.85,
			Timestamp:   time.Now(),
			CallerID:    "test-caller",
		}
		
		if err := explainabilityEngine.RecordDecision(ctx, decision); err != nil {
			t.Errorf("Failed to record decision: %v", err)
		}
		
		// Test explanation generation
		explanation, err := explainabilityEngine.Explain(ctx, "trace-123", true)
		if err != nil {
			t.Errorf("Failed to generate explanation: %v", err)
		}
		if explanation.Explanation == "" {
			t.Errorf("Expected non-empty explanation")
		}
		
		if err := explainabilityEngine.Shutdown(ctx); err != nil {
			t.Errorf("Failed to shutdown explainability engine: %v", err)
		}
	})
}

// TestArbitrationEngine tests the arbitration engine functionality
func TestArbitrationEngine(t *testing.T) {
	ctx := context.Background()
	
	// Create dependencies
	securityManager := security.NewManager(&security.Config{
		PostQuantumEnabled: true,
		TLSEnabled:         true,
	})
	
	policyEngine := policy.NewEngine(&policy.Config{
		DefaultPolicy: "allow",
		AuditEnabled:  true,
	})
	
	scheduler := scheduler.NewTripleHelixScheduler(&scheduler.Config{
		MaxConcurrentTasks: 100,
		PriorityDimensions: []string{"urgency", "importance", "efficiency", "energy", "trust"},
		PreemptionEnabled:  true,
		MaxRetries:         3,
		RetryDelay:         time.Second,
		TaskTimeout:        30 * time.Second,
	})
	
	// Initialize scheduler
	if err := scheduler.Initialize(ctx); err != nil {
		t.Fatalf("Failed to initialize scheduler: %v", err)
	}
	defer scheduler.Shutdown(ctx)
	
	// Create arbitration engine
	arbitrationEngine := arbitration.NewEngine(&arbitration.Config{
		Scheduler:       scheduler,
		PolicyEngine:    policyEngine,
		SecurityManager: securityManager,
	})
	
	if err := arbitrationEngine.Initialize(ctx); err != nil {
		t.Errorf("Failed to initialize arbitration engine: %v", err)
	}
	defer arbitrationEngine.Shutdown(ctx)
	
	if err := arbitrationEngine.HealthCheck(ctx); err != nil {
		t.Errorf("Arbitration engine health check failed: %v", err)
	}
	
	// Test task arbitration
	task := &arbitration.Task{
		ID:           "test-task-1",
		Description:  "Test arbitration task",
		Requirements: []string{"capability1", "capability2"},
		Metadata:     map[string]string{"priority": "high"},
		Priority:     100,
		Deadline:     time.Now().Add(time.Minute),
		Type:         arbitration.TaskTypeArbitration,
		AgentID:      "test-agent",
	}
	
	result, err := arbitrationEngine.Arbitrate(ctx, task, "allow")
	if err != nil {
		t.Errorf("Failed to arbitrate task: %v", err)
	}
	
	if result.TaskID != task.ID {
		t.Errorf("Expected task ID %s, got %s", task.ID, result.TaskID)
	}
	
	if result.AssignedAgent != task.AgentID {
		t.Errorf("Expected agent ID %s, got %s", task.AgentID, result.AssignedAgent)
	}
	
	if result.Confidence <= 0 {
		t.Errorf("Expected positive confidence, got %f", result.Confidence)
	}
	
	// Test task commitment
	commitID, err := arbitrationEngine.CommitTask(ctx, task, "test-agent")
	if err != nil {
		t.Errorf("Failed to commit task: %v", err)
	}
	
	if commitID == "" {
		t.Errorf("Expected non-empty commit ID")
	}
}

// TestMemoryContextManager tests the memory context manager (requires Redis)
func TestMemoryContextManager(t *testing.T) {
	t.Skip("Skipping memory context manager test - requires Redis")
	
	ctx := context.Background()
	
	config := &memory.Config{
		RedisAddr:          "localhost:6379",
		RedisPassword:      "",
		RedisDB:            0,
		MaxNamespaces:      100,
		MaxContextSize:     1024 * 1024, // 1MB
		TTL:                time.Hour,
		CompressionEnabled: true,
		SnapshotRetention:  24 * time.Hour,
	}
	
	contextManager := memory.NewContextManager(config)
	
	if err := contextManager.Initialize(ctx); err != nil {
		t.Errorf("Failed to initialize context manager: %v", err)
	}
	defer contextManager.Shutdown(ctx)
	
	if err := contextManager.HealthCheck(ctx); err != nil {
		t.Errorf("Context manager health check failed: %v", err)
	}
	
	// Test write and read
	namespace := "test-namespace"
	key := "test-key"
	data := []byte("test data")
	metadata := map[string]string{"type": "test"}
	
	writeResult, err := contextManager.Write(ctx, namespace, key, data, metadata)
	if err != nil {
		t.Errorf("Failed to write data: %v", err)
	}
	
	if writeResult.Version <= 0 {
		t.Errorf("Expected positive version, got %d", writeResult.Version)
	}
	
	readResult, err := contextManager.Read(ctx, namespace, key, 0)
	if err != nil {
		t.Errorf("Failed to read data: %v", err)
	}
	
	if string(readResult.Data) != string(data) {
		t.Errorf("Expected data %s, got %s", string(data), string(readResult.Data))
	}
	
	// Test snapshot
	snapshotID, err := contextManager.Snapshot(ctx, namespace, "test snapshot")
	if err != nil {
		t.Errorf("Failed to create snapshot: %v", err)
	}
	
	if snapshotID == "" {
		t.Errorf("Expected non-empty snapshot ID")
	}
	
	// Test metrics
	metrics := contextManager.GetMetrics()
	if metrics["total_writes"].(int64) != 1 {
		t.Errorf("Expected 1 write, got %v", metrics["total_writes"])
	}
	
	if metrics["total_reads"].(int64) != 1 {
		t.Errorf("Expected 1 read, got %v", metrics["total_reads"])
	}
}

// TestSyscallDispatcher tests the syscall dispatcher
func TestSyscallDispatcher(t *testing.T) {
	ctx := context.Background()
	
	// Create all dependencies
	securityManager := security.NewManager(&security.Config{
		PostQuantumEnabled: true,
		TLSEnabled:         true,
	})
	
	policyEngine := policy.NewEngine(&policy.Config{
		DefaultPolicy: "allow",
		AuditEnabled:  true,
	})
	
	scheduler := scheduler.NewTripleHelixScheduler(&scheduler.Config{
		MaxConcurrentTasks: 100,
		PriorityDimensions: []string{"urgency", "importance", "efficiency", "energy", "trust"},
		PreemptionEnabled:  true,
		MaxRetries:         3,
		RetryDelay:         time.Second,
		TaskTimeout:        30 * time.Second,
	})
	
	arbitrationEngine := arbitration.NewEngine(&arbitration.Config{
		Scheduler:       scheduler,
		PolicyEngine:    policyEngine,
		SecurityManager: securityManager,
	})
	
	explainabilityEngine := explainability.NewEngine(&explainability.Config{
		AuditRetention: 24 * time.Hour,
		TraceEnabled:   true,
	})
	
	// Mock memory manager for testing (without Redis dependency)
	memoryManager := &MockMemoryManager{}
	
	// Initialize components
	if err := scheduler.Initialize(ctx); err != nil {
		t.Fatalf("Failed to initialize scheduler: %v", err)
	}
	defer scheduler.Shutdown(ctx)
	
	// Create syscall dispatcher
	dispatcher := syscallpkg.NewDispatcher(&syscallpkg.Config{
		ArbitrationEngine:    arbitrationEngine,
		MemoryManager:        memoryManager,
		PolicyEngine:         policyEngine,
		SecurityManager:      securityManager,
		ExplainabilityEngine: explainabilityEngine,
	})
	
	// Test health check syscall
	healthReq := &pb.HealthCheckRequest{
		CallerId: "test-caller",
		Detailed: true,
	}
	
	healthResp, err := dispatcher.HealthCheck(ctx, healthReq)
	if err != nil {
		t.Errorf("Health check syscall failed: %v", err)
	}
	
	if healthResp.Status != "healthy" && healthResp.Status != "degraded" {
		t.Errorf("Expected healthy or degraded status, got %s", healthResp.Status)
	}
	
	if healthResp.Timestamp <= 0 {
		t.Errorf("Expected positive timestamp, got %d", healthResp.Timestamp)
	}
}

// MockMemoryManager is a mock implementation for testing
type MockMemoryManager struct{}

func (m *MockMemoryManager) Initialize(ctx context.Context) error { return nil }
func (m *MockMemoryManager) Shutdown(ctx context.Context) error   { return nil }
func (m *MockMemoryManager) HealthCheck(ctx context.Context) error { return nil }

func (m *MockMemoryManager) Read(ctx context.Context, namespace, key string, version int64) (*memory.ContextData, error) {
	return &memory.ContextData{
		Data:      []byte("mock data"),
		Version:   1,
		Hash:      "mock-hash",
		Timestamp: time.Now(),
		Metadata:  map[string]string{"mock": "true"},
	}, nil
}

func (m *MockMemoryManager) Write(ctx context.Context, namespace, key string, data []byte, metadata map[string]string) (*memory.WriteResult, error) {
	return &memory.WriteResult{
		Version: 1,
		Hash:    "mock-hash",
	}, nil
}

func (m *MockMemoryManager) Snapshot(ctx context.Context, namespace, description string) (string, error) {
	return "mock-snapshot-id", nil
}

func (m *MockMemoryManager) Restore(ctx context.Context, snapshotID string, force bool) (*memory.RestoreResult, error) {
	return &memory.RestoreResult{
		Namespace:     "mock-namespace",
		RestoredItems: 1,
	}, nil
}

// TestPerformanceTargets tests that performance targets are met
func TestPerformanceTargets(t *testing.T) {
	ctx := context.Background()
	
	// Create minimal components for performance testing
	policyEngine := policy.NewEngine(&policy.Config{
		DefaultPolicy: "allow",
		AuditEnabled:  false, // Disable for performance
	})
	
	// Test policy query performance (should be < 1ms)
	start := time.Now()
	for i := 0; i < 1000; i++ {
		_, err := policyEngine.Query(ctx, "allow", "test query", map[string]string{})
		if err != nil {
			t.Errorf("Policy query failed: %v", err)
		}
	}
	elapsed := time.Since(start)
	avgLatency := elapsed / 1000
	
	if avgLatency > time.Millisecond {
		t.Errorf("Policy query average latency %v exceeds 1ms target", avgLatency)
	}
	
	t.Logf("Policy query average latency: %v", avgLatency)
}

// TestConcurrentOperations tests concurrent operations
func TestConcurrentOperations(t *testing.T) {
	ctx := context.Background()
	
	scheduler := scheduler.NewTripleHelixScheduler(&scheduler.Config{
		MaxConcurrentTasks: 1000,
		PriorityDimensions: []string{"urgency", "importance", "efficiency"},
		PreemptionEnabled:  false, // Disable for this test
		MaxRetries:         1,
		RetryDelay:         time.Millisecond,
		TaskTimeout:        time.Second,
	})
	
	if err := scheduler.Initialize(ctx); err != nil {
		t.Fatalf("Failed to initialize scheduler: %v", err)
	}
	defer scheduler.Shutdown(ctx)
	
	// Schedule 100 tasks concurrently
	numTasks := 100
	done := make(chan bool, numTasks)
	
	for i := 0; i < numTasks; i++ {
		go func(id int) {
			task := &scheduler.ScheduledTask{
				ID:               fmt.Sprintf("concurrent-task-%d", id),
				Type:             scheduler.TaskTypeArbitration,
				UrgencyScore:     0.5,
				ImportanceScore:  0.5,
				EfficiencyScore:  0.5,
				EnergyScore:      0.5,
				TrustScore:       0.5,
				AgentID:          fmt.Sprintf("agent-%d", id%10),
				Deadline:         time.Now().Add(time.Minute),
				MaxRetries:       1,
			}
			
			err := scheduler.ScheduleTask(task)
			if err != nil {
				t.Errorf("Failed to schedule task %d: %v", id, err)
			}
			done <- true
		}(i)
	}
	
	// Wait for all tasks to be scheduled
	for i := 0; i < numTasks; i++ {
		<-done
	}
	
	// Give some time for tasks to be processed
	time.Sleep(100 * time.Millisecond)
	
	// Check metrics
	metrics := scheduler.GetSchedulerMetrics()
	scheduled := metrics["total_tasks_scheduled"].(int64)
	
	if scheduled != int64(numTasks) {
		t.Errorf("Expected %d scheduled tasks, got %d", numTasks, scheduled)
	}
	
	t.Logf("Successfully scheduled %d tasks concurrently", numTasks)
} 