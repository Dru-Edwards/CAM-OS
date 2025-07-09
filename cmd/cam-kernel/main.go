package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cam-os/kernel/internal/arbitration"
	"github.com/cam-os/kernel/internal/explainability"
	"github.com/cam-os/kernel/internal/memory"
	"github.com/cam-os/kernel/internal/policy"
	"github.com/cam-os/kernel/internal/scheduler"
	"github.com/cam-os/kernel/internal/security"
	syscallpkg "github.com/cam-os/kernel/internal/syscall"
	pb "github.com/cam-os/kernel/proto/generated"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const (
	// Kernel version
	KernelVersion = "1.0.0"
	
	// Default configuration
	DefaultPort = ":8080"
	DefaultLogLevel = "info"
	
	// Performance targets from MANIFEST.toml
	SyscallLatencyTarget = 1 * time.Millisecond
	ArbitrationLatencyTarget = 100 * time.Millisecond
	ContextLatencyTarget = 10 * time.Millisecond
)

// KernelConfig holds the kernel configuration
type KernelConfig struct {
	Port           string
	LogLevel       string
	RedisAddr      string
	TLSEnabled     bool
	PostQuantum    bool
	MetricsEnabled bool
}

// Kernel represents the CAM-OS kernel
type Kernel struct {
	config *KernelConfig
	server *grpc.Server
	
	// Core components
	arbitrationEngine   *arbitration.Engine
	memoryManager      *memory.ContextManager
	policyEngine       *policy.Engine
	scheduler          *scheduler.TripleHelixScheduler
	securityManager    *security.Manager
	explainabilityEngine *explainability.Engine
	syscallDispatcher  *syscallpkg.Dispatcher
}

func main() {
	fmt.Printf("CAM-OS Kernel v%s starting...\n", KernelVersion)
	
	// Load configuration
	config := loadConfig()
	
	// Create kernel instance
	kernel, err := NewKernel(config)
	if err != nil {
		log.Fatalf("Failed to create kernel: %v", err)
	}
	
	// Start kernel
	if err := kernel.Start(); err != nil {
		log.Fatalf("Failed to start kernel: %v", err)
	}
	
	// Wait for shutdown signal
	kernel.WaitForShutdown()
}

// NewKernel creates a new CAM-OS kernel instance
func NewKernel(config *KernelConfig) (*Kernel, error) {
	// Initialize core components
	securityManager := security.NewManager(&security.Config{
		PostQuantumEnabled: config.PostQuantum,
		TLSEnabled:        config.TLSEnabled,
	})
	
	memoryManager := memory.NewContextManager(&memory.Config{
		RedisAddr:     config.RedisAddr,
		MaxNamespaces: 10000,
		MaxContextSize: 100 * 1024 * 1024, // 100MB
	})
	
	policyEngine := policy.NewEngine(&policy.Config{
		DefaultPolicy: "allow",
		AuditEnabled:  true,
	})
	
	scheduler := scheduler.NewTripleHelixScheduler(&scheduler.Config{
		MaxConcurrentTasks: 10000,
		PriorityDimensions: []string{"urgency", "importance", "efficiency", "energy", "trust"},
		PreemptionEnabled:  true,
	})
	
	arbitrationEngine := arbitration.NewEngine(&arbitration.Config{
		Scheduler:     scheduler,
		PolicyEngine:  policyEngine,
		SecurityManager: securityManager,
	})
	
	explainabilityEngine := explainability.NewEngine(&explainability.Config{
		AuditRetention: 7 * 24 * time.Hour, // 7 days
		TraceEnabled:   true,
	})
	
	syscallDispatcher := syscallpkg.NewDispatcher(&syscallpkg.Config{
		ArbitrationEngine:   arbitrationEngine,
		MemoryManager:      memoryManager,
		PolicyEngine:       policyEngine,
		SecurityManager:    securityManager,
		ExplainabilityEngine: explainabilityEngine,
	})
	
	return &Kernel{
		config:               config,
		arbitrationEngine:    arbitrationEngine,
		memoryManager:       memoryManager,
		policyEngine:        policyEngine,
		scheduler:           scheduler,
		securityManager:     securityManager,
		explainabilityEngine: explainabilityEngine,
		syscallDispatcher:   syscallDispatcher,
	}, nil
}

// Start starts the kernel
func (k *Kernel) Start() error {
	// Create gRPC server
	var opts []grpc.ServerOption
	
	if k.config.TLSEnabled {
		// TODO: Add TLS credentials with post-quantum support
		fmt.Println("TLS support not yet implemented")
	}
	
	k.server = grpc.NewServer(opts...)
	
	// Register syscall service
	pb.RegisterSyscallServiceServer(k.server, k.syscallDispatcher)
	
	// Enable reflection for debugging
	reflection.Register(k.server)
	
	// Start listening
	listener, err := net.Listen("tcp", k.config.Port)
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}
	
	fmt.Printf("CAM-OS Kernel listening on %s\n", k.config.Port)
	
	// Start server in goroutine
	go func() {
		if err := k.server.Serve(listener); err != nil {
			log.Printf("Server error: %v", err)
		}
	}()
	
	// Initialize components
	if err := k.initializeComponents(); err != nil {
		return fmt.Errorf("failed to initialize components: %v", err)
	}
	
	fmt.Println("CAM-OS Kernel started successfully")
	return nil
}

// initializeComponents initializes all kernel components
func (k *Kernel) initializeComponents() error {
	ctx := context.Background()
	
	// Initialize security manager
	if err := k.securityManager.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize security manager: %v", err)
	}
	
	// Initialize memory manager
	if err := k.memoryManager.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize memory manager: %v", err)
	}
	
	// Initialize policy engine
	if err := k.policyEngine.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize policy engine: %v", err)
	}
	
	// Initialize scheduler
	if err := k.scheduler.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize scheduler: %v", err)
	}
	
	// Initialize arbitration engine
	if err := k.arbitrationEngine.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize arbitration engine: %v", err)
	}
	
	// Initialize explainability engine
	if err := k.explainabilityEngine.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize explainability engine: %v", err)
	}
	
	return nil
}

// WaitForShutdown waits for shutdown signal and gracefully shuts down
func (k *Kernel) WaitForShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	
	<-sigChan
	fmt.Println("\nShutdown signal received, shutting down gracefully...")
	
	k.Shutdown()
}

// Shutdown gracefully shuts down the kernel
func (k *Kernel) Shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	// Stop accepting new requests
	if k.server != nil {
		k.server.GracefulStop()
	}
	
	// Shutdown components
	k.shutdownComponents(ctx)
	
	fmt.Println("CAM-OS Kernel shutdown complete")
}

// shutdownComponents shuts down all kernel components
func (k *Kernel) shutdownComponents(ctx context.Context) {
	// Shutdown in reverse order of initialization
	if err := k.explainabilityEngine.Shutdown(ctx); err != nil {
		log.Printf("Error shutting down explainability engine: %v", err)
	}
	
	if err := k.arbitrationEngine.Shutdown(ctx); err != nil {
		log.Printf("Error shutting down arbitration engine: %v", err)
	}
	
	if err := k.scheduler.Shutdown(ctx); err != nil {
		log.Printf("Error shutting down scheduler: %v", err)
	}
	
	if err := k.policyEngine.Shutdown(ctx); err != nil {
		log.Printf("Error shutting down policy engine: %v", err)
	}
	
	if err := k.memoryManager.Shutdown(ctx); err != nil {
		log.Printf("Error shutting down memory manager: %v", err)
	}
	
	if err := k.securityManager.Shutdown(ctx); err != nil {
		log.Printf("Error shutting down security manager: %v", err)
	}
}

// loadConfig loads kernel configuration from environment and files
func loadConfig() *KernelConfig {
	return &KernelConfig{
		Port:           getEnv("CAM_KERNEL_PORT", DefaultPort),
		LogLevel:       getEnv("CAM_LOG_LEVEL", DefaultLogLevel),
		RedisAddr:      getEnv("CAM_REDIS_ADDR", "localhost:6379"),
		TLSEnabled:     getEnv("CAM_TLS_ENABLED", "false") == "true",
		PostQuantum:    getEnv("CAM_POST_QUANTUM", "true") == "true",
		MetricsEnabled: getEnv("CAM_METRICS_ENABLED", "true") == "true",
	}
}

// getEnv gets environment variable with default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
} 