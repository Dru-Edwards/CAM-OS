package integration

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cam-os/kernel/internal/syscall"
	pb "github.com/cam-os/kernel/proto/generated"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// TestConfig represents test configuration
type TestConfig struct {
	SyscallTimeout time.Duration
	ServerAddr     string
}

// setupTestClient creates a test gRPC client connection
func setupTestClient() (pb.SyscallServiceClient, *grpc.ClientConn, error) {
	// Get server address from environment or use default
	serverAddr := os.Getenv("CAM_TEST_SERVER_ADDR")
	if serverAddr == "" {
		serverAddr = "localhost:50051"
	}

	// Create gRPC connection
	conn, err := grpc.Dial(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to server: %v", err)
	}

	// Create client
	client := pb.NewSyscallServiceClient(conn)

	return client, conn, nil
}

// loadTestConfig loads test configuration
func loadTestConfig() (*TestConfig, error) {
	// Load syscall configuration
	syscallConfig := syscall.DefaultConfig()

	config := &TestConfig{
		SyscallTimeout: syscallConfig.SyscallTimeout,
		ServerAddr:     "localhost:50051",
	}

	// Override with environment variables if present
	if addr := os.Getenv("CAM_TEST_SERVER_ADDR"); addr != "" {
		config.ServerAddr = addr
	}

	return config, nil
}

// setupTestServer starts a test server for integration tests
func setupTestServer() error {
	// This would start the CAM-OS server for testing
	// For now, we assume the server is already running
	log.Println("Using existing CAM-OS server for integration tests")
	return nil
}

// cleanupTestServer shuts down the test server
func cleanupTestServer() error {
	// Cleanup logic would go here
	return nil
}
