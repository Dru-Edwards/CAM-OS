package syscall_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cam-os/kernel/internal/arbitration"
	"github.com/cam-os/kernel/internal/explainability"
	"github.com/cam-os/kernel/internal/memory"
	"github.com/cam-os/kernel/internal/policy"
	"github.com/cam-os/kernel/internal/security"
	"github.com/cam-os/kernel/internal/syscall"
	"github.com/cam-os/kernel/internal/syscall/handlers"
	pb "github.com/cam-os/kernel/proto/generated"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc/codes"
)

// Mock implementations for testing
type MockArbitrationEngine struct {
	mock.Mock
}

func (m *MockArbitrationEngine) Arbitrate(ctx context.Context, task *arbitration.Task, policyID string) (*arbitration.Result, error) {
	args := m.Called(ctx, task, policyID)
	return args.Get(0).(*arbitration.Result), args.Error(1)
}

func (m *MockArbitrationEngine) CommitTask(ctx context.Context, task *arbitration.Task, agentID string) (string, error) {
	args := m.Called(ctx, task, agentID)
	return args.String(0), args.Error(1)
}

func (m *MockArbitrationEngine) RollbackTask(ctx context.Context, taskID, reason string) error {
	args := m.Called(ctx, taskID, reason)
	return args.Error(0)
}

func (m *MockArbitrationEngine) RegisterAgent(ctx context.Context, agentID string, capabilities []string, metadata map[string]string) error {
	args := m.Called(ctx, agentID, capabilities, metadata)
	return args.Error(0)
}

func (m *MockArbitrationEngine) HealthCheck(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

type MockMemoryManager struct {
	mock.Mock
}

func (m *MockMemoryManager) Read(ctx context.Context, namespace, key, version string) (*memory.ContextData, error) {
	args := m.Called(ctx, namespace, key, version)
	return args.Get(0).(*memory.ContextData), args.Error(1)
}

func (m *MockMemoryManager) Write(ctx context.Context, namespace, key string, data []byte, metadata map[string]string) (*memory.WriteResult, error) {
	args := m.Called(ctx, namespace, key, data, metadata)
	return args.Get(0).(*memory.WriteResult), args.Error(1)
}

func (m *MockMemoryManager) Snapshot(ctx context.Context, namespace, description string) (string, error) {
	args := m.Called(ctx, namespace, description)
	return args.String(0), args.Error(1)
}

func (m *MockMemoryManager) Restore(ctx context.Context, snapshotID string, force bool) (*memory.RestoreResult, error) {
	args := m.Called(ctx, snapshotID, force)
	return args.Get(0).(*memory.RestoreResult), args.Error(1)
}

func (m *MockMemoryManager) ListVersions(ctx context.Context, namespace, key string, limit int) ([]*memory.VersionInfo, error) {
	args := m.Called(ctx, namespace, key, limit)
	return args.Get(0).([]*memory.VersionInfo), args.Error(1)
}

func (m *MockMemoryManager) HealthCheck(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

type MockPolicyEngine struct {
	mock.Mock
}

func (m *MockPolicyEngine) Query(ctx context.Context, policyID, query string, context map[string]string) (*policy.QueryResult, error) {
	args := m.Called(ctx, policyID, query, context)
	return args.Get(0).(*policy.QueryResult), args.Error(1)
}

func (m *MockPolicyEngine) Update(ctx context.Context, policyID string, policyData []byte, metadata map[string]string) (string, error) {
	args := m.Called(ctx, policyID, policyData, metadata)
	return args.String(0), args.Error(1)
}

func (m *MockPolicyEngine) HealthCheck(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

type MockSecurityManager struct {
	mock.Mock
}

func (m *MockSecurityManager) TmpSignEnhanced(ctx context.Context, data []byte, keyID string) (*security.EnhancedSignResult, error) {
	args := m.Called(ctx, data, keyID)
	return args.Get(0).(*security.EnhancedSignResult), args.Error(1)
}

func (m *MockSecurityManager) VerifyManifest(ctx context.Context, manifest, signature, publicKey []byte) (*security.VerificationResult, error) {
	args := m.Called(ctx, manifest, signature, publicKey)
	return args.Get(0).(*security.VerificationResult), args.Error(1)
}

func (m *MockSecurityManager) EstablishSecureChannel(ctx context.Context, peerID, protocol string) (*security.ChannelResult, error) {
	args := m.Called(ctx, peerID, protocol)
	return args.Get(0).(*security.ChannelResult), args.Error(1)
}

func (m *MockSecurityManager) HealthCheck(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

type MockExplainabilityEngine struct {
	mock.Mock
}

func (m *MockExplainabilityEngine) Explain(ctx context.Context, traceID string, includeReasoning bool) (*explainability.Explanation, error) {
	args := m.Called(ctx, traceID, includeReasoning)
	return args.Get(0).(*explainability.Explanation), args.Error(1)
}

func (m *MockExplainabilityEngine) EmitTrace(ctx context.Context, event *explainability.TraceEvent) error {
	args := m.Called(ctx, event)
	return args.Error(0)
}

func (m *MockExplainabilityEngine) EmitMetric(ctx context.Context, event *explainability.MetricEvent) (string, error) {
	args := m.Called(ctx, event)
	return args.String(0), args.Error(1)
}

func (m *MockExplainabilityEngine) ApplySystemTuning(ctx context.Context, parameters map[string]string, profile string, dryRun bool) (*explainability.TuningResult, error) {
	args := m.Called(ctx, parameters, profile, dryRun)
	return args.Get(0).(*explainability.TuningResult), args.Error(1)
}

func (m *MockExplainabilityEngine) RecordDecision(ctx context.Context, decision *explainability.Decision) error {
	args := m.Called(ctx, decision)
	return args.Error(0)
}

// Test setup helper
func setupTestHandlers() (
	handlers.CoreHandler,
	handlers.MemoryHandler,
	handlers.SecurityHandler,
	handlers.ObservabilityHandler,
	*MockArbitrationEngine,
	*MockMemoryManager,
	*MockPolicyEngine,
	*MockSecurityManager,
	*MockExplainabilityEngine,
) {
	config := syscall.DefaultConfig()
	config.ArbitrationTimeout = 10 * time.Millisecond // Short timeout for tests
	config.MemoryTimeout = 10 * time.Millisecond
	config.SecurityTimeout = 10 * time.Millisecond
	config.ExplainabilityTimeout = 10 * time.Millisecond

	errorSanitizer := syscall.NewErrorSanitizer(false, nil) // Don't redact for tests

	mockArbitration := &MockArbitrationEngine{}
	mockMemory := &MockMemoryManager{}
	mockPolicy := &MockPolicyEngine{}
	mockSecurity := &MockSecurityManager{}
	mockExplainability := &MockExplainabilityEngine{}

	coreHandler := handlers.NewCoreHandler(
		mockArbitration,
		mockPolicy,
		mockExplainability,
		config,
		errorSanitizer,
	)

	memoryHandler := handlers.NewMemoryHandler(
		mockMemory,
		config,
		errorSanitizer,
	)

	securityHandler := handlers.NewSecurityHandler(
		mockSecurity,
		config,
		errorSanitizer,
	)

	observabilityHandler := handlers.NewObservabilityHandler(
		mockExplainability,
		config,
		errorSanitizer,
	)

	return coreHandler, memoryHandler, securityHandler, observabilityHandler,
		mockArbitration, mockMemory, mockPolicy, mockSecurity, mockExplainability
}

// Core Handler Tests
func TestCoreHandler_Arbitrate_Success(t *testing.T) {
	coreHandler, _, _, _, mockArbitration, _, _, _, mockExplainability := setupTestHandlers()

	// Setup expectations
	expectedResult := &arbitration.Result{
		TaskID:        "task-123",
		AssignedAgent: "agent-456",
		Provider:      "test-provider",
		Confidence:    0.95,
		Reasoning:     "Best match",
		TraceID:       "trace-789",
		Timestamp:     time.Now(),
	}

	mockArbitration.On("Arbitrate", mock.Anything, mock.Anything, "policy-123").Return(expectedResult, nil)
	mockExplainability.On("RecordDecision", mock.Anything, mock.Anything).Return(nil)

	// Create request
	req := &pb.ArbitrateRequest{
		Task: &pb.Task{
			Id:          "task-123",
			Description: "Test task",
			AgentId:     "agent-456",
		},
		PolicyId: "policy-123",
		CallerId: "test-caller",
	}

	// Execute
	resp, err := coreHandler.Arbitrate(context.Background(), req)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, int32(codes.OK), resp.StatusCode)
	assert.Equal(t, "task-123", resp.Result.TaskId)
	assert.Equal(t, "agent-456", resp.Result.AssignedAgent)
	
	mockArbitration.AssertExpectations(t)
	mockExplainability.AssertExpectations(t)
}

func TestCoreHandler_Arbitrate_ValidationError(t *testing.T) {
	coreHandler, _, _, _, _, _, _, _, _ := setupTestHandlers()

	// Test missing task
	req := &pb.ArbitrateRequest{
		CallerId: "test-caller",
	}

	resp, err := coreHandler.Arbitrate(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, int32(codes.InvalidArgument), resp.StatusCode)
	assert.Contains(t, resp.Error, "task is required")
}

func TestCoreHandler_Arbitrate_InvalidAgentID(t *testing.T) {
	coreHandler, _, _, _, _, _, _, _, _ := setupTestHandlers()

	req := &pb.ArbitrateRequest{
		Task: &pb.Task{
			Id:      "task-123",
			AgentId: "invalid@agent#id", // Invalid characters
		},
		CallerId: "test-caller",
	}

	resp, err := coreHandler.Arbitrate(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, int32(codes.InvalidArgument), resp.StatusCode)
	assert.Contains(t, resp.Error, "contains invalid characters")
}

func TestCoreHandler_CommitTask_Success(t *testing.T) {
	coreHandler, _, _, _, mockArbitration, _, _, _, _ := setupTestHandlers()

	mockArbitration.On("CommitTask", mock.Anything, mock.Anything, "agent-123").Return("commit-456", nil)

	req := &pb.CommitTaskRequest{
		Task: &pb.Task{
			Id:      "task-123",
			AgentId: "agent-123",
		},
		AgentId:  "agent-123",
		CallerId: "test-caller",
	}

	resp, err := coreHandler.CommitTask(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, int32(codes.OK), resp.StatusCode)
	assert.Equal(t, "task-123", resp.TaskId)
	assert.Equal(t, "commit-456", resp.CommitId)

	mockArbitration.AssertExpectations(t)
}

func TestCoreHandler_HealthCheck_Success(t *testing.T) {
	coreHandler, _, _, _, mockArbitration, _, mockPolicy, _, _ := setupTestHandlers()

	mockArbitration.On("HealthCheck", mock.Anything).Return(nil)
	mockPolicy.On("HealthCheck", mock.Anything).Return(nil)

	req := &pb.HealthCheckRequest{
		CallerId: "test-caller",
	}

	resp, err := coreHandler.HealthCheck(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, int32(codes.OK), resp.StatusCode)
	assert.Equal(t, "healthy", resp.Status)
	assert.Equal(t, "healthy", resp.Components["arbitration"])
	assert.Equal(t, "healthy", resp.Components["policy"])

	mockArbitration.AssertExpectations(t)
	mockPolicy.AssertExpectations(t)
}

// Memory Handler Tests
func TestMemoryHandler_ContextRead_Success(t *testing.T) {
	_, memoryHandler, _, _, _, mockMemory, _, _, _ := setupTestHandlers()

	expectedData := &memory.ContextData{
		Data:    []byte("test data"),
		Version: "v1",
		Hash:    "abc123",
	}

	mockMemory.On("Read", mock.Anything, "test-ns", "test-key", "v1").Return(expectedData, nil)

	req := &pb.ContextReadRequest{
		Namespace: "test-ns",
		Key:       "test-key",
		Version:   "v1",
		CallerId:  "test-caller",
	}

	resp, err := memoryHandler.ContextRead(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, int32(codes.OK), resp.StatusCode)
	assert.Equal(t, []byte("test data"), resp.Data)
	assert.Equal(t, "v1", resp.Version)
	assert.Equal(t, "abc123", resp.Hash)

	mockMemory.AssertExpectations(t)
}

func TestMemoryHandler_ContextRead_InvalidNamespace(t *testing.T) {
	_, memoryHandler, _, _, _, _, _, _, _ := setupTestHandlers()

	req := &pb.ContextReadRequest{
		Namespace: "INVALID-NAMESPACE!", // Invalid characters
		Key:       "test-key",
		CallerId:  "test-caller",
	}

	resp, err := memoryHandler.ContextRead(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, int32(codes.InvalidArgument), resp.StatusCode)
	assert.Contains(t, resp.Error, "contains invalid characters")
}

func TestMemoryHandler_ContextWrite_PayloadTooLarge(t *testing.T) {
	_, memoryHandler, _, _, _, _, _, _, _ := setupTestHandlers()

	largeData := make([]byte, 2*1024*1024) // 2MB, exceeds 1MB limit

	req := &pb.ContextWriteRequest{
		Namespace: "test-ns",
		Key:       "test-key",
		Data:      largeData,
		CallerId:  "test-caller",
	}

	resp, err := memoryHandler.ContextWrite(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, int32(codes.InvalidArgument), resp.StatusCode)
	assert.Contains(t, resp.Error, "payload too large")
}

// Security Handler Tests
func TestSecurityHandler_TmpSign_Success(t *testing.T) {
	_, _, securityHandler, _, _, _, _, mockSecurity, _ := setupTestHandlers()

	expectedResult := &security.EnhancedSignResult{
		Signature: []byte("signature"),
		Algorithm: "ECDSA-SHA256",
		KeyID:     "key-123",
		KeyHandle: "handle-456",
		CertChain: [][]byte{[]byte("cert1"), []byte("cert2")},
		Timestamp: time.Now(),
	}

	mockSecurity.On("TmpSignEnhanced", mock.Anything, []byte("test data"), "key-123").Return(expectedResult, nil)

	req := &pb.TmpSignRequest{
		Data:     []byte("test data"),
		KeyId:    "key-123",
		CallerId: "test-caller",
	}

	resp, err := securityHandler.TmpSign(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, int32(codes.OK), resp.StatusCode)
	assert.Equal(t, []byte("signature"), resp.Signature)
	assert.Equal(t, "ECDSA-SHA256", resp.Algorithm)
	assert.Equal(t, "key-123", resp.KeyId)
	assert.Equal(t, "handle-456", resp.KeyHandle)
	assert.Len(t, resp.CertChain, 2)

	mockSecurity.AssertExpectations(t)
}

func TestSecurityHandler_TmpSign_EmptyData(t *testing.T) {
	_, _, securityHandler, _, _, _, _, _, _ := setupTestHandlers()

	req := &pb.TmpSignRequest{
		Data:     []byte{}, // Empty data
		CallerId: "test-caller",
	}

	resp, err := securityHandler.TmpSign(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, int32(codes.InvalidArgument), resp.StatusCode)
	assert.Contains(t, resp.Error, "data is required")
}

func TestSecurityHandler_EstablishSecureChannel_InvalidProtocol(t *testing.T) {
	_, _, securityHandler, _, _, _, _, _, _ := setupTestHandlers()

	req := &pb.EstablishSecureChannelRequest{
		PeerId:   "peer-123",
		Protocol: "invalid-protocol",
		CallerId: "test-caller",
	}

	resp, err := securityHandler.EstablishSecureChannel(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, int32(codes.InvalidArgument), resp.StatusCode)
	assert.Contains(t, resp.Error, "unsupported protocol")
}

// Observability Handler Tests
func TestObservabilityHandler_EmitMetric_Success(t *testing.T) {
	_, _, _, observabilityHandler, _, _, _, _, mockExplainability := setupTestHandlers()

	mockExplainability.On("EmitMetric", mock.Anything, mock.Anything).Return("metric-123", nil)

	req := &pb.EmitMetricRequest{
		Name:     "test.metric",
		Value:    42.0,
		Type:     "gauge",
		Labels:   map[string]string{"env": "test"},
		CallerId: "test-caller",
	}

	resp, err := observabilityHandler.EmitMetric(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, int32(codes.OK), resp.StatusCode)
	assert.Equal(t, "metric-123", resp.MetricId)

	mockExplainability.AssertExpectations(t)
}

func TestObservabilityHandler_EmitMetric_TooManyLabels(t *testing.T) {
	_, _, _, observabilityHandler, _, _, _, _, _ := setupTestHandlers()

	// Create more than 20 labels
	labels := make(map[string]string)
	for i := 0; i < 25; i++ {
		labels[fmt.Sprintf("label%d", i)] = "value"
	}

	req := &pb.EmitMetricRequest{
		Name:     "test.metric",
		Value:    42.0,
		Labels:   labels,
		CallerId: "test-caller",
	}

	resp, err := observabilityHandler.EmitMetric(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, int32(codes.InvalidArgument), resp.StatusCode)
	assert.Contains(t, resp.Error, "too many labels")
}

func TestObservabilityHandler_SystemTuning_InvalidProfile(t *testing.T) {
	_, _, _, observabilityHandler, _, _, _, _, _ := setupTestHandlers()

	req := &pb.SystemTuningRequest{
		TuningProfile: "invalid-profile",
		CallerId:      "test-caller",
	}

	resp, err := observabilityHandler.SystemTuning(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, int32(codes.InvalidArgument), resp.StatusCode)
	assert.Contains(t, resp.Error, "invalid tuning profile")
}

// Timeout Tests
func TestCoreHandler_Arbitrate_Timeout(t *testing.T) {
	coreHandler, _, _, _, mockArbitration, _, _, _, _ := setupTestHandlers()

	// Mock a slow operation that will exceed the timeout
	mockArbitration.On("Arbitrate", mock.Anything, mock.Anything, "").Return(
		(*arbitration.Result)(nil), context.DeadlineExceeded)

	req := &pb.ArbitrateRequest{
		Task: &pb.Task{
			Id: "task-123",
		},
		CallerId: "test-caller",
	}

	resp, err := coreHandler.Arbitrate(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, int32(codes.Internal), resp.StatusCode)
	assert.Contains(t, resp.Error, "timeout exceeded")

	mockArbitration.AssertExpectations(t)
}

// Benchmark tests
func BenchmarkCoreHandler_Arbitrate(b *testing.B) {
	coreHandler, _, _, _, mockArbitration, _, _, _, mockExplainability := setupTestHandlers()

	expectedResult := &arbitration.Result{
		TaskID:        "task-123",
		AssignedAgent: "agent-456",
		TraceID:       "trace-789",
		Timestamp:     time.Now(),
	}

	mockArbitration.On("Arbitrate", mock.Anything, mock.Anything, "").Return(expectedResult, nil)
	mockExplainability.On("RecordDecision", mock.Anything, mock.Anything).Return(nil)

	req := &pb.ArbitrateRequest{
		Task: &pb.Task{
			Id: "task-123",
		},
		CallerId: "test-caller",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = coreHandler.Arbitrate(context.Background(), req)
	}
} 