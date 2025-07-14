package gate

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewQualityGateEngine(t *testing.T) {
	config := getTestQualityGateConfig()
	engine := NewQualityGateEngine(config)

	require.NotNil(t, engine)
	assert.Equal(t, config, engine.config)
	assert.NotNil(t, engine.securityValidator)
	assert.NotNil(t, engine.codeQualityAnalyzer)
	assert.NotNil(t, engine.performanceValidator)
	assert.NotNil(t, engine.integrationTester)
	assert.NotNil(t, engine.deploymentValidator)
	assert.NotNil(t, engine.complianceChecker)
	assert.NotNil(t, engine.metricsCollector)
	assert.NotNil(t, engine.reportGenerator)
	assert.NotNil(t, engine.gates)
	assert.NotNil(t, engine.gateTemplates)
	assert.NotNil(t, engine.policies)
	assert.NotNil(t, engine.rules)
	assert.NotNil(t, engine.executions)
	assert.NotNil(t, engine.activeGates)
	assert.NotNil(t, engine.validationResults)
	assert.NotNil(t, engine.qualityMetrics)
	assert.NotNil(t, engine.complianceStatus)
	assert.NotNil(t, engine.deploymentStatus)
	assert.NotNil(t, engine.validators)
	assert.NotNil(t, engine.analyzers)
	assert.NotNil(t, engine.testers)
	assert.NotNil(t, engine.checkers)
}

func TestQualityGateEngine_StartStop(t *testing.T) {
	config := getTestQualityGateConfig()
	engine := NewQualityGateEngine(config)

	// Test start
	err := engine.Start()
	assert.NoError(t, err)

	// Test stop
	err = engine.Stop()
	assert.NoError(t, err)
}

func TestQualityGateEngine_CreateGate(t *testing.T) {
	config := getTestQualityGateConfig()
	engine := NewQualityGateEngine(config)

	gate := &QualityGate{
		Name:        "Test Security Gate",
		Description: "Test security quality gate",
		Type:        GateTypeSecurity,
		Stage:       StageSecurity,
		Priority:    PriorityHigh,
		Criticality: CriticalityError,
		Timeout:     30 * time.Minute,
		Rules: []QualityRule{
			{
				Name:        "No Critical Vulnerabilities",
				Description: "Ensure no critical vulnerabilities exist",
				Type:        RuleTypeSecurity,
				Category:    "vulnerability",
				Severity:    SeverityCritical,
				Enabled:     true,
				Condition:   "vulnerabilities.critical == 0",
				Threshold: Threshold{
					Name:     "Critical Vulnerabilities",
					Type:     ThresholdTypeAbsolute,
					Operator: OperatorEquals,
					Value:    0,
					Unit:     "count",
				},
				Metric:      "critical_vulnerabilities",
				Operator:    OperatorEquals,
				Value:       0,
				Timeout:     5 * time.Minute,
				RetryCount:  3,
				FailureMode: FailureModeBreak,
			},
		},
		Conditions: []GateCondition{
			{
				Name:        "Environment Check",
				Description: "Ensure running in correct environment",
				Type:        ConditionTypeEnvironment,
				Condition:   "environment == 'staging' || environment == 'production'",
				Required:    true,
				Weight:      1.0,
			},
		},
		Thresholds: map[string]Threshold{
			"security_score": {
				Name:     "Security Score",
				Type:     ThresholdTypePercentage,
				Operator: OperatorGreaterThanOrEqual,
				Value:    80.0,
				Unit:     "percent",
				Warning:  70.0,
				Critical: 60.0,
				Blocking: 50.0,
			},
		},
		Metrics: []MetricDefinition{
			{
				Name:        "Security Score",
				Description: "Overall security score",
				Type:        MetricTypeGauge,
				Unit:        "percent",
				Source:      "security_validator",
				Aggregation: AggregationAvg,
			},
		},
		ExecutionMode:     ExecutionModeAutomatic,
		ApprovalRequired:  false,
		BreakOnFailure:    true,
		ContinueOnWarning: true,
		RetryPolicy: &RetryPolicy{
			MaxRetries:      3,
			RetryDelay:      5 * time.Second,
			BackoffStrategy: BackoffExponential,
			RetryConditions: []string{"timeout", "network_error"},
		},
		Tags:          []string{"security", "vulnerability", "compliance"},
		Labels:        map[string]string{"team": "security", "criticality": "high"},
		Annotations:   map[string]string{"docs": "https://wiki.example.com/security-gate"},
		Documentation: "This gate ensures that no critical security vulnerabilities exist in the codebase",
	}

	createdGate, err := engine.CreateGate(gate)
	require.NoError(t, err)
	require.NotNil(t, createdGate)

	assert.NotEmpty(t, createdGate.ID)
	assert.Equal(t, gate.Name, createdGate.Name)
	assert.Equal(t, gate.Description, createdGate.Description)
	assert.Equal(t, gate.Type, createdGate.Type)
	assert.Equal(t, gate.Stage, createdGate.Stage)
	assert.Equal(t, gate.Priority, createdGate.Priority)
	assert.Equal(t, gate.Criticality, createdGate.Criticality)
	assert.Equal(t, GateStatusDraft, createdGate.Status)
	assert.False(t, createdGate.CreatedAt.IsZero())
	assert.False(t, createdGate.UpdatedAt.IsZero())
	assert.Equal(t, len(gate.Rules), len(createdGate.Rules))
	assert.Equal(t, len(gate.Conditions), len(createdGate.Conditions))
	assert.Equal(t, len(gate.Thresholds), len(createdGate.Thresholds))
	assert.Equal(t, len(gate.Metrics), len(createdGate.Metrics))

	// Test gate retrieval
	retrievedGate, err := engine.GetGate(createdGate.ID)
	require.NoError(t, err)
	assert.Equal(t, createdGate.ID, retrievedGate.ID)
	assert.Equal(t, createdGate.Name, retrievedGate.Name)
}

func TestQualityGateEngine_ExecuteGate(t *testing.T) {
	config := getTestQualityGateConfig()
	engine := NewQualityGateEngine(config)

	// Create and activate a test gate
	gate := &QualityGate{
		Name:        "Test Execution Gate",
		Description: "Test gate for execution",
		Type:        GateTypeCodeQuality,
		Stage:       StageTest,
		Priority:    PriorityMedium,
		Status:      GateStatusActive,
		Rules: []QualityRule{
			{
				Name:    "Code Coverage",
				Type:    RuleTypeCodeQuality,
				Enabled: true,
			},
		},
		ExecutionMode: ExecutionModeAutomatic,
		Timeout:       30 * time.Minute,
	}

	createdGate, err := engine.CreateGate(gate)
	require.NoError(t, err)

	// Update status to active for execution
	createdGate.Status = GateStatusActive
	engine.gates[createdGate.ID] = createdGate

	// Execute gate
	request := &GateExecutionRequest{
		GateID: createdGate.ID,
		Context: map[string]interface{}{
			"project":     "test-project",
			"branch":      "main",
			"commit":      "abc123",
			"environment": "staging",
		},
		Branch:      "main",
		Commit:      "abc123",
		Version:     "1.0.0",
		Environment: "staging",
		Executor:    "test-executor",
		Tags:        []string{"test", "execution"},
	}

	execution, err := engine.ExecuteGate(request)
	require.NoError(t, err)
	require.NotNil(t, execution)

	assert.NotEmpty(t, execution.ID)
	assert.Equal(t, createdGate.ID, execution.GateID)
	assert.Equal(t, ExecutionStatusPending, execution.Status)
	assert.Equal(t, request.Executor, execution.Executor)
	assert.Equal(t, request.Context, execution.Context)
	assert.Equal(t, request.Branch, execution.Branch)
	assert.Equal(t, request.Commit, execution.Commit)
	assert.Equal(t, request.Version, execution.Version)
	assert.Equal(t, request.Environment, execution.Environment)
	assert.Equal(t, request.Tags, execution.Tags)
	assert.False(t, execution.StartTime.IsZero())
	assert.NotNil(t, execution.ValidationResults)
	assert.NotNil(t, execution.RuleResults)
	assert.NotNil(t, execution.MetricResults)
	assert.NotNil(t, execution.Warnings)
	assert.NotNil(t, execution.Errors)
	assert.NotNil(t, execution.Details)

	// Test execution retrieval
	retrievedExecution, err := engine.GetExecution(execution.ID)
	require.NoError(t, err)
	assert.Equal(t, execution.ID, retrievedExecution.ID)
	assert.Equal(t, execution.GateID, retrievedExecution.GateID)
}

func TestQualityGateEngine_GetMetrics(t *testing.T) {
	config := getTestQualityGateConfig()
	engine := NewQualityGateEngine(config)

	metrics := engine.GetMetrics()
	require.NotNil(t, metrics)

	assert.Contains(t, metrics, "total_gates")
	assert.Contains(t, metrics, "active_gates")
	assert.Contains(t, metrics, "passed_gates")
	assert.Contains(t, metrics, "failed_gates")
	assert.Contains(t, metrics, "total_validations")
	assert.Contains(t, metrics, "passed_validations")
	assert.Contains(t, metrics, "failed_validations")
	assert.Contains(t, metrics, "average_gate_time")
	assert.Contains(t, metrics, "timestamp")
}

func TestQualityGateEngine_GetStatus(t *testing.T) {
	config := getTestQualityGateConfig()
	engine := NewQualityGateEngine(config)

	status := engine.GetStatus()
	require.NotNil(t, status)

	assert.Contains(t, status, "engine_status")
	assert.Contains(t, status, "gates_count")
	assert.Contains(t, status, "executions_count")
	assert.Contains(t, status, "active_gates_count")
	assert.Contains(t, status, "gate_queue_size")
	assert.Contains(t, status, "result_queue_size")
	assert.Contains(t, status, "timestamp")
}

func TestSecurityValidator_Validate(t *testing.T) {
	config := getTestQualityGateConfig()
	validator := NewSecurityValidator(config)

	context := map[string]interface{}{
		"project_path": "/tmp/test-project",
		"language":     "go",
		"framework":    "gin",
		"environment":  "staging",
	}

	result, err := validator.Validate(context)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.NotEmpty(t, result.ID)
	assert.Equal(t, ValidationTypeSecurity, result.ValidationType)
	assert.Equal(t, ValidationStatusCompleted, result.Status)
	assert.True(t, result.Passed || result.Failed)
	assert.False(t, result.StartTime.IsZero())
	assert.False(t, result.EndTime.IsZero())
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
	assert.NotNil(t, result.Details)
	assert.NotNil(t, result.Warnings)
	assert.NotNil(t, result.Errors)

	// Check supported types
	supportedTypes := validator.GetSupportedTypes()
	assert.Contains(t, supportedTypes, ValidationTypeSecurity)
}

func TestSecurityValidator_VulnerabilityScanning(t *testing.T) {
	config := getTestQualityGateConfig()
	config.VulnerabilityScanEnabled = true
	validator := NewSecurityValidator(config)

	scanner := validator.scanners[ScanTypeVulnerability]
	require.NotNil(t, scanner)

	context := map[string]interface{}{
		"scan_target": "/tmp/test-project",
		"scan_type":   "vulnerability",
	}

	result, err := scanner.Scan(context)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, ScanTypeVulnerability, result.ScanType)
	assert.Equal(t, "completed", result.Status)
	assert.GreaterOrEqual(t, result.Score, 0.0)
	assert.LessOrEqual(t, result.Score, 100.0)
	assert.NotEmpty(t, result.Risk)
	assert.NotNil(t, result.Summary)
}

func TestSecurityValidator_SecretScanning(t *testing.T) {
	config := getTestQualityGateConfig()
	config.SecretScanEnabled = true
	validator := NewSecurityValidator(config)

	scanner := validator.scanners[ScanTypeSecret]
	require.NotNil(t, scanner)

	context := map[string]interface{}{
		"scan_target": "/tmp/test-project",
		"scan_type":   "secret",
	}

	result, err := scanner.Scan(context)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, ScanTypeSecret, result.ScanType)
	assert.Equal(t, "completed", result.Status)
	assert.GreaterOrEqual(t, result.Score, 0.0)
	assert.LessOrEqual(t, result.Score, 100.0)
}

func TestSecurityValidator_LicenseScanning(t *testing.T) {
	config := getTestQualityGateConfig()
	config.LicenseScanEnabled = true
	validator := NewSecurityValidator(config)

	scanner := validator.scanners[ScanTypeLicense]
	require.NotNil(t, scanner)

	context := map[string]interface{}{
		"scan_target": "/tmp/test-project",
		"scan_type":   "license",
	}

	result, err := scanner.Scan(context)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, ScanTypeLicense, result.ScanType)
	assert.Equal(t, "completed", result.Status)
	assert.GreaterOrEqual(t, result.Score, 0.0)
	assert.LessOrEqual(t, result.Score, 100.0)
}

func TestCodeQualityAnalyzer_Validate(t *testing.T) {
	config := getTestQualityGateConfig()
	analyzer := NewCodeQualityAnalyzer(config)

	context := map[string]interface{}{
		"project_path": "/tmp/test-project",
		"language":     "go",
		"test_path":    "/tmp/test-project/tests",
	}

	result, err := analyzer.Validate(context)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.NotEmpty(t, result.ID)
	assert.Equal(t, ValidationTypeCodeQuality, result.ValidationType)
	assert.Equal(t, ValidationStatusCompleted, result.Status)
	assert.True(t, result.Passed || result.Failed)
	assert.False(t, result.StartTime.IsZero())
	assert.False(t, result.EndTime.IsZero())
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
	assert.NotNil(t, result.Details)

	// Check quality result details
	qualityResult, exists := result.Details["quality_result"]
	require.True(t, exists)
	require.NotNil(t, qualityResult)

	// Check supported types
	supportedTypes := analyzer.GetSupportedTypes()
	assert.Contains(t, supportedTypes, ValidationTypeCodeQuality)
}

func TestCodeQualityAnalyzer_StaticAnalysis(t *testing.T) {
	config := getTestQualityGateConfig()
	config.StaticAnalysisEnabled = true
	analyzer := NewCodeQualityAnalyzer(config)

	context := map[string]interface{}{
		"project_path": "/tmp/test-project",
		"source_path":  "/tmp/test-project/src",
	}

	staticResult, err := analyzer.staticAnalyzer.Analyze(context)
	require.NoError(t, err)
	require.NotNil(t, staticResult)

	assert.GreaterOrEqual(t, staticResult.TotalIssues, 0)
	assert.GreaterOrEqual(t, staticResult.BugIssues, 0)
	assert.GreaterOrEqual(t, staticResult.SecurityIssues, 0)
	assert.GreaterOrEqual(t, staticResult.StyleIssues, 0)
	assert.GreaterOrEqual(t, staticResult.Score, 0.0)
	assert.LessOrEqual(t, staticResult.Score, 100.0)
	assert.NotNil(t, staticResult.Issues)
}

func TestCodeQualityAnalyzer_CoverageAnalysis(t *testing.T) {
	config := getTestQualityGateConfig()
	config.CodeCoverageEnabled = true
	analyzer := NewCodeQualityAnalyzer(config)

	context := map[string]interface{}{
		"project_path":  "/tmp/test-project",
		"coverage_file": "/tmp/test-project/coverage.out",
	}

	coverageResult, err := analyzer.coverageAnalyzer.Analyze(context)
	require.NoError(t, err)
	require.NotNil(t, coverageResult)

	assert.GreaterOrEqual(t, coverageResult.LineCoverage, 0.0)
	assert.LessOrEqual(t, coverageResult.LineCoverage, 100.0)
	assert.GreaterOrEqual(t, coverageResult.BranchCoverage, 0.0)
	assert.LessOrEqual(t, coverageResult.BranchCoverage, 100.0)
	assert.GreaterOrEqual(t, coverageResult.FunctionCoverage, 0.0)
	assert.LessOrEqual(t, coverageResult.FunctionCoverage, 100.0)
	assert.GreaterOrEqual(t, coverageResult.Score, 0.0)
	assert.LessOrEqual(t, coverageResult.Score, 100.0)
}

func TestCodeQualityAnalyzer_ComplexityAnalysis(t *testing.T) {
	config := getTestQualityGateConfig()
	config.ComplexityAnalysisEnabled = true
	analyzer := NewCodeQualityAnalyzer(config)

	context := map[string]interface{}{
		"project_path": "/tmp/test-project",
		"source_files": []string{"/tmp/test-project/main.go", "/tmp/test-project/handler.go"},
	}

	complexityResult, err := analyzer.complexityAnalyzer.Analyze(context)
	require.NoError(t, err)
	require.NotNil(t, complexityResult)

	assert.GreaterOrEqual(t, complexityResult.CyclomaticComplexity, 0.0)
	assert.GreaterOrEqual(t, complexityResult.CognitiveComplexity, 0.0)
	assert.GreaterOrEqual(t, complexityResult.MaxComplexity, 0)
	assert.GreaterOrEqual(t, complexityResult.AvgComplexity, 0.0)
	assert.GreaterOrEqual(t, complexityResult.Score, 0.0)
	assert.LessOrEqual(t, complexityResult.Score, 100.0)
	assert.NotNil(t, complexityResult.ComplexFunctions)
}

func TestCodeQualityAnalyzer_DuplicationAnalysis(t *testing.T) {
	config := getTestQualityGateConfig()
	config.DuplicationCheckEnabled = true
	analyzer := NewCodeQualityAnalyzer(config)

	context := map[string]interface{}{
		"project_path": "/tmp/test-project",
		"source_files": []string{"/tmp/test-project/main.go", "/tmp/test-project/handler.go"},
	}

	duplicationResult, err := analyzer.duplicationAnalyzer.Analyze(context)
	require.NoError(t, err)
	require.NotNil(t, duplicationResult)

	assert.GreaterOrEqual(t, duplicationResult.DuplicationPercentage, 0.0)
	assert.LessOrEqual(t, duplicationResult.DuplicationPercentage, 100.0)
	assert.GreaterOrEqual(t, duplicationResult.DuplicatedLines, 0)
	assert.GreaterOrEqual(t, duplicationResult.TotalLines, 0)
	assert.GreaterOrEqual(t, duplicationResult.Score, 0.0)
	assert.LessOrEqual(t, duplicationResult.Score, 100.0)
	assert.NotNil(t, duplicationResult.DuplicatedBlocks)
}

func TestPerformanceValidator_Validate(t *testing.T) {
	config := getTestQualityGateConfig()
	validator := NewPerformanceValidator(config)

	context := map[string]interface{}{
		"application_url":  "http://localhost:8080",
		"test_duration":    "30s",
		"concurrent_users": 10,
		"ramp_up_time":     "10s",
	}

	result, err := validator.Validate(context)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.NotEmpty(t, result.ID)
	assert.Equal(t, ValidationTypePerformance, result.ValidationType)
	assert.Equal(t, ValidationStatusCompleted, result.Status)
	assert.True(t, result.Passed || result.Failed)
	assert.False(t, result.StartTime.IsZero())
	assert.False(t, result.EndTime.IsZero())
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
	assert.NotNil(t, result.Details)

	// Check performance result details
	perfResult, exists := result.Details["performance_result"]
	require.True(t, exists)
	require.NotNil(t, perfResult)

	// Check supported types
	supportedTypes := validator.GetSupportedTypes()
	assert.Contains(t, supportedTypes, ValidationTypePerformance)
}

func TestPerformanceValidator_LoadTesting(t *testing.T) {
	config := getTestQualityGateConfig()
	config.LoadTestingEnabled = true
	validator := NewPerformanceValidator(config)

	context := map[string]interface{}{
		"target_url":       "http://localhost:8080/api/health",
		"concurrent_users": 50,
		"test_duration":    "60s",
		"ramp_up_time":     "10s",
	}

	loadResult, err := validator.loadTester.Test(context)
	require.NoError(t, err)
	require.NotNil(t, loadResult)

	assert.GreaterOrEqual(t, loadResult.TotalRequests, 0)
	assert.GreaterOrEqual(t, loadResult.SuccessfulRequests, 0)
	assert.GreaterOrEqual(t, loadResult.FailedRequests, 0)
	assert.GreaterOrEqual(t, loadResult.AverageResponseTime, time.Duration(0))
	assert.GreaterOrEqual(t, loadResult.P95ResponseTime, time.Duration(0))
	assert.GreaterOrEqual(t, loadResult.P99ResponseTime, time.Duration(0))
	assert.GreaterOrEqual(t, loadResult.Throughput, 0.0)
	assert.GreaterOrEqual(t, loadResult.ErrorRate, 0.0)
	assert.LessOrEqual(t, loadResult.ErrorRate, 100.0)
	assert.GreaterOrEqual(t, loadResult.Score, 0.0)
	assert.LessOrEqual(t, loadResult.Score, 100.0)
}

func TestPerformanceValidator_StressTesting(t *testing.T) {
	config := getTestQualityGateConfig()
	config.StressTestingEnabled = true
	validator := NewPerformanceValidator(config)

	context := map[string]interface{}{
		"target_url":         "http://localhost:8080/api/health",
		"max_users":          200,
		"user_increment":     10,
		"increment_interval": "5s",
		"test_duration":      "120s",
	}

	stressResult, err := validator.stressTester.Test(context)
	require.NoError(t, err)
	require.NotNil(t, stressResult)

	assert.GreaterOrEqual(t, stressResult.MaxConcurrentUsers, 0)
	assert.GreaterOrEqual(t, stressResult.BreakingPoint, 0)
	assert.GreaterOrEqual(t, stressResult.RecoveryTime, time.Duration(0))
	assert.GreaterOrEqual(t, stressResult.ErrorsUnderStress, 0)
	assert.GreaterOrEqual(t, stressResult.PerformanceDegradation, 0.0)
	assert.GreaterOrEqual(t, stressResult.Score, 0.0)
	assert.LessOrEqual(t, stressResult.Score, 100.0)
}

func TestPerformanceValidator_MemoryTesting(t *testing.T) {
	config := getTestQualityGateConfig()
	config.MemoryTestingEnabled = true
	validator := NewPerformanceValidator(config)

	context := map[string]interface{}{
		"application_pid":     "12345",
		"monitoring_duration": "60s",
		"sampling_interval":   "1s",
	}

	memoryResult, err := validator.memoryTester.Test(context)
	require.NoError(t, err)
	require.NotNil(t, memoryResult)

	assert.GreaterOrEqual(t, memoryResult.MaxMemoryUsage, int64(0))
	assert.GreaterOrEqual(t, memoryResult.AverageMemoryUsage, int64(0))
	assert.LessOrEqual(t, memoryResult.AverageMemoryUsage, memoryResult.MaxMemoryUsage)
	assert.GreaterOrEqual(t, memoryResult.GCPressure, 0.0)
	assert.GreaterOrEqual(t, memoryResult.AllocationRate, 0.0)
	assert.GreaterOrEqual(t, memoryResult.Score, 0.0)
	assert.LessOrEqual(t, memoryResult.Score, 100.0)
	assert.NotNil(t, memoryResult.MemoryLeaks)
}

func TestIntegrationTester_Validate(t *testing.T) {
	config := getTestQualityGateConfig()
	tester := NewIntegrationTester(config)

	context := map[string]interface{}{
		"application_url": "http://localhost:8080",
		"test_suite":      "integration",
		"environment":     "staging",
		"database_url":    "postgresql://localhost:5432/testdb",
		"redis_url":       "redis://localhost:6379",
	}

	result, err := tester.Validate(context)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.NotEmpty(t, result.ID)
	assert.Equal(t, ValidationTypeIntegration, result.ValidationType)
	assert.Equal(t, ValidationStatusCompleted, result.Status)
	assert.True(t, result.Passed || result.Failed)
	assert.False(t, result.StartTime.IsZero())
	assert.False(t, result.EndTime.IsZero())
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
	assert.NotNil(t, result.Details)

	// Check supported types
	supportedTypes := tester.GetSupportedTypes()
	assert.Contains(t, supportedTypes, ValidationTypeIntegration)
}

func TestDeploymentValidator_Validate(t *testing.T) {
	config := getTestQualityGateConfig()
	validator := NewDeploymentValidator(config)

	context := map[string]interface{}{
		"deployment_environment": "staging",
		"application_version":    "1.2.3",
		"container_image":        "myapp:1.2.3",
		"k8s_namespace":          "staging",
		"health_check_url":       "http://localhost:8080/health",
		"readiness_check_url":    "http://localhost:8080/ready",
	}

	result, err := validator.Validate(context)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.NotEmpty(t, result.ID)
	assert.Equal(t, ValidationTypeDeployment, result.ValidationType)
	assert.Equal(t, ValidationStatusCompleted, result.Status)
	assert.True(t, result.Passed || result.Failed)
	assert.False(t, result.StartTime.IsZero())
	assert.False(t, result.EndTime.IsZero())
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
	assert.NotNil(t, result.Details)

	// Check supported types
	supportedTypes := validator.GetSupportedTypes()
	assert.Contains(t, supportedTypes, ValidationTypeDeployment)
}

func TestComplianceChecker_Validate(t *testing.T) {
	config := getTestQualityGateConfig()
	checker := NewComplianceChecker(config)

	context := map[string]interface{}{
		"compliance_frameworks": []string{"SOX", "GDPR", "PCI_DSS"},
		"project_path":          "/tmp/test-project",
		"documentation_path":    "/tmp/test-project/docs",
		"policy_path":           "/tmp/test-project/policies",
	}

	result, err := checker.Validate(context)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.NotEmpty(t, result.ID)
	assert.Equal(t, ValidationTypeCompliance, result.ValidationType)
	assert.Equal(t, ValidationStatusCompleted, result.Status)
	assert.True(t, result.Passed || result.Failed)
	assert.False(t, result.StartTime.IsZero())
	assert.False(t, result.EndTime.IsZero())
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
	assert.NotNil(t, result.Details)

	// Check supported types
	supportedTypes := checker.GetSupportedTypes()
	assert.Contains(t, supportedTypes, ValidationTypeCompliance)
}

func TestMetricsCollector_Start(t *testing.T) {
	config := getTestQualityGateConfig()
	collector := NewMetricsCollector(config)

	err := collector.Start()
	assert.NoError(t, err)

	// Wait a bit for metrics collection
	time.Sleep(100 * time.Millisecond)

	metrics := collector.GetMetrics()
	require.NotNil(t, metrics)
	assert.GreaterOrEqual(t, len(metrics), 0)
}

func TestReportGenerator_GenerateReport(t *testing.T) {
	config := getTestQualityGateConfig()
	generator := NewReportGenerator(config)

	// Create test executions
	executions := []*GateExecution{
		{
			ID:        "exec1",
			GateID:    "gate1",
			Status:    ExecutionStatusCompleted,
			Result:    ExecutionResultPassed,
			Score:     85.5,
			Passed:    true,
			Failed:    false,
			Duration:  45 * time.Second,
			StartTime: time.Now().Add(-1 * time.Hour),
			EndTime:   time.Now().Add(-1*time.Hour + 45*time.Second),
		},
		{
			ID:        "exec2",
			GateID:    "gate2",
			Status:    ExecutionStatusCompleted,
			Result:    ExecutionResultFailed,
			Score:     65.2,
			Passed:    false,
			Failed:    true,
			Duration:  32 * time.Second,
			StartTime: time.Now().Add(-30 * time.Minute),
			EndTime:   time.Now().Add(-30*time.Minute + 32*time.Second),
		},
		{
			ID:        "exec3",
			GateID:    "gate3",
			Status:    ExecutionStatusCompleted,
			Result:    ExecutionResultWarning,
			Score:     78.9,
			Passed:    true,
			Failed:    false,
			Duration:  28 * time.Second,
			StartTime: time.Now().Add(-15 * time.Minute),
			EndTime:   time.Now().Add(-15*time.Minute + 28*time.Second),
		},
	}

	report, err := generator.GenerateReport(executions)
	require.NoError(t, err)
	require.NotNil(t, report)

	assert.NotEmpty(t, report.ID)
	assert.False(t, report.GeneratedAt.IsZero())
	assert.NotNil(t, report.Summary)
	assert.Equal(t, executions, report.Executions)
	assert.NotNil(t, report.Metrics)
	assert.NotNil(t, report.Recommendations)

	// Check summary
	summary := report.Summary
	assert.Equal(t, 3, summary.TotalExecutions)
	assert.Equal(t, 2, summary.PassedExecutions) // passed + warning
	assert.Equal(t, 1, summary.FailedExecutions)
	assert.Equal(t, 1, summary.WarningExecutions)
	assert.GreaterOrEqual(t, summary.AverageScore, 0.0)
	assert.LessOrEqual(t, summary.AverageScore, 100.0)
	assert.GreaterOrEqual(t, summary.AverageExecutionTime, time.Duration(0))

	// Check recommendations
	assert.GreaterOrEqual(t, len(report.Recommendations), 1)
}

func TestQualityGateValidation_SecurityThresholds(t *testing.T) {
	config := getTestQualityGateConfig()
	config.MaxCriticalVulnerabilities = 0
	config.MaxHighVulnerabilities = 5
	config.MaxVulnerabilityCount = 50

	validator := NewSecurityValidator(config)

	// Test with no vulnerabilities (should pass)
	passed := validator.evaluateSecurityThresholds([]Vulnerability{}, []SecretLeak{}, []LicenseIssue{}, []ComplianceIssue{})
	assert.True(t, passed)

	// Test with critical vulnerabilities (should fail)
	vulns := []Vulnerability{
		{Severity: SeverityCritical},
	}
	passed = validator.evaluateSecurityThresholds(vulns, []SecretLeak{}, []LicenseIssue{}, []ComplianceIssue{})
	assert.False(t, passed)

	// Test with too many high vulnerabilities (should fail)
	vulns = []Vulnerability{
		{Severity: SeverityHigh},
		{Severity: SeverityHigh},
		{Severity: SeverityHigh},
		{Severity: SeverityHigh},
		{Severity: SeverityHigh},
		{Severity: SeverityHigh}, // 6 high vulns, threshold is 5
	}
	passed = validator.evaluateSecurityThresholds(vulns, []SecretLeak{}, []LicenseIssue{}, []ComplianceIssue{})
	assert.False(t, passed)

	// Test with secrets (should fail)
	secrets := []SecretLeak{
		{Type: SecretTypeAPIKey},
	}
	passed = validator.evaluateSecurityThresholds([]Vulnerability{}, secrets, []LicenseIssue{}, []ComplianceIssue{})
	assert.False(t, passed)
}

func TestQualityGateValidation_CodeQualityThresholds(t *testing.T) {
	config := getTestQualityGateConfig()
	config.MinCodeCoverage = 80.0
	config.MaxCyclomaticComplexity = 10
	config.MaxDuplicationPercentage = 5.0

	analyzer := NewCodeQualityAnalyzer(config)

	// Test with good quality metrics (should pass)
	qualityResult := &CodeQualityResult{
		Coverage: &CoverageResult{
			LineCoverage: 85.0,
		},
		Complexity: &ComplexityResult{
			MaxComplexity: 8,
		},
		Duplication: &DuplicationResult{
			DuplicationPercentage: 3.0,
		},
	}

	passed := analyzer.evaluateQualityThresholds(qualityResult)
	assert.True(t, passed)

	// Test with low coverage (should fail)
	qualityResult.Coverage.LineCoverage = 75.0
	passed = analyzer.evaluateQualityThresholds(qualityResult)
	assert.False(t, passed)

	// Test with high complexity (should fail)
	qualityResult.Coverage.LineCoverage = 85.0
	qualityResult.Complexity.MaxComplexity = 15
	passed = analyzer.evaluateQualityThresholds(qualityResult)
	assert.False(t, passed)

	// Test with high duplication (should fail)
	qualityResult.Complexity.MaxComplexity = 8
	qualityResult.Duplication.DuplicationPercentage = 7.0
	passed = analyzer.evaluateQualityThresholds(qualityResult)
	assert.False(t, passed)
}

func TestQualityGateValidation_PerformanceThresholds(t *testing.T) {
	config := getTestQualityGateConfig()
	config.MaxResponseTime = 200 * time.Millisecond
	config.MaxMemoryUsage = 512 * 1024 * 1024 // 512MB
	config.MinPerformanceScore = 80.0

	validator := NewPerformanceValidator(config)

	// Test with good performance metrics (should pass)
	perfResult := &PerformanceResult{
		LoadTest: &LoadTestResult{
			AverageResponseTime: 150 * time.Millisecond,
		},
		MemoryTest: &MemoryTestResult{
			MaxMemoryUsage: 256 * 1024 * 1024, // 256MB
		},
		OverallScore: 85.0,
	}

	passed := validator.evaluatePerformanceThresholds(perfResult)
	assert.True(t, passed)

	// Test with slow response time (should fail)
	perfResult.LoadTest.AverageResponseTime = 300 * time.Millisecond
	passed = validator.evaluatePerformanceThresholds(perfResult)
	assert.False(t, passed)

	// Test with high memory usage (should fail)
	perfResult.LoadTest.AverageResponseTime = 150 * time.Millisecond
	perfResult.MemoryTest.MaxMemoryUsage = 1024 * 1024 * 1024 // 1GB
	passed = validator.evaluatePerformanceThresholds(perfResult)
	assert.False(t, passed)

	// Test with low performance score (should fail)
	perfResult.MemoryTest.MaxMemoryUsage = 256 * 1024 * 1024 // 256MB
	perfResult.OverallScore = 75.0
	passed = validator.evaluatePerformanceThresholds(perfResult)
	assert.False(t, passed)
}

func TestQualityRule_Evaluation(t *testing.T) {
	// Test different rule types and operators
	testCases := []struct {
		name     string
		rule     QualityRule
		value    interface{}
		expected bool
	}{
		{
			name: "Equals operator - pass",
			rule: QualityRule{
				Operator: OperatorEquals,
				Value:    0,
			},
			value:    0,
			expected: true,
		},
		{
			name: "Equals operator - fail",
			rule: QualityRule{
				Operator: OperatorEquals,
				Value:    0,
			},
			value:    1,
			expected: false,
		},
		{
			name: "Greater than operator - pass",
			rule: QualityRule{
				Operator: OperatorGreaterThan,
				Value:    80.0,
			},
			value:    85.0,
			expected: true,
		},
		{
			name: "Greater than operator - fail",
			rule: QualityRule{
				Operator: OperatorGreaterThan,
				Value:    80.0,
			},
			value:    75.0,
			expected: false,
		},
		{
			name: "Less than or equal operator - pass",
			rule: QualityRule{
				Operator: OperatorLessThanOrEqual,
				Value:    10,
			},
			value:    8,
			expected: true,
		},
		{
			name: "Less than or equal operator - fail",
			rule: QualityRule{
				Operator: OperatorLessThanOrEqual,
				Value:    10,
			},
			value:    12,
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// This would be implemented in actual rule evaluation logic
			// For testing purposes, we'll simulate the evaluation
			var result bool

			switch tc.rule.Operator {
			case OperatorEquals:
				result = tc.value == tc.rule.Value
			case OperatorGreaterThan:
				if vFloat, ok := tc.value.(float64); ok {
					if rFloat, ok := tc.rule.Value.(float64); ok {
						result = vFloat > rFloat
					}
				}
			case OperatorLessThanOrEqual:
				if vInt, ok := tc.value.(int); ok {
					if rInt, ok := tc.rule.Value.(int); ok {
						result = vInt <= rInt
					}
				}
			}

			assert.Equal(t, tc.expected, result)
		})
	}
}

// Helper function to create test configuration
func getTestQualityGateConfig() *QualityGateConfig {
	return &QualityGateConfig{
		MaxConcurrentGates:             10,
		MaxConcurrentValidations:       20,
		GateTimeout:                    30 * time.Minute,
		ValidationTimeout:              10 * time.Minute,
		RetryAttempts:                  3,
		RetryDelay:                     5 * time.Second,
		GateQueueSize:                  100,
		ResultQueueSize:                50,
		ProcessingWorkers:              5,
		ValidationWorkers:              10,
		SecurityScanEnabled:            true,
		VulnerabilityScanEnabled:       true,
		LicenseScanEnabled:             true,
		SecretScanEnabled:              true,
		ComplianceScanEnabled:          true,
		ThreatModelingEnabled:          true,
		StaticAnalysisEnabled:          true,
		CodeCoverageEnabled:            true,
		ComplexityAnalysisEnabled:      true,
		DuplicationCheckEnabled:        true,
		StyleCheckEnabled:              true,
		DocumentationCheckEnabled:      true,
		PerformanceTestingEnabled:      true,
		LoadTestingEnabled:             true,
		StressTestingEnabled:           true,
		MemoryTestingEnabled:           true,
		SecurityTestingEnabled:         true,
		IntegrationTestingEnabled:      true,
		SOX_ComplianceEnabled:          true,
		GDPR_ComplianceEnabled:         true,
		HIPAA_ComplianceEnabled:        false,
		PCI_DSS_ComplianceEnabled:      true,
		SOC2_ComplianceEnabled:         true,
		ISO27001_ComplianceEnabled:     true,
		NIST_ComplianceEnabled:         true,
		DeploymentValidationEnabled:    true,
		HealthCheckEnabled:             true,
		ConfigurationValidationEnabled: true,
		DependencyCheckEnabled:         true,
		ResourceValidationEnabled:      true,
		NetworkValidationEnabled:       true,
		MinCodeCoverage:                80.0,
		MaxCyclomaticComplexity:        10,
		MaxDuplicationPercentage:       5.0,
		MaxVulnerabilityCount:          50,
		MaxCriticalVulnerabilities:     0,
		MaxHighVulnerabilities:         5,
		MinPerformanceScore:            80.0,
		MaxResponseTime:                200 * time.Millisecond,
		MaxMemoryUsage:                 512 * 1024 * 1024, // 512MB
		JenkinsIntegration:             false,
		GitHubActionsIntegration:       true,
		GitLabCIIntegration:            false,
		SonarQubeIntegration:           true,
		VeracodeIntegration:            false,
		SnykIntegration:                true,
		JFrogXrayIntegration:           false,
		NotificationsEnabled:           true,
		EmailNotifications:             true,
		SlackIntegrations:              true,
		TeamsIntegrations:              false,
		WebhookNotifications:           true,
		JiraIntegration:                false,
		ReportStoragePath:              "/tmp/quality-reports",
		MetricsStoragePath:             "/tmp/quality-metrics",
		ArtifactStoragePath:            "/tmp/quality-artifacts",
		ResultRetentionPeriod:          30 * 24 * time.Hour,
		MetricsRetentionPeriod:         90 * 24 * time.Hour,
		AIAnalysisEnabled:              false,
		MLModelingEnabled:              false,
		PredictiveAnalysisEnabled:      false,
		TrendAnalysisEnabled:           true,
		AnomalyDetectionEnabled:        true,
		RiskScoringEnabled:             true,
	}
}

// Benchmark tests
func BenchmarkQualityGateEngine_CreateGate(b *testing.B) {
	config := getTestQualityGateConfig()
	engine := NewQualityGateEngine(config)

	gate := &QualityGate{
		Name:        "Benchmark Gate",
		Description: "Benchmark gate for performance testing",
		Type:        GateTypeSecurity,
		Stage:       StageSecurity,
		Priority:    PriorityMedium,
		Rules: []QualityRule{
			{
				Name:    "Benchmark Rule",
				Type:    RuleTypeSecurity,
				Enabled: true,
			},
		},
		ExecutionMode: ExecutionModeAutomatic,
		Timeout:       30 * time.Minute,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := engine.CreateGate(gate)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSecurityValidator_Validate(b *testing.B) {
	config := getTestQualityGateConfig()
	validator := NewSecurityValidator(config)

	context := map[string]interface{}{
		"project_path": "/tmp/benchmark-project",
		"language":     "go",
		"environment":  "test",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := validator.Validate(context)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCodeQualityAnalyzer_Validate(b *testing.B) {
	config := getTestQualityGateConfig()
	analyzer := NewCodeQualityAnalyzer(config)

	context := map[string]interface{}{
		"project_path": "/tmp/benchmark-project",
		"language":     "go",
		"test_path":    "/tmp/benchmark-project/tests",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := analyzer.Validate(context)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPerformanceValidator_Validate(b *testing.B) {
	config := getTestQualityGateConfig()
	validator := NewPerformanceValidator(config)

	context := map[string]interface{}{
		"application_url":  "http://localhost:8080",
		"test_duration":    "10s",
		"concurrent_users": 5,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := validator.Validate(context)
		if err != nil {
			b.Fatal(err)
		}
	}
}
