package forensics

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewForensicEngine(t *testing.T) {
	config := &ForensicConfig{
		EnableMemoryAnalysis:   true,
		EnableDiskAnalysis:     true,
		EnableNetworkAnalysis:  true,
		EnableRegistryAnalysis: true,
		EnableLogAnalysis:      true,
		EnableMalwareAnalysis:  true,
		MaxEvidenceSize:        1024 * 1024 * 1024, // 1GB
		CompressionEnabled:     true,
		EncryptionEnabled:      true,
		HashingAlgorithm:       "sha256",
		AnalysisWorkers:        4,
		MaxConcurrentAnalysis:  10,
		AnalysisTimeout:        30 * time.Minute,
		MaxMemoryUsage:         2 * 1024 * 1024 * 1024, // 2GB
		TempDirectory:          "/tmp/forensics",
		EvidenceStoragePath:    "/var/lib/forensics/evidence",
		ReportStoragePath:      "/var/lib/forensics/reports",
		RetentionPeriod:        365 * 24 * time.Hour, // 1 year
		BackupEnabled:          true,
		BackupInterval:         24 * time.Hour,
		RequireDigitalSignature: true,
		AuditTrailEnabled:      true,
		TimestampingEnabled:    true,
		AutoIncidentCreation:   true,
		ComplianceMode:         "strict",
		DataClassification:     "confidential",
		PrivacyMode:            true,
		CacheSize:              1000,
		IndexingEnabled:        true,
		SearchOptimization:     true,
		SIEMIntegration:        true,
		TIPIntegration:         true,
		SOARIntegration:        true,
		AlertThreshold:         0.8,
		AlertsEnabled:          true,
		RealTimeAlerts:         true,
	}

	engine := NewForensicEngine(config)
	require.NotNil(t, engine)
	assert.Equal(t, config, engine.config)
	assert.NotNil(t, engine.evidenceCollector)
	assert.NotNil(t, engine.artifactAnalyzer)
	assert.NotNil(t, engine.timelineBuilder)
	assert.NotNil(t, engine.reportGenerator)
	assert.NotNil(t, engine.chainOfCustody)
	assert.NotNil(t, engine.incidentManager)
	assert.NotNil(t, engine.cases)
	assert.NotNil(t, engine.evidence)
	assert.NotNil(t, engine.artifacts)
	assert.NotNil(t, engine.timelines)
	assert.NotNil(t, engine.reports)
}

func TestForensicEngine_StartStop(t *testing.T) {
	config := getTestConfig()
	engine := NewForensicEngine(config)

	// Test start
	err := engine.Start()
	assert.NoError(t, err)

	// Test stop
	err = engine.Stop()
	assert.NoError(t, err)
}

func TestForensicEngine_CreateCase(t *testing.T) {
	config := getTestConfig()
	engine := NewForensicEngine(config)

	caseInfo := &ForensicCase{
		Title:            "Test Case",
		Description:      "Test case for unit testing",
		CaseType:         CaseTypeCyberIncident,
		Priority:         CasePriorityHigh,
		Status:           CaseStatusNew,
		Severity:         CaseSeverityHigh,
		Investigator:     "test_investigator",
		AssignedTeam:     []string{"forensics_team"},
		Organization:     "test_org",
		Jurisdiction:     "test_jurisdiction",
		IncidentType:     "malware",
		SuspectedActors:  []string{"unknown"},
		AffectedSystems:  []string{"server1", "server2"},
		AffectedUsers:    []string{"user1", "user2"},
		LegalHold:        true,
		CourtAdmissible:  true,
		ComplianceFramework: "ISO27001",
		DataClassification:  "confidential",
		PrivacyImpact:      "high",
		Tags:               []string{"malware", "investigation"},
	}

	createdCase, err := engine.CreateCase(caseInfo)
	require.NoError(t, err)
	require.NotNil(t, createdCase)

	assert.NotEmpty(t, createdCase.ID)
	assert.Equal(t, caseInfo.Title, createdCase.Title)
	assert.Equal(t, caseInfo.Description, createdCase.Description)
	assert.Equal(t, caseInfo.CaseType, createdCase.CaseType)
	assert.Equal(t, caseInfo.Priority, createdCase.Priority)
	assert.Equal(t, caseInfo.Severity, createdCase.Severity)
	assert.Equal(t, caseInfo.Investigator, createdCase.Investigator)
	assert.False(t, createdCase.CreatedAt.IsZero())
	assert.False(t, createdCase.UpdatedAt.IsZero())

	// Test case retrieval
	retrievedCase, err := engine.GetCase(createdCase.ID)
	require.NoError(t, err)
	assert.Equal(t, createdCase.ID, retrievedCase.ID)
	assert.Equal(t, createdCase.Title, retrievedCase.Title)
}

func TestForensicEngine_CollectEvidence(t *testing.T) {
	config := getTestConfig()
	engine := NewForensicEngine(config)

	// Create test case first
	caseInfo := &ForensicCase{
		Title:        "Test Case",
		Description:  "Test case for evidence collection",
		CaseType:     CaseTypeCyberIncident,
		Priority:     CasePriorityHigh,
		Status:       CaseStatusNew,
		Severity:     CaseSeverityHigh,
		Investigator: "test_investigator",
	}

	createdCase, err := engine.CreateCase(caseInfo)
	require.NoError(t, err)

	// Create temporary test file
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test_evidence.txt")
	testContent := "This is test evidence content"
	err = os.WriteFile(testFile, []byte(testContent), 0644)
	require.NoError(t, err)

	// Create evidence request
	evidenceRequest := &EvidenceRequest{
		Name:             "Test Evidence",
		Description:      "Test evidence file",
		Type:             EvidenceTypeFile,
		Source:           "test_system",
		Location:         testFile,
		Collector:        "test_collector",
		CollectionMethod: "manual",
		CollectionTool:   "test_tool",
		Metadata:         map[string]interface{}{"test": "value"},
		Tags:             []string{"test", "evidence"},
	}

	evidence, err := engine.CollectEvidence(createdCase.ID, evidenceRequest)
	require.NoError(t, err)
	require.NotNil(t, evidence)

	assert.NotEmpty(t, evidence.ID)
	assert.Equal(t, evidenceRequest.Name, evidence.Name)
	assert.Equal(t, evidenceRequest.Description, evidence.Description)
	assert.Equal(t, evidenceRequest.Type, evidence.Type)
	assert.Equal(t, evidenceRequest.Source, evidence.Source)
	assert.Equal(t, evidenceRequest.Location, evidence.Location)
	assert.Equal(t, evidenceRequest.Collector, evidence.Collector)
	assert.Equal(t, evidenceRequest.CollectionMethod, evidence.CollectionMethod)
	assert.Equal(t, evidenceRequest.CollectionTool, evidence.CollectionTool)
	assert.Equal(t, int64(len(testContent)), evidence.Size)
	assert.Equal(t, AnalysisStatusPending, evidence.AnalysisStatus)
	assert.NotEmpty(t, evidence.MD5Hash)
	assert.NotEmpty(t, evidence.SHA1Hash)
	assert.NotEmpty(t, evidence.SHA256Hash)
	assert.NotEmpty(t, evidence.SHA512Hash)
	assert.False(t, evidence.CollectedAt.IsZero())

	// Test evidence retrieval
	retrievedEvidence, err := engine.GetEvidence(evidence.ID)
	require.NoError(t, err)
	assert.Equal(t, evidence.ID, retrievedEvidence.ID)
	assert.Equal(t, evidence.Name, retrievedEvidence.Name)
}

func TestForensicEngine_AnalyzeEvidence(t *testing.T) {
	config := getTestConfig()
	engine := NewForensicEngine(config)

	// Create test case and evidence
	caseInfo := &ForensicCase{
		Title:        "Test Case",
		Description:  "Test case for evidence analysis",
		CaseType:     CaseTypeCyberIncident,
		Priority:     CasePriorityHigh,
		Status:       CaseStatusNew,
		Severity:     CaseSeverityHigh,
		Investigator: "test_investigator",
	}

	createdCase, err := engine.CreateCase(caseInfo)
	require.NoError(t, err)

	// Create temporary test file
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test_evidence.txt")
	testContent := "This is test evidence content"
	err = os.WriteFile(testFile, []byte(testContent), 0644)
	require.NoError(t, err)

	evidenceRequest := &EvidenceRequest{
		Name:             "Test Evidence",
		Description:      "Test evidence file",
		Type:             EvidenceTypeFile,
		Source:           "test_system",
		Location:         testFile,
		Collector:        "test_collector",
		CollectionMethod: "manual",
		CollectionTool:   "test_tool",
		Metadata:         map[string]interface{}{"test": "value"},
		Tags:             []string{"test", "evidence"},
	}

	evidence, err := engine.CollectEvidence(createdCase.ID, evidenceRequest)
	require.NoError(t, err)

	// Analyze evidence
	analysisResult, err := engine.AnalyzeEvidence(evidence.ID)
	require.NoError(t, err)
	require.NotNil(t, analysisResult)

	assert.NotEmpty(t, analysisResult.ID)
	assert.NotEmpty(t, analysisResult.AnalyzerName)
	assert.NotEmpty(t, analysisResult.AnalysisType)
	assert.NotEmpty(t, analysisResult.Result)
	assert.Greater(t, analysisResult.Confidence, 0.0)
	assert.False(t, analysisResult.Timestamp.IsZero())
}

func TestForensicEngine_BuildTimeline(t *testing.T) {
	config := getTestConfig()
	engine := NewForensicEngine(config)

	// Create test case
	caseInfo := &ForensicCase{
		Title:        "Test Case",
		Description:  "Test case for timeline building",
		CaseType:     CaseTypeCyberIncident,
		Priority:     CasePriorityHigh,
		Status:       CaseStatusNew,
		Severity:     CaseSeverityHigh,
		Investigator: "test_investigator",
	}

	createdCase, err := engine.CreateCase(caseInfo)
	require.NoError(t, err)

	// Build timeline
	timeline, err := engine.BuildTimeline(createdCase.ID)
	require.NoError(t, err)
	require.NotNil(t, timeline)

	assert.NotEmpty(t, timeline.ID)
	assert.Equal(t, createdCase.ID, timeline.CaseID)
	assert.NotEmpty(t, timeline.Name)
	assert.NotEmpty(t, timeline.Description)
	assert.False(t, timeline.CreatedAt.IsZero())
	assert.False(t, timeline.UpdatedAt.IsZero())
	assert.NotNil(t, timeline.Events)
	assert.NotNil(t, timeline.Patterns)
	assert.NotNil(t, timeline.Anomalies)
	assert.NotNil(t, timeline.Correlations)
}

func TestForensicEngine_GenerateReport(t *testing.T) {
	config := getTestConfig()
	engine := NewForensicEngine(config)

	// Create test case
	caseInfo := &ForensicCase{
		Title:        "Test Case",
		Description:  "Test case for report generation",
		CaseType:     CaseTypeCyberIncident,
		Priority:     CasePriorityHigh,
		Status:       CaseStatusNew,
		Severity:     CaseSeverityHigh,
		Investigator: "test_investigator",
	}

	createdCase, err := engine.CreateCase(caseInfo)
	require.NoError(t, err)

	// Generate report
	report, err := engine.GenerateReport(createdCase.ID, ReportTypeTechnical)
	require.NoError(t, err)
	require.NotNil(t, report)

	assert.NotEmpty(t, report.ID)
	assert.Equal(t, createdCase.ID, report.CaseID)
	assert.Equal(t, ReportTypeTechnical, report.Type)
	assert.Equal(t, ReportStatusDraft, report.Status)
	assert.NotEmpty(t, report.Title)
	assert.NotEmpty(t, report.ExecutiveSummary)
	assert.NotEmpty(t, report.Methodology)
	assert.NotNil(t, report.Findings)
	assert.NotNil(t, report.Conclusions)
	assert.NotNil(t, report.Recommendations)
	assert.False(t, report.CreatedAt.IsZero())
	assert.False(t, report.UpdatedAt.IsZero())
}

func TestForensicEngine_GetMetrics(t *testing.T) {
	config := getTestConfig()
	engine := NewForensicEngine(config)

	metrics := engine.GetMetrics()
	require.NotNil(t, metrics)

	assert.Contains(t, metrics, "total_cases")
	assert.Contains(t, metrics, "active_cases")
	assert.Contains(t, metrics, "completed_cases")
	assert.Contains(t, metrics, "evidence_collected")
	assert.Contains(t, metrics, "artifacts_analyzed")
	assert.Contains(t, metrics, "timelines_built")
	assert.Contains(t, metrics, "reports_generated")
}

func TestForensicEngine_GetStatus(t *testing.T) {
	config := getTestConfig()
	engine := NewForensicEngine(config)

	status := engine.GetStatus()
	require.NotNil(t, status)

	assert.Contains(t, status, "engine_status")
	assert.Contains(t, status, "cases_count")
	assert.Contains(t, status, "evidence_count")
	assert.Contains(t, status, "artifacts_count")
	assert.Contains(t, status, "timelines_count")
	assert.Contains(t, status, "reports_count")
}

func TestEvidenceCollector_FileCollection(t *testing.T) {
	config := getTestConfig()
	collector := NewEvidenceCollector(config)

	// Create temporary test file
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test_file.txt")
	testContent := "This is test file content"
	err := os.WriteFile(testFile, []byte(testContent), 0644)
	require.NoError(t, err)

	// Set up evidence storage directory
	config.EvidenceStoragePath = tempDir

	request := &EvidenceRequest{
		Name:             "Test File",
		Description:      "Test file for collection",
		Type:             EvidenceTypeFile,
		Source:           "test_system",
		Location:         testFile,
		Collector:        "test_collector",
		CollectionMethod: "manual",
		CollectionTool:   "test_tool",
		Metadata:         map[string]interface{}{"test": "value"},
		Tags:             []string{"test", "file"},
	}

	evidence, err := collector.Collect(request)
	require.NoError(t, err)
	require.NotNil(t, evidence)

	assert.NotEmpty(t, evidence.ID)
	assert.Equal(t, request.Name, evidence.Name)
	assert.Equal(t, request.Type, evidence.Type)
	assert.Equal(t, int64(len(testContent)), evidence.Size)
	assert.NotEmpty(t, evidence.MD5Hash)
	assert.NotEmpty(t, evidence.SHA1Hash)
	assert.NotEmpty(t, evidence.SHA256Hash)
	assert.NotEmpty(t, evidence.SHA512Hash)
}

func TestArtifactAnalyzer_FileAnalysis(t *testing.T) {
	config := getTestConfig()
	analyzer := NewArtifactAnalyzer(config)

	// Create test evidence
	tempDir := t.TempDir()
	evidence := &DigitalEvidence{
		ID:          "test_evidence",
		Name:        "Test Evidence",
		Type:        EvidenceTypeFile,
		Source:      "test_system",
		Location:    filepath.Join(tempDir, "test_file.txt"),
		Size:        1024,
		MD5Hash:     "test_md5",
		SHA256Hash:  "test_sha256",
		StoragePath: filepath.Join(tempDir, "test_file.txt"),
	}

	// Create the test file
	err := os.WriteFile(evidence.StoragePath, []byte("test content"), 0644)
	require.NoError(t, err)

	artifacts, err := analyzer.Analyze(evidence)
	require.NoError(t, err)
	require.NotNil(t, artifacts)
	assert.Greater(t, len(artifacts), 0)

	artifact := artifacts[0]
	assert.NotEmpty(t, artifact.ID)
	assert.Equal(t, evidence.ID, artifact.EvidenceID)
	assert.Equal(t, ArtifactTypeFile, artifact.Type)
	assert.Equal(t, "file_system", artifact.Category)
	assert.Equal(t, evidence.Source, artifact.Source)
	assert.False(t, artifact.ExtractedAt.IsZero())
}

func TestMalwareAnalyzer_HashDetection(t *testing.T) {
	config := getTestConfig()
	analyzer := NewMalwareAnalyzer(config)

	// Create test evidence with known malware hash
	evidence := &DigitalEvidence{
		ID:         "test_evidence",
		Name:       "Test Evidence",
		Type:       EvidenceTypeFile,
		Source:     "test_system",
		SHA256Hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // Known test hash
	}

	detections, err := analyzer.AnalyzeForMalware(evidence)
	require.NoError(t, err)
	require.NotNil(t, detections)

	if len(detections) > 0 {
		detection := detections[0]
		assert.NotEmpty(t, detection.ID)
		assert.Equal(t, evidence.ID, detection.EvidenceID)
		assert.Equal(t, "hash_signature", detection.DetectionType)
		assert.NotEmpty(t, detection.MalwareName)
		assert.Greater(t, detection.Confidence, 0.0)
		assert.False(t, detection.Timestamp.IsZero())
	}
}

func TestTimelineBuilder_BuildTimeline(t *testing.T) {
	config := getTestConfig()
	builder := NewTimelineBuilder(config)

	// Create test evidence
	evidence := []*DigitalEvidence{
		{
			ID:          "evidence1",
			Name:        "Evidence 1",
			Type:        EvidenceTypeFile,
			Source:      "system1",
			CollectedAt: time.Now().Add(-2 * time.Hour),
			Collector:   "collector1",
		},
		{
			ID:          "evidence2",
			Name:        "Evidence 2",
			Type:        EvidenceTypeLog,
			Source:      "system2",
			CollectedAt: time.Now().Add(-1 * time.Hour),
			Collector:   "collector2",
		},
	}

	// Create test artifacts
	artifacts := []*ForensicArtifact{
		{
			ID:          "artifact1",
			Name:        "Artifact 1",
			Type:        ArtifactTypeFile,
			Category:    "file_system",
			Source:      "system1",
			EvidenceID:  "evidence1",
			ExtractedAt: time.Now().Add(-90 * time.Minute),
		},
		{
			ID:          "artifact2",
			Name:        "Artifact 2",
			Type:        ArtifactTypeLogEntry,
			Category:    "logs",
			Source:      "system2",
			EvidenceID:  "evidence2",
			ExtractedAt: time.Now().Add(-30 * time.Minute),
		},
	}

	timeline, err := builder.BuildTimeline("test_case", evidence, artifacts)
	require.NoError(t, err)
	require.NotNil(t, timeline)

	assert.NotEmpty(t, timeline.ID)
	assert.Equal(t, "test_case", timeline.CaseID)
	assert.NotEmpty(t, timeline.Name)
	assert.NotEmpty(t, timeline.Description)
	assert.Equal(t, 4, timeline.EventCount) // 2 evidence + 2 artifacts
	assert.Len(t, timeline.Events, 4)
	assert.False(t, timeline.CreatedAt.IsZero())
	assert.False(t, timeline.UpdatedAt.IsZero())
	assert.False(t, timeline.StartTime.IsZero())
	assert.False(t, timeline.EndTime.IsZero())

	// Verify events are sorted by timestamp
	for i := 1; i < len(timeline.Events); i++ {
		assert.True(t, timeline.Events[i-1].Timestamp.Before(timeline.Events[i].Timestamp) ||
			timeline.Events[i-1].Timestamp.Equal(timeline.Events[i].Timestamp))
	}
}

func TestReportGenerator_GenerateReport(t *testing.T) {
	config := getTestConfig()
	generator := NewReportGenerator(config)

	// Create test case
	case_ := &ForensicCase{
		ID:           "test_case",
		Title:        "Test Case",
		Description:  "Test case for report generation",
		CaseType:     CaseTypeCyberIncident,
		Priority:     CasePriorityHigh,
		Status:       CaseStatusCompleted,
		Severity:     CaseSeverityHigh,
		Investigator: "test_investigator",
	}

	// Create test evidence
	evidence := []*DigitalEvidence{
		{
			ID:   "evidence1",
			Name: "Evidence 1",
			Type: EvidenceTypeFile,
		},
	}

	// Create test artifacts
	artifacts := []*ForensicArtifact{
		{
			ID:   "artifact1",
			Name: "Artifact 1",
			Type: ArtifactTypeFile,
		},
	}

	// Create test timeline
	timeline := &ForensicTimeline{
		ID:     "timeline1",
		CaseID: "test_case",
		Name:   "Test Timeline",
	}

	report, err := generator.GenerateReport(case_, evidence, artifacts, timeline, ReportTypeTechnical)
	require.NoError(t, err)
	require.NotNil(t, report)

	assert.NotEmpty(t, report.ID)
	assert.Equal(t, case_.ID, report.CaseID)
	assert.Equal(t, ReportTypeTechnical, report.Type)
	assert.Equal(t, ReportStatusDraft, report.Status)
	assert.Equal(t, case_.Investigator, report.Author)
	assert.NotEmpty(t, report.Title)
	assert.NotEmpty(t, report.ExecutiveSummary)
	assert.NotEmpty(t, report.Methodology)
	assert.NotEmpty(t, report.Findings)
	assert.NotEmpty(t, report.Conclusions)
	assert.NotEmpty(t, report.Recommendations)
	assert.Equal(t, []string{"evidence1"}, report.EvidenceAnalyzed)
	assert.Equal(t, []string{"artifact1"}, report.KeyArtifacts)
	assert.Equal(t, []string{"timeline1"}, report.TimelinesSummarized)
	assert.False(t, report.CreatedAt.IsZero())
	assert.False(t, report.UpdatedAt.IsZero())
}

func TestChainOfCustody_AddCustodyEntry(t *testing.T) {
	config := getTestConfig()
	config.RequireDigitalSignature = true
	coc := NewChainOfCustody(config)

	entry, err := coc.AddCustodyEntry("evidence1", "collected", "investigator1", "lab1", "initial_collection", "Evidence collected from crime scene")
	require.NoError(t, err)
	require.NotNil(t, entry)

	assert.NotEmpty(t, entry.ID)
	assert.Equal(t, "collected", entry.Action)
	assert.Equal(t, "investigator1", entry.Actor)
	assert.Equal(t, "lab1", entry.Location)
	assert.Equal(t, "initial_collection", entry.Reason)
	assert.Equal(t, "Evidence collected from crime scene", entry.Notes)
	assert.NotEmpty(t, entry.DigitalSignature)
	assert.False(t, entry.Timestamp.IsZero())
}

func TestChainOfCustody_ValidateCustodyChain(t *testing.T) {
	config := getTestConfig()
	config.RequireDigitalSignature = true
	coc := NewChainOfCustody(config)

	// Create test evidence with custody chain
	evidence := &DigitalEvidence{
		ID:   "evidence1",
		Name: "Test Evidence",
		CustodyChain: []CustodyEntry{
			{
				ID:        "custody1",
				Timestamp: time.Now().Add(-2 * time.Hour),
				Action:    "collected",
				Actor:     "investigator1",
				Location:  "lab1",
				Reason:    "initial_collection",
				Notes:     "Evidence collected",
			},
			{
				ID:        "custody2",
				Timestamp: time.Now().Add(-1 * time.Hour),
				Action:    "analyzed",
				Actor:     "analyst1",
				Location:  "lab2",
				Reason:    "forensic_analysis",
				Notes:     "Evidence analyzed",
			},
		},
	}

	// Generate signatures for custody entries
	for i := range evidence.CustodyChain {
		signature, err := coc.generateDigitalSignature(&evidence.CustodyChain[i])
		require.NoError(t, err)
		evidence.CustodyChain[i].DigitalSignature = signature
	}

	err := coc.ValidateCustodyChain(evidence)
	assert.NoError(t, err)
}

func TestIncidentManager_CreateIncidentResponse(t *testing.T) {
	config := getTestConfig()
	manager := NewIncidentManager(config)

	response, err := manager.CreateIncidentResponse("incident1", "case1", "containment")
	require.NoError(t, err)
	require.NotNil(t, response)

	assert.NotEmpty(t, response.ID)
	assert.Equal(t, "incident1", response.IncidentID)
	assert.Equal(t, "case1", response.CaseID)
	assert.Equal(t, "containment", response.Type)
	assert.Equal(t, "created", response.Status)
	assert.False(t, response.CreatedAt.IsZero())
	assert.False(t, response.UpdatedAt.IsZero())
	assert.NotNil(t, response.Actions)
}

func TestDigitalEvidence_Hash(t *testing.T) {
	evidence := &DigitalEvidence{
		ID:         "evidence1",
		Name:       "Test Evidence",
		SHA256Hash: "test_sha256_hash",
	}

	hash := evidence.Hash()
	assert.Equal(t, "test_sha256_hash", hash)
}

// Helper function to create test configuration
func getTestConfig() *ForensicConfig {
	return &ForensicConfig{
		EnableMemoryAnalysis:   true,
		EnableDiskAnalysis:     true,
		EnableNetworkAnalysis:  true,
		EnableRegistryAnalysis: true,
		EnableLogAnalysis:      true,
		EnableMalwareAnalysis:  true,
		MaxEvidenceSize:        1024 * 1024 * 1024, // 1GB
		CompressionEnabled:     true,
		EncryptionEnabled:      true,
		HashingAlgorithm:       "sha256",
		AnalysisWorkers:        2,
		MaxConcurrentAnalysis:  5,
		AnalysisTimeout:        10 * time.Minute,
		MaxMemoryUsage:         1024 * 1024 * 1024, // 1GB
		TempDirectory:          "/tmp/forensics",
		EvidenceStoragePath:    "/tmp/forensics/evidence",
		ReportStoragePath:      "/tmp/forensics/reports",
		RetentionPeriod:        30 * 24 * time.Hour, // 30 days
		BackupEnabled:          false,
		BackupInterval:         24 * time.Hour,
		RequireDigitalSignature: false,
		AuditTrailEnabled:      true,
		TimestampingEnabled:    true,
		AutoIncidentCreation:   true,
		ComplianceMode:         "standard",
		DataClassification:     "internal",
		PrivacyMode:            false,
		CacheSize:              100,
		IndexingEnabled:        true,
		SearchOptimization:     true,
		SIEMIntegration:        false,
		TIPIntegration:         false,
		SOARIntegration:        false,
		AlertThreshold:         0.7,
		AlertsEnabled:          true,
		RealTimeAlerts:         true,
	}
}

// Benchmark tests
func BenchmarkForensicEngine_CreateCase(b *testing.B) {
	config := getTestConfig()
	engine := NewForensicEngine(config)

	caseInfo := &ForensicCase{
		Title:        "Benchmark Case",
		Description:  "Benchmark case for performance testing",
		CaseType:     CaseTypeCyberIncident,
		Priority:     CasePriorityHigh,
		Status:       CaseStatusNew,
		Severity:     CaseSeverityHigh,
		Investigator: "benchmark_investigator",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := engine.CreateCase(caseInfo)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEvidenceCollector_Collect(b *testing.B) {
	config := getTestConfig()
	collector := NewEvidenceCollector(config)

	// Create temporary test file
	tempDir := b.TempDir()
	testFile := filepath.Join(tempDir, "benchmark_file.txt")
	err := os.WriteFile(testFile, []byte("benchmark content"), 0644)
	if err != nil {
		b.Fatal(err)
	}

	config.EvidenceStoragePath = tempDir

	request := &EvidenceRequest{
		Name:             "Benchmark Evidence",
		Description:      "Benchmark evidence for performance testing",
		Type:             EvidenceTypeFile,
		Source:           "benchmark_system",
		Location:         testFile,
		Collector:        "benchmark_collector",
		CollectionMethod: "manual",
		CollectionTool:   "benchmark_tool",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := collector.Collect(request)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkArtifactAnalyzer_Analyze(b *testing.B) {
	config := getTestConfig()
	analyzer := NewArtifactAnalyzer(config)

	// Create test evidence
	tempDir := b.TempDir()
	testFile := filepath.Join(tempDir, "benchmark_file.txt")
	err := os.WriteFile(testFile, []byte("benchmark content"), 0644)
	if err != nil {
		b.Fatal(err)
	}

	evidence := &DigitalEvidence{
		ID:          "benchmark_evidence",
		Name:        "Benchmark Evidence",
		Type:        EvidenceTypeFile,
		Source:      "benchmark_system",
		StoragePath: testFile,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := analyzer.Analyze(evidence)
		if err != nil {
			b.Fatal(err)
		}
	}
} 