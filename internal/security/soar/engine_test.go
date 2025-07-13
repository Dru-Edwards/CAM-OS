package soar

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSOAREngine(t *testing.T) {
	config := getTestSOARConfig()
	engine := NewSOAREngine(config)

	require.NotNil(t, engine)
	assert.Equal(t, config, engine.config)
	assert.NotNil(t, engine.playbookManager)
	assert.NotNil(t, engine.workflowEngine)
	assert.NotNil(t, engine.orchestrator)
	assert.NotNil(t, engine.responseManager)
	assert.NotNil(t, engine.incidentManager)
	assert.NotNil(t, engine.alertManager)
	assert.NotNil(t, engine.integrationManager)
	assert.NotNil(t, engine.automationEngine)
	assert.NotNil(t, engine.playbooks)
	assert.NotNil(t, engine.workflows)
	assert.NotNil(t, engine.incidents)
	assert.NotNil(t, engine.responses)
	assert.NotNil(t, engine.alerts)
	assert.NotNil(t, engine.integrations)
	assert.NotNil(t, engine.automationRules)
	assert.NotNil(t, engine.executionContext)
	assert.NotNil(t, engine.activeWorkflows)
}

func TestSOAREngine_StartStop(t *testing.T) {
	config := getTestSOARConfig()
	engine := NewSOAREngine(config)

	// Test start
	err := engine.Start()
	assert.NoError(t, err)

	// Test stop
	err = engine.Stop()
	assert.NoError(t, err)
}

func TestSOAREngine_CreatePlaybook(t *testing.T) {
	config := getTestSOARConfig()
	engine := NewSOAREngine(config)

	workflow := &Workflow{
		ID:          "test_workflow",
		Name:        "Test Workflow",
		Description: "Test workflow for playbook",
		Status:      WorkflowStatusActive,
		Steps: []WorkflowStep{
			{
				ID:     "step1",
				Name:   "Test Step",
				Type:   StepTypeAction,
				Action: "test_action",
			},
		},
		StartStep: "step1",
		EndSteps:  []string{"step1"},
	}

	playbook := &Playbook{
		Name:        "Test Playbook",
		Description: "Test playbook for SOAR engine",
		Version:     "1.0",
		Category:    "test",
		Severity:    "medium",
		Priority:    "high",
		Tags:        []string{"test", "playbook"},
		Triggers: []PlaybookTrigger{
			{
				Name:      "Test Trigger",
				Type:      TriggerTypeAlert,
				Condition: "alert.severity == 'high'",
				Enabled:   true,
			},
		},
		Workflow:         workflow,
		Conditions:       []PlaybookCondition{},
		Prerequisites:    []string{},
		Dependencies:     []string{},
		ExecutionMode:    ExecutionModeAutomatic,
		ApprovalRequired: false,
		Timeout:          30 * time.Minute,
		RetryPolicy: &RetryPolicy{
			MaxRetries:      3,
			RetryDelay:      5 * time.Second,
			BackoffStrategy: "exponential",
		},
		ComplianceFramework: "NIST",
		Variables:           map[string]string{},
		Parameters:          map[string]interface{}{},
		Metadata:            map[string]interface{}{},
	}

	createdPlaybook, err := engine.CreatePlaybook(playbook)
	require.NoError(t, err)
	require.NotNil(t, createdPlaybook)

	assert.NotEmpty(t, createdPlaybook.ID)
	assert.Equal(t, playbook.Name, createdPlaybook.Name)
	assert.Equal(t, playbook.Description, createdPlaybook.Description)
	assert.Equal(t, playbook.Version, createdPlaybook.Version)
	assert.Equal(t, playbook.Category, createdPlaybook.Category)
	assert.Equal(t, playbook.Severity, createdPlaybook.Severity)
	assert.Equal(t, playbook.Priority, createdPlaybook.Priority)
	assert.Equal(t, PlaybookStatusDraft, createdPlaybook.Status)
	assert.False(t, createdPlaybook.CreatedAt.IsZero())
	assert.False(t, createdPlaybook.UpdatedAt.IsZero())

	// Test playbook retrieval
	retrievedPlaybook, err := engine.GetPlaybook(createdPlaybook.ID)
	require.NoError(t, err)
	assert.Equal(t, createdPlaybook.ID, retrievedPlaybook.ID)
	assert.Equal(t, createdPlaybook.Name, retrievedPlaybook.Name)
}

func TestSOAREngine_ExecutePlaybook(t *testing.T) {
	config := getTestSOARConfig()
	engine := NewSOAREngine(config)

	workflow := &Workflow{
		ID:          "test_workflow",
		Name:        "Test Workflow",
		Description: "Test workflow for execution",
		Status:      WorkflowStatusActive,
		Steps: []WorkflowStep{
			{
				ID:        "step1",
				Name:      "Test Step",
				Type:      StepTypeAction,
				Action:    "test_action",
				OnSuccess: "step2",
			},
			{
				ID:     "step2",
				Name:   "Final Step",
				Type:   StepTypeAction,
				Action: "final_action",
			},
		},
		StartStep: "step1",
		EndSteps:  []string{"step2"},
	}

	playbook := &Playbook{
		Name:          "Test Execution Playbook",
		Description:   "Test playbook for execution",
		Version:       "1.0",
		Status:        PlaybookStatusActive,
		Workflow:      workflow,
		ExecutionMode: ExecutionModeAutomatic,
		Timeout:       30 * time.Minute,
	}

	createdPlaybook, err := engine.CreatePlaybook(playbook)
	require.NoError(t, err)

	// Update status to active for execution
	createdPlaybook.Status = PlaybookStatusActive
	engine.playbooks[createdPlaybook.ID] = createdPlaybook

	// Execute playbook
	context := map[string]interface{}{
		"incident_id": "test_incident",
		"severity":    "high",
	}

	executionContext, err := engine.ExecutePlaybook(createdPlaybook.ID, context)
	require.NoError(t, err)
	require.NotNil(t, executionContext)

	assert.NotEmpty(t, executionContext.ID)
	assert.Equal(t, createdPlaybook.ID, executionContext.PlaybookID)
	assert.Equal(t, workflow.ID, executionContext.WorkflowID)
	assert.Equal(t, "running", executionContext.Status)
	assert.False(t, executionContext.StartTime.IsZero())
	assert.Equal(t, context, executionContext.Variables)
}

func TestSOAREngine_CreateIncident(t *testing.T) {
	config := getTestSOARConfig()
	engine := NewSOAREngine(config)

	incident := &Incident{
		Title:                "Test Security Incident",
		Description:          "Test incident for SOAR engine",
		Severity:             IncidentSeverityHigh,
		Priority:             IncidentPriorityHigh,
		Category:             "security",
		Type:                 "malware",
		Source:               "test_source",
		Detector:             "test_detector",
		FirstSeen:            time.Now().Add(-1 * time.Hour),
		LastSeen:             time.Now(),
		EventCount:           5,
		BusinessImpact:       "high",
		TechnicalImpact:      "medium",
		AffectedAssets:       []string{"server1", "server2"},
		AffectedUsers:        []string{"user1", "user2"},
		AffectedSystems:      []string{"system1", "system2"},
		ThreatActors:         []string{"APT1"},
		AttackVectors:        []string{"phishing", "malware"},
		IOCs:                 []string{"hash1", "domain1"},
		MITRE_TTPs:           []string{"T1566", "T1204"},
		Tags:                 []string{"malware", "incident"},
		ComplianceImpact:     "high",
		RegulatoryImpact:     "medium",
		NotificationRequired: true,
		ReportingRequired:    true,
		Metadata: map[string]interface{}{
			"source_ip": "192.168.1.100",
			"dest_ip":   "10.0.0.1",
		},
		Evidence: []string{"evidence1", "evidence2"},
		Timeline: []string{"timeline1"},
		Notes:    []string{"Initial investigation started"},
	}

	createdIncident, err := engine.CreateIncident(incident)
	require.NoError(t, err)
	require.NotNil(t, createdIncident)

	assert.NotEmpty(t, createdIncident.ID)
	assert.Equal(t, incident.Title, createdIncident.Title)
	assert.Equal(t, incident.Description, createdIncident.Description)
	assert.Equal(t, incident.Severity, createdIncident.Severity)
	assert.Equal(t, incident.Priority, createdIncident.Priority)
	assert.Equal(t, incident.Category, createdIncident.Category)
	assert.Equal(t, incident.Type, createdIncident.Type)
	assert.Equal(t, IncidentStatusNew, createdIncident.Status)
	assert.False(t, createdIncident.CreatedAt.IsZero())
	assert.False(t, createdIncident.UpdatedAt.IsZero())

	// Test incident retrieval
	retrievedIncident, err := engine.GetIncident(createdIncident.ID)
	require.NoError(t, err)
	assert.Equal(t, createdIncident.ID, retrievedIncident.ID)
	assert.Equal(t, createdIncident.Title, retrievedIncident.Title)
}

func TestSOAREngine_CreateAlert(t *testing.T) {
	config := getTestSOARConfig()
	engine := NewSOAREngine(config)

	alert := &Alert{
		Title:        "Test Security Alert",
		Description:  "Test alert for SOAR engine",
		Severity:     AlertSeverityHigh,
		Priority:     AlertPriorityHigh,
		Category:     "security",
		Type:         "malware_detected",
		Source:       "test_source",
		Detector:     "test_detector",
		EventCount:   3,
		FirstSeen:    time.Now().Add(-30 * time.Minute),
		LastSeen:     time.Now(),
		Acknowledged: false,
		Escalated:    false,
		Context: map[string]interface{}{
			"source_ip": "192.168.1.100",
			"dest_ip":   "10.0.0.1",
			"protocol":  "HTTP",
		},
		Evidence:           []string{"evidence1", "evidence2"},
		IOCs:               []string{"hash1", "domain1"},
		MITRE_TTPs:         []string{"T1566", "T1204"},
		Tags:               []string{"malware", "alert"},
		ThreatIntelligence: []string{"ti1", "ti2"},
		GeolocationData: map[string]interface{}{
			"country": "US",
			"city":    "New York",
		},
		AssetInformation: map[string]interface{}{
			"hostname": "server1",
			"ip":       "192.168.1.100",
		},
		UserInformation: map[string]interface{}{
			"username": "user1",
			"email":    "user1@example.com",
		},
		Metadata: map[string]interface{}{
			"rule_id":   "rule1",
			"rule_name": "Malware Detection",
		},
		Notes: []string{"Initial detection", "Investigation started"},
	}

	createdAlert, err := engine.CreateAlert(alert)
	require.NoError(t, err)
	require.NotNil(t, createdAlert)

	assert.NotEmpty(t, createdAlert.ID)
	assert.Equal(t, alert.Title, createdAlert.Title)
	assert.Equal(t, alert.Description, createdAlert.Description)
	assert.Equal(t, alert.Severity, createdAlert.Severity)
	assert.Equal(t, alert.Priority, createdAlert.Priority)
	assert.Equal(t, alert.Category, createdAlert.Category)
	assert.Equal(t, alert.Type, createdAlert.Type)
	assert.Equal(t, AlertStatusNew, createdAlert.Status)
	assert.False(t, createdAlert.CreatedAt.IsZero())
	assert.False(t, createdAlert.UpdatedAt.IsZero())

	// Test alert retrieval
	retrievedAlert, err := engine.GetAlert(createdAlert.ID)
	require.NoError(t, err)
	assert.Equal(t, createdAlert.ID, retrievedAlert.ID)
	assert.Equal(t, createdAlert.Title, retrievedAlert.Title)
}

func TestSOAREngine_GetMetrics(t *testing.T) {
	config := getTestSOARConfig()
	engine := NewSOAREngine(config)

	metrics := engine.GetMetrics()
	require.NotNil(t, metrics)

	assert.Contains(t, metrics, "total_playbooks")
	assert.Contains(t, metrics, "active_playbooks")
	assert.Contains(t, metrics, "total_workflows")
	assert.Contains(t, metrics, "active_workflows")
	assert.Contains(t, metrics, "total_incidents")
	assert.Contains(t, metrics, "active_incidents")
	assert.Contains(t, metrics, "total_responses")
	assert.Contains(t, metrics, "active_responses")
	assert.Contains(t, metrics, "total_alerts")
	assert.Contains(t, metrics, "processed_alerts")
	assert.Contains(t, metrics, "automation_rules")
	assert.Contains(t, metrics, "successful_responses")
	assert.Contains(t, metrics, "failed_responses")
	assert.Contains(t, metrics, "timestamp")
}

func TestSOAREngine_GetStatus(t *testing.T) {
	config := getTestSOARConfig()
	engine := NewSOAREngine(config)

	status := engine.GetStatus()
	require.NotNil(t, status)

	assert.Contains(t, status, "engine_status")
	assert.Contains(t, status, "playbooks_count")
	assert.Contains(t, status, "workflows_count")
	assert.Contains(t, status, "incidents_count")
	assert.Contains(t, status, "responses_count")
	assert.Contains(t, status, "alerts_count")
	assert.Contains(t, status, "integrations_count")
	assert.Contains(t, status, "automation_rules_count")
	assert.Contains(t, status, "execution_contexts")
	assert.Contains(t, status, "active_workflows")
	assert.Contains(t, status, "alert_queue_size")
	assert.Contains(t, status, "incident_queue_size")
	assert.Contains(t, status, "response_queue_size")
	assert.Contains(t, status, "workflow_queue_size")
	assert.Contains(t, status, "timestamp")
}

func TestPlaybookManager_CreatePlaybook(t *testing.T) {
	config := getTestSOARConfig()
	manager := NewPlaybookManager(config)

	workflow := &Workflow{
		ID:     "test_workflow",
		Name:   "Test Workflow",
		Status: WorkflowStatusActive,
		Steps: []WorkflowStep{
			{
				ID:     "step1",
				Name:   "Test Step",
				Type:   StepTypeAction,
				Action: "test_action",
			},
		},
		StartStep: "step1",
		EndSteps:  []string{"step1"},
	}

	playbook := &Playbook{
		Name:          "Test Playbook",
		Description:   "Test playbook for manager",
		Version:       "1.0",
		Category:      "test",
		Workflow:      workflow,
		ExecutionMode: ExecutionModeAutomatic,
		Timeout:       30 * time.Minute,
	}

	createdPlaybook, err := manager.CreatePlaybook(playbook)
	require.NoError(t, err)
	require.NotNil(t, createdPlaybook)

	assert.NotEmpty(t, createdPlaybook.ID)
	assert.Equal(t, playbook.Name, createdPlaybook.Name)
	assert.Equal(t, PlaybookStatusDraft, createdPlaybook.Status)
	assert.False(t, createdPlaybook.CreatedAt.IsZero())
	assert.False(t, createdPlaybook.UpdatedAt.IsZero())

	// Test playbook retrieval
	retrievedPlaybook, err := manager.GetPlaybook(createdPlaybook.ID)
	require.NoError(t, err)
	assert.Equal(t, createdPlaybook.ID, retrievedPlaybook.ID)
	assert.Equal(t, createdPlaybook.Name, retrievedPlaybook.Name)
}

func TestPlaybookManager_UpdatePlaybook(t *testing.T) {
	config := getTestSOARConfig()
	manager := NewPlaybookManager(config)

	workflow := &Workflow{
		ID:     "test_workflow",
		Name:   "Test Workflow",
		Status: WorkflowStatusActive,
		Steps: []WorkflowStep{
			{
				ID:     "step1",
				Name:   "Test Step",
				Type:   StepTypeAction,
				Action: "test_action",
			},
		},
		StartStep: "step1",
		EndSteps:  []string{"step1"},
	}

	playbook := &Playbook{
		Name:          "Test Playbook",
		Description:   "Test playbook for update",
		Version:       "1.0",
		Category:      "test",
		Workflow:      workflow,
		ExecutionMode: ExecutionModeAutomatic,
		Timeout:       30 * time.Minute,
	}

	createdPlaybook, err := manager.CreatePlaybook(playbook)
	require.NoError(t, err)

	// Update playbook
	updates := &Playbook{
		Name:        "Updated Test Playbook",
		Description: "Updated test playbook",
		Status:      PlaybookStatusActive,
	}

	updatedPlaybook, err := manager.UpdatePlaybook(createdPlaybook.ID, updates)
	require.NoError(t, err)
	require.NotNil(t, updatedPlaybook)

	assert.Equal(t, updates.Name, updatedPlaybook.Name)
	assert.Equal(t, updates.Description, updatedPlaybook.Description)
	assert.Equal(t, updates.Status, updatedPlaybook.Status)
	assert.True(t, updatedPlaybook.UpdatedAt.After(updatedPlaybook.CreatedAt))
}

func TestPlaybookManager_ListPlaybooks(t *testing.T) {
	config := getTestSOARConfig()
	manager := NewPlaybookManager(config)

	workflow := &Workflow{
		ID:     "test_workflow",
		Name:   "Test Workflow",
		Status: WorkflowStatusActive,
		Steps: []WorkflowStep{
			{
				ID:     "step1",
				Name:   "Test Step",
				Type:   StepTypeAction,
				Action: "test_action",
			},
		},
		StartStep: "step1",
		EndSteps:  []string{"step1"},
	}

	// Create multiple playbooks
	for i := 0; i < 3; i++ {
		playbook := &Playbook{
			Name:          fmt.Sprintf("Test Playbook %d", i),
			Description:   fmt.Sprintf("Test playbook %d", i),
			Version:       "1.0",
			Category:      "test",
			Workflow:      workflow,
			ExecutionMode: ExecutionModeAutomatic,
			Timeout:       30 * time.Minute,
		}

		_, err := manager.CreatePlaybook(playbook)
		require.NoError(t, err)
	}

	playbooks := manager.ListPlaybooks()
	assert.Len(t, playbooks, 3)

	for _, playbook := range playbooks {
		assert.NotEmpty(t, playbook.ID)
		assert.NotEmpty(t, playbook.Name)
		assert.Contains(t, playbook.Name, "Test Playbook")
	}
}

func TestPlaybookManager_DeletePlaybook(t *testing.T) {
	config := getTestSOARConfig()
	manager := NewPlaybookManager(config)

	workflow := &Workflow{
		ID:     "test_workflow",
		Name:   "Test Workflow",
		Status: WorkflowStatusActive,
		Steps: []WorkflowStep{
			{
				ID:     "step1",
				Name:   "Test Step",
				Type:   StepTypeAction,
				Action: "test_action",
			},
		},
		StartStep: "step1",
		EndSteps:  []string{"step1"},
	}

	playbook := &Playbook{
		Name:          "Test Playbook",
		Description:   "Test playbook for deletion",
		Version:       "1.0",
		Category:      "test",
		Workflow:      workflow,
		ExecutionMode: ExecutionModeAutomatic,
		Timeout:       30 * time.Minute,
	}

	createdPlaybook, err := manager.CreatePlaybook(playbook)
	require.NoError(t, err)

	// Delete playbook
	err = manager.DeletePlaybook(createdPlaybook.ID)
	assert.NoError(t, err)

	// Verify deletion
	_, err = manager.GetPlaybook(createdPlaybook.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "playbook not found")
}

func TestWorkflowEngine_CreateWorkflow(t *testing.T) {
	config := getTestSOARConfig()
	engine := NewWorkflowEngine(config)

	workflow := &Workflow{
		Name:        "Test Workflow",
		Description: "Test workflow for engine",
		Version:     "1.0",
		Steps: []WorkflowStep{
			{
				ID:        "step1",
				Name:      "Test Step",
				Type:      StepTypeAction,
				Action:    "test_action",
				OnSuccess: "step2",
			},
			{
				ID:     "step2",
				Name:   "Final Step",
				Type:   StepTypeAction,
				Action: "final_action",
			},
		},
		StartStep:     "step1",
		EndSteps:      []string{"step2"},
		Timeout:       30 * time.Minute,
		MaxExecutions: 10,
		RetryPolicy: &RetryPolicy{
			MaxRetries:      3,
			RetryDelay:      5 * time.Second,
			BackoffStrategy: "exponential",
		},
		ErrorHandling: &ErrorHandling{
			Strategy:        "continue",
			MaxErrors:       5,
			ErrorActions:    []string{"log", "notify"},
			NotifyOnError:   true,
			EscalateOnError: false,
			LogErrors:       true,
		},
		Variables:  map[string]string{},
		Parameters: map[string]interface{}{},
		Metadata:   map[string]interface{}{},
	}

	createdWorkflow, err := engine.CreateWorkflow(workflow)
	require.NoError(t, err)
	require.NotNil(t, createdWorkflow)

	assert.NotEmpty(t, createdWorkflow.ID)
	assert.Equal(t, workflow.Name, createdWorkflow.Name)
	assert.Equal(t, workflow.Description, createdWorkflow.Description)
	assert.Equal(t, workflow.Version, createdWorkflow.Version)
	assert.Equal(t, WorkflowStatusDraft, createdWorkflow.Status)
	assert.False(t, createdWorkflow.CreatedAt.IsZero())
	assert.False(t, createdWorkflow.UpdatedAt.IsZero())
	assert.Equal(t, len(workflow.Steps), len(createdWorkflow.Steps))
	assert.Equal(t, workflow.StartStep, createdWorkflow.StartStep)
	assert.Equal(t, workflow.EndSteps, createdWorkflow.EndSteps)
}

func TestWorkflowEngine_ExecuteWorkflow(t *testing.T) {
	config := getTestSOARConfig()
	engine := NewWorkflowEngine(config)

	workflow := &Workflow{
		Name:        "Test Execution Workflow",
		Description: "Test workflow for execution",
		Version:     "1.0",
		Status:      WorkflowStatusActive,
		Steps: []WorkflowStep{
			{
				ID:        "step1",
				Name:      "Test Step",
				Type:      StepTypeAction,
				Action:    "test_action",
				OnSuccess: "step2",
			},
			{
				ID:     "step2",
				Name:   "Final Step",
				Type:   StepTypeAction,
				Action: "final_action",
			},
		},
		StartStep: "step1",
		EndSteps:  []string{"step2"},
		Timeout:   30 * time.Minute,
	}

	createdWorkflow, err := engine.CreateWorkflow(workflow)
	require.NoError(t, err)

	// Update status to active for execution
	createdWorkflow.Status = WorkflowStatusActive
	engine.workflows[createdWorkflow.ID] = createdWorkflow

	// Execute workflow
	context := map[string]interface{}{
		"test_var": "test_value",
		"count":    1,
	}

	execution, err := engine.ExecuteWorkflow(createdWorkflow.ID, context)
	require.NoError(t, err)
	require.NotNil(t, execution)

	assert.NotEmpty(t, execution.ID)
	assert.Equal(t, createdWorkflow.ID, execution.WorkflowID)
	assert.Equal(t, "running", execution.Status)
	assert.Equal(t, workflow.StartStep, execution.CurrentStep)
	assert.False(t, execution.StartTime.IsZero())
	assert.Equal(t, context, execution.Variables)
	assert.NotNil(t, execution.Results)
	assert.NotNil(t, execution.Errors)
}

func TestStepExecutors(t *testing.T) {
	config := getTestSOARConfig()

	// Test ActionExecutor
	actionExecutor := &ActionExecutor{config: config}
	step := &WorkflowStep{
		ID:     "test_step",
		Name:   "Test Action Step",
		Type:   StepTypeAction,
		Action: "test_action",
	}
	context := map[string]interface{}{"test": "value"}

	results, err := actionExecutor.Execute(step, context)
	require.NoError(t, err)
	assert.NotNil(t, results)
	assert.Contains(t, results, "action_executed")
	assert.Contains(t, results, "action_name")
	assert.Contains(t, results, "timestamp")
	assert.Equal(t, true, results["action_executed"])
	assert.Equal(t, "test_action", results["action_name"])

	// Test supported types
	supportedTypes := actionExecutor.GetSupportedTypes()
	assert.Contains(t, supportedTypes, StepTypeAction)

	// Test ConditionExecutor
	conditionExecutor := &ConditionExecutor{config: config}
	step.Type = StepTypeCondition
	step.Action = "test_condition"

	results, err = conditionExecutor.Execute(step, context)
	require.NoError(t, err)
	assert.NotNil(t, results)
	assert.Contains(t, results, "condition_evaluated")
	assert.Contains(t, results, "condition_result")
	assert.Contains(t, results, "timestamp")
	assert.Equal(t, true, results["condition_evaluated"])
	assert.Equal(t, true, results["condition_result"])

	// Test DelayExecutor
	delayExecutor := &DelayExecutor{config: config}
	step.Type = StepTypeDelay
	step.Timeout = 10 * time.Millisecond

	start := time.Now()
	results, err = delayExecutor.Execute(step, context)
	duration := time.Since(start)

	require.NoError(t, err)
	assert.NotNil(t, results)
	assert.Contains(t, results, "delay_completed")
	assert.Contains(t, results, "delay_duration")
	assert.Contains(t, results, "timestamp")
	assert.Equal(t, true, results["delay_completed"])
	assert.Equal(t, step.Timeout, results["delay_duration"])
	assert.GreaterOrEqual(t, duration, step.Timeout)
}

func TestResponseManager_CreateResponse(t *testing.T) {
	config := getTestSOARConfig()
	manager := NewResponseManager(config)

	response := &Response{
		Name:         "Test Response",
		Description:  "Test response for manager",
		Type:         ResponseTypeContainment,
		IncidentID:   "incident1",
		PlaybookID:   "playbook1",
		WorkflowID:   "workflow1",
		TriggerEvent: "alert_created",
		Actions: []ResponseAction{
			{
				Name:        "Block IP",
				Description: "Block malicious IP address",
				Type:        ActionTypeBlock,
				Parameters: map[string]interface{}{
					"ip": "192.168.1.100",
				},
				Timeout: 5 * time.Minute,
			},
		},
		ApprovalRequired: false,
		Metadata: map[string]interface{}{
			"priority": "high",
		},
		Tags:  []string{"containment", "response"},
		Notes: []string{"Automated response triggered"},
	}

	createdResponse, err := manager.CreateResponse(response)
	require.NoError(t, err)
	require.NotNil(t, createdResponse)

	assert.NotEmpty(t, createdResponse.ID)
	assert.Equal(t, response.Name, createdResponse.Name)
	assert.Equal(t, response.Description, createdResponse.Description)
	assert.Equal(t, response.Type, createdResponse.Type)
	assert.Equal(t, response.IncidentID, createdResponse.IncidentID)
	assert.Equal(t, response.PlaybookID, createdResponse.PlaybookID)
	assert.Equal(t, response.WorkflowID, createdResponse.WorkflowID)
	assert.Equal(t, ResponseStatusPending, createdResponse.Status)
	assert.False(t, createdResponse.CreatedAt.IsZero())
	assert.False(t, createdResponse.UpdatedAt.IsZero())
	assert.Equal(t, len(response.Actions), len(createdResponse.Actions))
}

func TestIncidentManager_CreateIncident(t *testing.T) {
	config := getTestSOARConfig()
	manager := NewIncidentManager(config)

	incident := &Incident{
		Title:                "Test Incident",
		Description:          "Test incident for manager",
		Severity:             IncidentSeverityHigh,
		Priority:             IncidentPriorityHigh,
		Category:             "security",
		Type:                 "malware",
		Source:               "test_source",
		Detector:             "test_detector",
		FirstSeen:            time.Now().Add(-1 * time.Hour),
		LastSeen:             time.Now(),
		EventCount:           5,
		BusinessImpact:       "high",
		TechnicalImpact:      "medium",
		AffectedAssets:       []string{"server1", "server2"},
		AffectedUsers:        []string{"user1", "user2"},
		AffectedSystems:      []string{"system1", "system2"},
		ThreatActors:         []string{"APT1"},
		AttackVectors:        []string{"phishing", "malware"},
		IOCs:                 []string{"hash1", "domain1"},
		MITRE_TTPs:           []string{"T1566", "T1204"},
		Tags:                 []string{"malware", "incident"},
		ComplianceImpact:     "high",
		RegulatoryImpact:     "medium",
		NotificationRequired: true,
		ReportingRequired:    true,
		Metadata: map[string]interface{}{
			"source_ip": "192.168.1.100",
			"dest_ip":   "10.0.0.1",
		},
		Evidence: []string{"evidence1", "evidence2"},
		Timeline: []string{"timeline1"},
		Notes:    []string{"Initial investigation started"},
	}

	createdIncident, err := manager.CreateIncident(incident)
	require.NoError(t, err)
	require.NotNil(t, createdIncident)

	assert.NotEmpty(t, createdIncident.ID)
	assert.Equal(t, incident.Title, createdIncident.Title)
	assert.Equal(t, incident.Description, createdIncident.Description)
	assert.Equal(t, incident.Severity, createdIncident.Severity)
	assert.Equal(t, incident.Priority, createdIncident.Priority)
	assert.Equal(t, incident.Category, createdIncident.Category)
	assert.Equal(t, incident.Type, createdIncident.Type)
	assert.Equal(t, IncidentStatusNew, createdIncident.Status)
	assert.False(t, createdIncident.CreatedAt.IsZero())
	assert.False(t, createdIncident.UpdatedAt.IsZero())

	// Test incident retrieval
	retrievedIncident, err := manager.GetIncident(createdIncident.ID)
	require.NoError(t, err)
	assert.Equal(t, createdIncident.ID, retrievedIncident.ID)
	assert.Equal(t, createdIncident.Title, retrievedIncident.Title)
}

func TestIncidentManager_UpdateIncident(t *testing.T) {
	config := getTestSOARConfig()
	manager := NewIncidentManager(config)

	incident := &Incident{
		Title:       "Test Incident",
		Description: "Test incident for update",
		Severity:    IncidentSeverityMedium,
		Priority:    IncidentPriorityMedium,
		Category:    "security",
		Type:        "malware",
	}

	createdIncident, err := manager.CreateIncident(incident)
	require.NoError(t, err)

	// Update incident
	updates := map[string]interface{}{
		"status":      IncidentStatusInvestigating,
		"severity":    IncidentSeverityHigh,
		"priority":    IncidentPriorityHigh,
		"assigned_to": "analyst1",
	}

	updatedIncident, err := manager.UpdateIncident(createdIncident.ID, updates)
	require.NoError(t, err)
	require.NotNil(t, updatedIncident)

	assert.Equal(t, IncidentStatusInvestigating, updatedIncident.Status)
	assert.Equal(t, IncidentSeverityHigh, updatedIncident.Severity)
	assert.Equal(t, IncidentPriorityHigh, updatedIncident.Priority)
	assert.Equal(t, "analyst1", updatedIncident.AssignedTo)
	assert.True(t, updatedIncident.UpdatedAt.After(updatedIncident.CreatedAt))
}

func TestIncidentManager_ListIncidents(t *testing.T) {
	config := getTestSOARConfig()
	manager := NewIncidentManager(config)

	// Create multiple incidents
	for i := 0; i < 3; i++ {
		incident := &Incident{
			Title:       fmt.Sprintf("Test Incident %d", i),
			Description: fmt.Sprintf("Test incident %d", i),
			Severity:    IncidentSeverityMedium,
			Priority:    IncidentPriorityMedium,
			Category:    "security",
			Type:        "malware",
		}

		_, err := manager.CreateIncident(incident)
		require.NoError(t, err)
	}

	incidents := manager.ListIncidents()
	assert.Len(t, incidents, 3)

	// Verify incidents are sorted by creation time (newest first)
	for i := 0; i < len(incidents)-1; i++ {
		assert.True(t, incidents[i].CreatedAt.After(incidents[i+1].CreatedAt) ||
			incidents[i].CreatedAt.Equal(incidents[i+1].CreatedAt))
	}
}

func TestAlertManager_CreateAlert(t *testing.T) {
	config := getTestSOARConfig()
	manager := NewAlertManager(config)

	alert := &Alert{
		Title:        "Test Alert",
		Description:  "Test alert for manager",
		Severity:     AlertSeverityHigh,
		Priority:     AlertPriorityHigh,
		Category:     "security",
		Type:         "malware_detected",
		Source:       "test_source",
		Detector:     "test_detector",
		EventCount:   3,
		FirstSeen:    time.Now().Add(-30 * time.Minute),
		LastSeen:     time.Now(),
		Acknowledged: false,
		Escalated:    false,
		Context: map[string]interface{}{
			"source_ip": "192.168.1.100",
			"dest_ip":   "10.0.0.1",
			"protocol":  "HTTP",
		},
		Evidence:           []string{"evidence1", "evidence2"},
		IOCs:               []string{"hash1", "domain1"},
		MITRE_TTPs:         []string{"T1566", "T1204"},
		Tags:               []string{"malware", "alert"},
		ThreatIntelligence: []string{"ti1", "ti2"},
		GeolocationData: map[string]interface{}{
			"country": "US",
			"city":    "New York",
		},
		AssetInformation: map[string]interface{}{
			"hostname": "server1",
			"ip":       "192.168.1.100",
		},
		UserInformation: map[string]interface{}{
			"username": "user1",
			"email":    "user1@example.com",
		},
		Metadata: map[string]interface{}{
			"rule_id":   "rule1",
			"rule_name": "Malware Detection",
		},
		Notes: []string{"Initial detection", "Investigation started"},
	}

	createdAlert, err := manager.CreateAlert(alert)
	require.NoError(t, err)
	require.NotNil(t, createdAlert)

	assert.NotEmpty(t, createdAlert.ID)
	assert.Equal(t, alert.Title, createdAlert.Title)
	assert.Equal(t, alert.Description, createdAlert.Description)
	assert.Equal(t, alert.Severity, createdAlert.Severity)
	assert.Equal(t, alert.Priority, createdAlert.Priority)
	assert.Equal(t, alert.Category, createdAlert.Category)
	assert.Equal(t, alert.Type, createdAlert.Type)
	assert.Equal(t, AlertStatusNew, createdAlert.Status)
	assert.False(t, createdAlert.CreatedAt.IsZero())
	assert.False(t, createdAlert.UpdatedAt.IsZero())

	// Test alert retrieval
	retrievedAlert, err := manager.GetAlert(createdAlert.ID)
	require.NoError(t, err)
	assert.Equal(t, createdAlert.ID, retrievedAlert.ID)
	assert.Equal(t, createdAlert.Title, retrievedAlert.Title)
}

func TestAlertManager_ListAlerts(t *testing.T) {
	config := getTestSOARConfig()
	manager := NewAlertManager(config)

	// Create multiple alerts
	for i := 0; i < 3; i++ {
		alert := &Alert{
			Title:       fmt.Sprintf("Test Alert %d", i),
			Description: fmt.Sprintf("Test alert %d", i),
			Severity:    AlertSeverityMedium,
			Priority:    AlertPriorityMedium,
			Category:    "security",
			Type:        "malware_detected",
			Source:      "test_source",
			Detector:    "test_detector",
		}

		_, err := manager.CreateAlert(alert)
		require.NoError(t, err)
	}

	alerts := manager.ListAlerts()
	assert.Len(t, alerts, 3)

	// Verify alerts are sorted by creation time (newest first)
	for i := 0; i < len(alerts)-1; i++ {
		assert.True(t, alerts[i].CreatedAt.After(alerts[i+1].CreatedAt) ||
			alerts[i].CreatedAt.Equal(alerts[i+1].CreatedAt))
	}
}

func TestIntegrationManager_CreateIntegration(t *testing.T) {
	config := getTestSOARConfig()
	manager := NewIntegrationManager(config)

	integration := &Integration{
		Name:        "Test SIEM Integration",
		Description: "Test SIEM integration for manager",
		Type:        IntegrationTypeSIEM,
		Endpoint:    "https://siem.example.com/api",
		Authentication: AuthenticationConfig{
			Type:   "api_key",
			APIKey: "test_api_key",
		},
		Configuration: map[string]interface{}{
			"timeout":     30,
			"retry_count": 3,
		},
		Capabilities: []string{"query", "create_alert", "update_alert"},
		Metadata: map[string]interface{}{
			"vendor":  "Test Vendor",
			"version": "1.0",
		},
		Tags: []string{"siem", "integration"},
	}

	createdIntegration, err := manager.CreateIntegration(integration)
	require.NoError(t, err)
	require.NotNil(t, createdIntegration)

	assert.NotEmpty(t, createdIntegration.ID)
	assert.Equal(t, integration.Name, createdIntegration.Name)
	assert.Equal(t, integration.Description, createdIntegration.Description)
	assert.Equal(t, integration.Type, createdIntegration.Type)
	assert.Equal(t, integration.Endpoint, createdIntegration.Endpoint)
	assert.Equal(t, IntegrationStatusActive, createdIntegration.Status)
	assert.False(t, createdIntegration.CreatedAt.IsZero())
	assert.False(t, createdIntegration.UpdatedAt.IsZero())
	assert.False(t, createdIntegration.LastHealthCheck.IsZero())

	// Test integration retrieval
	retrievedIntegration, err := manager.GetIntegration(createdIntegration.ID)
	require.NoError(t, err)
	assert.Equal(t, createdIntegration.ID, retrievedIntegration.ID)
	assert.Equal(t, createdIntegration.Name, retrievedIntegration.Name)
}

func TestAutomationEngine_CreateRule(t *testing.T) {
	config := getTestSOARConfig()
	engine := NewAutomationEngine(config)

	rule := &AutomationRule{
		Name:        "Test Automation Rule",
		Description: "Test automation rule for engine",
		Trigger: AutomationTrigger{
			Type:      TriggerTypeAlert,
			Condition: "alert.severity == 'high'",
			Parameters: map[string]interface{}{
				"threshold": 5,
			},
			Enabled: true,
		},
		Conditions: []AutomationCondition{
			{
				Type:      ConditionTypeData,
				Condition: "incident.status == 'new'",
				Parameters: map[string]interface{}{
					"max_age": "1h",
				},
				Required: true,
			},
		},
		Actions: []AutomationAction{
			{
				Type:   ActionTypeEscalate,
				Action: "escalate_to_soc",
				Parameters: map[string]interface{}{
					"team": "soc_team",
				},
				Timeout:    5 * time.Minute,
				RetryCount: 3,
			},
		},
		Priority: 1,
		Timeout:  30 * time.Minute,
		Metadata: map[string]interface{}{
			"category": "incident_response",
		},
		Tags: []string{"automation", "escalation"},
	}

	createdRule, err := engine.CreateRule(rule)
	require.NoError(t, err)
	require.NotNil(t, createdRule)

	assert.NotEmpty(t, createdRule.ID)
	assert.Equal(t, rule.Name, createdRule.Name)
	assert.Equal(t, rule.Description, createdRule.Description)
	assert.Equal(t, rule.Trigger.Type, createdRule.Trigger.Type)
	assert.Equal(t, rule.Trigger.Condition, createdRule.Trigger.Condition)
	assert.Equal(t, rule.Trigger.Enabled, createdRule.Trigger.Enabled)
	assert.Equal(t, len(rule.Conditions), len(createdRule.Conditions))
	assert.Equal(t, len(rule.Actions), len(createdRule.Actions))
	assert.Equal(t, rule.Priority, createdRule.Priority)
	assert.Equal(t, rule.Timeout, createdRule.Timeout)
	assert.Equal(t, AutomationStatusActive, createdRule.Status)
	assert.False(t, createdRule.CreatedAt.IsZero())
	assert.False(t, createdRule.UpdatedAt.IsZero())
}

func TestAutomationEngine_ExecuteRule(t *testing.T) {
	config := getTestSOARConfig()
	engine := NewAutomationEngine(config)

	rule := &AutomationRule{
		Name:        "Test Execution Rule",
		Description: "Test automation rule for execution",
		Status:      AutomationStatusActive,
		Trigger: AutomationTrigger{
			Type:      TriggerTypeAlert,
			Condition: "alert.severity == 'high'",
			Enabled:   true,
		},
		Conditions: []AutomationCondition{},
		Actions:    []AutomationAction{},
		Priority:   1,
		Timeout:    30 * time.Minute,
	}

	createdRule, err := engine.CreateRule(rule)
	require.NoError(t, err)

	// Execute rule
	context := map[string]interface{}{
		"alert_id":  "alert1",
		"severity":  "high",
		"timestamp": time.Now(),
	}

	err = engine.ExecuteRule(createdRule.ID, context)
	assert.NoError(t, err)
}

// Helper function to create test configuration
func getTestSOARConfig() *SOARConfig {
	return &SOARConfig{
		MaxConcurrentPlaybooks:         10,
		MaxConcurrentWorkflows:         20,
		MaxConcurrentResponses:         15,
		PlaybookTimeout:                30 * time.Minute,
		WorkflowTimeout:                60 * time.Minute,
		ResponseTimeout:                45 * time.Minute,
		AlertQueueSize:                 1000,
		IncidentQueueSize:              500,
		ResponseQueueSize:              200,
		WorkflowQueueSize:              100,
		ProcessingWorkers:              5,
		AutomationEnabled:              true,
		AutoPlaybookExecution:          true,
		AutoIncidentCreation:           true,
		AutoResponseEscalation:         true,
		AutoWorkflowOptimization:       true,
		AutoIntegrationHealing:         true,
		EnableSIEMIntegration:          true,
		EnableTIPIntegration:           true,
		EnableForensicsIntegration:     true,
		EnableThreatHuntingIntegration: true,
		EnableEDRIntegration:           true,
		EnableSOCIntegration:           true,
		PlaybookStoragePath:            "/tmp/soar/playbooks",
		PlaybookValidationEnabled:      true,
		PlaybookVersioning:             true,
		PlaybookBackup:                 true,
		WorkflowPersistence:            true,
		WorkflowRecovery:               true,
		WorkflowOptimization:           true,
		WorkflowMetrics:                true,
		ResponsePersistence:            true,
		ResponseValidation:             true,
		ResponseApproval:               false,
		ResponseAuditTrail:             true,
		AlertDeduplication:             true,
		AlertCorrelation:               true,
		AlertPrioritization:            true,
		AlertEnrichment:                true,
		IncidentCreationRules:          []IncidentCreationRule{},
		IncidentEscalationRules:        []IncidentEscalationRule{},
		IncidentSeverityRules:          []IncidentSeverityRule{},
		IncidentAssignmentRules:        []IncidentAssignmentRule{},
		AuthenticationEnabled:          true,
		AuthorizationEnabled:           true,
		EncryptionEnabled:              true,
		AuditLoggingEnabled:            true,
		ComplianceMode:                 "standard",
		CacheSize:                      1000,
		IndexingEnabled:                true,
		SearchOptimization:             true,
		MetricsCollection:              true,
		HealthChecking:                 true,
		NotificationEnabled:            true,
		EmailNotifications:             true,
		SlackIntegration:               true,
		TeamsIntegration:               true,
		PagerDutyIntegration:           true,
		WebhookNotifications:           true,
		ComplianceFramework:            "NIST",
		DataRetentionPeriod:            365 * 24 * time.Hour,
		AuditTrailRetention:            1095 * 24 * time.Hour, // 3 years
		PrivacyMode:                    false,
		DataClassification:             "internal",
	}
}

// Benchmark tests
func BenchmarkSOAREngine_CreatePlaybook(b *testing.B) {
	config := getTestSOARConfig()
	engine := NewSOAREngine(config)

	workflow := &Workflow{
		ID:        "benchmark_workflow",
		Name:      "Benchmark Workflow",
		Status:    WorkflowStatusActive,
		Steps:     []WorkflowStep{},
		StartStep: "step1",
		EndSteps:  []string{"step1"},
	}

	playbook := &Playbook{
		Name:          "Benchmark Playbook",
		Description:   "Benchmark playbook for performance testing",
		Version:       "1.0",
		Category:      "benchmark",
		Workflow:      workflow,
		ExecutionMode: ExecutionModeAutomatic,
		Timeout:       30 * time.Minute,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := engine.CreatePlaybook(playbook)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSOAREngine_CreateIncident(b *testing.B) {
	config := getTestSOARConfig()
	engine := NewSOAREngine(config)

	incident := &Incident{
		Title:       "Benchmark Incident",
		Description: "Benchmark incident for performance testing",
		Severity:    IncidentSeverityMedium,
		Priority:    IncidentPriorityMedium,
		Category:    "benchmark",
		Type:        "test",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := engine.CreateIncident(incident)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSOAREngine_CreateAlert(b *testing.B) {
	config := getTestSOARConfig()
	engine := NewSOAREngine(config)

	alert := &Alert{
		Title:       "Benchmark Alert",
		Description: "Benchmark alert for performance testing",
		Severity:    AlertSeverityMedium,
		Priority:    AlertPriorityMedium,
		Category:    "benchmark",
		Type:        "test",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := engine.CreateAlert(alert)
		if err != nil {
			b.Fatal(err)
		}
	}
}
