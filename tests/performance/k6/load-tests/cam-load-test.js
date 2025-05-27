import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';
import { SharedArray } from 'k6/data';
import { randomIntBetween, randomItem } from 'https://jslib.k6.io/k6-utils/1.2.0/index.js';

// Custom metrics for CAM-specific measurements
const arbitrationDecisionTime = new Trend('cam_arbitration_decision_time');
const providerSelectionAccuracy = new Rate('cam_provider_selection_accuracy');
const costOptimizationRate = new Trend('cam_cost_optimization_rate');
const agentCollaborationEfficiency = new Rate('cam_agent_collaboration_efficiency');
const providerSwitchRate = new Counter('cam_provider_switch_count');

// Test data shared across all VUs
const testData = new SharedArray('test_requests', function () {
  return JSON.parse(open('../fixtures/test-data/arbitration-requests.json'));
});

const scenarios = new SharedArray('test_scenarios', function () {
  return JSON.parse(open('../fixtures/scenarios/load-test-scenarios.json'));
});

// Configuration from environment variables
const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';
const API_KEY = __ENV.API_KEY || 'test_api_key';
const TEST_SCENARIO = __ENV.TEST_SCENARIO || 'basic';

// Load test scenario configuration
const scenarioConfig = scenarios.find(s => s.name === TEST_SCENARIO) || scenarios[0];

export let options = {
  scenarios: {
    [scenarioConfig.name]: {
      executor: 'ramping-vus',
      startVUs: scenarioConfig.users.initial,
      stages: [
        { duration: `${scenarioConfig.ramp_duration}s`, target: scenarioConfig.users.ramp_up },
        { duration: `${scenarioConfig.duration - (scenarioConfig.ramp_duration * 2)}s`, target: scenarioConfig.users.steady_state },
        { duration: `${scenarioConfig.ramp_duration}s`, target: scenarioConfig.users.ramp_down },
      ],
    },
  },
  thresholds: {
    http_req_duration: scenarioConfig.thresholds.http_req_duration || ['p(95)<500'],
    http_req_failed: scenarioConfig.thresholds.http_req_failed || ['rate<0.1'],
    http_reqs: scenarioConfig.thresholds.http_reqs || ['rate>50'],
    // CAM-specific thresholds
    cam_arbitration_decision_time: ['p(95)<100'],
    cam_provider_selection_accuracy: ['rate>0.95'],
    cam_cost_optimization_rate: ['p(95)<0.5'], // 50% cost reduction target
    cam_agent_collaboration_efficiency: ['rate>0.90'],
  },
  tags: {
    test_type: 'load_test',
    scenario: TEST_SCENARIO,
    version: '2.0.0',
  },
};

export function setup() {
  // Authenticate and get access token
  const authResponse = http.post(`${BASE_URL}/api/auth/token`, {
    api_key: API_KEY,
  });
  
  check(authResponse, {
    'authentication successful': (r) => r.status === 200,
  });
  
  const authData = authResponse.json();
  
  // Validate CAM system readiness
  const healthResponse = http.get(`${BASE_URL}/api/health`, {
    headers: {
      'Authorization': `Bearer ${authData.token}`,
    },
  });
  
  check(healthResponse, {
    'CAM system is healthy': (r) => r.status === 200 && r.json('status') === 'healthy',
    'arbitration engine ready': (r) => r.json('services.arbitration') === 'ready',
    'agent coordination ready': (r) => r.json('services.agents') === 'ready',
  });
  
  return {
    token: authData.token,
    userId: authData.user_id,
  };
}

export default function (data) {
  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${data.token}`,
    'X-User-ID': data.userId,
    'X-Test-Scenario': TEST_SCENARIO,
  };
  
  // Select test scenario based on weighted distribution
  const scenarioWeights = scenarioConfig.scenarios;
  const selectedScenario = selectWeightedScenario(scenarioWeights);
  
  switch (selectedScenario.name) {
    case 'arbitration_requests':
      performArbitrationRequest(headers);
      break;
    case 'direct_requests':
      performDirectRequest(headers);
      break;
    case 'agent_collaboration':
      performAgentCollaborationRequest(headers);
      break;
    case 'enterprise_features':
      performEnterpriseFeatureRequest(headers);
      break;
    default:
      performArbitrationRequest(headers);
  }
  
  // Random sleep between requests (1-3 seconds)
  sleep(randomIntBetween(1, 3));
}

function selectWeightedScenario(scenarios) {
  const totalWeight = scenarios.reduce((sum, scenario) => sum + scenario.weight, 0);
  const random = Math.random() * totalWeight;
  
  let weightSum = 0;
  for (const scenario of scenarios) {
    weightSum += scenario.weight;
    if (random <= weightSum) {
      return scenario;
    }
  }
  
  return scenarios[0]; // fallback
}

function performArbitrationRequest(headers) {
  const requestData = randomItem(testData);
  const startTime = Date.now();
  
  const response = http.post(`${BASE_URL}/api/v1/arbitrate`, JSON.stringify({
    prompt: requestData.prompt,
    context: requestData.context,
    requirements: {
      max_tokens: requestData.max_tokens || 1000,
      temperature: requestData.temperature || 0.7,
      quality_threshold: 0.8,
      cost_optimization: true,
    },
    metadata: {
      request_id: `load_test_${__VU}_${__ITER}`,
      test_scenario: TEST_SCENARIO,
    },
  }), { headers });
  
  const endTime = Date.now();
  const requestDuration = endTime - startTime;
  
  const success = check(response, {
    'arbitration request successful': (r) => r.status === 200,
    'arbitration decision made': (r) => r.json('decision') !== undefined,
    'provider selected': (r) => r.json('selected_provider') !== undefined,
    'cost optimization applied': (r) => r.json('cost_optimization.applied') === true,
    'response time acceptable': (r) => r.timings.duration < 1000,
  });
  
  if (success && response.status === 200) {
    const responseData = response.json();
    
    // Record CAM-specific metrics
    arbitrationDecisionTime.add(responseData.decision_time || requestDuration);
    providerSelectionAccuracy.add(responseData.provider_accuracy_score >= 0.9 ? 1 : 0);
    
    if (responseData.cost_optimization) {
      costOptimizationRate.add(responseData.cost_optimization.reduction_percentage || 0);
    }
    
    if (responseData.provider_switch) {
      providerSwitchRate.add(1);
    }
  }
}

function performDirectRequest(headers) {
  const requestData = randomItem(testData);
  
  const response = http.post(`${BASE_URL}/api/v1/generate`, JSON.stringify({
    provider: requestData.preferred_provider || 'openai',
    model: requestData.model || 'gpt-3.5-turbo',
    prompt: requestData.prompt,
    max_tokens: requestData.max_tokens || 500,
    temperature: requestData.temperature || 0.7,
    metadata: {
      request_id: `direct_test_${__VU}_${__ITER}`,
      bypass_arbitration: true,
    },
  }), { headers });
  
  check(response, {
    'direct request successful': (r) => r.status === 200,
    'response generated': (r) => r.json('response') !== undefined,
    'provider used': (r) => r.json('provider_used') !== undefined,
  });
}

function performAgentCollaborationRequest(headers) {
  const collaborationData = {
    task_type: 'collaborative_analysis',
    agents: randomIntBetween(3, 8),
    collaboration_mode: randomItem(['consensus', 'delegation', 'competition']),
    task_complexity: randomItem(['low', 'medium', 'high']),
    data: randomItem(testData).prompt,
    requirements: {
      consensus_threshold: 0.8,
      max_rounds: 5,
      timeout: 30000,
    },
  };
  
  const startTime = Date.now();
  
  const response = http.post(`${BASE_URL}/api/v1/agents/collaborate`, JSON.stringify(collaborationData), { headers });
  
  const endTime = Date.now();
  const collaborationTime = endTime - startTime;
  
  const success = check(response, {
    'collaboration initiated': (r) => r.status === 200,
    'agents coordinated': (r) => r.json('agents_participating') > 0,
    'consensus achieved': (r) => r.json('consensus_reached') === true,
    'collaboration efficient': (r) => r.timings.duration < 10000, // 10 seconds
  });
  
  if (success && response.status === 200) {
    const responseData = response.json();
    agentCollaborationEfficiency.add(responseData.consensus_reached ? 1 : 0);
  }
}

function performEnterpriseFeatureRequest(headers) {
  const enterpriseFeatures = [
    'cognitive_fingerprinting',
    'dynamic_context_compression',
    'semantic_caching',
    'policy_enforcement',
    'audit_logging',
  ];
  
  const selectedFeature = randomItem(enterpriseFeatures);
  const requestData = randomItem(testData);
  
  const response = http.post(`${BASE_URL}/api/v1/enterprise/${selectedFeature}`, JSON.stringify({
    ...requestData,
    enterprise_config: {
      feature: selectedFeature,
      optimization_level: 'aggressive',
      compliance_mode: true,
    },
  }), { headers });
  
  check(response, {
    'enterprise feature accessible': (r) => r.status === 200,
    'feature executed': (r) => r.json('feature_result') !== undefined,
    'compliance maintained': (r) => r.json('compliance_status') === 'compliant',
  });
}

export function teardown(data) {
  // Cleanup any test data or sessions
  const cleanupResponse = http.delete(`${BASE_URL}/api/test/cleanup`, {
    headers: {
      'Authorization': `Bearer ${data.token}`,
      'X-Test-Session': `load_test_${TEST_SCENARIO}`,
    },
  });
  
  check(cleanupResponse, {
    'cleanup successful': (r) => r.status === 200,
  });
  
  console.log(`Load test ${TEST_SCENARIO} completed successfully`);
}
