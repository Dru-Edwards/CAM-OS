// K6 Utility Functions for CAM Performance Testing

import { randomIntBetween, randomItem, randomString } from 'https://jslib.k6.io/k6-utils/1.2.0/index.js';

// Authentication utilities
export function authenticate(baseUrl, apiKey) {
  const authResponse = http.post(`${baseUrl}/api/auth/token`, {
    api_key: apiKey,
  });
  
  if (authResponse.status !== 200) {
    throw new Error(`Authentication failed: ${authResponse.status}`);
  }
  
  return authResponse.json();
}

// Request generators
export function generateArbitrationRequest(complexity = 'medium') {
  const complexityLevels = {
    simple: {
      promptLength: randomIntBetween(50, 200),
      contextSize: randomIntBetween(100, 500),
      maxTokens: randomIntBetween(100, 500),
      requirements: 1,
    },
    medium: {
      promptLength: randomIntBetween(200, 800),
      contextSize: randomIntBetween(500, 2000),
      maxTokens: randomIntBetween(500, 1500),
      requirements: randomIntBetween(2, 4),
    },
    complex: {
      promptLength: randomIntBetween(800, 2000),
      contextSize: randomIntBetween(2000, 8000),
      maxTokens: randomIntBetween(1500, 4000),
      requirements: randomIntBetween(4, 8),
    },
  };
  
  const config = complexityLevels[complexity];
  
  return {
    prompt: randomString(config.promptLength),
    context: randomString(config.contextSize),
    max_tokens: config.maxTokens,
    temperature: Math.random(),
    requirements: {
      quality_threshold: 0.8,
      cost_optimization: true,
      provider_preferences: generateProviderPreferences(),
      compliance_requirements: generateComplianceRequirements(),
    },
    metadata: {
      complexity: complexity,
      test_id: `test_${Date.now()}_${randomString(8)}`,
      priority: randomItem(['low', 'medium', 'high']),
    },
  };
}

export function generateAgentCollaborationRequest() {
  return {
    task_type: randomItem([
      'collaborative_analysis',
      'consensus_building',
      'competitive_evaluation',
      'distributed_processing',
      'knowledge_synthesis',
    ]),
    agents: randomIntBetween(3, 12),
    collaboration_mode: randomItem(['consensus', 'delegation', 'competition', 'hierarchical']),
    task_complexity: randomItem(['low', 'medium', 'high', 'extreme']),
    requirements: {
      consensus_threshold: Math.random() * 0.3 + 0.7, // 0.7 to 1.0
      max_rounds: randomIntBetween(3, 15),
      timeout: randomIntBetween(10000, 60000),
      coordination_strategy: randomItem(['broadcast', 'ring', 'star', 'mesh']),
    },
    data: randomString(randomIntBetween(500, 5000)),
  };
}

export function generateProviderPreferences() {
  const providers = ['openai', 'anthropic', 'google', 'cohere', 'azure'];
  const preferences = {};
  
  const selectedProviders = randomItem(providers, randomIntBetween(1, 3));
  selectedProviders.forEach(provider => {
    preferences[provider] = {
      weight: Math.random(),
      max_cost_per_token: Math.random() * 0.001 + 0.0001,
      required_features: randomItem(['streaming', 'function_calling', 'vision'], randomIntBetween(0, 2)),
    };
  });
  
  return preferences;
}

export function generateComplianceRequirements() {
  const requirements = [];
  const possibleRequirements = [
    'data_residency_us',
    'data_residency_eu',
    'hipaa_compliance',
    'gdpr_compliance',
    'sox_compliance',
    'pci_compliance',
    'audit_logging',
    'data_encryption',
  ];
  
  const count = randomIntBetween(0, 3);
  for (let i = 0; i < count; i++) {
    requirements.push(randomItem(possibleRequirements));
  }
  
  return [...new Set(requirements)]; // Remove duplicates
}

// Metrics collection utilities
export function collectSystemMetrics(response) {
  if (response.status === 200) {
    const data = response.json();
    return {
      response_time: response.timings.duration,
      arbitration_time: data.arbitration_time || 0,
      provider_selection_time: data.provider_selection_time || 0,
      cost_optimization_applied: data.cost_optimization?.applied || false,
      cost_reduction_percentage: data.cost_optimization?.reduction_percentage || 0,
      quality_score: data.quality_metrics?.score || 0,
      provider_used: data.selected_provider,
      tokens_used: data.usage?.total_tokens || 0,
      agent_count: data.agent_participation?.count || 0,
      consensus_rounds: data.consensus?.rounds || 0,
    };
  }
  return null;
}

// Test data generators
export function generateTestDataSet(size = 100) {
  const dataset = [];
  
  for (let i = 0; i < size; i++) {
    dataset.push({
      id: i,
      request: generateArbitrationRequest(randomItem(['simple', 'medium', 'complex'])),
      expected_outcome: {
        success: true,
        max_response_time: randomIntBetween(100, 1000),
        min_quality_score: 0.8,
      },
    });
  }
  
  return dataset;
}

// Load pattern generators
export function generateLoadPattern(pattern = 'steady') {
  const patterns = {
    steady: {
      stages: [
        { duration: '5m', target: 50 },
        { duration: '10m', target: 50 },
        { duration: '5m', target: 0 },
      ],
    },
    ramp_up: {
      stages: [
        { duration: '2m', target: 50 },
        { duration: '5m', target: 100 },
        { duration: '5m', target: 200 },
        { duration: '5m', target: 200 },
        { duration: '3m', target: 0 },
      ],
    },
    spike: {
      stages: [
        { duration: '2m', target: 50 },
        { duration: '30s', target: 300 },
        { duration: '2m', target: 50 },
        { duration: '30s', target: 400 },
        { duration: '2m', target: 50 },
        { duration: '2m', target: 0 },
      ],
    },
    wave: {
      stages: [
        { duration: '1m', target: 50 },
        { duration: '2m', target: 100 },
        { duration: '1m', target: 50 },
        { duration: '2m', target: 150 },
        { duration: '1m', target: 50 },
        { duration: '2m', target: 200 },
        { duration: '1m', target: 50 },
        { duration: '2m', target: 0 },
      ],
    },
  };
  
  return patterns[pattern] || patterns.steady;
}

// Error simulation utilities
export function simulateProviderFailure(probability = 0.1) {
  return Math.random() < probability;
}

export function simulateNetworkLatency(baseLatency = 100, variance = 50) {
  return baseLatency + (Math.random() - 0.5) * 2 * variance;
}

export function simulateRateLimitHit(probability = 0.05) {
  return Math.random() < probability;
}

// Validation utilities
export function validateResponse(response, expectedCriteria) {
  const validations = {};
  
  if (expectedCriteria.maxResponseTime) {
    validations.response_time_ok = response.timings.duration <= expectedCriteria.maxResponseTime;
  }
  
  if (expectedCriteria.minQualityScore && response.status === 200) {
    const data = response.json();
    validations.quality_score_ok = (data.quality_metrics?.score || 0) >= expectedCriteria.minQualityScore;
  }
  
  if (expectedCriteria.costOptimization) {
    const data = response.json();
    validations.cost_optimization_ok = data.cost_optimization?.applied === true;
  }
  
  validations.status_ok = response.status === 200;
  
  return validations;
}

// Performance threshold utilities
export function getPerformanceThresholds(tier = 'community') {
  const thresholds = {
    community: {
      max_latency_p95: 500,  // milliseconds
      min_throughput: 50,    // requests per second
      max_error_rate: 0.05,  // 5%
      max_arbitration_time: 100,
    },
    professional: {
      max_latency_p95: 250,
      min_throughput: 200,
      max_error_rate: 0.02,
      max_arbitration_time: 50,
    },
    enterprise: {
      max_latency_p95: 100,
      min_throughput: 1000,
      max_error_rate: 0.01,
      max_arbitration_time: 25,
    },
  };
  
  return thresholds[tier] || thresholds.community;
}

// Reporting utilities
export function generateTestSummary(metrics) {
  return {
    total_requests: metrics.http_reqs || 0,
    failed_requests: metrics.http_req_failed || 0,
    average_response_time: metrics.http_req_duration?.avg || 0,
    p95_response_time: metrics.http_req_duration?.p95 || 0,
    throughput: metrics.http_reqs?.rate || 0,
    error_rate: (metrics.http_req_failed?.rate || 0) * 100,
    custom_metrics: {
      arbitration_efficiency: metrics.cam_arbitration_decision_time?.avg || 0,
      cost_optimization_rate: metrics.cam_cost_optimization_rate?.avg || 0,
      provider_selection_accuracy: (metrics.cam_provider_selection_accuracy?.rate || 0) * 100,
      agent_collaboration_success: (metrics.cam_agent_collaboration_efficiency?.rate || 0) * 100,
    },
  };
}

// Test scenario utilities
export function selectTestScenario(scenarios, weights) {
  const totalWeight = weights.reduce((sum, weight) => sum + weight, 0);
  const random = Math.random() * totalWeight;
  
  let weightSum = 0;
  for (let i = 0; i < scenarios.length; i++) {
    weightSum += weights[i];
    if (random <= weightSum) {
      return scenarios[i];
    }
  }
  
  return scenarios[0]; // fallback
}

// Environment utilities
export function getEnvironmentConfig() {
  return {
    baseUrl: __ENV.BASE_URL || 'http://localhost:3000',
    apiKey: __ENV.API_KEY || 'test_api_key',
    tier: __ENV.TIER || 'community',
    testDuration: __ENV.TEST_DURATION || '300', // seconds
    maxVUs: parseInt(__ENV.MAX_VUS || '100'),
    scenario: __ENV.SCENARIO || 'basic',
    enableMetrics: __ENV.ENABLE_METRICS === 'true',
    enableTracing: __ENV.ENABLE_TRACING === 'true',
  };
}
