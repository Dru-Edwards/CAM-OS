import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter, Gauge } from 'k6/metrics';
import { SharedArray } from 'k6/data';
import { randomIntBetween, randomItem } from 'https://jslib.k6.io/k6-utils/1.2.0/index.js';

// Stress-specific metrics
const systemRecoveryTime = new Trend('stress_system_recovery_time');
const resourceExhaustionRate = new Rate('stress_resource_exhaustion_rate');
const errorCascadeDepth = new Counter('stress_error_cascade_depth');
const memoryPressureGauge = new Gauge('stress_memory_pressure');
const connectionPoolUtilization = new Gauge('stress_connection_pool_utilization');
const circuitBreakerActivations = new Counter('stress_circuit_breaker_activations');

// Test configuration
const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';
const API_KEY = __ENV.API_KEY || 'test_api_key';
const STRESS_TYPE = __ENV.STRESS_TYPE || 'memory';
const MAX_FAILURES = parseInt(__ENV.MAX_FAILURES || '100');

// Stress test scenarios
const stressScenarios = {
  memory: {
    name: 'Memory Stress Test',
    maxVUs: 1000,
    rampDuration: '2m',
    sustainDuration: '15m',
    payloadSizes: [1, 5, 10, 50, 100], // MB
  },
  concurrency: {
    name: 'Concurrency Stress Test',
    maxVUs: 2000,
    rampDuration: '5m',
    sustainDuration: '20m',
    connectionPoolSize: 200,
  },
  network: {
    name: 'Network Stress Test',
    maxVUs: 500,
    rampDuration: '3m',
    sustainDuration: '10m',
    maxConnections: 5000,
  },
  cpu: {
    name: 'CPU Stress Test',
    maxVUs: 100,
    rampDuration: '1m',
    sustainDuration: '30m',
    computeIntensive: true,
  },
};

const currentScenario = stressScenarios[STRESS_TYPE] || stressScenarios.memory;

export let options = {
  scenarios: {
    stress_ramp_up: {
      executor: 'ramping-vus',
      startVUs: 1,
      stages: [
        { duration: currentScenario.rampDuration, target: currentScenario.maxVUs },
        { duration: currentScenario.sustainDuration, target: currentScenario.maxVUs },
        { duration: '2m', target: 0 },
      ],
    },
  },
  thresholds: {
    // Relaxed thresholds for stress testing
    http_req_duration: ['p(95)<5000'], // 5 seconds under stress
    http_req_failed: ['rate<0.20'], // 20% failure rate acceptable under stress
    stress_resource_exhaustion_rate: ['rate<0.50'], // 50% resource exhaustion acceptable
    stress_system_recovery_time: ['p(95)<30000'], // 30 seconds recovery time
  },
  tags: {
    test_type: 'stress_test',
    stress_type: STRESS_TYPE,
    version: '2.0.0',
  },
};

export function setup() {
  console.log(`Starting ${currentScenario.name} with ${currentScenario.maxVUs} VUs`);
  
  // Authenticate
  const authResponse = http.post(`${BASE_URL}/api/auth/token`, {
    api_key: API_KEY,
  });
  
  check(authResponse, {
    'authentication successful': (r) => r.status === 200,
  });
  
  const authData = authResponse.json();
  
  // Initialize monitoring
  const monitoringResponse = http.post(`${BASE_URL}/api/test/monitoring/start`, JSON.stringify({
    test_type: 'stress',
    stress_type: STRESS_TYPE,
    expected_duration: parseInt(currentScenario.sustainDuration) * 60 + 300, // Add buffer
  }), {
    headers: {
      'Authorization': `Bearer ${authData.token}`,
      'Content-Type': 'application/json',
    },
  });
  
  return {
    token: authData.token,
    monitoringId: monitoringResponse.json('monitoring_id'),
  };
}

export default function (data) {
  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${data.token}`,
    'X-Stress-Test': STRESS_TYPE,
    'X-Monitoring-ID': data.monitoringId,
  };
  
  switch (STRESS_TYPE) {
    case 'memory':
      performMemoryStressTest(headers);
      break;
    case 'concurrency':
      performConcurrencyStressTest(headers);
      break;
    case 'network':
      performNetworkStressTest(headers);
      break;
    case 'cpu':
      performCPUStressTest(headers);
      break;
    default:
      performMemoryStressTest(headers);
  }
  
  // Variable sleep to create realistic load patterns
  sleep(randomIntBetween(0.1, 2));
}

function performMemoryStressTest(headers) {
  // Generate large payload to stress memory
  const payloadSize = randomItem(currentScenario.payloadSizes);
  const largePayload = generateLargePayload(payloadSize);
  
  const startTime = Date.now();
  
  const response = http.post(`${BASE_URL}/api/v1/stress/memory`, JSON.stringify({
    data: largePayload,
    processing_instructions: {
      memory_intensive: true,
      cache_bypass: true,
      gc_trigger: __ITER % 10 === 0, // Trigger GC every 10 iterations
    },
    metadata: {
      payload_size_mb: payloadSize,
      vu_id: __VU,
      iteration: __ITER,
    },
  }), { headers });
  
  const endTime = Date.now();
  const processingTime = endTime - startTime;
  
  const success = check(response, {
    'memory stress request processed': (r) => r.status === 200 || r.status === 503,
    'system still responsive': (r) => r.timings.duration < 30000, // 30 seconds max
  });
  
  // Track memory pressure indicators
  if (response.status === 503) {
    resourceExhaustionRate.add(1);
  } else {
    resourceExhaustionRate.add(0);
  }
  
  // Check for memory pressure signals in response
  if (response.status === 200) {
    const responseData = response.json();
    if (responseData.memory_pressure) {
      memoryPressureGauge.add(responseData.memory_pressure.percentage || 0);
    }
  }
  
  // Recovery time measurement
  if (response.status === 503) {
    const recoveryStart = Date.now();
    // Try a simple health check
    const healthResponse = http.get(`${BASE_URL}/api/health`, { headers });
    if (healthResponse.status === 200) {
      systemRecoveryTime.add(Date.now() - recoveryStart);
    }
  }
}

function performConcurrencyStressTest(headers) {
  // Simulate high concurrency scenarios
  const concurrentOperations = randomIntBetween(5, 20);
  const operationPromises = [];
  
  for (let i = 0; i < concurrentOperations; i++) {
    const operation = {
      type: randomItem(['arbitration', 'collaboration', 'direct']),
      complexity: randomItem(['low', 'medium', 'high']),
      timeout: randomIntBetween(5000, 30000),
    };
    
    operationPromises.push(operation);
  }
  
  const response = http.post(`${BASE_URL}/api/v1/stress/concurrency`, JSON.stringify({
    operations: operationPromises,
    concurrency_level: concurrentOperations,
    stress_mode: true,
  }), { headers });
  
  check(response, {
    'concurrency stress handled': (r) => r.status === 200 || r.status === 429,
    'no deadlocks detected': (r) => !r.json('deadlock_detected'),
    'thread pool responsive': (r) => r.json('thread_pool_status') !== 'exhausted',
  });
  
  // Track connection pool utilization
  if (response.status === 200) {
    const responseData = response.json();
    if (responseData.connection_pool_stats) {
      connectionPoolUtilization.add(responseData.connection_pool_stats.utilization_percentage);
    }
  }
}

function performNetworkStressTest(headers) {
  // Create multiple simultaneous connections
  const connectionCount = randomIntBetween(10, 50);
  const endpoints = [
    '/api/v1/arbitrate',
    '/api/v1/generate',
    '/api/v1/agents/status',
    '/api/v1/providers/health',
    '/api/v1/metrics',
  ];
  
  const requests = [];
  for (let i = 0; i < connectionCount; i++) {
    const endpoint = randomItem(endpoints);
    const requestData = {
      connection_id: `stress_${__VU}_${__ITER}_${i}`,
      keep_alive: true,
      timeout: 10000,
    };
    
    requests.push({
      method: 'POST',
      url: `${BASE_URL}${endpoint}`,
      body: JSON.stringify(requestData),
      params: { headers },
    });
  }
  
  // Send all requests simultaneously
  const responses = http.batch(requests);
  
  let successCount = 0;
  let connectionErrors = 0;
  
  responses.forEach((response, index) => {
    const success = check(response, {
      [`connection ${index} successful`]: (r) => r.status === 200,
      [`connection ${index} not timed out`]: (r) => r.timings.duration < 15000,
    });
    
    if (success) {
      successCount++;
    } else if (response.error && response.error.includes('connection')) {
      connectionErrors++;
    }
  });
  
  // Track network stress metrics
  if (connectionErrors > connectionCount * 0.5) {
    resourceExhaustionRate.add(1);
  } else {
    resourceExhaustionRate.add(0);
  }
}

function performCPUStressTest(headers) {
  // CPU-intensive arbitration with complex algorithms
  const complexRequest = {
    prompt: generateComplexPrompt(),
    requirements: {
      algorithm_complexity: 'maximum',
      decision_tree_depth: 10,
      consensus_rounds: 20,
      parallel_processing: true,
      cpu_intensive_analysis: true,
    },
    stress_parameters: {
      computation_cycles: randomIntBetween(1000000, 10000000),
      algorithm_iterations: randomIntBetween(100, 1000),
      matrix_operations: true,
    },
  };
  
  const response = http.post(`${BASE_URL}/api/v1/stress/cpu`, JSON.stringify(complexRequest), { 
    headers,
    timeout: '60s', // Allow longer processing time for CPU stress
  });
  
  check(response, {
    'cpu stress request processed': (r) => r.status === 200 || r.status === 408,
    'no cpu throttling detected': (r) => !r.json('cpu_throttling'),
    'algorithms completed': (r) => r.json('computation_completed') === true,
  });
  
  // Check for CPU pressure indicators
  if (response.status === 200) {
    const responseData = response.json();
    if (responseData.cpu_usage_peak > 95) {
      resourceExhaustionRate.add(1);
    } else {
      resourceExhaustionRate.add(0);
    }
  }
}

function generateLargePayload(sizeMB) {
  const sizeBytes = sizeMB * 1024 * 1024;
  const chunkSize = 1024; // 1KB chunks
  const chunks = [];
  
  for (let i = 0; i < sizeBytes / chunkSize; i++) {
    chunks.push('x'.repeat(chunkSize));
  }
  
  return {
    size_mb: sizeMB,
    data: chunks,
    metadata: {
      generated_at: new Date().toISOString(),
      chunk_count: chunks.length,
      total_size_bytes: sizeBytes,
    },
  };
}

function generateComplexPrompt() {
  const complexityFactors = [
    'multi-step reasoning',
    'contextual analysis',
    'pattern recognition',
    'semantic understanding',
    'cross-reference validation',
    'temporal analysis',
    'causal inference',
    'probabilistic reasoning',
  ];
  
  return {
    main_prompt: 'Analyze the following complex scenario requiring ' + randomItem(complexityFactors),
    context_layers: randomIntBetween(5, 15),
    reasoning_steps: randomIntBetween(10, 50),
    cross_references: randomIntBetween(3, 20),
    complexity_score: randomIntBetween(7, 10),
  };
}

export function teardown(data) {
  // Stop monitoring and collect stress test results
  const cleanupResponse = http.post(`${BASE_URL}/api/test/monitoring/stop`, JSON.stringify({
    monitoring_id: data.monitoringId,
    test_type: 'stress',
    stress_type: STRESS_TYPE,
  }), {
    headers: {
      'Authorization': `Bearer ${data.token}`,
      'Content-Type': 'application/json',
    },
  });
  
  check(cleanupResponse, {
    'stress test monitoring stopped': (r) => r.status === 200,
    'stress results collected': (r) => r.json('results_collected') === true,
  });
  
  console.log(`Stress test ${STRESS_TYPE} completed. System recovery initiated.`);
}
