// Arbitration Performance Benchmark Suite
import http from 'k6/http';
import { check, group } from 'k6';
import { Rate, Trend } from 'k6/metrics';
import { camTestUtils } from '../utils/cam-test-utils.js';

// Custom metrics for arbitration benchmarks
const arbitrationDecisionTime = new Trend('arbitration_decision_time', true);
const providerSelectionAccuracy = new Rate('provider_selection_accuracy');
const costOptimizationRate = new Rate('cost_optimization_effectiveness');

export let options = {
  scenarios: {
    simple_arbitration: {
      executor: 'constant-vus',
      vus: 5,
      duration: '2m',
      tags: { test_type: 'simple_arbitration' },
    },
    complex_arbitration: {
      executor: 'constant-vus',
      vus: 3,
      duration: '3m',
      tags: { test_type: 'complex_arbitration' },
      startTime: '2m',
    },
    multi_model_arbitration: {
      executor: 'constant-vus',
      vus: 2,
      duration: '4m',
      tags: { test_type: 'multi_model_arbitration' },
      startTime: '5m',
    },
  },
  thresholds: {
    'arbitration_decision_time': ['p95<500'], // 95% of arbitration decisions under 500ms
    'provider_selection_accuracy': ['rate>0.9'], // 90% accuracy in provider selection
    'cost_optimization_effectiveness': ['rate>0.8'], // 80% cost optimization success
    'http_req_duration': ['p95<2000'], // 95% of requests under 2s
    'http_req_failed': ['rate<0.05'], // Error rate under 5%
  },
};

export default function () {
  const baseUrl = __ENV.CAM_BASE_URL || 'http://localhost:3000';
  const apiToken = __ENV.CAM_API_TOKEN;

  group('Simple Arbitration Benchmark', function () {
    const startTime = Date.now();
    
    const response = http.post(`${baseUrl}/api/v1/arbitration/request`, JSON.stringify({
      prompt: "What is the capital of France?",
      models: ["gpt-3.5-turbo", "claude-3-haiku"],
      max_cost: 0.01,
      optimization_criteria: ["cost", "speed"],
      benchmark_mode: true
    }), {
      headers: camTestUtils.getAuthHeaders(apiToken),
    });

    const arbitrationTime = Date.now() - startTime;
    arbitrationDecisionTime.add(arbitrationTime);

    const success = check(response, {
      'status is 200': (r) => r.status === 200,
      'has arbitration_id': (r) => JSON.parse(r.body).arbitration_id !== undefined,
      'has selected_provider': (r) => JSON.parse(r.body).selected_provider !== undefined,
      'decision time under 1s': () => arbitrationTime < 1000,
    });

    if (success && response.status === 200) {
      const result = JSON.parse(response.body);
      // Check if the selected provider is cost-optimal
      const isCostOptimal = result.cost_analysis && result.cost_analysis.is_optimal;
      costOptimizationRate.add(isCostOptimal ? 1 : 0);
      providerSelectionAccuracy.add(1);
    } else {
      providerSelectionAccuracy.add(0);
      costOptimizationRate.add(0);
    }
  });

  group('Complex Arbitration Benchmark', function () {
    const complexPrompt = `
      Analyze the following complex scenario: A multinational corporation is considering 
      expanding into emerging markets. Evaluate the risks, opportunities, and strategic 
      recommendations for market entry in three different regions, considering economic, 
      political, and cultural factors. Provide a comprehensive analysis with data-driven 
      insights and actionable recommendations.
    `;

    const startTime = Date.now();
    
    const response = http.post(`${baseUrl}/api/v1/arbitration/request`, JSON.stringify({
      prompt: complexPrompt,
      models: ["gpt-4", "claude-3-opus", "gemini-pro"],
      max_cost: 0.50,
      optimization_criteria: ["quality", "depth"],
      quality_threshold: 0.9,
      benchmark_mode: true
    }), {
      headers: camTestUtils.getAuthHeaders(apiToken),
    });

    const arbitrationTime = Date.now() - startTime;
    arbitrationDecisionTime.add(arbitrationTime);

    const success = check(response, {
      'status is 200': (r) => r.status === 200,
      'has quality_score': (r) => JSON.parse(r.body).quality_analysis !== undefined,
      'meets quality threshold': (r) => {
        const result = JSON.parse(r.body);
        return result.quality_analysis && result.quality_analysis.score >= 0.9;
      },
      'decision time under 2s': () => arbitrationTime < 2000,
    });

    if (success && response.status === 200) {
      const result = JSON.parse(response.body);
      const meetsQuality = result.quality_analysis && result.quality_analysis.score >= 0.9;
      providerSelectionAccuracy.add(meetsQuality ? 1 : 0);
    } else {
      providerSelectionAccuracy.add(0);
    }
  });

  group('Multi-Model Arbitration Benchmark', function () {
    const startTime = Date.now();
    
    const response = http.post(`${baseUrl}/api/v1/arbitration/compare`, JSON.stringify({
      prompt: "Compare the effectiveness of different machine learning algorithms for fraud detection",
      providers: ["openai", "anthropic", "google", "mistral"],
      comparison_criteria: ["accuracy", "cost", "speed", "reliability"],
      max_cost: 1.0,
      benchmark_mode: true
    }), {
      headers: camTestUtils.getAuthHeaders(apiToken),
    });

    const arbitrationTime = Date.now() - startTime;
    arbitrationDecisionTime.add(arbitrationTime);

    const success = check(response, {
      'status is 200': (r) => r.status === 200,
      'has comparison_results': (r) => JSON.parse(r.body).comparison_results !== undefined,
      'has recommended_provider': (r) => JSON.parse(r.body).recommended_provider !== undefined,
      'all providers evaluated': (r) => {
        const result = JSON.parse(r.body);
        return result.comparison_results && Object.keys(result.comparison_results).length >= 3;
      },
      'decision time under 3s': () => arbitrationTime < 3000,
    });

    if (success && response.status === 200) {
      const result = JSON.parse(response.body);
      const hasRecommendation = result.recommended_provider !== undefined;
      providerSelectionAccuracy.add(hasRecommendation ? 1 : 0);
      
      // Check cost optimization effectiveness
      const costOptimized = result.cost_analysis && result.cost_analysis.savings_percentage > 0;
      costOptimizationRate.add(costOptimized ? 1 : 0);
    } else {
      providerSelectionAccuracy.add(0);
      costOptimizationRate.add(0);
    }
  });
}

export function handleSummary(data) {
  return {
    'arbitration-benchmark-results.json': JSON.stringify(data, null, 2),
    'arbitration-benchmark-summary.txt': camTestUtils.generateTextSummary(data, 'Arbitration Performance Benchmark'),
  };
}
