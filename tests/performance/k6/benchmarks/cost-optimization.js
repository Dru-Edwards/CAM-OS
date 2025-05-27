// Cost Optimization Benchmark Suite
import http from 'k6/http';
import { check, group } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';
import { camTestUtils } from '../utils/cam-test-utils.js';

// Custom metrics for cost optimization benchmarks
const costSavingsRate = new Trend('cost_savings_percentage', true);
const optimizationAccuracy = new Rate('cost_optimization_accuracy');
const budgetComplianceRate = new Rate('budget_compliance_rate');
const costPredictionAccuracy = new Rate('cost_prediction_accuracy');

export let options = {
  scenarios: {
    basic_cost_optimization: {
      executor: 'constant-vus',
      vus: 4,
      duration: '3m',
      tags: { optimization_type: 'basic' },
    },
    advanced_cost_optimization: {
      executor: 'constant-vus',
      vus: 3,
      duration: '4m',
      tags: { optimization_type: 'advanced' },
      startTime: '3m',
    },
    budget_constrained_optimization: {
      executor: 'constant-vus',
      vus: 2,
      duration: '3m',
      tags: { optimization_type: 'budget_constrained' },
      startTime: '7m',
    },
  },
  thresholds: {
    'cost_savings_percentage': ['p50>15'], // Median savings > 15%
    'cost_optimization_accuracy': ['rate>0.9'], // 90% accuracy in optimization
    'budget_compliance_rate': ['rate>0.95'], // 95% budget compliance
    'cost_prediction_accuracy': ['rate>0.85'], // 85% prediction accuracy
    'http_req_duration': ['p95<3000'], // 95% of requests under 3s
    'http_req_failed': ['rate<0.05'], // Error rate under 5%
  },
};

export default function () {
  const baseUrl = __ENV.CAM_BASE_URL || 'http://localhost:3000';
  const apiToken = __ENV.CAM_API_TOKEN;

  group('Basic Cost Optimization', function () {
    const response = http.post(`${baseUrl}/api/v1/optimization/cost`, JSON.stringify({
      prompt: "Summarize the key findings from the latest climate research",
      target_quality: 0.8,
      max_cost: 0.10,
      optimization_strategy: "cost_first",
      providers: ["openai", "anthropic", "google"],
      benchmark_mode: true
    }), {
      headers: camTestUtils.getAuthHeaders(apiToken),
    });

    const success = check(response, {
      'status is 200': (r) => r.status === 200,
      'has optimization_result': (r) => JSON.parse(r.body).optimization_result !== undefined,
      'cost within budget': (r) => {
        const result = JSON.parse(r.body);
        return result.final_cost <= 0.10;
      },
      'quality threshold met': (r) => {
        const result = JSON.parse(r.body);
        return result.quality_score >= 0.8;
      },
    });

    if (success && response.status === 200) {
      const result = JSON.parse(response.body);
      
      // Calculate cost savings
      const originalCost = result.baseline_cost || 0.10;
      const optimizedCost = result.final_cost;
      const savingsPercentage = ((originalCost - optimizedCost) / originalCost) * 100;
      costSavingsRate.add(savingsPercentage);
      
      // Check optimization accuracy
      const withinBudget = result.final_cost <= 0.10;
      const meetsQuality = result.quality_score >= 0.8;
      optimizationAccuracy.add(withinBudget && meetsQuality ? 1 : 0);
      budgetComplianceRate.add(withinBudget ? 1 : 0);
      
      // Check cost prediction accuracy
      const predictedCost = result.predicted_cost;
      const actualCost = result.final_cost;
      const predictionError = Math.abs(predictedCost - actualCost) / actualCost;
      costPredictionAccuracy.add(predictionError < 0.1 ? 1 : 0); // Within 10% accuracy
    } else {
      optimizationAccuracy.add(0);
      budgetComplianceRate.add(0);
      costPredictionAccuracy.add(0);
    }
  });

  group('Advanced Cost Optimization', function () {
    const complexPrompt = `
      Conduct a comprehensive analysis of the global supply chain disruptions 
      impact on technology companies. Include market analysis, risk assessment, 
      mitigation strategies, and financial projections for the next 2 years.
    `;

    const response = http.post(`${baseUrl}/api/v1/optimization/cost`, JSON.stringify({
      prompt: complexPrompt,
      target_quality: 0.9,
      max_cost: 2.0,
      optimization_strategy: "balanced",
      quality_weights: {
        "depth": 0.3,
        "accuracy": 0.4,
        "completeness": 0.3
      },
      cost_constraints: {
        "prefer_efficient_models": true,
        "allow_model_mixing": true,
        "enable_caching": true
      },
      benchmark_mode: true
    }), {
      headers: camTestUtils.getAuthHeaders(apiToken),
    });

    const success = check(response, {
      'status is 200': (r) => r.status === 200,
      'advanced optimization applied': (r) => {
        const result = JSON.parse(r.body);
        return result.optimization_techniques && result.optimization_techniques.length > 2;
      },
      'cost efficiency achieved': (r) => {
        const result = JSON.parse(r.body);
        return result.efficiency_score > 0.8;
      },
      'quality maintained': (r) => {
        const result = JSON.parse(r.body);
        return result.quality_score >= 0.9;
      },
    });

    if (success && response.status === 200) {
      const result = JSON.parse(response.body);
      
      // Advanced optimization metrics
      const savingsPercentage = result.cost_analysis.savings_percentage;
      costSavingsRate.add(savingsPercentage);
      
      const withinBudget = result.final_cost <= 2.0;
      const meetsQuality = result.quality_score >= 0.9;
      const efficientExecution = result.efficiency_score > 0.8;
      
      optimizationAccuracy.add(withinBudget && meetsQuality && efficientExecution ? 1 : 0);
      budgetComplianceRate.add(withinBudget ? 1 : 0);
      
      // Check prediction accuracy for complex scenarios
      const predictionAccuracy = result.prediction_metrics.accuracy_score;
      costPredictionAccuracy.add(predictionAccuracy > 0.85 ? 1 : 0);
    } else {
      optimizationAccuracy.add(0);
      budgetComplianceRate.add(0);
      costPredictionAccuracy.add(0);
    }
  });

  group('Budget Constrained Optimization', function () {
    const response = http.post(`${baseUrl}/api/v1/optimization/budget-constrained`, JSON.stringify({
      prompts: [
        "What are the main benefits of renewable energy?",
        "Explain the basics of machine learning",
        "Describe the process of photosynthesis",
        "What factors influence stock market prices?",
        "How does blockchain technology work?"
      ],
      total_budget: 0.25,
      minimum_quality: 0.75,
      optimization_mode: "maximize_quality_within_budget",
      distribution_strategy: "adaptive",
      benchmark_mode: true
    }), {
      headers: camTestUtils.getAuthHeaders(apiToken),
    });

    const success = check(response, {
      'status is 200': (r) => r.status === 200,
      'budget not exceeded': (r) => {
        const result = JSON.parse(r.body);
        return result.total_cost <= 0.25;
      },
      'minimum quality maintained': (r) => {
        const result = JSON.parse(r.body);
        return result.average_quality >= 0.75;
      },
      'all prompts processed': (r) => {
        const result = JSON.parse(r.body);
        return result.processed_prompts === 5;
      },
      'efficient distribution': (r) => {
        const result = JSON.parse(r.body);
        return result.distribution_efficiency > 0.8;
      },
    });

    if (success && response.status === 200) {
      const result = JSON.parse(response.body);
      
      // Budget constraint compliance
      const budgetCompliance = result.total_cost <= 0.25;
      budgetComplianceRate.add(budgetCompliance ? 1 : 0);
      
      // Quality and efficiency optimization
      const qualityMaintained = result.average_quality >= 0.75;
      const efficientDistribution = result.distribution_efficiency > 0.8;
      optimizationAccuracy.add(budgetCompliance && qualityMaintained && efficientDistribution ? 1 : 0);
      
      // Calculate savings from optimal distribution
      const theoreticalCost = result.baseline_total_cost;
      const actualCost = result.total_cost;
      const savingsPercentage = ((theoreticalCost - actualCost) / theoreticalCost) * 100;
      costSavingsRate.add(savingsPercentage);
      
      // Prediction accuracy for batch optimization
      const batchPredictionAccuracy = result.batch_prediction_accuracy;
      costPredictionAccuracy.add(batchPredictionAccuracy > 0.8 ? 1 : 0);
    } else {
      optimizationAccuracy.add(0);
      budgetComplianceRate.add(0);
      costPredictionAccuracy.add(0);
    }
  });
}

export function handleSummary(data) {
  return {
    'cost-optimization-benchmark-results.json': JSON.stringify(data, null, 2),
    'cost-optimization-benchmark-summary.txt': camTestUtils.generateTextSummary(data, 'Cost Optimization Benchmark'),
  };
}
