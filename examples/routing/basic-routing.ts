/**
 * Basic Routing Example - CAM Classic functionality
 * 
 * This example demonstrates how to use the Complete Arbitration Mesh
 * for intelligent AI request routing, preserving all original CAM capabilities.
 */

import { CompleteArbitrationMesh } from '../src/index.js';
import type { AICoreRequest } from '../src/shared/types.js';

async function basicRoutingExample() {
  // Initialize the Complete Arbitration Mesh
  const cam = new CompleteArbitrationMesh({
    apiKey: 'cam_example_key_12345',
    jwtSecret: 'your-secret-key-change-in-production',
    logLevel: 'info',
    environment: 'development'
  });

  try {
    console.log('🚀 Starting basic routing example...\n');

    // Example 1: Simple text generation request
    console.log('Example 1: Simple text generation');
    const simpleRequest: AICoreRequest = {
      prompt: 'Explain quantum computing in simple terms',
      model: 'gpt-4',
      temperature: 0.7,
      maxTokens: 200
    };

    const response1 = await cam.routeRequest(simpleRequest);
    console.log('✅ Response:', response1.content.substring(0, 100) + '...');
    console.log('📊 Provider:', response1.provider);
    console.log('⏱️ Latency:', response1.latency + 'ms');
    console.log('💰 Cost: $' + response1.cost.toFixed(4));
    console.log();

    // Example 2: Request with specific requirements
    console.log('Example 2: Request with cost optimization');
    const costOptimizedRequest: AICoreRequest = {
      prompt: 'Write a haiku about artificial intelligence',
      requirements: {
        cost: 'minimize',
        performance: 'balanced'
      }
    };

    const response2 = await cam.routeRequest(costOptimizedRequest);
    console.log('✅ Response:', response2.content);
    console.log('📊 Provider:', response2.provider);
    console.log('💰 Cost: $' + response2.cost.toFixed(4));
    console.log();

    // Example 3: Request with compliance requirements
    console.log('Example 3: Request with compliance requirements');
    const complianceRequest: AICoreRequest = {
      prompt: 'Analyze this financial data for trends',
      requirements: {
        compliance: ['SOX', 'GDPR'],
        region: 'us-east-1'
      }
    };

    const response3 = await cam.routeRequest(complianceRequest);
    console.log('✅ Response:', response3.content.substring(0, 100) + '...');
    console.log('📊 Provider:', response3.provider);
    console.log('🛡️ Compliance verified for requirements');
    console.log();

    // Example 4: Get optimal provider without making request
    console.log('Example 4: Provider recommendation');
    const provider = await cam.getOptimalProvider({
      cost: 'optimize',
      performance: 'fast',
      capabilities: ['text-generation', 'code-generation']
    });

    console.log('🎯 Recommended provider:', provider.name);
    console.log('💲 Pricing: $' + provider.pricing.inputTokens + '/1K input tokens');
    console.log('🌍 Available regions:', provider.regions.join(', '));
    console.log();

    // Example 5: System health check
    console.log('Example 5: System health check');
    const health = await cam.getHealthStatus();
    console.log('💚 Overall status:', health.status);
    console.log('📈 Routing component:', health.details.routing.status);
    console.log();

    console.log('🎉 Basic routing examples completed successfully!');

  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    // Clean shutdown
    await cam.shutdown();
    console.log('🔒 System shutdown complete');
  }
}

// Run the example
if (import.meta.url === `file://${process.argv[1]}`) {
  basicRoutingExample().catch(console.error);
}

export { basicRoutingExample };
