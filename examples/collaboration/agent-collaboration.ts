/**
 * Agent Collaboration Example - IACP functionality
 * 
 * This example demonstrates the new collaboration capabilities
 * that extend the Complete Arbitration Mesh platform.
 */

import { CompleteArbitrationMesh } from '../src/index.js';
import type { 
  CollaborationRequest, 
  ComplexTask, 
  CollaborationWorkflow,
  WorkflowStep 
} from '../src/shared/types.js';

async function agentCollaborationExample() {
  // Initialize the Complete Arbitration Mesh
  const cam = new CompleteArbitrationMesh({
    apiKey: 'cam_collaboration_key_67890',
    jwtSecret: 'your-secret-key-change-in-production',
    logLevel: 'info',
    environment: 'development'
  });

  try {
    console.log('🤖 Starting agent collaboration example...\n');

    // Example 1: Simple collaboration session
    console.log('Example 1: Simple multi-agent collaboration');
    const collaborationRequest: CollaborationRequest = {
      task: 'Create a comprehensive marketing strategy for a new AI product',
      requirements: ['market-research', 'content-creation', 'data-analysis'],
      decomposition: 'auto',
      timeout: 300000 // 5 minutes
    };

    const session = await cam.initiateCollaboration(collaborationRequest);
    console.log('✅ Collaboration session created:', session.id);
    console.log('👥 Participating agents:', session.agents.length);
    console.log('📋 Task:', session.task);
    console.log();

    // Example 2: Agent discovery
    console.log('Example 2: Discover available agents');
    const requiredCapabilities = [
      {
        type: 'data-scientist',
        skills: ['machine-learning', 'statistics', 'python'],
        specializations: ['predictive-modeling'],
        quality: 0.8,
        cost: 0.1
      },
      {
        type: 'content-writer',
        skills: ['writing', 'marketing', 'seo'],
        specializations: ['technical-writing'],
        quality: 0.9,
        cost: 0.05
      }
    ];

    const availableAgents = await cam.discoverAgents(requiredCapabilities);
    console.log('🔍 Found agents:', availableAgents.length);
    
    availableAgents.forEach((agent, index) => {
      console.log(`  ${index + 1}. ${agent.name} (${agent.type})`);
      console.log(`     Skills: ${agent.capabilities.skills.join(', ')}`);
      console.log(`     Status: ${agent.status}, Reputation: ${agent.reputation}`);
    });
    console.log();

    // Example 3: Task decomposition
    console.log('Example 3: Complex task decomposition');
    const complexTask: ComplexTask = {
      id: 'task-ai-product-launch',
      description: 'Launch a new AI product including market analysis, product positioning, and go-to-market strategy',
      requirements: ['market-research', 'competitive-analysis', 'content-creation', 'campaign-design'],
      constraints: {
        budget: 50000,
        timeline: '8 weeks',
        target_audience: 'enterprise'
      },
      priority: 'high'
    };

    const taskComponents = await cam.decomposeTask(complexTask);
    console.log('🧩 Task decomposed into', taskComponents.length, 'components:');
    
    taskComponents.forEach((component, index) => {
      console.log(`  ${index + 1}. ${component.description}`);
      console.log(`     Required capabilities: ${component.requiredCapabilities.join(', ')}`);
      console.log(`     Dependencies: ${component.dependencies.length > 0 ? component.dependencies.join(', ') : 'None'}`);
      console.log(`     Estimated duration: ${component.estimatedDuration / 1000}s`);
    });
    console.log();

    // Example 4: Workflow orchestration
    console.log('Example 4: Orchestrate a complete workflow');
    
    const workflowSteps: WorkflowStep[] = [
      {
        id: 'step-1',
        type: 'task',
        agent: 'market-researcher',
        input: { topic: 'AI product market analysis' },
        dependencies: [],
        timeout: 60000
      },
      {
        id: 'step-2',
        type: 'task',
        agent: 'content-creator',
        input: { format: 'marketing-copy', target: 'enterprise' },
        dependencies: ['step-1'],
        timeout: 90000
      },
      {
        id: 'step-3',
        type: 'decision',
        agent: 'strategy-advisor',
        input: { criteria: 'market-fit', threshold: 0.8 },
        dependencies: ['step-1', 'step-2'],
        timeout: 30000
      }
    ];

    const workflow: CollaborationWorkflow = {
      id: 'workflow-product-launch',
      name: 'AI Product Launch Workflow',
      steps: workflowSteps,
      agents: ['market-researcher', 'content-creator', 'strategy-advisor'],
      timeout: 300000,
      metadata: {
        priority: 'high',
        category: 'product-launch'
      }
    };

    const workflowResult = await cam.orchestrateWorkflow(workflow);
    console.log('🎯 Workflow completed successfully!');
    console.log('📊 Result summary:', workflowResult.result);
    console.log('👥 Participating agents:', workflowResult.participatingAgents.join(', '));
    console.log('⏱️ Total duration:', workflowResult.metadata.duration + 'ms');
    console.log('💰 Total cost: $' + workflowResult.metadata.cost.toFixed(3));
    console.log('⭐ Quality score:', workflowResult.metadata.quality);
    console.log();

    // Example 5: Execution path analysis
    console.log('Example 5: Execution path details');
    console.log('📈 Execution steps:');
    workflowResult.executionPath.forEach((step, index) => {
      console.log(`  ${index + 1}. ${step.stepId} by ${step.agent}`);
      console.log(`     Status: ${step.status}`);
      console.log(`     Duration: ${new Date(step.endTime).getTime() - new Date(step.startTime).getTime()}ms`);
      console.log(`     Output: ${step.output}`);
    });
    console.log();

    console.log('🎉 Agent collaboration examples completed successfully!');

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
  agentCollaborationExample().catch(console.error);
}

export { agentCollaborationExample };
