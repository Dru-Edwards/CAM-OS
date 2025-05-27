/**
 * Complete Arbitration Mesh - Core Integration
 * 
 * This is the main class that integrates the routing system (CAM Core) with
 * the Inter-Agent Collaboration Protocol (IACP) to provide a unified platform
 * for both intelligent request routing and sophisticated multi-agent collaboration.
 */

import { FastPathRouter } from '../routing/fastpath-router.js';
import { CollaborationEngine } from '../collaboration/collaboration-engine.js';
import { StateManager } from './state-manager.js';
import { AuthenticationService } from './auth-service.js';
import { Logger } from '../shared/logger.js';
import { Config } from '../shared/config.js';
import type {
  AICoreRequest,
  AICoreResponse,
  CollaborationRequest,
  CollaborationSession,
  AgentCapabilities,
  AgentInfo,
  ComplexTask,
  TaskComponents,
  CollaborationWorkflow,
  CollaborationResult,
  ProviderRequirements,
  ProviderInfo,
  PolicyValidationRequest,
  PolicyValidationResult,
  ConfigurationUpdate,
  ConfigurationResult,
  MetricsQuery,
  MetricsData
} from '../shared/types';

export interface CompleteArbitrationMeshOptions {
  apiKey: string;
  endpoint?: string;
  jwtSecret?: string;
  tokenExpiry?: string;
  logLevel?: 'debug' | 'info' | 'warn' | 'error';
  environment?: 'development' | 'staging' | 'production';
}

export class CompleteArbitrationMesh {
  private fastPathRouter: FastPathRouter;
  private collaborationEngine: CollaborationEngine;
  private stateManager: StateManager;
  private authService: AuthenticationService;
  private logger: Logger;
  private config: Config;

  constructor(options: CompleteArbitrationMeshOptions) {
    this.config = new Config({
      logLevel: options.logLevel || 'info',
      environment: options.environment || 'development',
      apiVersion: '2.0.0'
    });
    
    this.logger = new Logger('CompleteArbitrationMesh');
      this.stateManager = new StateManager();
    this.authService = new AuthenticationService({ 
      jwtSecret: options.jwtSecret || 'default-secret-change-in-production',
      tokenExpiry: options.tokenExpiry || '24h'
    });
    
    this.fastPathRouter = new FastPathRouter();
    this.collaborationEngine = new CollaborationEngine();

    this.logger.info('Complete Arbitration Mesh initialized successfully');
  }

  // =========================================================================
  // CAM Core Functionality (Routing)
  // =========================================================================

  /**
   * Route a request to the optimal AI provider based on policies and requirements
   * This is the core CAM Classic functionality preserved from the original system
   */
  async routeRequest(request: AICoreRequest): Promise<AICoreResponse> {
    this.logger.debug('Routing request through FastPath system', { request });
    
    try {
      const result = await this.fastPathRouter.routeRequest(request);
        this.logger.info('Request routed successfully', {
        provider: result.provider,
        latency: result.metadata?.['latency'] || result.latency,
        cost: result.metadata?.['cost'] || result.cost
      });
      
      return result;
    } catch (error) {
      this.logger.error('Request routing failed', { error, request });
      throw error;
    }
  }

  /**
   * Get the optimal provider for given requirements without making a request
   */
  async getOptimalProvider(requirements: ProviderRequirements): Promise<ProviderInfo> {
    return this.fastPathRouter.getOptimalProvider(requirements);
  }

  /**
   * Validate a request against current policies
   */
  async validatePolicy(request: PolicyValidationRequest): Promise<PolicyValidationResult> {
    return this.fastPathRouter.validatePolicy(request);
  }

  // =========================================================================
  // IACP Functionality (Collaboration)
  // =========================================================================

  /**
   * Initiate a collaboration session between multiple agents
   * This is the new IACP functionality that extends the platform
   */
  async initiateCollaboration(request: CollaborationRequest): Promise<CollaborationSession> {
    this.logger.debug('Initiating collaboration session', { request });
    
    try {
      const session = await this.collaborationEngine.initiateCollaboration(request);
      
      this.logger.info('Collaboration session initiated successfully', {
        sessionId: session.id,
        agentCount: session.agents.length,
        taskType: request.task
      });
      
      return session;
    } catch (error) {
      this.logger.error('Collaboration initiation failed', { error, request });
      throw error;
    }
  }

  /**
   * Discover available agents based on required capabilities
   */
  async discoverAgents(capabilities: AgentCapabilities[]): Promise<AgentInfo[]> {
    return this.collaborationEngine.discoverAgents(capabilities);
  }

  /**
   * Decompose a complex task into manageable components
   */
  async decomposeTask(task: ComplexTask): Promise<TaskComponents[]> {
    return this.collaborationEngine.decomposeTask(task);
  }

  /**
   * Orchestrate a complete collaboration workflow
   */
  async orchestrateWorkflow(workflow: CollaborationWorkflow): Promise<CollaborationResult> {
    this.logger.debug('Orchestrating collaboration workflow', { workflow });
    
    try {
      const result = await this.collaborationEngine.orchestrateWorkflow(workflow);
      
      this.logger.info('Workflow orchestration completed', {
        workflowId: workflow.id,
        duration: result.metadata?.duration,
        agentCount: result.participatingAgents.length
      });
      
      return result;
    } catch (error) {
      this.logger.error('Workflow orchestration failed', { error, workflow });
      throw error;
    }
  }

  // =========================================================================
  // Shared Functionality
  // =========================================================================
  /**
   * Update system configuration
   */
  async manageConfiguration(config: ConfigurationUpdate): Promise<ConfigurationResult> {
    this.logger.debug('Updating configuration', { config });
    
    try {
      const result = await this.stateManager.updateConfiguration(config);
      
      // Update internal configuration
      if (config.logLevel) {
        this.config.update({ logLevel: config.logLevel });
      }
      
      this.logger.info('Configuration updated successfully', { result });
      return result;
    } catch (error) {
      this.logger.error('Configuration update failed', { error, config });
      throw error;
    }
  }

  /**
   * Get system metrics and telemetry data
   */
  async getMetrics(metricsRequest: MetricsQuery): Promise<MetricsData> {
    return this.stateManager.getMetrics(metricsRequest);
  }

  /**
   * Get current system health status
   */
  async getHealthStatus(): Promise<{ status: 'healthy' | 'degraded' | 'unhealthy'; details: any }> {
    const routingHealth = await this.fastPathRouter.getHealthStatus();
    const collaborationHealth = await this.collaborationEngine.getHealthStatus();
    const stateHealth = await this.stateManager.getHealthStatus();

    const allHealthy = [routingHealth, collaborationHealth, stateHealth].every(h => h.status === 'healthy');
    const anyUnhealthy = [routingHealth, collaborationHealth, stateHealth].some(h => h.status === 'unhealthy');

    const overallStatus = anyUnhealthy ? 'unhealthy' : allHealthy ? 'healthy' : 'degraded';

    return {
      status: overallStatus,
      details: {
        routing: routingHealth,
        collaboration: collaborationHealth,
        state: stateHealth,
        timestamp: new Date().toISOString()
      }
    };
  }

  /**
   * Gracefully shutdown the system
   */
  async shutdown(): Promise<void> {
    this.logger.info('Initiating graceful shutdown');
    
    try {
      await Promise.all([
        this.fastPathRouter.shutdown(),
        this.collaborationEngine.shutdown(),
        this.stateManager.shutdown()
      ]);
      
      this.logger.info('Complete Arbitration Mesh shutdown completed');
    } catch (error) {
      this.logger.error('Error during shutdown', { error });
      throw error;
    }
  }
}
