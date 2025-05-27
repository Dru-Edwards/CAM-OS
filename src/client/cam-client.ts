/**
 * Unified client for the Complete Arbitration Mesh
 * Provides a simple interface for both routing and collaboration functionality
 */

import { Logger } from '../shared/logger';
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
  MetricsQuery,
  MetricsData,
  AuthToken
} from '../shared/types';

export interface CAMClientOptions {
  apiKey: string;
  endpoint?: string;
  timeout?: number;
  retries?: number;
  logger?: Logger;
}

export class CAMClient {
  private apiKey: string;
  private endpoint: string;
  private timeout: number;
  private retries: number;
  private logger: Logger;

  constructor(options: CAMClientOptions) {
    this.apiKey = options.apiKey;
    this.endpoint = options.endpoint || 'https://api.complete-cam.com';
    this.timeout = options.timeout || 30000;
    this.retries = options.retries || 3;
    this.logger = options.logger || new Logger('info');
  }

  // =========================================================================
  // CAM Core Methods (Routing) - Backward Compatible
  // =========================================================================

  /**
   * Route a request to the optimal AI provider
   * This maintains 100% backward compatibility with original CAM
   */
  async routeRequest(request: AICoreRequest): Promise<AICoreResponse> {
    this.logger.debug('Routing request', { request });

    const response = await this.makeRequest<AICoreResponse>('POST', '/v2/route', {
      ...request,
      timestamp: new Date().toISOString()
    });

    this.logger.info('Request routed successfully', {
      provider: response.provider,
      latency: response.latency,
      cost: response.cost
    });

    return response;
  }

  /**
   * Get optimal provider without making a request
   */
  async getOptimalProvider(requirements: ProviderRequirements): Promise<ProviderInfo> {
    return this.makeRequest<ProviderInfo>('POST', '/v2/providers/optimal', requirements);
  }

  /**
   * List available providers
   */
  async listProviders(): Promise<ProviderInfo[]> {
    return this.makeRequest<ProviderInfo[]>('GET', '/v2/providers');
  }

  // =========================================================================
  // IACP Methods (Collaboration) - New Functionality
  // =========================================================================

  /**
   * Initiate a collaboration session
   */
  async initiateCollaboration(request: CollaborationRequest): Promise<CollaborationSession> {
    this.logger.debug('Initiating collaboration', { request });

    const session = await this.makeRequest<CollaborationSession>('POST', '/v2/collaboration/initiate', {
      ...request,
      timestamp: new Date().toISOString()
    });

    this.logger.info('Collaboration initiated', {
      sessionId: session.id,
      agentCount: session.agents.length
    });

    return session;
  }

  /**
   * Discover available agents
   */
  async discoverAgents(capabilities: AgentCapabilities[]): Promise<AgentInfo[]> {
    return this.makeRequest<AgentInfo[]>('POST', '/v2/collaboration/agents/discover', {
      capabilities,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Decompose a complex task
   */
  async decomposeTask(task: ComplexTask): Promise<TaskComponents[]> {
    return this.makeRequest<TaskComponents[]>('POST', '/v2/collaboration/tasks/decompose', {
      task,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Execute a collaboration workflow
   */
  async executeWorkflow(workflow: CollaborationWorkflow): Promise<CollaborationResult> {
    this.logger.debug('Executing workflow', { workflowId: workflow.id });

    const result = await this.makeRequest<CollaborationResult>('POST', '/v2/collaboration/workflows/execute', {
      workflow,
      timestamp: new Date().toISOString()
    });

    this.logger.info('Workflow executed', {
      workflowId: workflow.id,
      duration: result.metadata.duration,
      participatingAgents: result.participatingAgents.length
    });

    return result;
  }

  /**
   * Get collaboration session status
   */
  async getCollaborationStatus(sessionId: string): Promise<CollaborationSession> {
    return this.makeRequest<CollaborationSession>('GET', `/v2/collaboration/sessions/${sessionId}`);
  }

  // =========================================================================
  // Shared Methods
  // =========================================================================

  /**
   * Get system metrics
   */
  async getMetrics(query: MetricsQuery): Promise<MetricsData> {
    return this.makeRequest<MetricsData>('POST', '/v2/metrics', query);
  }

  /**
   * Get system health status
   */
  async getHealth(): Promise<{ status: string; details: any }> {
    return this.makeRequest('GET', '/v2/health');
  }

  /**
   * Validate API connection
   */
  async validateConnection(): Promise<{ valid: boolean; message: string }> {
    try {
      const health = await this.getHealth();
      return {
        valid: health.status === 'healthy',
        message: health.status === 'healthy' ? 'Connection successful' : 'Service degraded'
      };
    } catch (error) {
      return {
        valid: false,
        message: `Connection failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }
  }

  // =========================================================================
  // Private Helper Methods
  // =========================================================================

  private async makeRequest<T>(method: string, path: string, data?: any): Promise<T> {
    const url = `${this.endpoint}${path}`;
    let lastError: Error | null = null;

    for (let attempt = 0; attempt < this.retries; attempt++) {
      try {
        const response = await this.executeRequest(method, url, data);
        return response;
      } catch (error) {
        lastError = error instanceof Error ? error : new Error('Unknown error');
        
        if (attempt < this.retries - 1) {
          const delay = Math.pow(2, attempt) * 1000; // Exponential backoff
          this.logger.warn(`Request failed, retrying in ${delay}ms`, { attempt: attempt + 1, error: lastError.message });
          await this.sleep(delay);
        }
      }
    }

    this.logger.error('Request failed after all retries', { error: lastError });
    throw lastError;
  }

  private async executeRequest<T>(method: string, url: string, data?: any): Promise<T> {
    const headers: Record<string, string> = {
      'Authorization': `Bearer ${this.apiKey}`,
      'Content-Type': 'application/json',
      'User-Agent': 'CAM-Client/2.0.0',
      'X-API-Version': '2.0'
    };

    const requestOptions: RequestInit = {
      method,
      headers,
      signal: AbortSignal.timeout(this.timeout)
    };

    if (data && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
      requestOptions.body = JSON.stringify(data);
    }

    this.logger.debug('Making HTTP request', { method, url, hasData: !!data });

    const response = await fetch(url, requestOptions);

    if (!response.ok) {
      const errorText = await response.text();
      let errorData;
      
      try {
        errorData = JSON.parse(errorText);
      } catch {
        errorData = { message: errorText };
      }

      const error = new Error(`HTTP ${response.status}: ${errorData.message || response.statusText}`);
      (error as any).status = response.status;
      (error as any).data = errorData;
      
      throw error;
    }

    const result = await response.json();
    this.logger.debug('HTTP request successful', { status: response.status });
    
    return result;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
