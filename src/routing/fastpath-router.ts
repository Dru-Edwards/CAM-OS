/**
 * FastPath Router - Core routing engine from original CAM system
 * This preserves all the original CAM routing functionality
 */

import { Logger } from '../shared/logger.js';
import { CAMError } from '../shared/errors.js';
import type {
  AICoreRequest,
  AICoreResponse,
  ProviderRequirements,
  ProviderInfo,
  PolicyValidationRequest,
  PolicyValidationResult
} from '../shared/types.js';
import type { ProviderConfig } from '../shared/config.js';
import fs from 'fs';
import path from 'path';
import fetch from 'node-fetch';

export class FastPathRouter {
  private logger: Logger;
  private providerConfigs: Record<string, ProviderConfig> = {};
  constructor() {
    this.logger = new Logger('info'); // Initialize with a valid LogLevel
    this.logger.info('FastPath Router initialized');
  }

  async routeRequest(request: AICoreRequest): Promise<AICoreResponse> {
    this.logger.debug('FastPath routing request', { request });

    try {
      // 1. Validate the request
      await this.validateRequest(request);      // 2. Apply policies
      const policyResult = await this.applyPolicies(request);
      if (!policyResult.allowed) {
        throw new CAMError('POLICY_VIOLATION', `Policy violation: ${policyResult.reason}`);
      }

      // 3. Select optimal provider
      const provider = await this.selectProvider(request.requirements || {});

      // 4. Route to provider
      const response = await this.executeRequest(request, provider);

      // 5. Record metrics
      await this.recordMetrics(request, response, provider);

      return response;
    } catch (error) {
      this.logger.error('FastPath routing failed', { error, request });
      throw error;
    }
  }

  async getOptimalProvider(requirements: ProviderRequirements): Promise<ProviderInfo> {
    this.logger.debug('Getting optimal provider', { requirements });

    // Get all available providers
    const providers = await this.getAvailableProviders();
    
    if (providers.length === 0) {
      throw new CAMError('NO_PROVIDERS_AVAILABLE', 'No AI providers are currently available');
    }

    // Filter providers based on requirements
    let eligibleProviders = providers.filter((provider: ProviderInfo) => {
      // Filter by status - only use available or degraded providers
      if (provider.status === 'unavailable') return false;
      
      // Filter by region if specified
      if (requirements.region && !provider.regions.includes(requirements.region)) return false;
      
      // Filter by capabilities if specified
      if (requirements.capabilities && requirements.capabilities.length > 0) {
        const hasAllCapabilities = requirements.capabilities.every(cap => 
          provider.capabilities.includes(cap)
        );
        if (!hasAllCapabilities) return false;
      }
      
      return true;
    });

    if (eligibleProviders.length === 0) {
      throw new CAMError('NO_MATCHING_PROVIDERS', 'No providers match the specified requirements');
    }

    // Apply scoring based on cost and performance requirements
    const scoredProviders = eligibleProviders.map((provider: ProviderInfo) => {
      let score = 0;
      
      // Cost scoring
      if (requirements.cost === 'minimize') {
        // Prioritize lowest cost
        const costFactor = 1 - ((provider.pricing.inputTokens + provider.pricing.outputTokens) / 0.1); // Normalize to 0-1 range
        score += costFactor * 3; // Higher weight for cost minimization
      } else if (requirements.cost === 'optimize') {
        // Balance cost and quality
        const costFactor = 1 - ((provider.pricing.inputTokens + provider.pricing.outputTokens) / 0.1);
        score += costFactor * 2;
      } else if (requirements.cost === 'performance') {
        // Cost is less important
        const costFactor = 1 - ((provider.pricing.inputTokens + provider.pricing.outputTokens) / 0.1);
        score += costFactor * 1;
      }
      
      // Performance scoring
      // For now, we use a simple heuristic based on provider type
      // In a real implementation, this would use historical performance data
      if (requirements.performance === 'fast') {
        // Prioritize speed
        if (provider.type === 'anthropic') score += 1;
        if (provider.type === 'openai') score += 2;
      } else if (requirements.performance === 'balanced') {
        // Balance speed and quality
        if (provider.type === 'anthropic') score += 2;
        if (provider.type === 'openai') score += 2;
        if (provider.type === 'google') score += 2;
      } else if (requirements.performance === 'quality') {
        // Prioritize quality
        if (provider.type === 'anthropic') score += 3;
        if (provider.type === 'openai' && provider.models.includes('gpt-4')) score += 3;
        if (provider.type === 'google') score += 2;
      }
      
      // Status adjustment - slightly penalize degraded services
      if (provider.status === 'degraded') score *= 0.9;
      
      return { provider, score };
    });

    // Sort by score (highest first) and return the best provider
    scoredProviders.sort((a: {provider: ProviderInfo, score: number}, b: {provider: ProviderInfo, score: number}) => b.score - a.score);
    
    if (scoredProviders.length === 0) {
      throw new CAMError('NO_ELIGIBLE_PROVIDERS', 'No providers match the specified requirements');
    }
    
    // We know scoredProviders has at least one element because we checked length > 0
    // Using non-null assertion operator to inform TypeScript that this is guaranteed to exist
    const selectedProvider = scoredProviders[0]!.provider;
    const topScore = scoredProviders[0]!.score;
    
    this.logger.info('Selected optimal provider', { 
      providerId: selectedProvider.id, 
      score: topScore,
      requirements
    });
    
    return selectedProvider;
  }

  async validatePolicy(request: PolicyValidationRequest): Promise<PolicyValidationResult> {
    this.logger.debug('Validating policy', { request });

    try {
      // Get applicable policies for this request
      const applicablePolicies = await this.getApplicablePolicies(request);
      
      if (applicablePolicies.length === 0) {
        // No policies apply, default to allow
        return {
          allowed: true,
          policies: ['default-allow'],
          reason: 'No applicable policies found, default allow'
        };
      }
      
      // Evaluate each policy
      const evaluationResults = await Promise.all(
        applicablePolicies.map(policy => this.evaluatePolicy(request, policy))
      );
      
      // Check if any policy denies the request
      const deniedResults = evaluationResults.filter(result => !result.allowed);
      
      if (deniedResults.length > 0) {
        // Request is denied by at least one policy
        // We know deniedResults has at least one element because we checked length > 0
        // Using non-null assertion operator to inform TypeScript that this is guaranteed to exist
        const primaryDenial = deniedResults[0]!;
        return {
          allowed: false,
          policies: evaluationResults.map(result => result.policy),
          reason: `Policy violation: ${primaryDenial.reason}`
        };
      }
      
      // All policies allow the request
      return {
        allowed: true,
        policies: evaluationResults.map(result => result.policy),
        reason: 'Request complies with all applicable policies'
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.logger.error('Policy validation failed', { error: errorMessage, request });
      
      // Default to deny on error for security
      return {
        allowed: false,
        policies: ['error-handler'],
        reason: `Policy validation error: ${errorMessage}`
      };
    }
  }

  /**
   * Get health status of the routing system
   */
  async getHealthStatus(): Promise<any> {
    try {
      return {
        status: 'healthy',
        component: 'fastpath_router',
        timestamp: new Date().toISOString(),
        details: {
          providersAvailable: 3, // Mock data
          averageLatency: 150,
          errorRate: 0.01
        }
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        component: 'fastpath_router',
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString()
      };
    }
  }

  /**
   * Shutdown the router
   */
  async shutdown(): Promise<void> {
    this.logger.info('FastPath Router shutting down');
    // Cleanup logic would go here
  }
  private async validateRequest(request: AICoreRequest): Promise<void> {
    if (!request.prompt || typeof request.prompt !== 'string') {
      throw new CAMError('INVALID_REQUEST', 'Invalid request: prompt is required');
    }
  }

  private async applyPolicies(request: AICoreRequest): Promise<PolicyValidationResult> {
    // Convert AICoreRequest to PolicyValidationRequest
    const policyRequest: PolicyValidationRequest = {
      request: request,
      userId: request.metadata && request.metadata['userId'] ? request.metadata['userId'] as string : 'anonymous',
      context: {
        resourceId: request.metadata && request.metadata['resourceId'] ? request.metadata['resourceId'] as string : 'default',
        action: 'generate',
        content: request.prompt,
        ...request.metadata || {}
      }
    };
    
    // Validate against policies
    return await this.validatePolicy(policyRequest);
  }
  
  /**
   * Get applicable policies for a request
   */
  private async getApplicablePolicies(request: PolicyValidationRequest): Promise<string[]> {
    // In a real implementation, this would query a policy database or service
    // For now, return a set of default policies based on request type
    
    const defaultPolicies = ['content-safety'];
    
    // Add specific policies based on request type
    if (request.request.metadata && request.request.metadata['requestType'] === 'ai_completion') {
      defaultPolicies.push('token-quota');
      defaultPolicies.push('prompt-safety');
    }
    
    // Add compliance policies if needed
    if (request.context && request.context['compliance']) {
      const complianceRequirements = request.context['compliance'] as string[];
      if (complianceRequirements.includes('gdpr')) {
        defaultPolicies.push('gdpr-compliance');
      }
      if (complianceRequirements.includes('hipaa')) {
        defaultPolicies.push('hipaa-compliance');
      }
    }
    
    return defaultPolicies;
  }
  
  /**
   * Evaluate a specific policy against a request
   */
  private async evaluatePolicy(request: PolicyValidationRequest, policy: string): Promise<{
    policy: string;
    allowed: boolean;
    reason: string;
  }> {
    // In a real implementation, this would use a policy engine like OPA
    // For now, implement simple policy checks
    
    switch (policy) {
      case 'content-safety':
        // Check for prohibited content in the request
        const content = request.request.prompt;
        if (content && this.containsProhibitedContent(content)) {
          return {
            policy,
            allowed: false,
            reason: 'Content contains prohibited material'
          };
        }
        break;
        
      case 'token-quota':
        // Check if user has exceeded their token quota
        if (request.context && request.context['userTokenUsage']) {
          const usage = request.context['userTokenUsage'] as number;
          const quota = request.context['userTokenQuota'] as number || 1000000;
          
          if (usage > quota) {
            return {
              policy,
              allowed: false,
              reason: 'Token quota exceeded'
            };
          }
        }
        break;
        
      case 'gdpr-compliance':
        // Check for PII processing compliance
        if (request.context && request.context['containsPII'] && 
            !(request.context['piiConsent'] as boolean)) {
          return {
            policy,
            allowed: false,
            reason: 'GDPR compliance: PII processing requires explicit consent'
          };
        }
        break;
        
      case 'hipaa-compliance':
        // Check for PHI processing compliance
        if (request.context && request.context['containsPHI'] && 
            !(request.context['hipaaAuthorization'] as boolean)) {
          return {
            policy,
            allowed: false,
            reason: 'HIPAA compliance: PHI processing requires authorization'
          };
        }
        break;
    }
    
    // Default to allow if no specific violation found
    return {
      policy,
      allowed: true,
      reason: `Policy ${policy} check passed`
    };
  }
  
  /**
   * Check if content contains prohibited material
   * This is a simple implementation - a real one would use more sophisticated content filtering
   */
  private containsProhibitedContent(content: string): boolean {
    const prohibitedTerms = [
      'illegal activities',
      'child exploitation',
      'terrorism',
      'self-harm instructions',
      'hate speech'
    ];
    
    return prohibitedTerms.some(term => 
      content.toLowerCase().includes(term.toLowerCase())
    );
  }

  private async selectProvider(requirements: ProviderRequirements): Promise<ProviderInfo> {
    // Implement sophisticated provider selection logic
    // including cost optimization, performance requirements, availability, and load balancing
    return await this.getOptimalProvider(requirements);
  }

  private loadProviderConfigs(): void {
    if (Object.keys(this.providerConfigs).length > 0) return;

    const envConfig = process.env['CAM_PROVIDER_CONFIG'];
    if (envConfig) {
      try {
        const parsed = JSON.parse(envConfig) as ProviderConfig[];
        parsed.forEach(p => {
          if (p.enabled) this.providerConfigs[p.id] = p;
        });
      } catch (err) {
        this.logger.warn('Failed to parse CAM_PROVIDER_CONFIG', { error: err });
      }
    }

    if (Object.keys(this.providerConfigs).length === 0) {
      const filePath = process.env['CAM_PROVIDER_CONFIG_FILE'] || path.resolve('providers.json');
      if (fs.existsSync(filePath)) {
        try {
          const fileData = fs.readFileSync(filePath, 'utf-8');
          const parsed = JSON.parse(fileData) as ProviderConfig[];
          parsed.forEach(p => {
            if (p.enabled) this.providerConfigs[p.id] = p;
          });
        } catch (err) {
          this.logger.warn('Failed to load provider config file', { error: err });
        }
      }
    }
  }

  /**
   * Get all available AI providers from the provider registry
   * In a real implementation, this would query a database or service registry
   */
  private async getAvailableProviders(): Promise<ProviderInfo[]> {
    this.loadProviderConfigs();
    return Object.values(this.providerConfigs).map(cfg => ({
      id: cfg.id,
      name: cfg.id,
      type: cfg.type as any,
      models: (cfg as any).models || [],
      pricing: (cfg as any).pricing || { inputTokens: 0, outputTokens: 0, currency: 'USD' },
      capabilities: (cfg as any).capabilities || [],
      regions: (cfg as any).regions || [],
      status: cfg.enabled ? 'available' : 'unavailable'
    }));
  }

  private async executeRequest(request: AICoreRequest, provider: ProviderInfo): Promise<AICoreResponse> {
    this.logger.debug('Executing request with provider', { providerId: provider.id, request });
    
    const startTime = Date.now();
    let response: AICoreResponse;
    
    try {
      // Select the model to use - either the one specified in the request or the first available model
      const model = request.model && provider.models.includes(request.model) 
        ? request.model 
        : provider.models[0] || 'default-model';
      
      // Execute the request based on the provider type
      switch (provider.type) {
        case 'openai':
          response = await this.executeOpenAIRequest(request, provider, model);
          break;
        case 'anthropic':
          response = await this.executeAnthropicRequest(request, provider, model);
          break;
        case 'google':
          response = await this.executeGoogleRequest(request, provider, model);
          break;
        case 'azure':
          response = await this.executeAzureRequest(request, provider, model);
          break;
        default:
          throw new CAMError('UNSUPPORTED_PROVIDER', `Provider type ${provider.type} is not supported`);
      }
      
      const endTime = Date.now();
      const latency = endTime - startTime;
      
      // Add latency and cost information to the response
      response.latency = latency;
      
      // Calculate cost based on token usage and provider pricing
      const inputCost = (response.usage.promptTokens / 1000) * provider.pricing.inputTokens;
      const outputCost = (response.usage.completionTokens / 1000) * provider.pricing.outputTokens;
      response.cost = inputCost + outputCost;
      
      this.logger.info('Request executed successfully', {
        providerId: provider.id,
        model,
        latency,
        cost: response.cost,
        tokens: response.usage.totalTokens
      });
      
      return response;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.logger.error('Failed to execute request', { providerId: provider.id, error: errorMessage });
      
      // Fallback to a simulated response in case of error
      const endTime = Date.now();
      const latency = endTime - startTime;
      const model = provider.models[0] || 'default-model';
      
      return {
        content: `Error from ${provider.name}: ${errorMessage}. Fallback response for: ${request.prompt}`,
        provider: provider.id,
        model,
        usage: {
          promptTokens: Math.floor(request.prompt.length / 4),
          completionTokens: 50,
          totalTokens: Math.floor(request.prompt.length / 4) + 50
        },
        cost: 0.001, // Minimal cost for failed request
        latency,
        metadata: {
          provider: provider.name,
          timestamp: new Date().toISOString(),
          error: errorMessage,
          fallback: true
        }
      };
    }
  }
  
  /**
   * Execute a request with OpenAI
   * In a real implementation, this would use the OpenAI SDK
   */
  private async executeOpenAIRequest(request: AICoreRequest, provider: ProviderInfo, model: string): Promise<AICoreResponse> {
    const cfg = this.providerConfigs[provider.id];
    if (!cfg) throw new CAMError('CONFIG_NOT_FOUND', `Missing configuration for provider ${provider.id}`);

    const endpoint = cfg.endpoint || 'https://api.openai.com/v1/chat/completions';

    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${cfg.apiKey}`
        },
        body: JSON.stringify({
          model,
          messages: [{ role: 'user', content: request.prompt }],
          temperature: request.temperature ?? 0.7,
          max_tokens: request.maxTokens
        })
      });      const data = await res.json() as any;
      if (!res.ok) {
        throw new CAMError('PROVIDER_ERROR', data.error?.message || 'OpenAI request failed');
      }

      return {
        content: data.choices?.[0]?.message?.content || '',
        provider: provider.id,
        model,
        usage: {
          promptTokens: data.usage?.prompt_tokens || 0,
          completionTokens: data.usage?.completion_tokens || 0,
          totalTokens: data.usage?.total_tokens || 0
        },
        latency: 0,
        cost: 0,
        metadata: {
          provider: provider.name,
          timestamp: new Date().toISOString()
        }
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new CAMError('PROVIDER_ERROR', message);
    }
  }
  
  /**
   * Execute a request with Anthropic
   * In a real implementation, this would use the Anthropic SDK
   */
  private async executeAnthropicRequest(request: AICoreRequest, provider: ProviderInfo, model: string): Promise<AICoreResponse> {
    const cfg = this.providerConfigs[provider.id];
    if (!cfg) throw new CAMError('CONFIG_NOT_FOUND', `Missing configuration for provider ${provider.id}`);

    const endpoint = cfg.endpoint || 'https://api.anthropic.com/v1/messages';

    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': cfg.apiKey,
          'anthropic-version': '2023-06-01'
        },
        body: JSON.stringify({
          model,
          messages: [{ role: 'user', content: request.prompt }],
          temperature: request.temperature ?? 0.7,
          max_tokens: request.maxTokens
        })
      });      const data = await res.json() as any;
      if (!res.ok) {
        throw new CAMError('PROVIDER_ERROR', data.error?.message || 'Anthropic request failed');
      }

      const content = Array.isArray(data.content) ? data.content.map((p: any) => p.text).join(' ') : data.content?.[0]?.text || '';

      return {
        content,
        provider: provider.id,
        model,
        usage: {
          promptTokens: data.usage?.input_tokens || 0,
          completionTokens: data.usage?.output_tokens || 0,
          totalTokens: (data.usage?.input_tokens || 0) + (data.usage?.output_tokens || 0)
        },
        latency: 0,
        cost: 0,
        metadata: {
          provider: provider.name,
          timestamp: new Date().toISOString()
        }
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new CAMError('PROVIDER_ERROR', message);
    }
  }
  
  /**
   * Execute a request with Google
   * In a real implementation, this would use the Google Gemini API
   */
  private async executeGoogleRequest(request: AICoreRequest, provider: ProviderInfo, model: string): Promise<AICoreResponse> {
    const cfg = this.providerConfigs[provider.id];
    if (!cfg) throw new CAMError('CONFIG_NOT_FOUND', `Missing configuration for provider ${provider.id}`);

    const urlBase = cfg.endpoint || 'https://generativelanguage.googleapis.com/v1beta';
    const url = `${urlBase}/models/${model}:generateContent?key=${cfg.apiKey}`;

    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: request.prompt }] }],
          temperature: request.temperature ?? 0.7,
          generationConfig: { maxOutputTokens: request.maxTokens }
        })
      });      const data = await res.json() as any;
      if (!res.ok) {
        throw new CAMError('PROVIDER_ERROR', data.error?.message || 'Google request failed');
      }

      const text = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
      const usage = data.usageMetadata || {};

      return {
        content: text,
        provider: provider.id,
        model,
        usage: {
          promptTokens: usage.promptTokenCount || 0,
          completionTokens: usage.candidatesTokenCount || 0,
          totalTokens: usage.totalTokenCount || 0
        },
        latency: 0,
        cost: 0,
        metadata: { provider: provider.name, timestamp: new Date().toISOString() }
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new CAMError('PROVIDER_ERROR', message);
    }
  }
  
  /**
   * Execute a request with Azure OpenAI
   * In a real implementation, this would use the Azure OpenAI SDK
   */
  private async executeAzureRequest(request: AICoreRequest, provider: ProviderInfo, model: string): Promise<AICoreResponse> {
    const cfg = this.providerConfigs[provider.id];
    if (!cfg) throw new CAMError('CONFIG_NOT_FOUND', `Missing configuration for provider ${provider.id}`);

    const url = `${cfg.endpoint}/openai/deployments/${model}/chat/completions?api-version=2023-05-15`;

    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'api-key': cfg.apiKey
        },
        body: JSON.stringify({
          messages: [{ role: 'user', content: request.prompt }],
          temperature: request.temperature ?? 0.7,
          max_tokens: request.maxTokens
        })
      });      const data = await res.json() as any;
      if (!res.ok) {
        throw new CAMError('PROVIDER_ERROR', data.error?.message || 'Azure request failed');
      }

      return {
        content: data.choices?.[0]?.message?.content || '',
        provider: provider.id,
        model,
        usage: {
          promptTokens: data.usage?.prompt_tokens || 0,
          completionTokens: data.usage?.completion_tokens || 0,
          totalTokens: data.usage?.total_tokens || 0
        },
        latency: 0,
        cost: 0,
        metadata: {
          provider: provider.name,
          timestamp: new Date().toISOString(),
          region: request.requirements?.region || 'eastus'
        }
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new CAMError('PROVIDER_ERROR', message);
    }
  }

  private async recordMetrics(request: AICoreRequest, response: AICoreResponse, provider: ProviderInfo): Promise<void> {
    // Record metrics for monitoring and analytics
    this.logger.debug('Recording routing metrics', {
      provider: provider.id,
      latency: response.latency,
      cost: response.cost,
      tokens: response.usage.totalTokens
    });
  }
}
