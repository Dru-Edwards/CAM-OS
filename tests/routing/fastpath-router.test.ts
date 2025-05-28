import { FastPathRouter } from '../../src/routing/fastpath-router';
import { Logger } from '../../src/shared/logger';
import { LogLevel } from '../../src/shared/types';
import { CAMError } from '../../src/shared/errors';

jest.mock('../../src/shared/logger');

describe('FastPathRouter', () => {
  let router: FastPathRouter;
  let mockLogger: jest.Mocked<Logger>;

  beforeEach(() => {
    process.env.CAM_PROVIDER_CONFIG = JSON.stringify([
      {
        id: 'openai',
        type: 'openai',
        apiKey: 'test-openai',
        endpoint: 'https://api.openai.com/v1',
        models: ['gpt-4', 'gpt-3.5-turbo'],
        enabled: true,
        pricing: { inputTokens: 0.001, outputTokens: 0.002, currency: 'USD' },
        capabilities: ['text-generation'],
        regions: ['us-east-1']
      },
      {
        id: 'anthropic',
        type: 'anthropic',
        apiKey: 'test-anthropic',
        endpoint: 'https://api.anthropic.com',
        models: ['claude-3-haiku'],
        enabled: true,
        pricing: { inputTokens: 0.002, outputTokens: 0.004, currency: 'USD' },
        capabilities: ['text-generation'],
        regions: ['us-east-1']
      },
      {
        id: 'google',
        type: 'google',
        apiKey: 'test-google',
        endpoint: 'https://generativelanguage.googleapis.com/v1beta',
        models: ['gemini-pro'],
        enabled: true,
        pricing: { inputTokens: 0.003, outputTokens: 0.006, currency: 'USD' },
        capabilities: ['text-generation'],
        regions: ['us-central1']
      },
      {
        id: 'azure',
        type: 'azure',
        apiKey: 'test-azure',
        endpoint: 'https://azure.openai.com',
        models: ['gpt-4'],
        enabled: true,
        pricing: { inputTokens: 0.004, outputTokens: 0.008, currency: 'USD' },
        capabilities: ['text-generation'],
        regions: ['eastus']
      }
    ]);
    mockLogger = new Logger({ level: LogLevel.DEBUG }) as jest.Mocked<Logger>;
    router = new FastPathRouter(mockLogger);
    (global as any).fetch = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        choices: [{ message: { content: 'ok' } }],
        usage: { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 }
      })
    });
  });

  afterEach(() => {
    delete (global as any).fetch;
  });

  describe('getAvailableProviders', () => {
    it('should return a list of available providers', async () => {
      const providers = await router.getAvailableProviders();
      
      expect(providers).toBeDefined();
      expect(Array.isArray(providers)).toBe(true);
      expect(providers.length).toBeGreaterThan(0);
      
      // Check that each provider has the required fields
      providers.forEach(provider => {
        expect(provider.id).toBeDefined();
        expect(provider.name).toBeDefined();
        expect(provider.type).toBeDefined();
        expect(provider.models).toBeDefined();
        expect(provider.pricing).toBeDefined();
        expect(provider.capabilities).toBeDefined();
        expect(provider.regions).toBeDefined();
        expect(provider.status).toBeDefined();
      });
    });
  });

  describe('getOptimalProvider', () => {
    it('should select a provider based on cost requirements', async () => {
      const requirements = {
        cost: 'minimize' as const,
        performance: 'balanced' as const
      };
      
      const provider = await router.getOptimalProvider(requirements);
      
      expect(provider).toBeDefined();
      expect(provider.id).toBeDefined();
      expect(mockLogger.info).toHaveBeenCalledWith('Selected optimal provider', expect.any(Object));
    });

    it('should select a provider based on performance requirements', async () => {
      const requirements = {
        cost: 'performance' as const,
        performance: 'quality' as const
      };
      
      const provider = await router.getOptimalProvider(requirements);
      
      expect(provider).toBeDefined();
      expect(provider.id).toBeDefined();
      expect(mockLogger.info).toHaveBeenCalledWith('Selected optimal provider', expect.any(Object));
    });

    it('should filter providers by region', async () => {
      const requirements = {
        region: 'us-east-1'
      };
      
      const provider = await router.getOptimalProvider(requirements);
      
      expect(provider).toBeDefined();
      expect(provider.regions).toContain('us-east-1');
    });

    it('should filter providers by capabilities', async () => {
      const requirements = {
        capabilities: ['function-calling']
      };
      
      const provider = await router.getOptimalProvider(requirements);
      
      expect(provider).toBeDefined();
      expect(provider.capabilities).toContain('function-calling');
    });

    it('should throw an error when no providers match requirements', async () => {
      const requirements = {
        region: 'non-existent-region',
        capabilities: ['non-existent-capability']
      };
      
      await expect(router.getOptimalProvider(requirements)).rejects.toThrow(CAMError);
    });
  });

  describe('executeRequest', () => {
    it('should execute a request with the optimal provider', async () => {
      const request = {
        prompt: 'Test prompt',
        model: 'gpt-4',
        temperature: 0.7,
        maxTokens: 100,
        requirements: {
          cost: 'optimize' as const
        }
      };
      
      const response = await router.executeRequest(request);
      
      expect(response).toBeDefined();
      expect(response.content).toBeDefined();
      expect(response.provider).toBeDefined();
      expect(response.model).toBeDefined();
      expect(response.usage).toBeDefined();
      expect(response.cost).toBeDefined();
      expect(response.latency).toBeDefined();
    });

    it('should apply policies to requests', async () => {
      // Mock the validatePolicy method to test policy application
      const validatePolicySpy = jest.spyOn(router as any, 'validatePolicy');
      validatePolicySpy.mockResolvedValue({
        allowed: true,
        policies: ['test-policy'],
        reason: 'Test policy passed'
      });

      const request = {
        prompt: 'Test prompt',
        model: 'gpt-4',
        metadata: {
          userId: 'test-user'
        }
      };
      
      await router.executeRequest(request);
      
      expect(validatePolicySpy).toHaveBeenCalled();
    });

    it('should throw an error when policy validation fails', async () => {
      // Mock the validatePolicy method to reject the request
      const validatePolicySpy = jest.spyOn(router as any, 'validatePolicy');
      validatePolicySpy.mockResolvedValue({
        allowed: false,
        policies: ['test-policy'],
        reason: 'Policy violation'
      });

      const request = {
        prompt: 'Test prompt',
        model: 'gpt-4'
      };
      
      await expect(router.executeRequest(request)).rejects.toThrow('Policy violation');
    });
  });

  describe('validatePolicy', () => {
    it('should validate policies for a request', async () => {
      // This test accesses a private method, so we need to cast to any
      const router = new FastPathRouter(mockLogger);
      const validatePolicy = (router as any).validatePolicy.bind(router);
      
      const policyRequest = {
        request: {
          prompt: 'Test prompt',
          model: 'gpt-4'
        },
        userId: 'test-user',
        context: {
          resourceId: 'test-resource',
          action: 'generate'
        }
      };
      
      const result = await validatePolicy(policyRequest);
      
      expect(result).toBeDefined();
      expect(result.allowed).toBeDefined();
      expect(result.policies).toBeDefined();
      expect(result.reason).toBeDefined();
    });
  });

  describe('provider connectors', () => {
    it('should call OpenAI endpoint', async () => {
      const providers = await router.getAvailableProviders();
      const openai = providers.find(p => p.type === 'openai')!;
      const request = { prompt: 'hi', model: 'gpt-3.5-turbo' };
      await (router as any).executeRequest(request, openai);
      expect((global as any).fetch).toHaveBeenCalledWith(
        'https://api.openai.com/v1/chat/completions', expect.any(Object)
      );
    });

    it('should call Anthropic endpoint', async () => {
      const providers = await router.getAvailableProviders();
      const anth = providers.find(p => p.type === 'anthropic')!;
      const request = { prompt: 'hi', model: 'claude-3-haiku' };
      await (router as any).executeRequest(request, anth);
      expect((global as any).fetch).toHaveBeenCalledWith(
        'https://api.anthropic.com/v1/messages', expect.any(Object)
      );
    });

    it('should call Google endpoint', async () => {
      const providers = await router.getAvailableProviders();
      const google = providers.find(p => p.type === 'google')!;
      const request = { prompt: 'hi', model: 'gemini-pro' };
      await (router as any).executeRequest(request, google);
      expect((global as any).fetch).toHaveBeenCalledWith(
        expect.stringContaining('generativelanguage.googleapis.com'), expect.any(Object)
      );
    });

    it('should call Azure endpoint', async () => {
      const providers = await router.getAvailableProviders();
      const azure = providers.find(p => p.type === 'azure')!;
      const request = { prompt: 'hi', model: 'gpt-4' };
      await (router as any).executeRequest(request, azure);
      expect((global as any).fetch).toHaveBeenCalledWith(
        'https://azure.openai.com/openai/deployments/gpt-4/chat/completions?api-version=2023-05-15',
        expect.any(Object)
      );
    });
  });
});
