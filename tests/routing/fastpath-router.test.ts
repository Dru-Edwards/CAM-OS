import { FastPathRouter } from '../../src/routing/fastpath-router';
import { Logger } from '../../src/shared/logger';
import { LogLevel } from '../../src/shared/types';
import { CAMError } from '../../src/shared/errors';

jest.mock('../../src/shared/logger');

describe('FastPathRouter', () => {
  let router: FastPathRouter;
  let mockLogger: jest.Mocked<Logger>;

  beforeEach(() => {
    mockLogger = new Logger({ level: LogLevel.DEBUG }) as jest.Mocked<Logger>;
    router = new FastPathRouter(mockLogger);
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
});
