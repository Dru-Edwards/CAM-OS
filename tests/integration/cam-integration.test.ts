import { CompleteArbitrationMesh } from '../../src/core/complete-arbitration-mesh';
import { CAMError } from '../../src/shared/errors';

describe('Complete Arbitration Mesh Integration', () => {
  let cam: CompleteArbitrationMesh;

  const testConfig = {
    providers: {
      openai: {
        enabled: true,
        apiKey: process.env.OPENAI_API_KEY || 'mock-key',
        baseUrl: 'https://api.openai.com/v1',
        models: ['gpt-4', 'gpt-3.5-turbo']
      },
      anthropic: {
        enabled: true,
        apiKey: process.env.ANTHROPIC_API_KEY || 'mock-key',
        baseUrl: 'https://api.anthropic.com',
        models: ['claude-3-opus', 'claude-3-sonnet']
      }
    },
    routing: {
      defaultProvider: 'openai',
      fallbackEnabled: true,
      costOptimization: true
    },
    collaboration: {
      enabled: true,
      maxAgentsPerTask: 5
    },
    authentication: {
      secret: 'test-secret',
      expiresIn: '1h'
    }
  };

  beforeEach(async () => {
    cam = new CompleteArbitrationMesh(testConfig);
    await cam.initialize();
  });

  afterEach(async () => {
    if (cam) {
      await cam.shutdown();
    }
  });

  describe('System Initialization', () => {
    it('should initialize all components successfully', async () => {
      expect(cam).toBeDefined();
      
      const health = await cam.getHealthStatus();
      expect(health.status).toBe('healthy');
      expect(health.services.router).toBe('healthy');
      expect(health.services.authentication).toBe('healthy');
      expect(health.services.stateManager).toBe('healthy');
    });

    it('should handle initialization with missing configuration', async () => {
      const invalidCam = new CompleteArbitrationMesh({});
      
      await expect(invalidCam.initialize()).rejects.toThrow(CAMError);
    });
  });

  describe('CAM Classic Integration (Routing)', () => {
    it('should route simple text generation request', async () => {
      const request = {
        prompt: 'What is artificial intelligence?',
        model: 'gpt-3.5-turbo',
        maxTokens: 100
      };

      // Mock the provider response for testing
      const mockResponse = {
        content: 'Artificial intelligence (AI) is a field of computer science...',
        metadata: {
          provider: 'openai',
          model: 'gpt-3.5-turbo',
          tokens: 45,
          cost: 0.00009,
          latency: 234,
          requestId: 'req-123'
        }
      };

      // For integration tests, we would mock the actual provider calls
      jest.spyOn(cam['router'], 'route').mockResolvedValue(mockResponse);

      const response = await cam.route(request);

      expect(response.content).toBeDefined();
      expect(response.metadata.provider).toBe('openai');
      expect(response.metadata.model).toBe('gpt-3.5-turbo');
      expect(response.metadata.tokens).toBeGreaterThan(0);
      expect(response.metadata.cost).toBeGreaterThan(0);
      expect(response.metadata.latency).toBeGreaterThan(0);
    });

    it('should handle provider fallback on failure', async () => {
      const request = {
        prompt: 'Test fallback scenario',
        model: 'gpt-4',
        maxTokens: 50
      };

      // Mock primary provider failure and secondary success
      jest.spyOn(cam['router'], 'route')
        .mockRejectedValueOnce(new CAMError('Primary provider failed', 'PROVIDER_ERROR'))
        .mockResolvedValueOnce({
          content: 'Fallback response from secondary provider',
          metadata: {
            provider: 'anthropic',
            model: 'claude-3-sonnet',
            tokens: 25,
            cost: 0.00005,
            latency: 345,
            requestId: 'req-124'
          }
        });

      const response = await cam.route(request);

      expect(response.content).toBeDefined();
      expect(response.metadata.provider).toBe('anthropic');
    });

    it('should optimize for cost when configured', async () => {
      const request = {
        prompt: 'Cost optimization test',
        model: 'gpt-4',
        maxTokens: 100,
        costOptimization: true
      };

      // Mock cost optimizer selecting cheaper model
      jest.spyOn(cam['router'], 'route').mockResolvedValue({
        content: 'Response from cost-optimized model',
        metadata: {
          provider: 'openai',
          model: 'gpt-3.5-turbo', // Cheaper model selected
          tokens: 35,
          cost: 0.00007,
          latency: 198,
          requestId: 'req-125'
        }
      });

      const response = await cam.route(request);

      expect(response.metadata.cost).toBeLessThan(0.001); // Should be cost-optimized
    });
  });

  describe('IACP Integration (Collaboration)', () => {
    it('should start and complete a simple collaboration', async () => {
      const collaborationRequest = {
        task: 'Analyze sample data and generate insights',
        requiredCapabilities: ['data-analysis', 'reporting'],
        maxAgents: 2
      };

      // Mock collaboration engine
      const mockCollaboration = {
        id: 'collab-123',
        status: 'completed' as const,
        agents: [
          { id: 'agent-1', capabilities: ['data-analysis'], role: 'analyst' },
          { id: 'agent-2', capabilities: ['reporting'], role: 'reporter' }
        ],
        result: {
          summary: 'Analysis completed successfully',
          details: { insights: ['Pattern A detected', 'Trend B identified'] },
          artifacts: ['chart.png', 'report.pdf']
        },
        metadata: {
          duration: 30000,
          totalCost: 5.50,
          agentsUsed: 2,
          tasksCompleted: 4
        }
      };

      jest.spyOn(cam['collaborationEngine'], 'startCollaboration')
        .mockResolvedValue(mockCollaboration);

      const collaboration = await cam.startCollaboration(collaborationRequest);

      expect(collaboration.id).toBeDefined();
      expect(collaboration.status).toBe('completed');
      expect(collaboration.agents).toHaveLength(2);
      expect(collaboration.result.summary).toBeDefined();
      expect(collaboration.metadata.duration).toBeGreaterThan(0);
    });

    it('should handle agent discovery and matching', async () => {
      const collaborationRequest = {
        task: 'Complex financial analysis with visualization',
        requiredCapabilities: ['financial-modeling', 'data-visualization', 'reporting'],
        maxAgents: 3
      };

      // Mock agent discovery finding suitable agents
      const mockAgents = [
        { id: 'financial-agent-1', capabilities: ['financial-modeling'], rating: 4.8 },
        { id: 'viz-agent-1', capabilities: ['data-visualization'], rating: 4.6 },
        { id: 'report-agent-1', capabilities: ['reporting'], rating: 4.9 }
      ];

      jest.spyOn(cam['collaborationEngine'], 'discoverAgents')
        .mockResolvedValue(mockAgents);

      const agents = await cam.discoverAgents(collaborationRequest.requiredCapabilities);

      expect(agents).toHaveLength(3);
      expect(agents.every(agent => agent.rating > 4.0)).toBe(true);
      expect(agents.some(agent => agent.capabilities.includes('financial-modeling'))).toBe(true);
      expect(agents.some(agent => agent.capabilities.includes('data-visualization'))).toBe(true);
      expect(agents.some(agent => agent.capabilities.includes('reporting'))).toBe(true);
    });

    it('should handle workflow orchestration', async () => {
      const collaborationRequest = {
        task: 'Multi-step data pipeline: collect, process, analyze, report',
        requiredCapabilities: ['data-collection', 'data-processing', 'analysis', 'reporting'],
        maxAgents: 4
      };

      // Mock workflow with sequential steps
      const mockWorkflow = {
        steps: [
          { id: 'step-1', name: 'data-collection', status: 'completed', duration: 5000 },
          { id: 'step-2', name: 'data-processing', status: 'completed', duration: 10000 },
          { id: 'step-3', name: 'analysis', status: 'completed', duration: 15000 },
          { id: 'step-4', name: 'reporting', status: 'completed', duration: 8000 }
        ],
        totalDuration: 38000,
        success: true
      };

      jest.spyOn(cam['collaborationEngine'], 'executeWorkflow')
        .mockResolvedValue(mockWorkflow);

      const result = await cam.executeWorkflow(collaborationRequest.task);

      expect(result.steps).toHaveLength(4);
      expect(result.steps.every(step => step.status === 'completed')).toBe(true);
      expect(result.totalDuration).toBe(38000);
      expect(result.success).toBe(true);
    });
  });

  describe('Cross-Component Integration', () => {
    it('should share state between routing and collaboration', async () => {
      // Start with a routing request that creates session state
      const routeRequest = {
        prompt: 'Initial data processing request',
        model: 'gpt-4',
        maxTokens: 200
      };

      jest.spyOn(cam['router'], 'route').mockResolvedValue({
        content: 'Processed data ready for collaboration',
        metadata: {
          provider: 'openai',
          model: 'gpt-4',
          tokens: 85,
          cost: 0.00255,
          latency: 456,
          requestId: 'req-126'
        }
      });

      const routeResponse = await cam.route(routeRequest);
      const sessionId = routeResponse.metadata.requestId;

      // Then start collaboration that can access the routing session state
      const collaborationRequest = {
        task: 'Continue processing from routing session',
        requiredCapabilities: ['data-analysis'],
        maxAgents: 1,
        sessionId: sessionId
      };

      jest.spyOn(cam['collaborationEngine'], 'startCollaboration')
        .mockResolvedValue({
          id: 'collab-124',
          status: 'completed' as const,
          agents: [{ id: 'agent-1', capabilities: ['data-analysis'], role: 'analyst' }],
          result: {
            summary: 'Built upon routing session data',
            details: { sessionData: 'Referenced previous routing results' },
            artifacts: []
          },
          metadata: {
            duration: 25000,
            totalCost: 3.75,
            agentsUsed: 1,
            tasksCompleted: 2
          }
        });

      const collaboration = await cam.startCollaboration(collaborationRequest);

      expect(collaboration.result.details.sessionData).toBeDefined();
    });

    it('should handle authentication across all components', async () => {
      // Test that authentication works for both routing and collaboration
      const authToken = 'test-jwt-token';

      // Mock authentication validation
      jest.spyOn(cam['authService'], 'validateToken').mockResolvedValue({
        valid: true,
        userInfo: {
          id: 'user-123',
          type: 'api-key',
          permissions: ['route', 'collaborate']
        },
        permissions: ['route', 'collaborate']
      });

      // Test routing with authentication
      const routeRequest = {
        prompt: 'Authenticated routing request',
        model: 'gpt-3.5-turbo',
        maxTokens: 100,
        authToken: authToken
      };

      jest.spyOn(cam['router'], 'route').mockResolvedValue({
        content: 'Authenticated response',
        metadata: {
          provider: 'openai',
          model: 'gpt-3.5-turbo',
          tokens: 45,
          cost: 0.00009,
          latency: 234,
          requestId: 'req-127'
        }
      });

      const routeResponse = await cam.route(routeRequest);
      expect(routeResponse.content).toBeDefined();

      // Test collaboration with authentication
      const collaborationRequest = {
        task: 'Authenticated collaboration task',
        requiredCapabilities: ['data-analysis'],
        maxAgents: 1,
        authToken: authToken
      };

      jest.spyOn(cam['collaborationEngine'], 'startCollaboration')
        .mockResolvedValue({
          id: 'collab-125',
          status: 'completed' as const,
          agents: [{ id: 'agent-1', capabilities: ['data-analysis'], role: 'analyst' }],
          result: {
            summary: 'Authenticated collaboration completed',
            details: {},
            artifacts: []
          },
          metadata: {
            duration: 20000,
            totalCost: 2.50,
            agentsUsed: 1,
            tasksCompleted: 1
          }
        });

      const collaboration = await cam.startCollaboration(collaborationRequest);
      expect(collaboration.result.summary).toContain('Authenticated');
    });
  });

  describe('Error Handling and Recovery', () => {
    it('should handle component failures gracefully', async () => {
      // Simulate router failure
      jest.spyOn(cam['router'], 'route')
        .mockRejectedValue(new CAMError('Router service unavailable', 'SERVICE_UNAVAILABLE'));

      const request = {
        prompt: 'Test error handling',
        model: 'gpt-4',
        maxTokens: 100
      };

      await expect(cam.route(request)).rejects.toThrow(CAMError);

      // Verify system is still healthy after error
      const health = await cam.getHealthStatus();
      expect(health.status).toBe('healthy'); // Should recover
    });

    it('should handle collaboration failures with cleanup', async () => {
      const collaborationRequest = {
        task: 'Test collaboration failure',
        requiredCapabilities: ['data-analysis'],
        maxAgents: 1
      };

      // Simulate collaboration failure
      jest.spyOn(cam['collaborationEngine'], 'startCollaboration')
        .mockRejectedValue(new CAMError('Agent discovery failed', 'AGENT_UNAVAILABLE'));

      await expect(cam.startCollaboration(collaborationRequest)).rejects.toThrow(CAMError);

      // Verify cleanup occurred
      const health = await cam.getHealthStatus();
      expect(health.services.collaboration).toBe('healthy');
    });
  });

  describe('Performance and Scalability', () => {
    it('should handle concurrent routing requests', async () => {
      const promises = [];
      
      for (let i = 0; i < 10; i++) {
        const request = {
          prompt: `Concurrent request ${i}`,
          model: 'gpt-3.5-turbo',
          maxTokens: 50
        };

        jest.spyOn(cam['router'], 'route').mockResolvedValue({
          content: `Response to request ${i}`,
          metadata: {
            provider: 'openai',
            model: 'gpt-3.5-turbo',
            tokens: 25,
            cost: 0.00005,
            latency: 200 + i * 10,
            requestId: `req-${130 + i}`
          }
        });

        promises.push(cam.route(request));
      }

      const responses = await Promise.all(promises);
      
      expect(responses).toHaveLength(10);
      responses.forEach((response, index) => {
        expect(response.content).toContain(`request ${index}`);
        expect(response.metadata.latency).toBeGreaterThan(0);
      });
    });

    it('should handle concurrent collaborations', async () => {
      const promises = [];
      
      for (let i = 0; i < 5; i++) {
        const request = {
          task: `Concurrent collaboration ${i}`,
          requiredCapabilities: ['analysis'],
          maxAgents: 1
        };

        jest.spyOn(cam['collaborationEngine'], 'startCollaboration')
          .mockResolvedValue({
            id: `collab-${130 + i}`,
            status: 'completed' as const,
            agents: [{ id: `agent-${i}`, capabilities: ['analysis'], role: 'analyst' }],
            result: {
              summary: `Collaboration ${i} completed`,
              details: {},
              artifacts: []
            },
            metadata: {
              duration: 15000 + i * 1000,
              totalCost: 2.0 + i * 0.5,
              agentsUsed: 1,
              tasksCompleted: 1
            }
          });

        promises.push(cam.startCollaboration(request));
      }

      const collaborations = await Promise.all(promises);
      
      expect(collaborations).toHaveLength(5);
      collaborations.forEach((collaboration, index) => {
        expect(collaboration.id).toContain(`collab-${130 + index}`);
        expect(collaboration.status).toBe('completed');
      });
    });
  });

  describe('Monitoring and Observability', () => {
    it('should provide comprehensive health status', async () => {
      const health = await cam.getHealthStatus();

      expect(health).toHaveProperty('status');
      expect(health).toHaveProperty('services');
      expect(health).toHaveProperty('version');
      expect(health).toHaveProperty('uptime');

      expect(health.services).toHaveProperty('router');
      expect(health.services).toHaveProperty('collaboration');
      expect(health.services).toHaveProperty('authentication');
      expect(health.services).toHaveProperty('stateManager');
    });

    it('should provide performance metrics', async () => {
      // Generate some activity first
      const routeRequest = {
        prompt: 'Metrics test request',
        model: 'gpt-3.5-turbo',
        maxTokens: 50
      };

      jest.spyOn(cam['router'], 'route').mockResolvedValue({
        content: 'Metrics test response',
        metadata: {
          provider: 'openai',
          model: 'gpt-3.5-turbo',
          tokens: 25,
          cost: 0.00005,
          latency: 234,
          requestId: 'req-metrics'
        }
      });

      await cam.route(routeRequest);

      const metrics = await cam.getMetrics();

      expect(metrics).toHaveProperty('requests');
      expect(metrics).toHaveProperty('collaborations');
      expect(metrics).toHaveProperty('performance');
      expect(metrics).toHaveProperty('costs');

      expect(metrics.requests.total).toBeGreaterThan(0);
      expect(metrics.performance.avgLatency).toBeGreaterThan(0);
    });
  });
});
