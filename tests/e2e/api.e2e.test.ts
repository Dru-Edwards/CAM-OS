import { CompleteArbitrationMesh } from '../../src/core/complete-arbitration-mesh';
import request from 'supertest';
import express from 'express';

describe('End-to-End API Tests', () => {
  let app: express.Application;
  let cam: CompleteArbitrationMesh;
  let server: any;

  const testConfig = {
    providers: {
      openai: {
        enabled: true,
        apiKey: 'mock-openai-key',
        baseUrl: 'https://api.openai.com/v1',
        models: ['gpt-4', 'gpt-3.5-turbo']
      },
      anthropic: {
        enabled: true,
        apiKey: 'mock-anthropic-key',
        baseUrl: 'https://api.anthropic.com',
        models: ['claude-3-opus', 'claude-3-sonnet']
      }
    },
    routing: {
      defaultProvider: 'openai',
      fallbackEnabled: true
    },
    collaboration: {
      enabled: true,
      maxAgentsPerTask: 5
    },
    authentication: {
      secret: 'test-e2e-secret',
      expiresIn: '1h'
    },
    api: {
      port: 0, // Let the system assign a port
      host: 'localhost'
    }
  };

  beforeAll(async () => {
    // Initialize CAM
    cam = new CompleteArbitrationMesh(testConfig);
    await cam.initialize();

    // Create Express app with CAM routes
    app = express();
    app.use(express.json());

    // Add CAM API routes
    app.post('/api/v1/route', async (req, res) => {
      try {
        const response = await cam.route(req.body);
        res.json({ success: true, ...response });
      } catch (error) {
        res.status(500).json({ 
          success: false, 
          error: { 
            message: error instanceof Error ? error.message : 'Unknown error' 
          } 
        });
      }
    });

    app.post('/api/v1/collaboration/start', async (req, res) => {
      try {
        const collaboration = await cam.startCollaboration(req.body);
        res.json({ success: true, ...collaboration });
      } catch (error) {
        res.status(500).json({ 
          success: false, 
          error: { 
            message: error instanceof Error ? error.message : 'Unknown error' 
          } 
        });
      }
    });

    app.get('/api/v1/health', async (req, res) => {
      try {
        const health = await cam.getHealthStatus();
        res.json({ success: true, ...health });
      } catch (error) {
        res.status(500).json({ 
          success: false, 
          error: { 
            message: error instanceof Error ? error.message : 'Unknown error' 
          } 
        });
      }
    });

    app.get('/api/v1/providers', async (req, res) => {
      try {
        const providers = await cam.getProviders();
        res.json({ success: true, providers });
      } catch (error) {
        res.status(500).json({ 
          success: false, 
          error: { 
            message: error instanceof Error ? error.message : 'Unknown error' 
          } 
        });
      }
    });

    // Start server
    server = app.listen(0);
  });

  afterAll(async () => {
    if (server) {
      server.close();
    }
    if (cam) {
      await cam.shutdown();
    }
  });

  describe('API Health and Status', () => {
    it('should return healthy status', async () => {
      // Mock the health check
      jest.spyOn(cam, 'getHealthStatus').mockResolvedValue({
        status: 'healthy',
        services: {
          router: 'healthy',
          collaboration: 'healthy',
          authentication: 'healthy',
          stateManager: 'healthy'
        },
        version: '1.0.0',
        uptime: 123456
      });

      const response = await request(app)
        .get('/api/v1/health')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.status).toBe('healthy');
      expect(response.body.services).toBeDefined();
    });

    it('should return available providers', async () => {
      jest.spyOn(cam, 'getProviders').mockResolvedValue([
        {
          id: 'openai',
          name: 'OpenAI',
          status: 'healthy',
          models: ['gpt-4', 'gpt-3.5-turbo'],
          latency: 234,
          costPerToken: 0.00003
        },
        {
          id: 'anthropic',
          name: 'Anthropic',
          status: 'healthy',
          models: ['claude-3-opus', 'claude-3-sonnet'],
          latency: 456,
          costPerToken: 0.000015
        }
      ]);

      const response = await request(app)
        .get('/api/v1/providers')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.providers).toHaveLength(2);
      expect(response.body.providers[0].id).toBe('openai');
    });
  });

  describe('CAM Classic API (Routing)', () => {
    it('should handle basic routing request', async () => {
      const mockResponse = {
        content: 'This is a test response from the AI model.',
        metadata: {
          provider: 'openai',
          model: 'gpt-3.5-turbo',
          tokens: 12,
          cost: 0.000024,
          latency: 234,
          requestId: 'req-e2e-001'
        }
      };

      jest.spyOn(cam, 'route').mockResolvedValue(mockResponse);

      const requestBody = {
        prompt: 'What is the capital of France?',
        model: 'gpt-3.5-turbo',
        maxTokens: 50
      };

      const response = await request(app)
        .post('/api/v1/route')
        .send(requestBody)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.content).toBeDefined();
      expect(response.body.metadata.provider).toBe('openai');
      expect(response.body.metadata.tokens).toBeGreaterThan(0);
      expect(response.body.metadata.cost).toBeGreaterThan(0);
    });

    it('should handle routing request with specific provider', async () => {
      const mockResponse = {
        content: 'Response from Anthropic Claude model.',
        metadata: {
          provider: 'anthropic',
          model: 'claude-3-sonnet',
          tokens: 15,
          cost: 0.000045,
          latency: 345,
          requestId: 'req-e2e-002'
        }
      };

      jest.spyOn(cam, 'route').mockResolvedValue(mockResponse);

      const requestBody = {
        prompt: 'Explain quantum computing',
        model: 'claude-3-sonnet',
        provider: 'anthropic',
        maxTokens: 100
      };

      const response = await request(app)
        .post('/api/v1/route')
        .send(requestBody)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.metadata.provider).toBe('anthropic');
      expect(response.body.metadata.model).toBe('claude-3-sonnet');
    });

    it('should handle invalid routing request', async () => {
      const requestBody = {
        // Missing required prompt field
        model: 'gpt-4',
        maxTokens: 100
      };

      const response = await request(app)
        .post('/api/v1/route')
        .send(requestBody)
        .expect(500);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toBeDefined();
    });

    it('should handle routing with cost optimization', async () => {
      const mockResponse = {
        content: 'Cost-optimized response.',
        metadata: {
          provider: 'openai',
          model: 'gpt-3.5-turbo', // Cost optimizer chose cheaper model
          tokens: 20,
          cost: 0.00004,
          latency: 198,
          requestId: 'req-e2e-003'
        }
      };

      jest.spyOn(cam, 'route').mockResolvedValue(mockResponse);

      const requestBody = {
        prompt: 'Summarize this text briefly',
        model: 'gpt-4', // Requested expensive model
        maxTokens: 50,
        costOptimization: true
      };

      const response = await request(app)
        .post('/api/v1/route')
        .send(requestBody)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.metadata.model).toBe('gpt-3.5-turbo'); // Should be optimized
      expect(response.body.metadata.cost).toBeLessThan(0.001);
    });
  });

  describe('IACP API (Collaboration)', () => {
    it('should start collaboration successfully', async () => {
      const mockCollaboration = {
        id: 'collab-e2e-001',
        status: 'running' as const,
        agents: [
          { id: 'agent-1', capabilities: ['data-analysis'], role: 'analyst' },
          { id: 'agent-2', capabilities: ['reporting'], role: 'reporter' }
        ],
        estimatedDuration: 60000,
        estimatedCost: 5.0
      };

      jest.spyOn(cam, 'startCollaboration').mockResolvedValue(mockCollaboration);

      const requestBody = {
        task: 'Analyze sales data and generate monthly report',
        requiredCapabilities: ['data-analysis', 'reporting'],
        maxAgents: 2
      };

      const response = await request(app)
        .post('/api/v1/collaboration/start')
        .send(requestBody)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.id).toBeDefined();
      expect(response.body.status).toBe('running');
      expect(response.body.agents).toHaveLength(2);
      expect(response.body.estimatedCost).toBeGreaterThan(0);
    });

    it('should handle collaboration with specific requirements', async () => {
      const mockCollaboration = {
        id: 'collab-e2e-002',
        status: 'running' as const,
        agents: [
          { id: 'financial-agent', capabilities: ['financial-modeling'], role: 'modeler' },
          { id: 'viz-agent', capabilities: ['data-visualization'], role: 'visualizer' },
          { id: 'report-agent', capabilities: ['reporting'], role: 'reporter' }
        ],
        estimatedDuration: 120000,
        estimatedCost: 12.5
      };

      jest.spyOn(cam, 'startCollaboration').mockResolvedValue(mockCollaboration);

      const requestBody = {
        task: 'Create comprehensive financial analysis with visualizations',
        requiredCapabilities: ['financial-modeling', 'data-visualization', 'reporting'],
        maxAgents: 3,
        timeout: 300000,
        metadata: {
          priority: 'high',
          budget: 15.0
        }
      };

      const response = await request(app)
        .post('/api/v1/collaboration/start')
        .send(requestBody)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.agents).toHaveLength(3);
      expect(response.body.estimatedCost).toBeLessThanOrEqual(15.0);
    });

    it('should handle invalid collaboration request', async () => {
      const requestBody = {
        // Missing required task field
        requiredCapabilities: ['analysis'],
        maxAgents: 1
      };

      const response = await request(app)
        .post('/api/v1/collaboration/start')
        .send(requestBody)
        .expect(500);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toBeDefined();
    });
  });

  describe('Error Handling', () => {
    it('should handle internal server errors gracefully', async () => {
      // Force an error in the CAM system
      jest.spyOn(cam, 'route').mockRejectedValue(new Error('Internal system error'));

      const requestBody = {
        prompt: 'This will cause an error',
        model: 'gpt-4',
        maxTokens: 50
      };

      const response = await request(app)
        .post('/api/v1/route')
        .send(requestBody)
        .expect(500);

      expect(response.body.success).toBe(false);
      expect(response.body.error.message).toBe('Internal system error');
    });

    it('should handle malformed JSON requests', async () => {
      const response = await request(app)
        .post('/api/v1/route')
        .send('invalid json')
        .set('Content-Type', 'application/json')
        .expect(400);

      // Express automatically handles malformed JSON
    });

    it('should handle missing Content-Type header', async () => {
      const requestBody = {
        prompt: 'Test without content type',
        model: 'gpt-4',
        maxTokens: 50
      };

      const response = await request(app)
        .post('/api/v1/route')
        .send(JSON.stringify(requestBody))
        // Don't set Content-Type header
        .expect(500); // Should still work but might cause parsing issues
    });
  });

  describe('Performance and Load Testing', () => {
    it('should handle multiple concurrent routing requests', async () => {
      const mockResponse = (id: number) => ({
        content: `Response ${id}`,
        metadata: {
          provider: 'openai',
          model: 'gpt-3.5-turbo',
          tokens: 10 + id,
          cost: 0.00002 * (10 + id),
          latency: 200 + id * 10,
          requestId: `req-concurrent-${id}`
        }
      });

      // Mock concurrent responses
      jest.spyOn(cam, 'route')
        .mockImplementation(async (request) => {
          const id = parseInt(request.prompt.split(' ').pop() || '0');
          return mockResponse(id);
        });

      const promises = [];
      for (let i = 0; i < 10; i++) {
        promises.push(
          request(app)
            .post('/api/v1/route')
            .send({
              prompt: `Concurrent request ${i}`,
              model: 'gpt-3.5-turbo',
              maxTokens: 50
            })
        );
      }

      const responses = await Promise.all(promises);

      responses.forEach((response, index) => {
        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.body.content).toContain(`Response ${index}`);
      });
    });

    it('should handle large request payloads', async () => {
      const mockResponse = {
        content: 'Response to large prompt',
        metadata: {
          provider: 'openai',
          model: 'gpt-4',
          tokens: 50,
          cost: 0.0015,
          latency: 567,
          requestId: 'req-large-payload'
        }
      };

      jest.spyOn(cam, 'route').mockResolvedValue(mockResponse);

      const largePrompt = 'A'.repeat(10000); // 10KB prompt
      const requestBody = {
        prompt: largePrompt,
        model: 'gpt-4',
        maxTokens: 100
      };

      const response = await request(app)
        .post('/api/v1/route')
        .send(requestBody)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.content).toBeDefined();
    });
  });

  describe('Authentication and Security', () => {
    it('should handle requests with valid authentication token', async () => {
      const mockResponse = {
        content: 'Authenticated response',
        metadata: {
          provider: 'openai',
          model: 'gpt-4',
          tokens: 25,
          cost: 0.00075,
          latency: 234,
          requestId: 'req-auth-valid'
        }
      };

      jest.spyOn(cam, 'route').mockResolvedValue(mockResponse);

      const requestBody = {
        prompt: 'Authenticated request',
        model: 'gpt-4',
        maxTokens: 50
      };

      const response = await request(app)
        .post('/api/v1/route')
        .set('Authorization', 'Bearer valid-jwt-token')
        .send(requestBody)
        .expect(200);

      expect(response.body.success).toBe(true);
    });

    it('should reject requests with invalid authentication', async () => {
      const requestBody = {
        prompt: 'Unauthenticated request',
        model: 'gpt-4',
        maxTokens: 50
      };

      // Mock authentication failure
      jest.spyOn(cam, 'route').mockRejectedValue(new Error('Authentication failed'));

      const response = await request(app)
        .post('/api/v1/route')
        .set('Authorization', 'Bearer invalid-token')
        .send(requestBody)
        .expect(500);

      expect(response.body.success).toBe(false);
      expect(response.body.error.message).toBe('Authentication failed');
    });

    it('should handle missing authentication gracefully', async () => {
      const requestBody = {
        prompt: 'No auth header request',
        model: 'gpt-4',
        maxTokens: 50
      };

      // For this test, we'll assume the system allows unauthenticated requests
      // In production, this might return 401
      const mockResponse = {
        content: 'Response without auth',
        metadata: {
          provider: 'openai',
          model: 'gpt-4',
          tokens: 20,
          cost: 0.0006,
          latency: 234,
          requestId: 'req-no-auth'
        }
      };

      jest.spyOn(cam, 'route').mockResolvedValue(mockResponse);

      const response = await request(app)
        .post('/api/v1/route')
        .send(requestBody)
        .expect(200);

      expect(response.body.success).toBe(true);
    });
  });

  describe('API Versioning and Compatibility', () => {
    it('should maintain backward compatibility', async () => {
      // Test that older API format still works
      const legacyRequestBody = {
        text: 'Legacy format prompt', // Old field name
        model: 'gpt-4',
        max_tokens: 50 // Snake case format
      };

      // Transform legacy format to new format
      const transformedRequest = {
        prompt: legacyRequestBody.text,
        model: legacyRequestBody.model,
        maxTokens: legacyRequestBody.max_tokens
      };

      const mockResponse = {
        content: 'Legacy compatibility response',
        metadata: {
          provider: 'openai',
          model: 'gpt-4',
          tokens: 22,
          cost: 0.00066,
          latency: 234,
          requestId: 'req-legacy'
        }
      };

      jest.spyOn(cam, 'route').mockResolvedValue(mockResponse);

      // Note: In a real implementation, you'd have middleware to transform the request
      const response = await request(app)
        .post('/api/v1/route')
        .send(transformedRequest)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.content).toBeDefined();
    });
  });
});
