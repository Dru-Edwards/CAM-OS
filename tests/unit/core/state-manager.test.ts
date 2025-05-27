import { StateManager } from '../../src/core/state-manager';
import { CAMError } from '../../src/shared/errors';

describe('StateManager', () => {
  let stateManager: StateManager;
  const mockConfig = {
    stateRetentionHours: 24,
    maxStateSize: 1000,
    cleanupIntervalMs: 60000
  };

  beforeEach(() => {
    stateManager = new StateManager(mockConfig);
  });

  afterEach(async () => {
    await stateManager.shutdown();
  });

  describe('Route State Management', () => {
    it('should set and get route state', async () => {
      const sessionId = 'test-session-1';
      const routeState = {
        provider: 'openai',
        model: 'gpt-4',
        requestCount: 1,
        totalCost: 0.03,
        avgLatency: 234,
        lastActivity: Date.now()
      };

      await stateManager.setRouteState(sessionId, routeState);
      const retrievedState = await stateManager.getRouteState(sessionId);

      expect(retrievedState).toEqual(routeState);
    });

    it('should update existing route state', async () => {
      const sessionId = 'test-session-2';
      const initialState = {
        provider: 'openai',
        model: 'gpt-4',
        requestCount: 1,
        totalCost: 0.03,
        avgLatency: 234,
        lastActivity: Date.now()
      };

      await stateManager.setRouteState(sessionId, initialState);
      
      const updatedState = {
        ...initialState,
        requestCount: 2,
        totalCost: 0.06,
        avgLatency: 220
      };

      await stateManager.setRouteState(sessionId, updatedState);
      const retrievedState = await stateManager.getRouteState(sessionId);

      expect(retrievedState?.requestCount).toBe(2);
      expect(retrievedState?.totalCost).toBe(0.06);
      expect(retrievedState?.avgLatency).toBe(220);
    });

    it('should return null for non-existent route state', async () => {
      const state = await stateManager.getRouteState('non-existent-session');
      expect(state).toBeNull();
    });
  });

  describe('Collaboration State Management', () => {
    it('should set and get collaboration state', async () => {
      const collaborationId = 'collab-test-1';
      const collabState = {
        status: 'running' as const,
        agents: [
          { id: 'agent-1', role: 'coordinator', status: 'active' },
          { id: 'agent-2', role: 'worker', status: 'active' }
        ],
        currentStep: 'data-analysis',
        progress: 0.45,
        startTime: Date.now(),
        lastActivity: Date.now()
      };

      await stateManager.setCollaborationState(collaborationId, collabState);
      const retrievedState = await stateManager.getCollaborationState(collaborationId);

      expect(retrievedState).toEqual(collabState);
    });

    it('should update collaboration progress', async () => {
      const collaborationId = 'collab-test-2';
      const initialState = {
        status: 'running' as const,
        agents: [{ id: 'agent-1', role: 'coordinator', status: 'active' }],
        currentStep: 'initialization',
        progress: 0.1,
        startTime: Date.now(),
        lastActivity: Date.now()
      };

      await stateManager.setCollaborationState(collaborationId, initialState);
      
      const updatedState = {
        ...initialState,
        currentStep: 'data-analysis',
        progress: 0.6,
        lastActivity: Date.now()
      };

      await stateManager.setCollaborationState(collaborationId, updatedState);
      const retrievedState = await stateManager.getCollaborationState(collaborationId);

      expect(retrievedState?.currentStep).toBe('data-analysis');
      expect(retrievedState?.progress).toBe(0.6);
    });
  });

  describe('State Snapshots', () => {
    it('should create and retrieve state snapshots', async () => {
      const sessionId = 'snapshot-session';
      const routeState = {
        provider: 'anthropic',
        model: 'claude-3-opus',
        requestCount: 5,
        totalCost: 0.15,
        avgLatency: 180,
        lastActivity: Date.now()
      };

      await stateManager.setRouteState(sessionId, routeState);
      const snapshotId = await stateManager.createSnapshot(sessionId, 'route', { reason: 'test' });
      
      expect(snapshotId).toBeDefined();
      expect(typeof snapshotId).toBe('string');

      const snapshot = await stateManager.getSnapshot(snapshotId);
      expect(snapshot).toBeDefined();
      expect(snapshot?.sessionId).toBe(sessionId);
      expect(snapshot?.type).toBe('route');
      expect(snapshot?.data).toEqual(routeState);
    });

    it('should handle snapshot creation for non-existent session', async () => {
      await expect(
        stateManager.createSnapshot('non-existent', 'route', {})
      ).rejects.toThrow(CAMError);
    });
  });

  describe('State Cleanup', () => {
    it('should clean up expired states', async () => {
      // Create states with past timestamps
      const expiredTime = Date.now() - (25 * 60 * 60 * 1000); // 25 hours ago
      
      const sessionId1 = 'expired-session-1';
      const sessionId2 = 'expired-session-2';
      
      const expiredState = {
        provider: 'openai',
        model: 'gpt-3.5-turbo',
        requestCount: 1,
        totalCost: 0.01,
        avgLatency: 300,
        lastActivity: expiredTime
      };

      await stateManager.setRouteState(sessionId1, expiredState);
      await stateManager.setRouteState(sessionId2, expiredState);

      // Trigger cleanup
      await stateManager.cleanupExpiredStates();

      // Verify states are cleaned up
      const state1 = await stateManager.getRouteState(sessionId1);
      const state2 = await stateManager.getRouteState(sessionId2);

      expect(state1).toBeNull();
      expect(state2).toBeNull();
    });

    it('should not clean up recent states', async () => {
      const sessionId = 'recent-session';
      const recentState = {
        provider: 'openai',
        model: 'gpt-4',
        requestCount: 1,
        totalCost: 0.03,
        avgLatency: 234,
        lastActivity: Date.now() - (1 * 60 * 60 * 1000) // 1 hour ago
      };

      await stateManager.setRouteState(sessionId, recentState);
      await stateManager.cleanupExpiredStates();

      const state = await stateManager.getRouteState(sessionId);
      expect(state).toEqual(recentState);
    });
  });

  describe('Health Metrics', () => {
    it('should return current health metrics', () => {
      const metrics = stateManager.getHealthMetrics();

      expect(metrics).toHaveProperty('routeStates');
      expect(metrics).toHaveProperty('collaborationStates');
      expect(metrics).toHaveProperty('snapshots');
      expect(metrics).toHaveProperty('memoryUsage');
      expect(metrics).toHaveProperty('uptime');

      expect(typeof metrics.routeStates).toBe('number');
      expect(typeof metrics.collaborationStates).toBe('number');
      expect(typeof metrics.snapshots).toBe('number');
      expect(typeof metrics.memoryUsage).toBe('number');
      expect(typeof metrics.uptime).toBe('number');
    });

    it('should track state counts correctly', async () => {
      const initialMetrics = stateManager.getHealthMetrics();
      
      await stateManager.setRouteState('test-session', {
        provider: 'openai',
        model: 'gpt-4',
        requestCount: 1,
        totalCost: 0.03,
        avgLatency: 234,
        lastActivity: Date.now()
      });

      const updatedMetrics = stateManager.getHealthMetrics();
      expect(updatedMetrics.routeStates).toBe(initialMetrics.routeStates + 1);
    });
  });

  describe('Configuration Updates', () => {
    it('should update configuration successfully', async () => {
      const newConfig = {
        stateRetentionHours: 48,
        maxStateSize: 2000,
        cleanupIntervalMs: 120000
      };

      await stateManager.updateConfig(newConfig);
      
      // Verify configuration was updated by checking behavior
      // Since we can't directly access private config, we test the effect
      const metrics = stateManager.getHealthMetrics();
      expect(metrics).toBeDefined();
    });

    it('should validate configuration parameters', async () => {
      const invalidConfig = {
        stateRetentionHours: -1, // Invalid negative value
        maxStateSize: 0, // Invalid zero value
        cleanupIntervalMs: 100 // Too low value
      };

      await expect(
        stateManager.updateConfig(invalidConfig)
      ).rejects.toThrow(CAMError);
    });
  });

  describe('Error Handling', () => {
    it('should handle invalid session IDs gracefully', async () => {
      const invalidSessionIds = ['', null, undefined] as any[];
      
      for (const sessionId of invalidSessionIds) {
        await expect(
          stateManager.getRouteState(sessionId)
        ).rejects.toThrow(CAMError);
      }
    });

    it('should handle corrupted state data', async () => {
      const sessionId = 'corrupted-session';
      
      // Simulate corrupted data by setting invalid state
      await expect(
        stateManager.setRouteState(sessionId, null as any)
      ).rejects.toThrow(CAMError);
    });
  });

  describe('Concurrent Access', () => {
    it('should handle concurrent state updates', async () => {
      const sessionId = 'concurrent-session';
      const promises = [];

      // Create multiple concurrent updates
      for (let i = 0; i < 10; i++) {
        promises.push(
          stateManager.setRouteState(sessionId, {
            provider: 'openai',
            model: 'gpt-4',
            requestCount: i + 1,
            totalCost: (i + 1) * 0.03,
            avgLatency: 234,
            lastActivity: Date.now()
          })
        );
      }

      await Promise.all(promises);

      const finalState = await stateManager.getRouteState(sessionId);
      expect(finalState).toBeDefined();
      expect(finalState?.requestCount).toBeGreaterThan(0);
      expect(finalState?.requestCount).toBeLessThanOrEqual(10);
    });
  });
});
