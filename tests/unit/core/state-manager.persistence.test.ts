import fs from 'fs';
import { StateManager } from '../../../src/core/state-manager.js';

const testFile = 'tmp/state-manager-persistence.json';

function cleanup() {
  if (fs.existsSync(testFile)) {
    fs.unlinkSync(testFile);
  }
}

describe('StateManager persistence', () => {
  afterEach(() => {
    cleanup();
  });

  it('restores state from file backend', () => {
    cleanup();
    const manager = new StateManager({ backend: 'file', storagePath: testFile });
    manager.setRouteState('r1', {
      routeId: 'r1',
      status: 'active',
      lastUpdated: new Date().toISOString(),
      metrics: { requestCount: 1, averageLatency: 10, errorRate: 0 }
    });
    manager.shutdown();

    const manager2 = new StateManager({ backend: 'file', storagePath: testFile });
    const state = manager2.getRouteState('r1');
    expect(state).toBeDefined();
    expect(state?.status).toBe('active');
  });
});
