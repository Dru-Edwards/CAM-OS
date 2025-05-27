import { Logger } from '../shared/logger.js';
import { CAMError } from '../shared/errors.js';
import { 
  RouteState, 
  CollaborationState, 
  StateSnapshot,
  StateChangeEvent,
  StateManagerConfig 
} from '../shared/types.js';

/**
 * State Manager for Complete Arbitration Mesh
 * Manages both routing state (CAM Classic) and collaboration state (IACP)
 */
export class StateManager {
  private routeStates: Map<string, RouteState> = new Map();
  private collaborationStates: Map<string, CollaborationState> = new Map();
  private snapshots: StateSnapshot[] = [];
  private listeners: Set<(event: StateChangeEvent) => void> = new Set();
  private readonly maxSnapshots: number;
  private readonly logger: Logger;

  constructor(config: StateManagerConfig = {}) {
    this.maxSnapshots = config.maxSnapshots || 100;
    this.logger = new Logger('StateManager');
    
    this.logger.info('State Manager initialized', {
      maxSnapshots: this.maxSnapshots
    });
  }

  /**
   * Set route state (CAM Classic functionality)
   */
  setRouteState(routeId: string, state: RouteState): void {
    try {
      const previousState = this.routeStates.get(routeId);
      this.routeStates.set(routeId, {
        ...state,
        lastUpdated: new Date().toISOString()
      });

      this.emitStateChange({
        type: 'route_state_changed',
        routeId,
        previousState,
        newState: state,
        timestamp: new Date().toISOString()
      });

      this.createSnapshot();
      
      this.logger.debug('Route state updated', { routeId, state });
    } catch (error) {
      this.logger.error('Failed to set route state', { routeId, error });
      throw new CAMError('STATE_UPDATE_FAILED', `Failed to update route state: ${error}`);
    }
  }

  /**
   * Get route state (CAM Classic functionality)
   */
  getRouteState(routeId: string): RouteState | undefined {
    return this.routeStates.get(routeId);
  }

  /**
   * Set collaboration state (IACP functionality)
   */
  setCollaborationState(sessionId: string, state: CollaborationState): void {
    try {
      const previousState = this.collaborationStates.get(sessionId);
      this.collaborationStates.set(sessionId, {
        ...state,
        lastUpdated: new Date().toISOString()
      });

      this.emitStateChange({
        type: 'collaboration_state_changed',
        sessionId,
        previousState,
        newState: state,
        timestamp: new Date().toISOString()
      });

      this.createSnapshot();
      
      this.logger.debug('Collaboration state updated', { sessionId, state });
    } catch (error) {
      this.logger.error('Failed to set collaboration state', { sessionId, error });
      throw new CAMError('STATE_UPDATE_FAILED', `Failed to update collaboration state: ${error}`);
    }
  }

  /**
   * Get collaboration state (IACP functionality)
   */
  getCollaborationState(sessionId: string): CollaborationState | undefined {
    return this.collaborationStates.get(sessionId);
  }

  /**
   * Get all active route states
   */
  getAllRouteStates(): Map<string, RouteState> {
    return new Map(this.routeStates);
  }

  /**
   * Get all active collaboration states
   */
  getAllCollaborationStates(): Map<string, CollaborationState> {
    return new Map(this.collaborationStates);
  }

  /**
   * Clear expired states based on TTL
   */
  cleanupExpiredStates(): void {
    const now = Date.now();
    let cleanedCount = 0;

    // Clean route states
    for (const [routeId, state] of this.routeStates.entries()) {
      if (state.expiresAt && new Date(state.expiresAt).getTime() < now) {
        this.routeStates.delete(routeId);
        cleanedCount++;
        
        this.emitStateChange({
          type: 'route_state_expired',
          routeId,
          timestamp: new Date().toISOString()
        });
      }
    }

    // Clean collaboration states
    for (const [sessionId, state] of this.collaborationStates.entries()) {
      if (state.expiresAt && new Date(state.expiresAt).getTime() < now) {
        this.collaborationStates.delete(sessionId);
        cleanedCount++;
        
        this.emitStateChange({
          type: 'collaboration_state_expired',
          sessionId,
          timestamp: new Date().toISOString()
        });
      }
    }

    if (cleanedCount > 0) {
      this.logger.info('Cleaned up expired states', { cleanedCount });
      this.createSnapshot();
    }
  }

  /**
   * Create a state snapshot
   */
  private createSnapshot(): void {
    const snapshot: StateSnapshot = {
      timestamp: new Date().toISOString(),
      routeStates: new Map(this.routeStates),
      collaborationStates: new Map(this.collaborationStates)
    };

    this.snapshots.push(snapshot);

    // Maintain snapshot limit
    if (this.snapshots.length > this.maxSnapshots) {
      this.snapshots = this.snapshots.slice(-this.maxSnapshots);
    }
  }

  /**
   * Get state snapshot by timestamp
   */
  getSnapshot(timestamp?: string): StateSnapshot | undefined {
    if (!timestamp) {
      return this.snapshots[this.snapshots.length - 1];
    }
    
    return this.snapshots.find(s => s.timestamp === timestamp);
  }

  /**
   * Get all snapshots
   */
  getAllSnapshots(): StateSnapshot[] {
    return [...this.snapshots];
  }

  /**
   * Restore state from snapshot
   */
  restoreFromSnapshot(timestamp: string): boolean {
    try {
      const snapshot = this.getSnapshot(timestamp);
      if (!snapshot) {
        this.logger.warn('Snapshot not found', { timestamp });
        return false;
      }

      this.routeStates = new Map(snapshot.routeStates);
      this.collaborationStates = new Map(snapshot.collaborationStates);

      this.emitStateChange({
        type: 'state_restored',
        timestamp: new Date().toISOString(),
        snapshotTimestamp: timestamp
      });

      this.logger.info('State restored from snapshot', { timestamp });
      return true;
    } catch (error) {
      this.logger.error('Failed to restore from snapshot', { timestamp, error });
      throw new CAMError('STATE_RESTORE_FAILED', `Failed to restore state: ${error}`);
    }
  }

  /**
   * Add state change listener
   */
  addStateChangeListener(listener: (event: StateChangeEvent) => void): void {
    this.listeners.add(listener);
  }

  /**
   * Remove state change listener
   */
  removeStateChangeListener(listener: (event: StateChangeEvent) => void): void {
    this.listeners.delete(listener);
  }

  /**
   * Emit state change event
   */
  private emitStateChange(event: StateChangeEvent): void {
    for (const listener of this.listeners) {
      try {
        listener(event);
      } catch (error) {
        this.logger.error('State change listener failed', { error });
      }
    }
  }

  /**
   * Get system health metrics
   */
  getHealthMetrics() {
    return {
      routeStatesCount: this.routeStates.size,
      collaborationStatesCount: this.collaborationStates.size,
      snapshotsCount: this.snapshots.length,
      listenersCount: this.listeners.size,
      memoryUsage: {
        routeStates: this.estimateMapSize(this.routeStates),
        collaborationStates: this.estimateMapSize(this.collaborationStates),
        snapshots: this.snapshots.length * 1024 // Rough estimate
      }
    };
  }

  /**
   * Estimate memory usage of a Map
   */
  private estimateMapSize(map: Map<string, any>): number {
    let size = 0;
    for (const [key, value] of map.entries()) {
      size += key.length * 2; // UTF-16 chars
      size += JSON.stringify(value).length * 2;
    }
    return size;
  }

  /**
   * Shutdown and cleanup
   */
  shutdown(): void {
    this.routeStates.clear();
    this.collaborationStates.clear();
    this.snapshots.length = 0;
    this.listeners.clear();
    
    this.logger.info('State Manager shutdown complete');
  }

  /**
   * Update system configuration
   */
  async updateConfiguration(config: any): Promise<any> {
    try {
      this.logger.info('Configuration update requested', { config });
      
      // Mock configuration update - in production this would update actual config
      const updatedFields: string[] = [];
      
      if (config.logLevel) {
        updatedFields.push('logLevel');
      }
      
      if (config.policies) {
        updatedFields.push('policies');
      }
      
      if (config.collaboration) {
        updatedFields.push('collaboration');
      }

      const result = {
        success: true,
        message: 'Configuration updated successfully',
        updatedFields,
        timestamp: new Date().toISOString()
      };
      
      this.logger.info('Configuration updated', result);
      return result;
    } catch (error) {
      this.logger.error('Configuration update failed', { error });
      throw new CAMError('CONFIG_UPDATE_FAILED', `Failed to update configuration: ${error}`);
    }
  }

  /**
   * Get system metrics
   */
  async getMetrics(query: any): Promise<any> {
    try {
      const metrics = this.getHealthMetrics();
      
      return {
        timeRange: {
          start: query.startTime || new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
          end: query.endTime || new Date().toISOString()
        },
        granularity: query.granularity || 'hour',
        data: [
          {
            timestamp: new Date().toISOString(),
            metric: 'route_states_count',
            value: metrics.routeStatesCount,
            labels: { component: 'state_manager' }
          },
          {
            timestamp: new Date().toISOString(),
            metric: 'collaboration_states_count',
            value: metrics.collaborationStatesCount,
            labels: { component: 'state_manager' }
          },
          {
            timestamp: new Date().toISOString(),
            metric: 'memory_usage_bytes',
            value: metrics.memoryUsage.routeStates + metrics.memoryUsage.collaborationStates,
            labels: { component: 'state_manager' }
          }
        ]
      };
    } catch (error) {
      this.logger.error('Failed to get metrics', { error });
      throw new CAMError('METRICS_FAILED', `Failed to get metrics: ${error}`);
    }
  }

  /**
   * Get health status
   */
  async getHealthStatus(): Promise<any> {
    try {
      const metrics = this.getHealthMetrics();
      
      // Determine health based on metrics
      let status: 'healthy' | 'degraded' | 'unhealthy' = 'healthy';
      
      if (metrics.routeStatesCount > 10000 || metrics.collaborationStatesCount > 1000) {
        status = 'degraded';
      }
      
      if (metrics.memoryUsage.routeStates + metrics.memoryUsage.collaborationStates > 100 * 1024 * 1024) { // 100MB
        status = 'unhealthy';
      }

      return {
        status,
        component: 'state_manager',
        metrics,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      this.logger.error('Health check failed', { error });
      return {
        status: 'unhealthy',
        component: 'state_manager',
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString()
      };
    }
  }
}
