import fs from 'fs';
import path from 'path';
import { RouteState, CollaborationState, StateSnapshot } from '../shared/types.js';

export interface PersistedState {
  routeStates: Array<[string, RouteState]>;
  collaborationStates: Array<[string, CollaborationState]>;
  snapshots: StateSnapshot[];
}

export interface PersistenceAdapter {
  load(): PersistedState;
  save(state: PersistedState): void;
}

export class InMemoryPersistence implements PersistenceAdapter {
  private state: PersistedState = { routeStates: [], collaborationStates: [], snapshots: [] };

  load(): PersistedState {
    return JSON.parse(JSON.stringify(this.state));
  }

  save(state: PersistedState): void {
    this.state = JSON.parse(JSON.stringify(state));
  }
}

export class FilePersistence implements PersistenceAdapter {
  constructor(private filePath: string) {}

  load(): PersistedState {
    try {
      if (!fs.existsSync(this.filePath)) {
        return { routeStates: [], collaborationStates: [], snapshots: [] };
      }
      const data = fs.readFileSync(this.filePath, 'utf-8');
      return JSON.parse(data);
    } catch {
      return { routeStates: [], collaborationStates: [], snapshots: [] };
    }
  }

  save(state: PersistedState): void {
    const dir = path.dirname(this.filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(this.filePath, JSON.stringify(state, null, 2), 'utf-8');
  }
}
