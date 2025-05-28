import type { AgentInfo, AgentCapabilities } from '../shared/types.js';

/**
 * Simple in-memory registry used for tests and local execution.
 */
export class AgentRegistry {
  private agents: AgentInfo[];

  constructor() {
    this.agents = [
      {
        id: 'agent-analyst',
        name: 'Data Analyst',
        type: 'analysis',
        capabilities: {
          type: 'analysis',
          skills: ['data-analysis', 'statistics', 'python'],
          specializations: ['financial-modeling'],
          quality: 0.9,
          cost: 0.1
        },
        status: 'available',
        reputation: 0.95,
        metadata: {}
      },
      {
        id: 'agent-reporter',
        name: 'Reporting Specialist',
        type: 'reporting',
        capabilities: {
          type: 'reporting',
          skills: ['reporting', 'writing'],
          specializations: ['data-visualization'],
          quality: 0.85,
          cost: 0.05
        },
        status: 'available',
        reputation: 0.9,
        metadata: {}
      },
      {
        id: 'agent-visualizer',
        name: 'Visualization Expert',
        type: 'visualization',
        capabilities: {
          type: 'visualization',
          skills: ['data-visualization', 'charting'],
          specializations: ['d3.js'],
          quality: 0.88,
          cost: 0.07
        },
        status: 'available',
        reputation: 0.92,
        metadata: {}
      },
      {
        id: 'agent-financial',
        name: 'Financial Modeler',
        type: 'financial-modeling',
        capabilities: {
          type: 'financial-modeling',
          skills: ['financial-modeling', 'forecasting'],
          specializations: ['risk-analysis'],
          quality: 0.93,
          cost: 0.12
        },
        status: 'available',
        reputation: 0.94,
        metadata: {}
      }
    ];
  }

  /**
   * Find agents that satisfy the given capability requirements.
   */
  findAgents(requirements: string[]): AgentInfo[] {
    const matched: AgentInfo[] = [];
    const added = new Set<string>();
    for (const req of requirements) {
      const candidates = this.agents
        .filter(a =>
          a.type === req ||
          a.capabilities.skills.includes(req) ||
          a.capabilities.specializations.includes(req)
        )
        .sort((a, b) => b.capabilities.quality - a.capabilities.quality);
      if (candidates.length > 0) {
        const candidate = candidates[0];
        if (!added.has(candidate.id)) {
          matched.push(candidate);
          added.add(candidate.id);
        }
      }
    }
    return matched;
  }

  getAllAgents(): AgentInfo[] {
    return [...this.agents];
  }

  registerAgent(agent: AgentInfo): void {
    this.agents.push(agent);
  }
}

