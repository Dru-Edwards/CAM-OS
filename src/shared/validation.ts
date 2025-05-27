/**
 * Request validation utilities for the Complete Arbitration Mesh
 */

import { ValidationError } from './errors';
import type {
  AICoreRequest,
  CollaborationRequest,
  ProviderRequirements,
  AgentCapabilities,
  ComplexTask,
  CollaborationWorkflow
} from './types';

export interface ValidationResult {
  valid: boolean;
  errors: string[];
}

export function validateRequest(request: any, type: 'routing' | 'collaboration'): ValidationResult {
  if (type === 'routing') {
    return validateRoutingRequest(request);
  } else {
    return validateCollaborationRequest(request);
  }
}

export function validateRoutingRequest(request: AICoreRequest): ValidationResult {
  const errors: string[] = [];

  // Required fields
  if (!request.prompt || typeof request.prompt !== 'string') {
    errors.push('prompt is required and must be a string');
  }

  // Optional fields validation
  if (request.temperature !== undefined) {
    if (typeof request.temperature !== 'number' || request.temperature < 0 || request.temperature > 2) {
      errors.push('temperature must be a number between 0 and 2');
    }
  }

  if (request.maxTokens !== undefined) {
    if (typeof request.maxTokens !== 'number' || request.maxTokens < 1) {
      errors.push('maxTokens must be a positive number');
    }
  }

  if (request.requirements) {
    const reqValidation = validateProviderRequirements(request.requirements);
    errors.push(...reqValidation.errors);
  }

  return { valid: errors.length === 0, errors };
}

export function validateCollaborationRequest(request: CollaborationRequest): ValidationResult {
  const errors: string[] = [];

  // Required fields
  if (!request.task || typeof request.task !== 'string') {
    errors.push('task is required and must be a string');
  }

  if (!Array.isArray(request.requirements)) {
    errors.push('requirements must be an array');
  } else if (request.requirements.length === 0) {
    errors.push('requirements array cannot be empty');
  }

  // Optional fields validation
  if (request.decomposition && !['auto', 'manual'].includes(request.decomposition)) {
    errors.push('decomposition must be either "auto" or "manual"');
  }

  if (request.timeout !== undefined) {
    if (typeof request.timeout !== 'number' || request.timeout < 1000) {
      errors.push('timeout must be a number >= 1000 (milliseconds)');
    }
  }

  if (request.agents) {
    if (!Array.isArray(request.agents)) {
      errors.push('agents must be an array');
    } else {
      request.agents.forEach((agent, index) => {
        if (typeof agent !== 'string') {
          errors.push(`agents[${index}] must be a string`);
        }
      });
    }
  }

  return { valid: errors.length === 0, errors };
}

export function validateProviderRequirements(requirements: ProviderRequirements): ValidationResult {
  const errors: string[] = [];

  if (requirements.cost && !['minimize', 'optimize', 'performance'].includes(requirements.cost)) {
    errors.push('cost must be one of: minimize, optimize, performance');
  }

  if (requirements.performance && !['fast', 'balanced', 'quality'].includes(requirements.performance)) {
    errors.push('performance must be one of: fast, balanced, quality');
  }

  if (requirements.compliance && !Array.isArray(requirements.compliance)) {
    errors.push('compliance must be an array');
  }

  if (requirements.region && typeof requirements.region !== 'string') {
    errors.push('region must be a string');
  }

  if (requirements.capabilities && !Array.isArray(requirements.capabilities)) {
    errors.push('capabilities must be an array');
  }

  return { valid: errors.length === 0, errors };
}

export function validateAgentCapabilities(capabilities: AgentCapabilities): ValidationResult {
  const errors: string[] = [];

  if (!capabilities.type || typeof capabilities.type !== 'string') {
    errors.push('type is required and must be a string');
  }

  if (!Array.isArray(capabilities.skills)) {
    errors.push('skills must be an array');
  }

  if (!Array.isArray(capabilities.specializations)) {
    errors.push('specializations must be an array');
  }

  if (typeof capabilities.quality !== 'number' || capabilities.quality < 0 || capabilities.quality > 1) {
    errors.push('quality must be a number between 0 and 1');
  }

  if (typeof capabilities.cost !== 'number' || capabilities.cost < 0) {
    errors.push('cost must be a non-negative number');
  }

  return { valid: errors.length === 0, errors };
}

export function validateComplexTask(task: ComplexTask): ValidationResult {
  const errors: string[] = [];

  if (!task.id || typeof task.id !== 'string') {
    errors.push('id is required and must be a string');
  }

  if (!task.description || typeof task.description !== 'string') {
    errors.push('description is required and must be a string');
  }

  if (!Array.isArray(task.requirements)) {
    errors.push('requirements must be an array');
  }

  if (!['low', 'medium', 'high', 'critical'].includes(task.priority)) {
    errors.push('priority must be one of: low, medium, high, critical');
  }

  return { valid: errors.length === 0, errors };
}

export function validateCollaborationWorkflow(workflow: CollaborationWorkflow): ValidationResult {
  const errors: string[] = [];

  if (!workflow.id || typeof workflow.id !== 'string') {
    errors.push('id is required and must be a string');
  }

  if (!workflow.name || typeof workflow.name !== 'string') {
    errors.push('name is required and must be a string');
  }

  if (!Array.isArray(workflow.steps)) {
    errors.push('steps must be an array');
  } else if (workflow.steps.length === 0) {
    errors.push('workflow must have at least one step');
  }

  if (!Array.isArray(workflow.agents)) {
    errors.push('agents must be an array');
  }

  if (typeof workflow.timeout !== 'number' || workflow.timeout < 1000) {
    errors.push('timeout must be a number >= 1000 (milliseconds)');
  }

  // Validate each step
  workflow.steps?.forEach((step, index) => {
    if (!step.id || typeof step.id !== 'string') {
      errors.push(`steps[${index}].id is required and must be a string`);
    }

    if (!['task', 'decision', 'parallel', 'sequential'].includes(step.type)) {
      errors.push(`steps[${index}].type must be one of: task, decision, parallel, sequential`);
    }

    if (!Array.isArray(step.dependencies)) {
      errors.push(`steps[${index}].dependencies must be an array`);
    }

    if (typeof step.timeout !== 'number' || step.timeout < 1000) {
      errors.push(`steps[${index}].timeout must be a number >= 1000 (milliseconds)`);
    }
  });

  return { valid: errors.length === 0, errors };
}

export function throwIfInvalid(validation: ValidationResult, operation: string): void {
  if (!validation.valid) {
    throw new ValidationError(`Validation failed for ${operation}: ${validation.errors.join(', ')}`, {
      operation,
      details: { errors: validation.errors }
    });
  }
}
