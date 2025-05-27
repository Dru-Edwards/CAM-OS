/**
 * Custom error classes for the Complete Arbitration Mesh
 */

export interface ErrorContext {
  requestId?: string;
  userId?: string;
  operation?: string;
  details?: Record<string, any>;
}

export class CAMError extends Error {
  public readonly code: string;
  public readonly context: ErrorContext;
  public readonly timestamp: string;

  constructor(message: string, code: string, context: ErrorContext = {}) {
    super(message);
    this.name = 'CAMError';
    this.code = code;
    this.context = context;
    this.timestamp = new Date().toISOString();
  }

  toJSON() {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      context: this.context,
      timestamp: this.timestamp,
      stack: this.stack
    };
  }
}

export class RoutingError extends CAMError {
  constructor(message: string, context: ErrorContext = {}) {
    super(message, 'ROUTING_ERROR', context);
    this.name = 'RoutingError';
  }
}

export class CollaborationError extends CAMError {
  constructor(message: string, context: ErrorContext = {}) {
    super(message, 'COLLABORATION_ERROR', context);
    this.name = 'CollaborationError';
  }
}

export class AuthenticationError extends CAMError {
  constructor(message: string, context: ErrorContext = {}) {
    super(message, 'AUTHENTICATION_ERROR', context);
    this.name = 'AuthenticationError';
  }
}

export class ValidationError extends CAMError {
  constructor(message: string, context: ErrorContext = {}) {
    super(message, 'VALIDATION_ERROR', context);
    this.name = 'ValidationError';
  }
}

export class ConfigurationError extends CAMError {
  constructor(message: string, context: ErrorContext = {}) {
    super(message, 'CONFIGURATION_ERROR', context);
    this.name = 'ConfigurationError';
  }
}

export class ProviderError extends CAMError {
  constructor(message: string, context: ErrorContext = {}) {
    super(message, 'PROVIDER_ERROR', context);
    this.name = 'ProviderError';
  }
}

export class AgentError extends CAMError {
  constructor(message: string, context: ErrorContext = {}) {
    super(message, 'AGENT_ERROR', context);
    this.name = 'AgentError';
  }
}

export class TimeoutError extends CAMError {
  constructor(message: string, context: ErrorContext = {}) {
    super(message, 'TIMEOUT_ERROR', context);
    this.name = 'TimeoutError';
  }
}

export class RateLimitError extends CAMError {
  constructor(message: string, context: ErrorContext = {}) {
    super(message, 'RATE_LIMIT_ERROR', context);
    this.name = 'RateLimitError';
  }
}
