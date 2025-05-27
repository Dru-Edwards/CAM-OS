/**
 * CAM SDK Error Classes
 * 
 * Custom error types for the Complete Arbitration Mesh SDK.
 */

/**
 * Base CAM error class
 */
export class CAMError extends Error {
  public readonly code: string;
  public readonly statusCode?: number;
  public readonly details?: any;
  public readonly requestId?: string;

  constructor(message: string, code: string, statusCode?: number, details?: any, requestId?: string) {
    super(message);
    this.name = 'CAMError';
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
    this.requestId = requestId;

    // Maintain proper stack trace
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, CAMError);
    }
  }
}

/**
 * Authentication error
 */
export class CAMAuthenticationError extends CAMError {
  constructor(message: string = 'Authentication failed', details?: any, requestId?: string) {
    super(message, 'AUTHENTICATION_ERROR', 401, details, requestId);
    this.name = 'CAMAuthenticationError';
  }
}

/**
 * Authorization error
 */
export class CAMAuthorizationError extends CAMError {
  constructor(message: string = 'Authorization failed', details?: any, requestId?: string) {
    super(message, 'AUTHORIZATION_ERROR', 403, details, requestId);
    this.name = 'CAMAuthorizationError';
  }
}

/**
 * Rate limit error
 */
export class CAMRateLimitError extends CAMError {
  public readonly retryAfter: number;
  public readonly limit: number;
  public readonly remaining: number;
  public readonly resetTime: Date;

  constructor(
    message: string = 'Rate limit exceeded',
    retryAfter: number = 60,
    limit: number = 1000,
    remaining: number = 0,
    resetTime: Date = new Date(Date.now() + retryAfter * 1000),
    requestId?: string
  ) {
    super(message, 'RATE_LIMIT_ERROR', 429, { retryAfter, limit, remaining, resetTime }, requestId);
    this.name = 'CAMRateLimitError';
    this.retryAfter = retryAfter;
    this.limit = limit;
    this.remaining = remaining;
    this.resetTime = resetTime;
  }
}

/**
 * Validation error
 */
export class CAMValidationError extends CAMError {
  public readonly validationErrors: ValidationErrorDetail[];

  constructor(message: string = 'Validation failed', validationErrors: ValidationErrorDetail[] = [], requestId?: string) {
    super(message, 'VALIDATION_ERROR', 400, { validationErrors }, requestId);
    this.name = 'CAMValidationError';
    this.validationErrors = validationErrors;
  }
}

export interface ValidationErrorDetail {
  field: string;
  message: string;
  code: string;
  value?: any;
}

/**
 * Timeout error
 */
export class CAMTimeoutError extends CAMError {
  public readonly timeout: number;

  constructor(message: string = 'Request timed out', timeout: number = 30000, requestId?: string) {
    super(message, 'TIMEOUT_ERROR', 408, { timeout }, requestId);
    this.name = 'CAMTimeoutError';
    this.timeout = timeout;
  }
}

/**
 * Network error
 */
export class CAMNetworkError extends CAMError {
  public readonly originalError: Error;

  constructor(message: string = 'Network error', originalError: Error, requestId?: string) {
    super(message, 'NETWORK_ERROR', undefined, { originalError: originalError.message }, requestId);
    this.name = 'CAMNetworkError';
    this.originalError = originalError;
  }
}

/**
 * Provider error
 */
export class CAMProviderError extends CAMError {
  public readonly provider: string;
  public readonly providerError: any;

  constructor(
    message: string = 'Provider error',
    provider: string,
    providerError: any,
    statusCode?: number,
    requestId?: string
  ) {
    super(message, 'PROVIDER_ERROR', statusCode, { provider, providerError }, requestId);
    this.name = 'CAMProviderError';
    this.provider = provider;
    this.providerError = providerError;
  }
}

/**
 * Collaboration error
 */
export class CAMCollaborationError extends CAMError {
  public readonly collaborationId?: string;
  public readonly failedAgents: string[];
  public readonly iteration?: number;

  constructor(
    message: string = 'Collaboration failed',
    failedAgents: string[] = [],
    collaborationId?: string,
    iteration?: number,
    requestId?: string
  ) {
    super(message, 'COLLABORATION_ERROR', 500, { collaborationId, failedAgents, iteration }, requestId);
    this.name = 'CAMCollaborationError';
    this.collaborationId = collaborationId;
    this.failedAgents = failedAgents;
    this.iteration = iteration;
  }
}

/**
 * Configuration error
 */
export class CAMConfigurationError extends CAMError {
  public readonly configField: string;

  constructor(message: string = 'Configuration error', configField: string = 'unknown') {
    super(message, 'CONFIGURATION_ERROR', undefined, { configField });
    this.name = 'CAMConfigurationError';
    this.configField = configField;
  }
}

/**
 * Service unavailable error
 */
export class CAMServiceUnavailableError extends CAMError {
  public readonly service: string;
  public readonly retryAfter?: number;

  constructor(
    message: string = 'Service unavailable',
    service: string = 'unknown',
    retryAfter?: number,
    requestId?: string
  ) {
    super(message, 'SERVICE_UNAVAILABLE', 503, { service, retryAfter }, requestId);
    this.name = 'CAMServiceUnavailableError';
    this.service = service;
    this.retryAfter = retryAfter;
  }
}

/**
 * Quota exceeded error
 */
export class CAMQuotaExceededError extends CAMError {
  public readonly quotaType: string;
  public readonly limit: number;
  public readonly used: number;
  public readonly resetTime?: Date;

  constructor(
    message: string = 'Quota exceeded',
    quotaType: string = 'requests',
    limit: number = 0,
    used: number = 0,
    resetTime?: Date,
    requestId?: string
  ) {
    super(message, 'QUOTA_EXCEEDED', 429, { quotaType, limit, used, resetTime }, requestId);
    this.name = 'CAMQuotaExceededError';
    this.quotaType = quotaType;
    this.limit = limit;
    this.used = used;
    this.resetTime = resetTime;
  }
}

/**
 * Model not available error
 */
export class CAMModelNotAvailableError extends CAMError {
  public readonly model: string;
  public readonly provider: string;
  public readonly availableAlternatives: string[];

  constructor(
    message: string = 'Model not available',
    model: string,
    provider: string,
    availableAlternatives: string[] = [],
    requestId?: string
  ) {
    super(message, 'MODEL_NOT_AVAILABLE', 404, { model, provider, availableAlternatives }, requestId);
    this.name = 'CAMModelNotAvailableError';
    this.model = model;
    this.provider = provider;
    this.availableAlternatives = availableAlternatives;
  }
}

/**
 * Content filter error
 */
export class CAMContentFilterError extends CAMError {
  public readonly filterType: string;
  public readonly content: string;

  constructor(
    message: string = 'Content filtered',
    filterType: string = 'safety',
    content: string = '',
    requestId?: string
  ) {
    super(message, 'CONTENT_FILTERED', 400, { filterType, content }, requestId);
    this.name = 'CAMContentFilterError';
    this.filterType = filterType;
    this.content = content;
  }
}

/**
 * Error factory function to create appropriate error types from API responses
 */
export function createCAMError(
  errorData: any,
  statusCode?: number,
  requestId?: string
): CAMError {
  const { code, message, details } = errorData;

  switch (code) {
    case 'AUTHENTICATION_ERROR':
      return new CAMAuthenticationError(message, details, requestId);
    
    case 'AUTHORIZATION_ERROR':
      return new CAMAuthorizationError(message, details, requestId);
    
    case 'RATE_LIMIT_ERROR':
      return new CAMRateLimitError(
        message,
        details?.retryAfter,
        details?.limit,
        details?.remaining,
        details?.resetTime ? new Date(details.resetTime) : undefined,
        requestId
      );
    
    case 'VALIDATION_ERROR':
      return new CAMValidationError(message, details?.validationErrors, requestId);
    
    case 'TIMEOUT_ERROR':
      return new CAMTimeoutError(message, details?.timeout, requestId);
    
    case 'NETWORK_ERROR':
      return new CAMNetworkError(message, new Error(details?.originalError || 'Unknown network error'), requestId);
    
    case 'PROVIDER_ERROR':
      return new CAMProviderError(
        message,
        details?.provider || 'unknown',
        details?.providerError,
        statusCode,
        requestId
      );
    
    case 'COLLABORATION_ERROR':
      return new CAMCollaborationError(
        message,
        details?.failedAgents || [],
        details?.collaborationId,
        details?.iteration,
        requestId
      );
    
    case 'CONFIGURATION_ERROR':
      return new CAMConfigurationError(message, details?.configField);
    
    case 'SERVICE_UNAVAILABLE':
      return new CAMServiceUnavailableError(
        message,
        details?.service || 'unknown',
        details?.retryAfter,
        requestId
      );
    
    case 'QUOTA_EXCEEDED':
      return new CAMQuotaExceededError(
        message,
        details?.quotaType || 'requests',
        details?.limit || 0,
        details?.used || 0,
        details?.resetTime ? new Date(details.resetTime) : undefined,
        requestId
      );
    
    case 'MODEL_NOT_AVAILABLE':
      return new CAMModelNotAvailableError(
        message,
        details?.model || 'unknown',
        details?.provider || 'unknown',
        details?.availableAlternatives || [],
        requestId
      );
    
    case 'CONTENT_FILTERED':
      return new CAMContentFilterError(
        message,
        details?.filterType || 'safety',
        details?.content || '',
        requestId
      );
    
    default:
      return new CAMError(message || 'Unknown error', code || 'UNKNOWN_ERROR', statusCode, details, requestId);
  }
}

/**
 * Check if an error is a CAM error
 */
export function isCAMError(error: any): error is CAMError {
  return error instanceof CAMError;
}

/**
 * Check if an error is retryable
 */
export function isRetryableError(error: any): boolean {
  if (!isCAMError(error)) {
    return false;
  }

  // Retryable error types
  const retryableCodes = [
    'TIMEOUT_ERROR',
    'NETWORK_ERROR',
    'SERVICE_UNAVAILABLE',
    'RATE_LIMIT_ERROR'
  ];

  return retryableCodes.includes(error.code);
}

/**
 * Get retry delay for an error
 */
export function getRetryDelay(error: any, attempt: number, baseDelay: number = 1000): number {
  if (error instanceof CAMRateLimitError) {
    return error.retryAfter * 1000; // Convert to milliseconds
  }

  if (error instanceof CAMServiceUnavailableError && error.retryAfter) {
    return error.retryAfter * 1000;
  }

  // Exponential backoff with jitter
  const exponentialDelay = baseDelay * Math.pow(2, attempt - 1);
  const jitter = Math.random() * 0.1 * exponentialDelay;
  return Math.min(exponentialDelay + jitter, 60000); // Max 60 seconds
}
