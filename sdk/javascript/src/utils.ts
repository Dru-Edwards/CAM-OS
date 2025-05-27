/**
 * Complete Arbitration Mesh SDK - Utility Functions
 * 
 * Common utility functions for the CAM JavaScript/TypeScript SDK.
 */

import * as Types from './types';
import * as Errors from './errors';

/**
 * Logger interface for standardized logging
 */
export interface Logger {
  debug(message: string, meta?: any): void;
  info(message: string, meta?: any): void;
  warn(message: string, meta?: any): void;
  error(message: string, meta?: any): void;
}

/**
 * Default console logger implementation
 */
export class ConsoleLogger implements Logger {
  constructor(private level: Types.LogLevel = 'info') {}

  private shouldLog(level: Types.LogLevel): boolean {
    const levels: Record<Types.LogLevel, number> = {
      debug: 0,
      info: 1,
      warn: 2,
      error: 3
    };
    return levels[level] >= levels[this.level];
  }

  debug(message: string, meta?: any): void {
    if (this.shouldLog('debug')) {
      console.debug(`[CAM SDK] ${message}`, meta || '');
    }
  }

  info(message: string, meta?: any): void {
    if (this.shouldLog('info')) {
      console.info(`[CAM SDK] ${message}`, meta || '');
    }
  }

  warn(message: string, meta?: any): void {
    if (this.shouldLog('warn')) {
      console.warn(`[CAM SDK] ${message}`, meta || '');
    }
  }

  error(message: string, meta?: any): void {
    if (this.shouldLog('error')) {
      console.error(`[CAM SDK] ${message}`, meta || '');
    }
  }
}

/**
 * Create a retry wrapper function with exponential backoff
 */
export function createRetryWrapper<T extends (...args: any[]) => Promise<any>>(
  fn: T,
  maxRetries: number = 3,
  baseDelay: number = 1000,
  logger?: Logger
): T {
  return (async (...args: Parameters<T>): Promise<ReturnType<T>> => {
    let lastError: Error;
    
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        return await fn(...args);
      } catch (error) {
        lastError = error as Error;
        
        // Don't retry on certain error types
        if (
          error instanceof Errors.CAMAuthenticationError ||
          error instanceof Errors.CAMValidationError ||
          error instanceof Errors.CAMConfigurationError
        ) {
          throw error;
        }
        
        if (attempt === maxRetries) {
          logger?.error(`Final retry attempt failed`, { 
            attempt: attempt + 1, 
            error: error.message 
          });
          break;
        }
        
        const delay = baseDelay * Math.pow(2, attempt) + Math.random() * 1000;
        logger?.warn(`Retry attempt ${attempt + 1}/${maxRetries + 1} after ${delay}ms`, {
          error: error.message
        });
        
        await sleep(delay);
      }
    }
    
    throw lastError;
  }) as T;
}

/**
 * Sleep utility function
 */
export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Validate request parameters
 */
export function validateRequest(request: Types.CAMRequest): void {
  if (!request) {
    throw new Errors.CAMValidationError('Request is required', 'request');
  }

  if (!request.message || typeof request.message !== 'string') {
    throw new Errors.CAMValidationError('Message is required and must be a string', 'message');
  }

  if (request.model && typeof request.model !== 'string') {
    throw new Errors.CAMValidationError('Model must be a string', 'model');
  }

  if (request.maxTokens && (!Number.isInteger(request.maxTokens) || request.maxTokens <= 0)) {
    throw new Errors.CAMValidationError('Max tokens must be a positive integer', 'maxTokens');
  }

  if (request.temperature && (typeof request.temperature !== 'number' || request.temperature < 0 || request.temperature > 2)) {
    throw new Errors.CAMValidationError('Temperature must be a number between 0 and 2', 'temperature');
  }

  if (request.topP && (typeof request.topP !== 'number' || request.topP < 0 || request.topP > 1)) {
    throw new Errors.CAMValidationError('TopP must be a number between 0 and 1', 'topP');
  }

  if (request.stream && typeof request.stream !== 'boolean') {
    throw new Errors.CAMValidationError('Stream must be a boolean', 'stream');
  }
}

/**
 * Validate collaboration request parameters
 */
export function validateCollaborationRequest(request: Types.CollaborationRequest): void {
  if (!request) {
    throw new Errors.CAMValidationError('Collaboration request is required', 'request');
  }

  if (!request.sessionId || typeof request.sessionId !== 'string') {
    throw new Errors.CAMValidationError('Session ID is required and must be a string', 'sessionId');
  }

  if (!request.agents || !Array.isArray(request.agents) || request.agents.length === 0) {
    throw new Errors.CAMValidationError('Agents array is required and must not be empty', 'agents');
  }

  request.agents.forEach((agent, index) => {
    if (!agent.id || typeof agent.id !== 'string') {
      throw new Errors.CAMValidationError(`Agent ${index} ID is required and must be a string`, `agents[${index}].id`);
    }
    
    if (!agent.role || typeof agent.role !== 'string') {
      throw new Errors.CAMValidationError(`Agent ${index} role is required and must be a string`, `agents[${index}].role`);
    }
  });

  if (!request.task || typeof request.task !== 'string') {
    throw new Errors.CAMValidationError('Task is required and must be a string', 'task');
  }

  if (request.maxRounds && (!Number.isInteger(request.maxRounds) || request.maxRounds <= 0)) {
    throw new Errors.CAMValidationError('Max rounds must be a positive integer', 'maxRounds');
  }
}

/**
 * Parse API response and handle errors
 */
export async function parseResponse<T>(response: Response): Promise<T> {
  const contentType = response.headers.get('content-type');
  
  if (!response.ok) {
    let errorMessage = `HTTP ${response.status}: ${response.statusText}`;
    let errorDetails: any = {};
    
    try {
      if (contentType?.includes('application/json')) {
        const errorData = await response.json();
        errorMessage = errorData.message || errorData.error || errorMessage;
        errorDetails = errorData;
      } else {
        errorMessage = await response.text() || errorMessage;
      }
    } catch {
      // Ignore parsing errors, use default message
    }
    
    // Map HTTP status codes to specific error types
    switch (response.status) {
      case 401:
        throw new Errors.CAMAuthenticationError(errorMessage, errorDetails);
      case 403:
        throw new Errors.CAMAuthorizationError(errorMessage, errorDetails);
      case 429:
        throw new Errors.CAMRateLimitError(errorMessage, errorDetails);
      case 400:
        throw new Errors.CAMValidationError(errorMessage, errorDetails);
      case 408:
      case 504:
        throw new Errors.CAMTimeoutError(errorMessage, errorDetails);
      case 500:
      case 502:
      case 503:
        throw new Errors.CAMProviderError(errorMessage, errorDetails);
      default:
        throw new Errors.CAMAPIError(errorMessage, response.status, errorDetails);
    }
  }
  
  if (!contentType?.includes('application/json')) {
    throw new Errors.CAMAPIError('Expected JSON response', response.status);
  }
  
  try {
    return await response.json();
  } catch (error) {
    throw new Errors.CAMAPIError('Failed to parse JSON response', response.status, error);
  }
}

/**
 * Generate request signature for authentication
 */
export function generateRequestSignature(
  method: string,
  path: string,
  body: string,
  timestamp: number,
  apiKey: string
): string {
  // Simple signature generation - in production, use proper HMAC
  const payload = `${method}|${path}|${body}|${timestamp}`;
  return btoa(`${apiKey}:${payload}`);
}

/**
 * Format headers for API requests
 */
export function formatHeaders(
  apiKey: string,
  options: {
    contentType?: string;
    timestamp?: number;
    signature?: string;
    userAgent?: string;
  } = {}
): Record<string, string> {
  const timestamp = options.timestamp || Date.now();
  const headers: Record<string, string> = {
    'Authorization': `Bearer ${apiKey}`,
    'Content-Type': options.contentType || 'application/json',
    'User-Agent': options.userAgent || 'CAM-SDK-JS/1.0.0',
    'X-Timestamp': timestamp.toString(),
  };

  if (options.signature) {
    headers['X-Signature'] = options.signature;
  }

  return headers;
}

/**
 * Deep merge two objects
 */
export function deepMerge<T extends Record<string, any>>(target: T, source: Partial<T>): T {
  const result = { ...target };
  
  for (const key in source) {
    if (source.hasOwnProperty(key)) {
      const sourceValue = source[key];
      const targetValue = result[key];
      
      if (isObject(sourceValue) && isObject(targetValue)) {
        result[key] = deepMerge(targetValue, sourceValue);
      } else {
        result[key] = sourceValue as T[Extract<keyof T, string>];
      }
    }
  }
  
  return result;
}

/**
 * Check if value is a plain object
 */
function isObject(value: any): value is Record<string, any> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * Sanitize object for logging (remove sensitive data)
 */
export function sanitizeForLogging(obj: any): any {
  if (!isObject(obj)) {
    return obj;
  }
  
  const sanitized = { ...obj };
  const sensitiveKeys = ['apiKey', 'password', 'token', 'secret', 'authorization'];
  
  for (const key in sanitized) {
    if (sensitiveKeys.some(sensitive => key.toLowerCase().includes(sensitive))) {
      sanitized[key] = '[REDACTED]';
    } else if (isObject(sanitized[key])) {
      sanitized[key] = sanitizeForLogging(sanitized[key]);
    }
  }
  
  return sanitized;
}

/**
 * Generate unique request ID
 */
export function generateRequestId(): string {
  return `cam_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * Format duration in milliseconds to human-readable string
 */
export function formatDuration(ms: number): string {
  if (ms < 1000) {
    return `${ms}ms`;
  } else if (ms < 60000) {
    return `${(ms / 1000).toFixed(1)}s`;
  } else {
    return `${(ms / 60000).toFixed(1)}m`;
  }
}

/**
 * Validate URL format
 */
export function isValidUrl(url: string): boolean {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

/**
 * Extract hostname from URL
 */
export function extractHostname(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return 'unknown';
  }
}

/**
 * Calculate exponential backoff delay
 */
export function calculateBackoffDelay(
  attempt: number,
  baseDelay: number = 1000,
  maxDelay: number = 30000,
  jitter: boolean = true
): number {
  const exponentialDelay = baseDelay * Math.pow(2, attempt);
  const delay = Math.min(exponentialDelay, maxDelay);
  
  if (jitter) {
    // Add random jitter (±25%)
    const jitterAmount = delay * 0.25;
    return delay + (Math.random() - 0.5) * 2 * jitterAmount;
  }
  
  return delay;
}

/**
 * Chunk array into smaller arrays
 */
export function chunkArray<T>(array: T[], chunkSize: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < array.length; i += chunkSize) {
    chunks.push(array.slice(i, i + chunkSize));
  }
  return chunks;
}

/**
 * Rate limiter utility
 */
export class RateLimiter {
  private tokens: number;
  private lastRefill: number;
  private readonly maxTokens: number;
  private readonly refillRate: number; // tokens per second

  constructor(maxTokens: number, refillRate: number) {
    this.maxTokens = maxTokens;
    this.refillRate = refillRate;
    this.tokens = maxTokens;
    this.lastRefill = Date.now();
  }

  async waitForToken(): Promise<void> {
    this.refillTokens();
    
    if (this.tokens >= 1) {
      this.tokens -= 1;
      return;
    }
    
    // Calculate how long to wait for the next token
    const timeToNextToken = (1 / this.refillRate) * 1000;
    await sleep(timeToNextToken);
    
    return this.waitForToken();
  }

  private refillTokens(): void {
    const now = Date.now();
    const timePassed = (now - this.lastRefill) / 1000;
    const tokensToAdd = timePassed * this.refillRate;
    
    this.tokens = Math.min(this.maxTokens, this.tokens + tokensToAdd);
    this.lastRefill = now;
  }
}

/**
 * Simple in-memory cache implementation
 */
export class MemoryCache<T = any> {
  private cache = new Map<string, { value: T; expires: number }>();
  private readonly defaultTTL: number;

  constructor(defaultTTL: number = 300000) { // 5 minutes default
    this.defaultTTL = defaultTTL;
  }

  set(key: string, value: T, ttl?: number): void {
    const expires = Date.now() + (ttl || this.defaultTTL);
    this.cache.set(key, { value, expires });
  }

  get(key: string): T | undefined {
    const item = this.cache.get(key);
    
    if (!item) {
      return undefined;
    }
    
    if (Date.now() > item.expires) {
      this.cache.delete(key);
      return undefined;
    }
    
    return item.value;
  }

  delete(key: string): boolean {
    return this.cache.delete(key);
  }

  clear(): void {
    this.cache.clear();
  }

  size(): number {
    // Clean expired entries first
    this.cleanExpired();
    return this.cache.size;
  }

  private cleanExpired(): void {
    const now = Date.now();
    for (const [key, item] of this.cache.entries()) {
      if (now > item.expires) {
        this.cache.delete(key);
      }
    }
  }
}

/**
 * Event debouncer utility
 */
export function debounce<T extends (...args: any[]) => void>(
  func: T,
  wait: number
): T {
  let timeout: NodeJS.Timeout | null = null;
  
  return ((...args: Parameters<T>) => {
    if (timeout) {
      clearTimeout(timeout);
    }
    
    timeout = setTimeout(() => {
      func(...args);
    }, wait);
  }) as T;
}

/**
 * Event throttler utility
 */
export function throttle<T extends (...args: any[]) => void>(
  func: T,
  limit: number
): T {
  let inThrottle: boolean;
  
  return ((...args: Parameters<T>) => {
    if (!inThrottle) {
      func(...args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  }) as T;
}
