/**
 * Constants used throughout the Complete Arbitration Mesh
 */

export const VERSION = '2.0.0';
export const API_VERSION = '2.0';

export const DEFAULT_ENDPOINTS = {
  PRODUCTION: 'https://api.complete-cam.com',
  STAGING: 'https://staging-api.complete-cam.com',
  DEVELOPMENT: 'http://localhost:8080'
} as const;

export const SUPPORTED_PROVIDERS = [
  'openai',
  'anthropic',
  'google',
  'azure-openai',
  'custom'
] as const;

export const COLLABORATION_STATUSES = [
  'initializing',
  'active',
  'completed',
  'failed',
  'timeout'
] as const;

export const AGENT_STATUSES = [
  'available',
  'busy',
  'offline',
  'error'
] as const;

export const TASK_PRIORITIES = [
  'low',
  'medium',
  'high',
  'critical'
] as const;

export const WORKFLOW_STEP_TYPES = [
  'task',
  'decision',
  'parallel',
  'sequential'
] as const;

export const HEALTH_STATUSES = [
  'healthy',
  'degraded',
  'unhealthy'
] as const;

export const DEFAULT_TIMEOUTS = {
  REQUEST_TIMEOUT: 30000,
  COLLABORATION_TIMEOUT: 300000,
  AGENT_DISCOVERY_TIMEOUT: 10000,
  WORKFLOW_STEP_TIMEOUT: 60000
} as const;

export const DEFAULT_LIMITS = {
  MAX_CONCURRENT_REQUESTS: 1000,
  MAX_CONCURRENT_COLLABORATIONS: 100,
  MAX_AGENTS_PER_COLLABORATION: 10,
  MAX_WORKFLOW_STEPS: 50,
  MAX_MESSAGE_SIZE: 1024 * 1024, // 1MB
  MAX_RETRY_ATTEMPTS: 3
} as const;

export const METRICS_NAMES = {
  ROUTING: {
    REQUESTS_TOTAL: 'cam_routing_requests_total',
    REQUESTS_DURATION: 'cam_routing_requests_duration_seconds',
    REQUESTS_ERRORS: 'cam_routing_requests_errors_total',
    PROVIDER_LATENCY: 'cam_provider_latency_seconds',
    PROVIDER_COST: 'cam_provider_cost_total'
  },
  COLLABORATION: {
    SESSIONS_TOTAL: 'cam_collaboration_sessions_total',
    SESSIONS_DURATION: 'cam_collaboration_sessions_duration_seconds',
    SESSIONS_ERRORS: 'cam_collaboration_sessions_errors_total',
    AGENTS_DISCOVERED: 'cam_agents_discovered_total',
    TASKS_DECOMPOSED: 'cam_tasks_decomposed_total'
  },
  SYSTEM: {
    HEALTH_STATUS: 'cam_system_health_status',
    MEMORY_USAGE: 'cam_system_memory_usage_bytes',
    CPU_USAGE: 'cam_system_cpu_usage_percent',
    ACTIVE_CONNECTIONS: 'cam_system_active_connections'
  }
} as const;

export const ERROR_CODES = {
  // Authentication & Authorization
  UNAUTHORIZED: 'UNAUTHORIZED',
  FORBIDDEN: 'FORBIDDEN',
  INVALID_API_KEY: 'INVALID_API_KEY',
  TOKEN_EXPIRED: 'TOKEN_EXPIRED',

  // Validation
  INVALID_REQUEST: 'INVALID_REQUEST',
  MISSING_REQUIRED_FIELD: 'MISSING_REQUIRED_FIELD',
  INVALID_FIELD_VALUE: 'INVALID_FIELD_VALUE',

  // Routing
  NO_PROVIDERS_AVAILABLE: 'NO_PROVIDERS_AVAILABLE',
  PROVIDER_ERROR: 'PROVIDER_ERROR',
  POLICY_VIOLATION: 'POLICY_VIOLATION',
  ROUTING_FAILED: 'ROUTING_FAILED',

  // Collaboration
  AGENT_NOT_FOUND: 'AGENT_NOT_FOUND',
  COLLABORATION_FAILED: 'COLLABORATION_FAILED',
  TASK_DECOMPOSITION_FAILED: 'TASK_DECOMPOSITION_FAILED',
  WORKFLOW_EXECUTION_FAILED: 'WORKFLOW_EXECUTION_FAILED',

  // System
  INTERNAL_ERROR: 'INTERNAL_ERROR',
  SERVICE_UNAVAILABLE: 'SERVICE_UNAVAILABLE',
  TIMEOUT: 'TIMEOUT',
  RATE_LIMITED: 'RATE_LIMITED',
  QUOTA_EXCEEDED: 'QUOTA_EXCEEDED'
} as const;

export const HTTP_STATUS_CODES = {
  OK: 200,
  CREATED: 201,
  ACCEPTED: 202,
  NO_CONTENT: 204,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  METHOD_NOT_ALLOWED: 405,
  CONFLICT: 409,
  UNPROCESSABLE_ENTITY: 422,
  TOO_MANY_REQUESTS: 429,
  INTERNAL_SERVER_ERROR: 500,
  BAD_GATEWAY: 502,
  SERVICE_UNAVAILABLE: 503,
  GATEWAY_TIMEOUT: 504
} as const;
