/**
 * Shared types and interfaces for the Complete Arbitration Mesh
 */

// =========================================================================
// Core Configuration Types
// =========================================================================

export interface Config {
  logLevel: 'debug' | 'info' | 'warn' | 'error';
  apiVersion: string;
  environment: 'development' | 'staging' | 'production';
  update(config: Partial<Config>): void;
}

export interface ConfigurationUpdate {
  logLevel?: 'debug' | 'info' | 'warn' | 'error';
  policies?: PolicyConfiguration[];
  providers?: ProviderConfiguration[];
  collaboration?: CollaborationConfiguration;
}

export interface ConfigurationResult {
  success: boolean;
  message: string;
  updatedFields: string[];
  timestamp: string;
}

// =========================================================================
// Authentication & Authorization Types
// =========================================================================

export interface AuthToken {
  id: string;
  token: string;
  userId: string;
  expiresAt: string;
  permissions: Permission[];
}

export interface Session {
  id: string;
  type: 'routing' | 'collaboration' | 'hybrid';
  userId: string;
  createdAt: string;
  expiresAt: string;
  metadata: Record<string, any>;
}

// =========================================================================
// Extended Authentication Types (for new services)
// =========================================================================

export interface AuthRequest {
  clientId: string;
  type: 'api_key' | 'oauth' | 'certificate' | 'collaboration';
  credentials: {
    apiKey?: string;
    accessToken?: string;
    certificate?: string;
    sessionToken?: string;
    agentName?: string;
    name?: string;
    email?: string;
  };
}

export interface AuthResponse {
  success: boolean;
  token?: AuthToken;
  userInfo?: UserInfo;
  permissions?: Permission[];
  expiresAt?: string;
  error?: string;
  errorCode?: string;
}

export interface TokenValidationResult {
  valid: boolean;
  token?: AuthToken;
  userInfo?: UserInfo;
  permissions?: Permission[];
  error?: string;
  errorCode?: string;
}

export interface AuthConfig {
  jwtSecret?: string;
  tokenExpiry?: string;
  enableRefresh?: boolean;
}

export interface UserInfo {
  id: string;
  name: string;
  email: string;
  roles: string[];
  metadata?: Record<string, any>;
}

export interface Permission {
  resource: string;
  actions: string[];
  conditions?: Record<string, any>;
}

// =========================================================================
// State Management Types
// =========================================================================

export interface RouteState {
  routeId: string;
  status: 'active' | 'inactive' | 'error' | 'pending';
  lastUpdated: string;
  expiresAt?: string;
  metadata?: Record<string, any>;
  metrics?: {
    requestCount: number;
    averageLatency: number;
    errorRate: number;
  };
}

export interface CollaborationState {
  sessionId: string;
  status: 'active' | 'paused' | 'completed' | 'error';
  participants: string[];
  lastUpdated: string;
  expiresAt?: string;
  metadata?: Record<string, any>;
  progress?: {
    phase: string;
    completedSteps: number;
    totalSteps: number;
  };
}

export interface StateSnapshot {
  timestamp: string;
  routeStates: Map<string, RouteState>;
  collaborationStates: Map<string, CollaborationState>;
}

export interface StateChangeEvent {
  type: 'route_state_changed' | 'collaboration_state_changed' | 'route_state_expired' | 'collaboration_state_expired' | 'state_restored';
  timestamp: string;
  routeId?: string;
  sessionId?: string;
  previousState?: RouteState | CollaborationState;
  newState?: RouteState | CollaborationState;
  snapshotTimestamp?: string;
}

export interface StateManagerConfig {
  maxSnapshots?: number;
  cleanupInterval?: number;
}

// =========================================================================
// Routing Types (CAM Core)
// =========================================================================

export interface AICoreRequest {
  prompt: string;
  model?: string;
  temperature?: number;
  maxTokens?: number;
  requirements?: ProviderRequirements;
  metadata?: Record<string, any>;
}

export interface AICoreResponse {
  content: string;
  provider: string;
  model: string;
  usage: {
    promptTokens: number;
    completionTokens: number;
    totalTokens: number;
  };
  cost: number;
  latency: number;
  metadata?: Record<string, any>;
}

export interface ProviderRequirements {
  cost?: 'minimize' | 'optimize' | 'performance';
  performance?: 'fast' | 'balanced' | 'quality';
  compliance?: string[];
  region?: string;
  capabilities?: string[];
}

export interface ProviderInfo {
  id: string;
  name: string;
  type: 'openai' | 'anthropic' | 'google' | 'azure' | 'custom';
  models: string[];
  pricing: {
    inputTokens: number;
    outputTokens: number;
    currency: string;
  };
  capabilities: string[];
  regions: string[];
  status: 'available' | 'degraded' | 'unavailable';
}

export interface PolicyValidationRequest {
  request: AICoreRequest;
  userId: string;
  context: Record<string, any>;
}

export interface PolicyValidationResult {
  allowed: boolean;
  policies: string[];
  reason?: string;
  modifications?: Record<string, any>;
}

export interface PolicyConfiguration {
  id: string;
  name: string;
  rules: PolicyRule[];
  priority: number;
  enabled: boolean;
}

export interface PolicyRule {
  condition: string;
  action: 'allow' | 'deny' | 'modify' | 'route';
  parameters?: Record<string, any>;
}

export interface ProviderConfiguration {
  id: string;
  type: string;
  apiKey: string;
  endpoint?: string;
  models: string[];
  enabled: boolean;
}

// =========================================================================
// Collaboration Types (IACP)
// =========================================================================

export interface CollaborationRequest {
  task: string;
  requirements: string[];
  decomposition?: 'auto' | 'manual';
  agents?: string[];
  timeout?: number;
  metadata?: Record<string, any>;
}

export interface CollaborationSession {
  id: string;
  task: string;
  agents: AgentInfo[];
  status: 'initializing' | 'active' | 'completed' | 'failed';
  createdAt: string;
  updatedAt: string;
  metadata: Record<string, any>;
}

export interface CollaborationResult {
  sessionId: string;
  result: any;
  participatingAgents: string[];
  executionPath: ExecutionStep[];
  metadata: {
    duration: number;
    cost: number;
    quality: number;
  };
}

export interface AgentCapabilities {
  type: string;
  skills: string[];
  specializations: string[];
  quality: number;
  cost: number;
}

export interface AgentInfo {
  id: string;
  name: string;
  type: string;
  capabilities: AgentCapabilities;
  status: 'available' | 'busy' | 'offline';
  reputation: number;
  metadata: Record<string, any>;
}

export interface ComplexTask {
  id: string;
  description: string;
  requirements: string[];
  constraints: Record<string, any>;
  priority: 'low' | 'medium' | 'high' | 'critical';
}

export interface TaskComponents {
  id: string;
  parentTaskId: string;
  description: string;
  requiredCapabilities: string[];
  dependencies: string[];
  estimatedDuration: number;
  assignedAgent?: string;
}

export interface CollaborationWorkflow {
  id: string;
  name: string;
  steps: WorkflowStep[];
  agents: string[];
  timeout: number;
  metadata: Record<string, any>;
}

export interface WorkflowStep {
  id: string;
  type: 'task' | 'decision' | 'parallel' | 'sequential';
  agent?: string;
  input: any;
  output?: any;
  dependencies: string[];
  timeout: number;
}

export interface ExecutionStep {
  stepId: string;
  agent: string;
  startTime: string;
  endTime: string;
  input: any;
  output: any;
  status: 'completed' | 'failed' | 'skipped';
}

export interface CollaborationConfiguration {
  agentDiscovery: {
    timeout: number;
    retries: number;
    cacheTtl: number;
  };
  messaging: {
    encryption: boolean;
    compression: boolean;
    maxMessageSize: number;
  };
  orchestration: {
    maxConcurrentTasks: number;
    defaultTimeout: number;
    retryPolicy: RetryPolicy;
  };
}

export interface RetryPolicy {
  maxRetries: number;
  backoffMultiplier: number;
  maxBackoffTime: number;
}

// =========================================================================
// Metrics & Monitoring Types
// =========================================================================

export interface MetricsQuery {
  startTime: string;
  endTime: string;
  metrics: string[];
  granularity: 'minute' | 'hour' | 'day';
  filters?: Record<string, any>;
}

export interface MetricsData {
  timeRange: {
    start: string;
    end: string;
  };
  granularity: string;
  data: MetricDataPoint[];
}

export interface MetricDataPoint {
  timestamp: string;
  metric: string;
  value: number;
  labels: Record<string, string>;
}

// =========================================================================
// Error Types
// =========================================================================

export interface CAMErrorDetails {
  code: string;
  message: string;
  details?: Record<string, any>;
  timestamp: string;
  requestId?: string;
}

// =========================================================================
// Health Status Types
// =========================================================================

export interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  components: ComponentHealth[];
  timestamp: string;
}

export interface ComponentHealth {
  name: string;
  status: 'healthy' | 'degraded' | 'unhealthy';
  latency?: number;
  errorRate?: number;
  details?: Record<string, any>;
}
