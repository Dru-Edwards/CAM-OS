/**
 * CAM Client Types
 * 
 * TypeScript type definitions for the Complete Arbitration Mesh SDK.
 */

// Utility types
export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

// Base preferences interface
export interface Preferences {
  /** Cost preference weight (0-1) */
  costWeight?: number;
  
  /** Latency preference weight (0-1) */
  latencyWeight?: number;
  
  /** Quality preference weight (0-1) */
  qualityWeight?: number;
  
  /** Provider preferences */
  providerPreferences?: ProviderPreferences;
}

export interface ProviderPreferences {
  /** Preferred providers */
  preferred?: string[];
  
  /** Excluded providers */
  excluded?: string[];
  
  /** Provider-specific settings */
  settings?: Record<string, any>;
}

// Agent interface
export interface Agent {
  /** Unique agent identifier */
  id: string;
  
  /** Agent type/capability */
  type: string;
  
  /** Agent role in collaboration */
  role: string;
  
  /** Agent configuration */
  config?: Record<string, any>;
  
  /** Agent priority */
  priority?: number;
}

// Configuration interfaces
export interface MetricsConfig {
  enabled: boolean;
  endpoint?: string;
  interval?: number;
}

export interface TracingConfig {
  enabled: boolean;
  endpoint?: string;
  sampleRate?: number;
}

export interface ObservabilityOptions {
  /** Enable metrics collection */
  metrics?: boolean | MetricsConfig;
  
  /** Enable request tracing */
  tracing?: boolean | TracingConfig;
  
  /** Log level */
  logLevel?: LogLevel;
}

export interface ConnectionPoolOptions {
  maxSockets?: number;
  keepAlive?: boolean;
  timeout?: number;
}

export interface CacheOptions {
  enabled: boolean;
  ttl?: number;
  maxSize?: number;
}

export interface SecurityOptions {
  signRequests?: boolean;
  privateKey?: string;
}

export interface RateLimitingOptions {
  /** Rate limiting strategy */
  strategy?: 'exponential-backoff' | 'fixed-window' | 'sliding-window';
  
  /** Enable rate limiting */
  enabled?: boolean;
  
  /** Maximum requests per window */
  maxRequests?: number;
  
  /** Rate limiting window in milliseconds */
  windowMs?: number;
  
  /** Maximum retry attempts */
  maxRetries?: number;
  
  /** Base delay between requests */
  baseDelay?: number;
  
  /** Maximum delay between requests */
  maxDelay?: number;
}

// Base configuration
export interface CAMClientOptions {
  /** Your CAM API key */
  apiKey: string;
  
  /** API endpoint URL */
  endpoint?: string;
  
  /** Request timeout in milliseconds */
  timeout?: number;
  
  /** Maximum retry attempts */
  maxRetries?: number;
  
  /** Base retry delay in milliseconds */
  retryDelay?: number;
  
  /** Observability configuration */
  observability?: ObservabilityOptions;
  
  /** Connection pool configuration */
  connectionPool?: ConnectionPoolOptions;
  
  /** Cache configuration */
  cache?: CacheOptions;
  
  /** Security configuration */
  security?: SecurityOptions;
  
  /** Rate limiting configuration */
  rateLimiting?: RateLimitingOptions;
  
  /** Default preferences for requests */
  defaultPreferences?: Preferences;
}

// Main request interface for CAM
export interface CAMRequest {
  /** The message/prompt to send to the model */
  message: string;
  
  /** The model to use for the request */
  model: string;
  
  /** Maximum number of tokens to generate */
  maxTokens?: number;
  
  /** Temperature for response generation (0-2) */
  temperature?: number;
  
  /** Top-p sampling parameter (0-1) */
  topP?: number;
  
  /** Whether to stream the response */
  stream?: boolean;
  
  /** Additional request metadata */
  metadata?: Record<string, any>;
}

// Collaboration request interface
export interface CollaborationRequest {
  /** Session identifier */
  sessionId: string;
  
  /** Array of agents participating in collaboration */
  agents: Agent[];
  
  /** The task to collaborate on */
  task: string;
  
  /** Maximum number of collaboration rounds */
  maxRounds?: number;
  
  /** Collaboration preferences */
  preferences?: Preferences;
}

// Routing preferences
export interface RoutingPreferences {
  /** Prefer low cost routing */
  preferLowCost?: boolean;
  
  /** Prefer low latency routing */
  preferLowLatency?: boolean;
  
  /** Prefer high quality providers */
  preferHighQuality?: boolean;
  
  /** Provider blacklist */
  excludeProviders?: string[];
  
  /** Provider whitelist */
  includeProviders?: string[];
}

// Route request and response interfaces
export interface RouteRequest {
  /** The request to route */
  request: CAMRequest;
  
  /** Available providers for routing */
  providers?: string[];
  
  /** Routing preferences */
  preferences?: RoutingPreferences;
}

export interface UsageInfo {
  /** Token count */
  tokens: number;
  
  /** Cost in USD */
  cost: number;
  
  /** Latency in milliseconds */
  latency_ms: number;
  
  /** Input tokens */
  input_tokens?: number;
  
  /** Output tokens */
  output_tokens?: number;
}

export interface Alternative {
  provider: string;
  model: string;
  score: number;
  reason: string;
}

export interface RoutingDetails {
  /** Reason for selection */
  reason: string;
  
  /** Alternative options considered */
  alternatives: Alternative[];
  
  /** Routing strategy used */
  strategy: string;
  
  /** Evaluation metrics */
  evaluation: Record<string, number>;
}

export interface RouteResponse {
  /** Generated response text */
  text: string;
  
  /** Selected provider */
  provider: string;
  
  /** Selected model */
  model: string;
  
  /** Usage information */
  usage: UsageInfo;
  
  /** Routing details */
  routing_details: RoutingDetails;
  
  /** Unique request identifier */
  request_id: string;
  
  /** Response metadata */
  metadata?: Record<string, any>;
}

// Streaming types
export interface StreamRequest extends RouteRequest {
  stream: true;
}

export interface StreamChunk {
  /** Chunk type */
  type: 'token' | 'metadata' | 'complete' | 'error';
  
  /** Chunk data */
  data: string | Record<string, any>;
  
  /** Timestamp */
  timestamp: string;
  
  /** Sequence number */
  sequence?: number;
}

// Error response
export interface ErrorResponse {
  /** Error indicator */
  error: true;
  
  /** Error message */
  message: string;
  
  /** Error code */
  code: string;
  
  /** Request that failed */
  request?: RouteRequest;
}

// Client metrics types
export interface ClientMetrics {
  /** Total requests made */
  totalRequests: number;
  
  /** Successful requests */
  successfulRequests: number;
  
  /** Failed requests */
  failedRequests: number;
  
  /** Average response time */
  averageResponseTime: number;
  
  /** Total tokens used */
  totalTokens: number;
  
  /** Total cost */
  totalCost: number;
}
