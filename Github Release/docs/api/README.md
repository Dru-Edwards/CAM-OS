# API Reference

This document provides a comprehensive reference for the Complete Arbitration Mesh (CAM) Protocol API.

## Core Classes

### CompleteArbitrationMesh

The main entry point for interacting with the CAM Protocol.

```typescript
class CompleteArbitrationMesh {
  constructor(config: CAMConfig);
  
  // Routing methods
  routeRequest(request: AICoreRequest): Promise<AICoreResponse>;
  batchRouteRequests(requests: AICoreRequest[]): Promise<AICoreResponse[]>;
  
  // Collaboration methods
  decomposeTask(task: ComplexTask): Promise<TaskComponents[]>;
  discoverAgents(capabilities: AgentCapabilities[]): Promise<AgentInfo[]>;
  initiateCollaboration(request: CollaborationRequest): Promise<CollaborationSession>;
  
  // Policy management
  registerPolicy(policy: Policy): Promise<void>;
  updatePolicy(policyId: string, updates: Partial<Policy>): Promise<void>;
  deletePolicy(policyId: string): Promise<void>;
  
  // Monitoring and analytics
  getUsageStatistics(options: UsageStatisticsOptions): Promise<UsageStatistics>;
  getPerformanceMetrics(options: MetricsOptions): Promise<PerformanceMetrics>;
}
```

## Request and Response Types

### AICoreRequest

```typescript
interface AICoreRequest {
  prompt: string;
  model?: string;
  temperature?: number;
  maxTokens?: number;
  requirements?: ProviderRequirements;
  metadata?: Record<string, any>;
}
```

### AICoreResponse

```typescript
interface AICoreResponse {
  content: string;
  provider: string;
  model: string;
  cost: number;
  latency: number;
  usage: {
    promptTokens: number;
    completionTokens: number;
    totalTokens: number;
  };
  metadata?: Record<string, any>;
}
```

### CollaborationRequest

```typescript
interface CollaborationRequest {
  task: string;
  requirements: string[];
  decomposition?: 'auto' | 'manual';
  agents?: string[];
  timeout?: number;
  metadata?: Record<string, any>;
}
```

### CollaborationSession

```typescript
interface CollaborationSession {
  id: string;
  task: string;
  agents: AgentInfo[];
  status: 'initializing' | 'active' | 'completed' | 'failed';
  createdAt: string;
  updatedAt: string;
  metadata: Record<string, any>;
  
  // Methods
  getResult(): Promise<CollaborationResult>;
  pause(): Promise<void>;
  resume(): Promise<void>;
  cancel(): Promise<void>;
}
```

## Configuration

### CAMConfig

```typescript
interface CAMConfig {
  apiKey: string;
  environment?: 'development' | 'staging' | 'production';
  endpoint?: string;
  timeout?: number;
  defaultProviders?: string[];
  policies?: Policy[];
  logging?: {
    level: 'debug' | 'info' | 'warn' | 'error';
    destination?: 'console' | 'file';
    filePath?: string;
  };
}
```

## Policy Management

### Policy

```typescript
interface Policy {
  id?: string;
  name: string;
  description?: string;
  rules: PolicyRule[];
  priority?: number;
  enabled?: boolean;
}
```

### PolicyRule

```typescript
interface PolicyRule {
  condition: PolicyCondition;
  action: PolicyAction;
}
```

## Agent Collaboration

### ComplexTask

```typescript
interface ComplexTask {
  id: string;
  description: string;
  requirements: string[];
  constraints: Record<string, any>;
  priority: 'low' | 'medium' | 'high' | 'critical';
}
```

### AgentCapabilities

```typescript
interface AgentCapabilities {
  type: string;
  skills: string[];
  specializations: string[];
  quality: number;
  cost: number;
}
```

### AgentInfo

```typescript
interface AgentInfo {
  id: string;
  name: string;
  type: string;
  capabilities: AgentCapabilities;
  status: 'available' | 'busy' | 'offline';
  reputation: number;
  metadata: Record<string, any>;
}
```

## Error Handling

### CAMError

```typescript
class CAMError extends Error {
  code: string;
  details?: Record<string, any>;
  timestamp: string;
  requestId?: string;
}
```

## REST API Endpoints

The CAM Protocol also provides a REST API for non-TypeScript environments.

### Authentication

All API requests require authentication using the `Authorization` header:

```
Authorization: Bearer YOUR_API_KEY
```

### Routing Endpoints

#### POST /v2/route

Route a single request to the optimal provider.

#### POST /v2/route/batch

Route multiple requests in a single API call.

### Collaboration Endpoints

#### POST /v2/collaboration/decompose

Decompose a complex task into smaller components.

#### POST /v2/collaboration/discover

Discover agents with specific capabilities.

#### POST /v2/collaboration/initiate

Start a new collaboration session.

#### GET /v2/collaboration/:sessionId

Get the status of a collaboration session.

#### GET /v2/collaboration/:sessionId/result

Get the result of a completed collaboration session.

### Policy Endpoints

#### POST /v2/policies

Create a new policy.

#### PUT /v2/policies/:policyId

Update an existing policy.

#### DELETE /v2/policies/:policyId

Delete a policy.

### Monitoring Endpoints

#### GET /v2/monitoring/usage

Get usage statistics.

#### GET /v2/monitoring/performance

Get performance metrics.

## Webhook Events

The CAM Protocol can send webhook notifications for various events:

- `request.completed`: A request has been completed
- `collaboration.started`: A collaboration session has started
- `collaboration.completed`: A collaboration session has completed
- `policy.violated`: A policy violation has occurred
- `error.occurred`: An error has occurred

## Rate Limits

The CAM Protocol enforces rate limits based on your subscription tier:

- **Community**: 10 requests per minute
- **Professional**: 100 requests per minute
- **Enterprise**: 1,000 requests per minute

## Error Codes

- `auth_error`: Authentication error
- `invalid_request`: Invalid request parameters
- `rate_limit_exceeded`: Rate limit exceeded
- `provider_error`: Provider API error
- `policy_violation`: Policy violation
- `collaboration_error`: Collaboration error
- `internal_error`: Internal server error
