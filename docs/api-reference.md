# API Reference

Complete Arbitration Mesh provides both REST APIs and SDK interfaces for routing and collaboration operations.

## REST API Endpoints

### Base URL
- **Development**: `http://localhost:3000/api/v1`
- **Production**: `https://your-domain.com/api/v1`

### Authentication

All API requests require authentication via JWT token in the Authorization header:

```
Authorization: Bearer <your-jwt-token>
```

## CAM Classic APIs (Routing)

### POST /route

Route a single AI request to the optimal provider.

**Request:**
```json
{
  "prompt": "string",
  "model": "string",
  "maxTokens": "number",
  "temperature": "number",
  "provider": "string (optional)",
  "metadata": "object (optional)"
}
```

**Response:**
```json
{
  "success": true,
  "content": "string",
  "metadata": {
    "provider": "string",
    "model": "string",
    "tokens": "number",
    "cost": "number",
    "latency": "number",
    "requestId": "string"
  }
}
```

**Example:**
```bash
curl -X POST http://localhost:3000/api/v1/route \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-jwt-token" \
  -d '{
    "prompt": "Explain machine learning",
    "model": "gpt-4",
    "maxTokens": 500,
    "temperature": 0.7
  }'
```

### POST /route/batch

Route multiple requests in a single API call.

**Request:**
```json
{
  "requests": [
    {
      "id": "string",
      "prompt": "string",
      "model": "string",
      "maxTokens": "number"
    }
  ],
  "options": {
    "parallel": "boolean",
    "maxConcurrency": "number"
  }
}
```

**Response:**
```json
{
  "success": true,
  "results": [
    {
      "id": "string",
      "success": true,
      "content": "string",
      "metadata": { ... }
    }
  ],
  "summary": {
    "totalRequests": "number",
    "successful": "number",
    "failed": "number",
    "totalCost": "number",
    "avgLatency": "number"
  }
}
```

### GET /providers

List available AI providers and their status.

**Response:**
```json
{
  "success": true,
  "providers": [
    {
      "id": "openai",
      "name": "OpenAI",
      "status": "healthy",
      "models": ["gpt-4", "gpt-3.5-turbo"],
      "latency": 150,
      "costPerToken": 0.00003
    }
  ]
}
```

### GET /models

List available models across all providers.

**Response:**
```json
{
  "success": true,
  "models": [
    {
      "id": "gpt-4",
      "provider": "openai",
      "capabilities": ["text-generation", "reasoning"],
      "costPerToken": 0.00003,
      "maxTokens": 8192
    }
  ]
}
```

## IACP APIs (Collaboration)

### POST /collaboration/start

Start a new collaboration session.

**Request:**
```json
{
  "task": "string",
  "requiredCapabilities": ["string"],
  "maxAgents": "number",
  "timeout": "number",
  "metadata": "object (optional)"
}
```

**Response:**
```json
{
  "success": true,
  "collaborationId": "string",
  "agents": [
    {
      "id": "string",
      "capabilities": ["string"],
      "role": "string"
    }
  ],
  "estimatedDuration": "number",
  "estimatedCost": "number"
}
```

### GET /collaboration/{id}/status

Get collaboration session status.

**Response:**
```json
{
  "success": true,
  "collaborationId": "string",
  "status": "running",
  "progress": 0.45,
  "currentStep": "data-analysis",
  "agents": [
    {
      "id": "string",
      "status": "active",
      "currentTask": "string"
    }
  ],
  "elapsedTime": "number",
  "estimatedRemaining": "number"
}
```

### GET /collaboration/{id}/result

Get collaboration session results.

**Response:**
```json
{
  "success": true,
  "collaborationId": "string",
  "status": "completed",
  "result": {
    "summary": "string",
    "details": "object",
    "artifacts": ["string"]
  },
  "metadata": {
    "duration": "number",
    "totalCost": "number",
    "agentsUsed": "number",
    "tasksCompleted": "number"
  }
}
```

### POST /collaboration/{id}/cancel

Cancel a running collaboration session.

**Response:**
```json
{
  "success": true,
  "message": "Collaboration cancelled successfully"
}
```

### GET /agents

List available agents and their capabilities.

**Response:**
```json
{
  "success": true,
  "agents": [
    {
      "id": "data-analyst-01",
      "name": "Data Analyst",
      "capabilities": ["data-analysis", "visualization"],
      "status": "available",
      "rating": 4.8,
      "costPerHour": 10.0
    }
  ]
}
```

## System APIs

### GET /health

System health check.

**Response:**
```json
{
  "success": true,
  "status": "healthy",
  "services": {
    "router": "healthy",
    "collaboration": "healthy",
    "authentication": "healthy",
    "providers": "healthy"
  },
  "version": "1.0.0",
  "uptime": 86400
}
```

### GET /metrics

System metrics and performance data.

**Response:**
```json
{
  "success": true,
  "metrics": {
    "requests": {
      "total": 1000,
      "successful": 950,
      "failed": 50,
      "avgLatency": 234
    },
    "collaborations": {
      "active": 5,
      "completed": 25,
      "avgDuration": 1800
    },
    "costs": {
      "total": 125.50,
      "providers": {
        "openai": 75.30,
        "anthropic": 50.20
      }
    }
  }
}
```

## SDK Interfaces

### TypeScript/JavaScript SDK

#### CompleteArbitrationMesh Class

```typescript
class CompleteArbitrationMesh {
  constructor(options: CAMOptions)
  
  // Initialization
  async initialize(): Promise<void>
  async shutdown(): Promise<void>
  
  // CAM Classic Methods
  async route(request: RouteRequest): Promise<RouteResponse>
  async routeBatch(requests: BatchRouteRequest): Promise<BatchRouteResponse>
  
  // IACP Methods
  async startCollaboration(request: CollaborationRequest): Promise<Collaboration>
  async getCollaboration(id: string): Promise<Collaboration>
  async listAgents(): Promise<Agent[]>
  
  // Utility Methods
  async getProviders(): Promise<Provider[]>
  async getModels(): Promise<Model[]>
  async getHealth(): Promise<HealthStatus>
  async getMetrics(): Promise<Metrics>
}
```

#### Route Method

```typescript
interface RouteRequest {
  prompt: string;
  model?: string;
  maxTokens?: number;
  temperature?: number;
  provider?: string;
  metadata?: Record<string, any>;
}

interface RouteResponse {
  content: string;
  metadata: {
    provider: string;
    model: string;
    tokens: number;
    cost: number;
    latency: number;
    requestId: string;
  };
}

// Usage
const response = await cam.route({
  prompt: "Explain quantum computing",
  model: "gpt-4",
  maxTokens: 1000
});
```

#### Collaboration Method

```typescript
interface CollaborationRequest {
  task: string;
  requiredCapabilities: string[];
  maxAgents?: number;
  timeout?: number;
  metadata?: Record<string, any>;
}

class Collaboration {
  id: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  
  async getStatus(): Promise<CollaborationStatus>
  async getResult(): Promise<CollaborationResult>
  async cancel(): Promise<void>
  
  // Event listeners
  on(event: 'progress', callback: (progress: number) => void): void
  on(event: 'completed', callback: (result: CollaborationResult) => void): void
  on(event: 'error', callback: (error: Error) => void): void
}

// Usage
const collaboration = await cam.startCollaboration({
  task: "Analyze market trends and create investment strategy",
  requiredCapabilities: ["data-analysis", "financial-modeling"],
  maxAgents: 3
});

collaboration.on('progress', (progress) => {
  console.log(`Progress: ${progress * 100}%`);
});

const result = await collaboration.getResult();
```

### Python SDK

#### CompleteArbitrationMesh Class

```python
class CompleteArbitrationMesh:
    def __init__(self, options: CAMOptions)
    
    # Initialization
    async def initialize(self) -> None
    async def shutdown(self) -> None
    
    # CAM Classic Methods
    async def route(self, request: RouteRequest) -> RouteResponse
    async def route_batch(self, requests: BatchRouteRequest) -> BatchRouteResponse
    
    # IACP Methods
    async def start_collaboration(self, request: CollaborationRequest) -> Collaboration
    async def get_collaboration(self, id: str) -> Collaboration
    async def list_agents(self) -> List[Agent]
    
    # Utility Methods
    async def get_providers(self) -> List[Provider]
    async def get_models(self) -> List[Model]
    async def get_health(self) -> HealthStatus
    async def get_metrics(self) -> Metrics
```

#### Usage Examples

```python
from complete_arbitration_mesh import CompleteArbitrationMesh

# Initialize
cam = CompleteArbitrationMesh({
    'config_path': './cam-config.yaml'
})
await cam.initialize()

# Route request
response = await cam.route({
    'prompt': 'Explain quantum computing',
    'model': 'gpt-4',
    'max_tokens': 1000
})

# Start collaboration
collaboration = await cam.start_collaboration({
    'task': 'Analyze market trends and create investment strategy',
    'required_capabilities': ['data-analysis', 'financial-modeling'],
    'max_agents': 3
})

result = await collaboration.get_result()
```

## Error Handling

### Error Response Format

```json
{
  "success": false,
  "error": {
    "code": "string",
    "message": "string",
    "details": "object (optional)"
  },
  "requestId": "string"
}
```

### Common Error Codes

- `AUTH_INVALID_TOKEN`: Invalid or expired JWT token
- `AUTH_INSUFFICIENT_PERMISSIONS`: User lacks required permissions
- `ROUTE_NO_PROVIDERS_AVAILABLE`: No providers available for request
- `ROUTE_PROVIDER_ERROR`: Provider-specific error
- `ROUTE_QUOTA_EXCEEDED`: Request exceeds quota limits
- `COLLABORATION_AGENTS_UNAVAILABLE`: Required agents not available
- `COLLABORATION_TIMEOUT`: Collaboration exceeded timeout
- `VALIDATION_ERROR`: Request validation failed
- `INTERNAL_ERROR`: Internal system error

### Rate Limiting

API endpoints are rate limited. Limits are returned in response headers:

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1640995200
```

When rate limit is exceeded:

```json
{
  "success": false,
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded. Try again later."
  }
}
```

## Pagination

List endpoints support pagination:

**Request Parameters:**
- `page`: Page number (1-based)
- `limit`: Items per page (max 100)
- `sort`: Sort field
- `order`: Sort order (asc/desc)

**Response:**
```json
{
  "success": true,
  "data": [...],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 100,
    "totalPages": 5,
    "hasNext": true,
    "hasPrev": false
  }
}
```

## Webhooks

Configure webhooks to receive real-time notifications:

### Webhook Events

- `route.completed`: Route request completed
- `route.failed`: Route request failed
- `collaboration.started`: Collaboration started
- `collaboration.completed`: Collaboration completed
- `collaboration.failed`: Collaboration failed
- `system.alert`: System alert triggered

### Webhook Payload

```json
{
  "event": "route.completed",
  "timestamp": "2024-01-01T12:00:00Z",
  "data": {
    "requestId": "string",
    "result": {...}
  }
}
```
