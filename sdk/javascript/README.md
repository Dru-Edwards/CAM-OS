# CAM JavaScript/TypeScript SDK

Official JavaScript and TypeScript SDK for the Complete Arbitration Mesh platform.

## Installation

```bash
npm install @cam/sdk-js
# or
yarn add @cam/sdk-js
```

## Quick Start

```typescript
import { CAMClient } from '@cam/sdk-js';

const cam = new CAMClient({
  apiKey: process.env.CAM_API_KEY,
  endpoint: 'https://api.cam.example.com'
});

// Route a simple request
const response = await cam.route({
  prompt: 'Explain quantum computing in simple terms',
  preferences: {
    cost: 'optimize',
    performance: 'fast'
  }
});

console.log(response.text);
```

## Features

- ✅ **TypeScript Support**: Full type definitions included
- ✅ **Async/Await**: Modern Promise-based API
- ✅ **Browser & Node.js**: Universal compatibility
- ✅ **Tree Shaking**: Optimized bundle size
- ✅ **Retry Logic**: Automatic retry with exponential backoff
- ✅ **Rate Limiting**: Built-in rate limit handling
- ✅ **Request Routing**: Intelligent provider selection
- ✅ **Multi-Agent Collaboration**: Advanced agent orchestration
- ✅ **Real-time Events**: WebSocket and SSE support
- ✅ **Observability**: Built-in metrics and tracing

## API Reference

### CAMClient

#### Constructor

```typescript
new CAMClient(options: CAMClientOptions)
```

**Options:**
```typescript
interface CAMClientOptions {
  apiKey: string;                    // Your CAM API key
  endpoint?: string;                 // API endpoint (optional)
  timeout?: number;                  // Request timeout in ms (default: 30000)
  maxRetries?: number;               // Max retry attempts (default: 3)
  retryDelay?: number;               // Base retry delay in ms (default: 1000)
  observability?: ObservabilityOptions;
}

interface ObservabilityOptions {
  metrics?: boolean;                 // Enable metrics collection
  tracing?: boolean;                 // Enable request tracing
  logLevel?: 'debug' | 'info' | 'warn' | 'error';
}
```

#### Methods

##### route(request: RouteRequest): Promise&lt;RouteResponse&gt;

Route a request to the optimal AI provider.

```typescript
interface RouteRequest {
  prompt: string;                    // The input prompt
  task?: string;                     // Task type (text-generation, summarization, etc.)
  parameters?: {
    max_tokens?: number;
    temperature?: number;
    top_p?: number;
    frequency_penalty?: number;
    presence_penalty?: number;
  };
  preferences?: {
    cost?: 'optimize' | 'balanced' | 'performance';
    performance?: 'fast' | 'balanced' | 'quality';
    compliance?: string[];           // GDPR, HIPAA, etc.
    providers?: string[];            // Preferred providers
    exclude_providers?: string[];    // Excluded providers
  };
  metadata?: Record<string, any>;    // Additional metadata
}

interface RouteResponse {
  text: string;                      // Generated response
  provider: string;                  // Selected provider
  model: string;                     // Selected model
  usage: {
    tokens: number;
    cost: number;
    latency_ms: number;
  };
  routing_details: {
    reason: string;
    alternatives: Array<{
      provider: string;
      score: number;
      reason: string;
    }>;
  };
  request_id: string;                // Unique request identifier
}
```

Example:
```typescript
const response = await cam.route({
  prompt: 'Write a product description for a smart watch',
  task: 'text-generation',
  parameters: {
    max_tokens: 200,
    temperature: 0.7
  },
  preferences: {
    cost: 'optimize',
    compliance: ['gdpr']
  }
});
```

##### collaborate(request: CollaborationRequest): Promise&lt;CollaborationResponse&gt;

Orchestrate multi-agent collaboration.

```typescript
interface CollaborationRequest {
  task: string;                      // Main task description
  agents: string[] | AgentConfig[];  // Required agents
  workflow?: 'sequential' | 'parallel' | 'hierarchical' | 'custom';
  max_iterations?: number;           // Max collaboration rounds
  termination_criteria?: {
    min_consensus?: number;          // Minimum agreement threshold
    max_time_ms?: number;           // Maximum time limit
    quality_threshold?: number;      // Quality requirement
  };
  context?: Record<string, any>;     // Shared context
}

interface AgentConfig {
  type: string;                      // Agent type/capability
  role?: string;                     // Specific role in collaboration
  config?: Record<string, any>;      // Agent-specific configuration
}

interface CollaborationResponse {
  result: {
    text: string;                    // Final collaborative result
    confidence: number;              // Confidence score (0-1)
    consensus: number;               // Agreement level (0-1)
  };
  process: {
    workflow: string;                // Used workflow
    iterations: number;              // Number of rounds
    agents_used: string[];           // Participating agents
    duration_ms: number;             // Total time
  };
  contributions: Array<{
    agent: string;
    role: string;
    contribution: string;
    confidence: number;
    timestamp: string;
  }>;
  request_id: string;
}
```

Example:
```typescript
const collaboration = await cam.collaborate({
  task: 'Create a comprehensive marketing strategy for a new product',
  agents: [
    { type: 'market-researcher', role: 'analyze market trends' },
    { type: 'content-writer', role: 'create messaging' },
    { type: 'data-analyst', role: 'provide insights' }
  ],
  workflow: 'sequential',
  termination_criteria: {
    min_consensus: 0.8,
    max_time_ms: 60000
  }
});
```

##### stream(request: StreamRequest): AsyncGenerator&lt;StreamChunk&gt;

Stream responses in real-time.

```typescript
interface StreamRequest extends RouteRequest {
  stream: true;
}

interface StreamChunk {
  type: 'token' | 'metadata' | 'complete';
  data: string | Record<string, any>;
  timestamp: string;
}
```

Example:
```typescript
for await (const chunk of cam.stream({
  prompt: 'Write a long story about AI',
  stream: true
})) {
  if (chunk.type === 'token') {
    process.stdout.write(chunk.data as string);
  }
}
```

##### getModels(): Promise&lt;Model[]&gt;

Get available models and capabilities.

```typescript
interface Model {
  provider: string;
  model: string;
  capabilities: string[];
  pricing: {
    input_cost_per_token: number;
    output_cost_per_token: number;
  };
  performance: {
    avg_latency_ms: number;
    tokens_per_second: number;
  };
  context_length: number;
}
```

##### getUsage(options?: UsageOptions): Promise&lt;UsageStats&gt;

Get usage statistics and analytics.

```typescript
interface UsageOptions {
  start_date?: string;               // ISO date string
  end_date?: string;                 // ISO date string
  group_by?: 'day' | 'hour' | 'provider' | 'model';
}

interface UsageStats {
  total_requests: number;
  total_tokens: number;
  total_cost: number;
  avg_latency_ms: number;
  error_rate: number;
  breakdown: Array<{
    provider?: string;
    model?: string;
    date?: string;
    requests: number;
    tokens: number;
    cost: number;
  }>;
}
```

## Framework Integrations

### React

```bash
npm install @cam/react-sdk
```

#### CAMProvider

```typescript
import { CAMProvider } from '@cam/react-sdk';

function App() {
  return (
    <CAMProvider 
      apiKey={process.env.REACT_APP_CAM_API_KEY}
      endpoint="https://api.cam.example.com"
    >
      <ChatComponent />
    </CAMProvider>
  );
}
```

#### useCAM Hook

```typescript
import { useCAM } from '@cam/react-sdk';

function ChatComponent() {
  const { route, collaborate, loading, error } = useCAM();
  const [messages, setMessages] = useState([]);

  const handleSend = async (prompt: string) => {
    try {
      const response = await route({ prompt });
      setMessages(prev => [...prev, { text: response.text, sender: 'ai' }]);
    } catch (err) {
      console.error('Error:', err);
    }
  };

  return (
    <div>
      {loading && <div>Loading...</div>}
      {error && <div>Error: {error.message}</div>}
      {/* Chat UI */}
    </div>
  );
}
```

#### useCollaboration Hook

```typescript
import { useCollaboration } from '@cam/react-sdk';

function CollaborationDemo() {
  const { 
    collaborate, 
    isCollaborating, 
    progress, 
    contributions 
  } = useCollaboration();

  const startCollaboration = async () => {
    await collaborate({
      task: 'Design a mobile app',
      agents: ['ui-designer', 'ux-researcher', 'developer']
    });
  };

  return (
    <div>
      <button onClick={startCollaboration} disabled={isCollaborating}>
        Start Collaboration
      </button>
      
      {isCollaborating && (
        <div>
          <div>Progress: {Math.round(progress * 100)}%</div>
          <div>Contributions: {contributions.length}</div>
        </div>
      )}
    </div>
  );
}
```

### Next.js

#### API Routes

```typescript
// pages/api/chat.ts
import { CAMClient } from '@cam/sdk-js';
import type { NextApiRequest, NextApiResponse } from 'next';

const cam = new CAMClient({
  apiKey: process.env.CAM_API_KEY!
});

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const response = await cam.route(req.body);
    res.json(response);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
}
```

#### Streaming API

```typescript
// pages/api/stream.ts
import { CAMClient } from '@cam/sdk-js';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  const cam = new CAMClient({
    apiKey: process.env.CAM_API_KEY!
  });

  try {
    for await (const chunk of cam.stream(req.body)) {
      res.write(`data: ${JSON.stringify(chunk)}\n\n`);
    }
    res.end();
  } catch (error) {
    res.write(`data: ${JSON.stringify({ error: error.message })}\n\n`);
    res.end();
  }
}
```

### Express.js

```typescript
import express from 'express';
import { CAMClient } from '@cam/sdk-js';

const app = express();
const cam = new CAMClient({
  apiKey: process.env.CAM_API_KEY!
});

app.use(express.json());

// Simple routing endpoint
app.post('/api/chat', async (req, res) => {
  try {
    const response = await cam.route(req.body);
    res.json(response);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Collaboration endpoint
app.post('/api/collaborate', async (req, res) => {
  try {
    const response = await cam.collaborate(req.body);
    res.json(response);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Streaming endpoint
app.post('/api/stream', async (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  
  try {
    for await (const chunk of cam.stream(req.body)) {
      res.write(`data: ${JSON.stringify(chunk)}\n\n`);
    }
    res.end();
  } catch (error) {
    res.write(`data: ${JSON.stringify({ error: error.message })}\n\n`);
    res.end();
  }
});
```

## Error Handling

The SDK provides comprehensive error handling with specific error types:

```typescript
import { 
  CAMError, 
  CAMRateLimitError, 
  CAMAuthenticationError, 
  CAMValidationError,
  CAMTimeoutError
} from '@cam/sdk-js';

try {
  const response = await cam.route(request);
} catch (error) {
  if (error instanceof CAMRateLimitError) {
    // Handle rate limiting
    console.log(`Rate limited. Retry after: ${error.retryAfter}s`);
    setTimeout(() => cam.route(request), error.retryAfter * 1000);
  } else if (error instanceof CAMAuthenticationError) {
    // Handle authentication errors
    console.error('Invalid API key or expired token');
  } else if (error instanceof CAMValidationError) {
    // Handle validation errors
    console.error('Invalid request parameters:', error.details);
  } else if (error instanceof CAMTimeoutError) {
    // Handle timeouts
    console.error('Request timed out');
  } else {
    // Handle other errors
    console.error('Unexpected error:', error.message);
  }
}
```

## Testing

The SDK includes comprehensive testing utilities:

```typescript
import { createMockCAMClient, mockCollaboration } from '@cam/sdk-js/testing';

// Create a mock client
const mockCAM = createMockCAMClient({
  responses: {
    route: {
      text: 'Mock response',
      provider: 'mock-provider',
      usage: { tokens: 100, cost: 0.001, latency_ms: 50 }
    }
  }
});

// Mock collaboration
const mockCollab = mockCollaboration({
  result: {
    text: 'Collaborative result',
    confidence: 0.9,
    consensus: 0.85
  },
  process: {
    workflow: 'sequential',
    iterations: 3,
    agents_used: ['agent1', 'agent2']
  }
});

// Use in tests
describe('Chat component', () => {
  it('should handle successful responses', async () => {
    const response = await mockCAM.route({ prompt: 'test' });
    expect(response.text).toBe('Mock response');
  });
});
```

## Configuration

### Environment Variables

```bash
# Required
CAM_API_KEY=your_api_key_here

# Optional
CAM_ENDPOINT=https://api.cam.example.com
CAM_TIMEOUT=30000
CAM_MAX_RETRIES=3
CAM_RETRY_DELAY=1000
CAM_LOG_LEVEL=info
```

### Configuration File

```typescript
// cam.config.ts
import { CAMConfig } from '@cam/sdk-js';

export const config: CAMConfig = {
  apiKey: process.env.CAM_API_KEY!,
  endpoint: 'https://api.cam.example.com',
  timeout: 30000,
  maxRetries: 3,
  retryDelay: 1000,
  observability: {
    metrics: true,
    tracing: true,
    logLevel: 'info'
  },
  defaultPreferences: {
    cost: 'balanced',
    performance: 'balanced'
  }
};
```

## Performance Optimization

### Connection Pooling

```typescript
import { CAMClient } from '@cam/sdk-js';

const cam = new CAMClient({
  apiKey: process.env.CAM_API_KEY!,
  connectionPool: {
    maxSockets: 10,
    keepAlive: true,
    timeout: 30000
  }
});
```

### Request Caching

```typescript
import { CAMClient } from '@cam/sdk-js';

const cam = new CAMClient({
  apiKey: process.env.CAM_API_KEY!,
  cache: {
    enabled: true,
    ttl: 300000, // 5 minutes
    maxSize: 1000
  }
});
```

### Batch Requests

```typescript
const requests = [
  { prompt: 'Question 1' },
  { prompt: 'Question 2' },
  { prompt: 'Question 3' }
];

const responses = await cam.batchRoute(requests);
```

## Security

### Request Signing

```typescript
import { CAMClient } from '@cam/sdk-js';

const cam = new CAMClient({
  apiKey: process.env.CAM_API_KEY!,
  security: {
    signRequests: true,
    privateKey: process.env.CAM_PRIVATE_KEY
  }
});
```

### Rate Limiting

The SDK automatically handles rate limiting with exponential backoff:

```typescript
const cam = new CAMClient({
  apiKey: process.env.CAM_API_KEY!,
  rateLimiting: {
    strategy: 'exponential-backoff',
    maxRetries: 5,
    baseDelay: 1000,
    maxDelay: 30000
  }
});
```

## Monitoring and Observability

### Metrics

```typescript
import { CAMClient } from '@cam/sdk-js';

const cam = new CAMClient({
  apiKey: process.env.CAM_API_KEY!,
  observability: {
    metrics: {
      enabled: true,
      endpoint: 'https://metrics.example.com',
      interval: 60000 // 1 minute
    }
  }
});

// Access metrics
const metrics = cam.getMetrics();
console.log(metrics.totalRequests);
console.log(metrics.avgLatency);
console.log(metrics.errorRate);
```

### Tracing

```typescript
import { CAMClient } from '@cam/sdk-js';

const cam = new CAMClient({
  apiKey: process.env.CAM_API_KEY!,
  observability: {
    tracing: {
      enabled: true,
      endpoint: 'https://traces.example.com',
      sampleRate: 0.1 // 10% sampling
    }
  }
});
```

## Migration Guide

### From CAM v1.x

```typescript
// Old way
import { CAMClient } from '@cam/v1';
const cam = new CAMClient(apiKey);
const result = await cam.arbitrate(prompt);

// New way
import { CAMClient } from '@cam/sdk-js';
const cam = new CAMClient({ apiKey });
const result = await cam.route({ prompt });
```

### From Direct Provider APIs

```typescript
// Before (direct OpenAI)
import OpenAI from 'openai';
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const response = await openai.chat.completions.create({
  model: 'gpt-4',
  messages: [{ role: 'user', content: prompt }]
});

// After (CAM routing)
import { CAMClient } from '@cam/sdk-js';
const cam = new CAMClient({ apiKey: process.env.CAM_API_KEY });
const response = await cam.route({ prompt });
```

## Examples

### Simple Chat Bot

```typescript
import { CAMClient } from '@cam/sdk-js';
import readline from 'readline';

const cam = new CAMClient({
  apiKey: process.env.CAM_API_KEY!
});

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

async function chatBot() {
  console.log('CAM Chat Bot - Type "quit" to exit');
  
  const askQuestion = () => {
    rl.question('You: ', async (input) => {
      if (input.toLowerCase() === 'quit') {
        rl.close();
        return;
      }
      
      try {
        const response = await cam.route({
          prompt: input,
          preferences: { performance: 'fast' }
        });
        
        console.log(`Bot: ${response.text}`);
        console.log(`(${response.provider}/${response.model} - ${response.usage.latency_ms}ms)`);
      } catch (error) {
        console.error('Error:', error.message);
      }
      
      askQuestion();
    });
  };
  
  askQuestion();
}

chatBot();
```

### Content Generation Pipeline

```typescript
import { CAMClient } from '@cam/sdk-js';

const cam = new CAMClient({
  apiKey: process.env.CAM_API_KEY!
});

async function generateContent(topic: string) {
  // Step 1: Research
  const research = await cam.collaborate({
    task: `Research the topic: ${topic}`,
    agents: ['researcher', 'fact-checker'],
    workflow: 'parallel'
  });
  
  // Step 2: Generate outline
  const outline = await cam.route({
    prompt: `Based on this research: ${research.result.text}\n\nCreate a detailed outline for an article about ${topic}`,
    preferences: { performance: 'quality' }
  });
  
  // Step 3: Write content
  const content = await cam.collaborate({
    task: `Write a comprehensive article following this outline: ${outline.text}`,
    agents: ['writer', 'editor', 'seo-specialist'],
    workflow: 'sequential'
  });
  
  return {
    research: research.result.text,
    outline: outline.text,
    content: content.result.text,
    metadata: {
      research_confidence: research.result.confidence,
      content_consensus: content.result.consensus,
      total_cost: research.process.duration_ms + content.process.duration_ms
    }
  };
}

// Usage
generateContent('Quantum Computing Applications')
  .then(result => console.log(result))
  .catch(error => console.error(error));
```

## License

MIT License. See [LICENSE](./LICENSE) for details.

## Support

- **Documentation**: [docs.cam.example.com](https://docs.cam.example.com)
- **API Reference**: [api.cam.example.com](https://api.cam.example.com)
- **GitHub Issues**: [github.com/cam/sdk-js/issues](https://github.com/cam/sdk-js/issues)
- **Community**: [discord.gg/cam](https://discord.gg/cam)
