// SPDX-License-Identifier: Apache-2.0
const express = require('express');
const app = express();
const port = process.env.PORT || 3000;
const latencyMs = parseInt(process.env.LATENCY_MS || '200');
const maxTokens = parseInt(process.env.MAX_TOKENS || '1024');

app.use(express.json());

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'healthy', version: '1.0.0' });
});

// Simple chat completion endpoint
app.post('/v1/chat/completions', async (req, res) => {
  const { messages, model = 'toy-llm-1', max_tokens = maxTokens } = req.body;

  // Simulate processing latency
  await new Promise(resolve => setTimeout(resolve, latencyMs));

  // Get the last message content
  const lastMessage = messages[messages.length - 1];
  const prompt = lastMessage.content || '';

  // Generate a simple response based on the prompt
  const response = generateResponse(prompt, model, max_tokens);

  res.json({
    id: `chatcmpl-${Date.now()}`,
    object: 'chat.completion',
    created: Math.floor(Date.now() / 1000),
    model,
    choices: [
      {
        index: 0,
        message: {
          role: 'assistant',
          content: response
        },
        finish_reason: 'stop'
      }
    ],
    usage: {
      prompt_tokens: countTokens(prompt),
      completion_tokens: countTokens(response),
      total_tokens: countTokens(prompt) + countTokens(response)
    }
  });
});

// Simple completion endpoint
app.post('/v1/completions', async (req, res) => {
  const { prompt, model = 'toy-llm-1', max_tokens = maxTokens } = req.body;

  // Simulate processing latency
  await new Promise(resolve => setTimeout(resolve, latencyMs));

  // Generate a simple response
  const response = generateResponse(prompt, model, max_tokens);

  res.json({
    id: `cmpl-${Date.now()}`,
    object: 'text_completion',
    created: Math.floor(Date.now() / 1000),
    model,
    choices: [
      {
        text: response,
        index: 0,
        logprobs: null,
        finish_reason: 'stop'
      }
    ],
    usage: {
      prompt_tokens: countTokens(prompt),
      completion_tokens: countTokens(response),
      total_tokens: countTokens(prompt) + countTokens(response)
    }
  });
});

// Models list endpoint
app.get('/v1/models', (req, res) => {
  res.json({
    object: 'list',
    data: [
      {
        id: 'toy-llm-1',
        object: 'model',
        created: 1672531200,
        owned_by: 'cam-protocol'
      },
      {
        id: 'toy-llm-2',
        object: 'model',
        created: 1672531200,
        owned_by: 'cam-protocol'
      }
    ]
  });
});

// Metrics endpoint for Prometheus
app.get('/metrics', (req, res) => {
  res.set('Content-Type', 'text/plain');
  res.send(`
# HELP toy_llm_requests_total Total number of requests
# TYPE toy_llm_requests_total counter
toy_llm_requests_total{model="toy-llm-1"} ${Math.floor(Math.random() * 1000)}
toy_llm_requests_total{model="toy-llm-2"} ${Math.floor(Math.random() * 500)}

# HELP toy_llm_latency_seconds Request latency in seconds
# TYPE toy_llm_latency_seconds gauge
toy_llm_latency_seconds ${latencyMs / 1000}

# HELP toy_llm_tokens_total Total number of tokens processed
# TYPE toy_llm_tokens_total counter
toy_llm_tokens_total{type="prompt"} ${Math.floor(Math.random() * 10000)}
toy_llm_tokens_total{type="completion"} ${Math.floor(Math.random() * 20000)}
  `);
});

// Start the server
app.listen(port, () => {
  console.log(`Toy LLM service listening on port ${port}`);
});

// Helper function to generate a simple response
function generateResponse(prompt, model, maxTokens) {
  // Very simple response generation
  const promptLower = prompt.toLowerCase();
  
  if (promptLower.includes('hello') || promptLower.includes('hi')) {
    return 'Hello! I am a toy LLM model for the CAM Protocol quickstart example. I can help you test the routing and arbitration capabilities of the CAM Protocol.';
  }
  
  if (promptLower.includes('help') || promptLower.includes('how')) {
    return 'This is a simple toy LLM model for demonstration purposes. To test the CAM Protocol, try sending different types of prompts and observe how the routing works. Check the Grafana dashboard to see the metrics in action.';
  }
  
  if (promptLower.includes('what') && (promptLower.includes('cam') || promptLower.includes('protocol'))) {
    return 'The Complete Arbitration Mesh (CAM) Protocol is an intelligent orchestration and collaboration platform for modern AI ecosystems. It routes requests to optimal AI providers and enables advanced inter-agent collaboration.';
  }
  
  // Default response
  return `This is a simulated response from the ${model} model. Your prompt was: "${prompt}". In a real implementation, this would be a more sophisticated response from an actual language model. The CAM Protocol would route your request to the most appropriate model based on your needs.`;
}

// Simple token counting function (very approximate)
function countTokens(text) {
  if (!text) return 0;
  // Roughly 4 characters per token on average
  return Math.ceil(text.length / 4);
}
