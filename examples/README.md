# CAM Protocol Examples

This directory contains examples and demonstrations of the CAM Protocol in action.

## Available Examples

- **[Quickstart](./quickstart/)**: A complete Docker Compose setup for quickly getting started with CAM Protocol
- **[Toy LLM](./toy-llm/)**: A simple mock LLM service for demonstration purposes
- **[Collaboration](./collaboration/)**: Examples of using the Inter-Agent Collaboration Protocol
- **[Routing](./routing/)**: Examples of using the FastPath Routing System
- **[Enterprise](./enterprise/)**: Advanced examples for enterprise use cases
- **[Demonstration](./demonstration/)**: Complete demonstration scenarios

## Quickstart Example

For the fastest way to get started with CAM Protocol, see the [Quickstart](./quickstart/) directory, which includes a complete Docker Compose setup with:

- CAM Protocol Core Service
- Toy LLM Service
- Redis and PostgreSQL
- Prometheus and Grafana for monitoring

```bash
# Navigate to the quickstart directory
cd examples/quickstart

# Start the environment
docker-compose up -d

# Test the API
curl localhost:8080/mesh/chat -d '{"message":"Hello CAM!"}' -H "Content-Type: application/json" -H "Authorization: Bearer demo-key-for-quickstart"
```
