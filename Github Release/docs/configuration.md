# Configuration Guide

Complete Arbitration Mesh supports multiple configuration methods and formats for flexible deployment scenarios.

## Configuration Methods

1. **YAML Configuration File** (Recommended)
2. **Environment Variables**
3. **JSON Configuration**
4. **Programmatic Configuration**
5. **Remote Configuration** (Enterprise)

## Configuration File Structure

### Complete Configuration Example

```yaml
# cam-config.yaml
api:
  port: 3000
  host: "0.0.0.0"
  cors:
    enabled: true
    origins: ["*"]
  rateLimit:
    windowMs: 900000  # 15 minutes
    max: 100

authentication:
  type: "jwt"
  secret: "${JWT_SECRET}"
  expiresIn: "24h"
  issuer: "complete-arbitration-mesh"
  audience: "cam-api"
  refreshToken:
    enabled: true
    expiresIn: "7d"

providers:
  openai:
    enabled: true
    apiKey: "${OPENAI_API_KEY}"
    baseUrl: "https://api.openai.com/v1"
    timeout: 30000
    retries: 3
    models:
      - name: "gpt-4"
        maxTokens: 8192
        costPerToken: 0.00003
        capabilities: ["text-generation", "reasoning"]
      - name: "gpt-3.5-turbo"
        maxTokens: 4096
        costPerToken: 0.000002
        capabilities: ["text-generation"]
    
  anthropic:
    enabled: true
    apiKey: "${ANTHROPIC_API_KEY}"
    baseUrl: "https://api.anthropic.com"
    timeout: 30000
    retries: 3
    models:
      - name: "claude-3-opus"
        maxTokens: 4096
        costPerToken: 0.000015
        capabilities: ["text-generation", "reasoning"]
      - name: "claude-3-sonnet"
        maxTokens: 4096
        costPerToken: 0.000003
        capabilities: ["text-generation"]
  
  azure:
    enabled: false
    apiKey: "${AZURE_OPENAI_API_KEY}"
    baseUrl: "${AZURE_OPENAI_ENDPOINT}"
    apiVersion: "2023-12-01-preview"
    timeout: 30000
    retries: 3
    deployments:
      - name: "gpt-4-deployment"
        model: "gpt-4"
        maxTokens: 8192
        costPerToken: 0.00003

routing:
  defaultProvider: "openai"
  fallbackEnabled: true
  fallbackChain: ["openai", "anthropic"]
  
  selection:
    strategy: "optimal"  # optimal, cost, performance, random
    weights:
      cost: 0.3
      performance: 0.4
      reliability: 0.3
  
  costOptimization:
    enabled: true
    maxCostPerRequest: 1.0
    budgetLimit: 1000.0
    budgetPeriod: "monthly"
  
  performance:
    targetLatency: 2000  # ms
    circuitBreaker:
      enabled: true
      failureThreshold: 5
      resetTimeout: 60000

collaboration:
  enabled: true
  
  agents:
    registry: "local"  # local, distributed, marketplace
    maxAgentsPerTask: 10
    defaultTimeout: 300000  # 5 minutes
    
  discovery:
    strategy: "capability-based"  # capability-based, cost-based, performance-based
    matchingThreshold: 0.8
    
  orchestration:
    maxConcurrentTasks: 50
    taskTimeout: 600000  # 10 minutes
    retryAttempts: 3
    
  messaging:
    protocol: "internal"  # internal, mqtt, rabbitmq
    encryption: true
    compression: true

monitoring:
  enabled: true
  
  metrics:
    enabled: true
    endpoint: "/metrics"
    interval: 30000  # 30 seconds
    
  logging:
    level: "info"  # debug, info, warn, error
    format: "json"
    destination: "console"  # console, file, elasticsearch
    
  health:
    enabled: true
    endpoint: "/health"
    checks:
      - "providers"
      - "database"
      - "agents"
      
  tracing:
    enabled: false
    provider: "jaeger"  # jaeger, zipkin, datadog
    endpoint: "http://localhost:14268"

security:
  encryption:
    atRest: true
    inTransit: true
    algorithm: "AES-256-GCM"
    
  secrets:
    provider: "env"  # env, vault, aws-secrets, azure-keyvault
    rotation: false
    
  network:
    allowedIPs: []  # Empty array allows all
    blockedIPs: []
    
  compliance:
    gdpr: false
    hipaa: false
    soc2: false

storage:
  type: "memory"  # memory, redis, postgresql, mongodb
  
  redis:
    host: "localhost"
    port: 6379
    password: "${REDIS_PASSWORD}"
    database: 0
    
  postgresql:
    host: "localhost"
    port: 5432
    database: "cam"
    username: "${DB_USERNAME}"
    password: "${DB_PASSWORD}"
    ssl: true

cache:
  enabled: true
  ttl: 3600  # 1 hour
  maxSize: 1000
  provider: "memory"  # memory, redis

development:
  debug: false
  hotReload: false
  mockProviders: false
  seedData: false
```

## Environment-Based Configuration

### Core Environment Variables

```bash
# API Configuration
CAM_API_PORT=3000
CAM_API_HOST=0.0.0.0

# Authentication
JWT_SECRET=your-super-secret-jwt-key
JWT_EXPIRES_IN=24h

# Provider API Keys
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
AZURE_OPENAI_API_KEY=...
AZURE_OPENAI_ENDPOINT=https://...

# Database
REDIS_PASSWORD=your-redis-password
DB_USERNAME=postgres
DB_PASSWORD=your-db-password

# Monitoring
CAM_LOG_LEVEL=info
CAM_METRICS_ENABLED=true

# Security
CAM_ENCRYPTION_KEY=your-encryption-key
```

### Provider-Specific Configuration

#### OpenAI Configuration

```yaml
providers:
  openai:
    enabled: true
    apiKey: "${OPENAI_API_KEY}"
    organization: "${OPENAI_ORG_ID}"  # Optional
    baseUrl: "https://api.openai.com/v1"
    timeout: 30000
    retries: 3
    rateLimits:
      requestsPerMinute: 3500
      tokensPerMinute: 90000
    features:
      streaming: true
      functionCalling: true
      vision: true
```

#### Anthropic Configuration

```yaml
providers:
  anthropic:
    enabled: true
    apiKey: "${ANTHROPIC_API_KEY}"
    baseUrl: "https://api.anthropic.com"
    version: "2023-06-01"
    timeout: 30000
    retries: 3
    rateLimits:
      requestsPerMinute: 1000
      tokensPerMinute: 40000
```

#### Azure OpenAI Configuration

```yaml
providers:
  azure:
    enabled: true
    apiKey: "${AZURE_OPENAI_API_KEY}"
    baseUrl: "${AZURE_OPENAI_ENDPOINT}"
    apiVersion: "2023-12-01-preview"
    timeout: 30000
    retries: 3
    deployments:
      gpt4:
        deploymentName: "gpt-4-deployment"
        model: "gpt-4"
        version: "0613"
      gpt35:
        deploymentName: "gpt-35-turbo-deployment"
        model: "gpt-3.5-turbo"
        version: "0613"
```

#### Custom Provider Configuration

```yaml
providers:
  custom:
    enabled: true
    name: "Custom LLM Provider"
    apiKey: "${CUSTOM_API_KEY}"
    baseUrl: "https://api.custom-provider.com"
    headers:
      "X-Custom-Header": "value"
    authentication:
      type: "bearer"  # bearer, api-key, oauth
    models:
      - name: "custom-model-1"
        endpoint: "/v1/completions"
        maxTokens: 4096
        costPerToken: 0.00001
```

## Advanced Configuration

### Policy Engine Configuration

```yaml
policy:
  enabled: true
  engine: "opa"  # opa, custom
  
  opa:
    bundleUrl: "https://policy-server.com/bundles"
    policies:
      - name: "access_control"
        path: "./policies/access.rego"
      - name: "cost_limits"
        path: "./policies/cost.rego"
      - name: "compliance"
        path: "./policies/compliance.rego"
        
  rules:
    maxTokensPerRequest: 8192
    maxCostPerRequest: 10.0
    allowedModels: ["gpt-4", "gpt-3.5-turbo"]
    blockedUsers: []
```

### Agent Configuration

```yaml
agents:
  builtin:
    dataAnalyst:
      enabled: true
      capabilities: ["data-analysis", "visualization"]
      models: ["gpt-4", "claude-3-opus"]
      maxConcurrentTasks: 5
      costPerHour: 10.0
      
    researcher:
      enabled: true
      capabilities: ["research", "fact-checking"]
      models: ["gpt-4"]
      tools: ["web-search", "database-query"]
      maxConcurrentTasks: 3
      costPerHour: 15.0
      
  external:
    marketplaceUrl: "https://agent-marketplace.com"
    authentication:
      type: "api-key"
      key: "${MARKETPLACE_API_KEY}"
    discovery:
      enabled: true
      updateInterval: 3600000  # 1 hour
```

### Load Balancing Configuration

```yaml
loadBalancing:
  strategy: "weighted_round_robin"  # round_robin, weighted_round_robin, least_connections
  
  weights:
    openai: 0.5
    anthropic: 0.3
    azure: 0.2
    
  healthChecks:
    enabled: true
    interval: 30000  # 30 seconds
    timeout: 5000   # 5 seconds
    unhealthyThreshold: 3
    healthyThreshold: 2
```

### Caching Configuration

```yaml
cache:
  enabled: true
  provider: "redis"
  
  redis:
    host: "localhost"
    port: 6379
    password: "${REDIS_PASSWORD}"
    database: 1
    keyPrefix: "cam:cache:"
    
  policies:
    defaultTTL: 3600  # 1 hour
    maxSize: 10000
    evictionPolicy: "LRU"
    
  rules:
    - pattern: "route:*"
      ttl: 1800      # 30 minutes
    - pattern: "collaboration:*"
      ttl: 7200      # 2 hours
    - pattern: "agents:*"
      ttl: 3600      # 1 hour
```

## Configuration Validation

### Schema Validation

The system validates configuration against a JSON schema:

```typescript
interface CAMConfig {
  api?: APIConfig;
  authentication: AuthConfig;
  providers: Record<string, ProviderConfig>;
  routing: RoutingConfig;
  collaboration?: CollaborationConfig;
  monitoring?: MonitoringConfig;
  security?: SecurityConfig;
  storage?: StorageConfig;
  cache?: CacheConfig;
}
```

### Environment Variable Substitution

Environment variables can be referenced using `${VAR_NAME}` syntax:

```yaml
providers:
  openai:
    apiKey: "${OPENAI_API_KEY}"
    baseUrl: "${OPENAI_BASE_URL:-https://api.openai.com/v1}"  # With default
```

### Configuration Precedence

1. Command line arguments (highest)
2. Environment variables
3. Configuration file
4. Default values (lowest)

## Development vs Production

### Development Configuration

```yaml
development:
  debug: true
  hotReload: true
  mockProviders: true
  seedData: true
  
monitoring:
  logging:
    level: "debug"
    
security:
  encryption:
    atRest: false  # For easier debugging
```

### Production Configuration

```yaml
production:
  debug: false
  
monitoring:
  logging:
    level: "warn"
    destination: "elasticsearch"
    
security:
  encryption:
    atRest: true
    inTransit: true
  secrets:
    provider: "vault"
  compliance:
    soc2: true
```

## Configuration Management

### Hot Reloading

Enable configuration hot reloading for development:

```yaml
configuration:
  hotReload: true
  watchFiles: ["./cam-config.yaml"]
  reloadInterval: 5000  # 5 seconds
```

### Remote Configuration

For distributed deployments:

```yaml
configuration:
  source: "remote"
  remote:
    provider: "consul"  # consul, etcd, aws-parameter-store
    endpoint: "http://consul:8500"
    prefix: "cam/config"
    polling: true
    pollInterval: 60000  # 1 minute
```

### Configuration Encryption

Encrypt sensitive configuration values:

```bash
# Encrypt a value
cam-cli config encrypt --value "secret-api-key"

# Use in configuration
providers:
  openai:
    apiKey: "encrypted:AES256:base64encodedvalue"
```

## Troubleshooting Configuration

### Common Issues

1. **Environment Variable Not Found**
   ```
   Error: Environment variable OPENAI_API_KEY not found
   ```
   Solution: Ensure all required environment variables are set

2. **Invalid YAML Syntax**
   ```
   Error: Invalid YAML at line 15: unexpected character
   ```
   Solution: Validate YAML syntax using online tools

3. **Schema Validation Failed**
   ```
   Error: Configuration validation failed: providers.openai.timeout must be a number
   ```
   Solution: Check configuration against schema

### Validation Commands

```bash
# Validate configuration file
cam-cli config validate --file ./cam-config.yaml

# Test provider connectivity
cam-cli config test-providers

# Check environment variables
cam-cli config check-env

# Show effective configuration
cam-cli config show --merged
```

### Debug Configuration Loading

Enable debug logging to troubleshoot configuration issues:

```yaml
monitoring:
  logging:
    level: "debug"
    loggers:
      - "config"
      - "providers"
```

This will output detailed logs about configuration loading and validation.
