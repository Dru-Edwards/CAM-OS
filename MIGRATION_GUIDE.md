# Migration Guide: CAM v1.x → Complete CAM v2.0

## 📋 Overview
This guide provides step-by-step instructions for migrating from the original Cognitive Arbitration Mesh (CAM) Protocol v1.x to the Complete Arbitration Mesh v2.0.0, which introduces the Inter-Agent Collaboration Protocol (IACP) alongside enhanced routing capabilities.

> ⚠️ **BREAKING CHANGES**: This is a major version upgrade with significant breaking changes. Plan for thorough testing and gradual rollout.

---

## 🎯 Migration Strategy

### Recommended Migration Path
1. **Parallel Deployment** (Recommended for production)
2. **Gradual Traffic Migration** with load balancer
3. **Data Migration** with zero downtime
4. **Feature Validation** and rollback capability
5. **Complete Cutover** after validation

### Migration Timeline
- **Planning Phase**: 1-2 weeks
- **Infrastructure Setup**: 1 week  
- **Application Migration**: 1-2 weeks
- **Testing & Validation**: 1 week
- **Production Cutover**: 1-2 days

---

## 🔍 PRE-MIGRATION ASSESSMENT

### 1. **Current State Analysis**
Run this assessment script to analyze your current CAM v1.x deployment:

```bash
#!/bin/bash
# migration-assessment.sh

echo "=== CAM v1.x Migration Assessment ==="

# Check current version
echo "Current CAM Version:"
kubectl get deployment cam-app -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null || echo "Not deployed on Kubernetes"

# Check database schema
echo -e "\nDatabase Schema Version:"
psql $DATABASE_URL -c "SELECT version FROM schema_versions ORDER BY version DESC LIMIT 1;" 2>/dev/null || echo "Database not accessible"

# Check API endpoints in use
echo -e "\nCurrent API Usage (last 24h):"
kubectl logs deployment/cam-app --since=24h | grep "GET\|POST\|PUT\|DELETE" | cut -d' ' -f3 | sort | uniq -c | sort -nr

# Check integration points
echo -e "\nActive Integrations:"
kubectl get configmap cam-config -o yaml | grep -E "(openai|anthropic|google|azure)" || echo "No integration config found"

echo -e "\n=== Assessment Complete ==="
```

### 2. **Compatibility Matrix**

| Component | v1.x | v2.0 | Migration Required |
|-----------|------|------|-------------------|
| **API Endpoints** | `/api/route` | `/api/routeRequest` | ✅ Yes - Update clients |
| **Authentication** | Basic + JWT | Enhanced JWT | ⚠️ Partial - Update tokens |
| **Database Schema** | Core routing | + Collaboration | ✅ Yes - Run migrations |
| **Configuration** | Env vars | StateManager | ✅ Yes - Update config |
| **Provider Integration** | Direct calls | FastPath routing | ⚠️ Partial - Update flow |

---

## 🏗️ INFRASTRUCTURE MIGRATION

### 1. **Kubernetes Migration**

#### **Step 1: Deploy v2.0 Infrastructure**
```bash
# Create new namespace for v2.0
kubectl create namespace cam-v2

# Deploy Complete CAM v2.0
helm install cam-v2 ./deployment/helm/cam-chart \
  --namespace cam-v2 \
  --values values-migration.yaml
```

#### **Migration Values (values-migration.yaml)**
```yaml
# Special migration configuration
image:
  repository: cam-protocol/complete-arbitration-mesh
  tag: "2.0.0"

# Reduced resources during migration
replicaCount: 2

# Migration-specific settings
config:
  migrationMode: true
  legacyApiSupport: true
  dualWrite: true  # Write to both v1 and v2 schemas

# Database migration settings
database:
  migrationDatabase: "cam_v1_production"
  targetDatabase: "cam_v2_production"

service:
  # Use different port during migration
  port: 8081
```

#### **Step 2: Parallel Deployment Setup**
```bash
# Update load balancer to route traffic
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cam-migration-ingress
  annotations:
    nginx.ingress.kubernetes.io/canary: "true"
    nginx.ingress.kubernetes.io/canary-weight: "10"  # Start with 10% traffic
spec:
  rules:
  - host: api.your-domain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: cam-v2-service
            port:
              number: 8081
EOF
```

### 2. **Database Migration**

#### **Step 1: Schema Migration**
```sql
-- migration-v2.sql
-- Run this script to prepare database for v2.0

-- Add collaboration tables
CREATE TABLE IF NOT EXISTS collaboration_sessions (
  id VARCHAR(255) PRIMARY KEY,
  task TEXT NOT NULL,
  status VARCHAR(50) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  metadata JSONB
);

CREATE TABLE IF NOT EXISTS collaboration_agents (
  id VARCHAR(255) PRIMARY KEY,
  session_id VARCHAR(255) REFERENCES collaboration_sessions(id),
  name VARCHAR(255) NOT NULL,
  type VARCHAR(100) NOT NULL,
  capabilities JSONB,
  status VARCHAR(50) NOT NULL,
  metadata JSONB
);

CREATE TABLE IF NOT EXISTS collaboration_workflows (
  id VARCHAR(255) PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  steps JSONB NOT NULL,
  agents JSONB,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  metadata JSONB
);

-- Add new columns to existing tables
ALTER TABLE requests ADD COLUMN IF NOT EXISTS fastpath_route JSONB;
ALTER TABLE requests ADD COLUMN IF NOT EXISTS collaboration_session_id VARCHAR(255);

-- Create indexes for performance
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_collaboration_sessions_status ON collaboration_sessions(status);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_collaboration_agents_session ON collaboration_agents(session_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_requests_collaboration ON requests(collaboration_session_id);

-- Update schema version
INSERT INTO schema_versions (version, applied_at) VALUES ('2.0.0', CURRENT_TIMESTAMP);
```

#### **Step 2: Data Migration Script**
```bash
#!/bin/bash
# data-migration.sh

echo "Starting CAM v1.x → v2.0 data migration..."

# Backup current data
pg_dump $DATABASE_URL > cam_v1_backup_$(date +%Y%m%d_%H%M%S).sql

# Run schema migration
psql $DATABASE_URL -f migration-v2.sql

# Migrate provider configurations
psql $DATABASE_URL <<EOF
-- Convert old provider configs to new FastPath format
INSERT INTO fastpath_providers (id, name, config, capabilities)
SELECT 
  concat('fp_', id),
  name,
  jsonb_build_object(
    'endpoint', endpoint_url,
    'apiKey', api_key,
    'rateLimit', rate_limit,
    'legacy', true
  ),
  jsonb_build_object(
    'models', supported_models,
    'performance', performance_metrics
  )
FROM providers 
WHERE active = true;
EOF

echo "Data migration completed successfully!"
```

---

## 🔧 APPLICATION CODE MIGRATION

### 1. **Client Code Migration**

#### **Before (v1.x)**
```javascript
const CAM = require('@cam-protocol/arbitration-mesh');

const cam = new CAM({
  apiKey: process.env.CAM_API_KEY,
  endpoint: 'https://api.cam-protocol.com'
});

// Route request
const result = await cam.route({
  prompt: "Analyze this data",
  provider: "auto",
  maxCost: 0.10
});
```

#### **After (v2.0)**
```typescript
import { CompleteArbitrationMesh } from '@cam-protocol/complete-arbitration-mesh';

const cam = new CompleteArbitrationMesh({
  apiKey: process.env.CAM_API_KEY,
  endpoint: 'https://api.complete-cam.com'
});

// Enhanced routing
const result = await cam.routeRequest({
  prompt: "Analyze this data",
  requirements: { 
    cost: "optimize", 
    performance: "balanced" 
  }
});

// NEW: Agent collaboration
const collaboration = await cam.initiateCollaboration({
  task: "Complex data analysis",
  requirements: ["data-analyst", "visualization-expert"],
  decomposition: "auto"
});
```

#### **Migration Helper Script**
```bash
#!/bin/bash
# client-migration-helper.sh

echo "Updating client code for CAM v2.0..."

# Update package.json
npm uninstall @cam-protocol/arbitration-mesh
npm install @cam-protocol/complete-arbitration-mesh@2.0.0

# Find and update import statements
find . -name "*.js" -o -name "*.ts" | xargs sed -i 's/@cam-protocol\/arbitration-mesh/@cam-protocol\/complete-arbitration-mesh/g'

# Update method calls
find . -name "*.js" -o -name "*.ts" | xargs sed -i 's/\.route(/\.routeRequest(/g'

echo "Client code updated. Please review and test manually."
```

### 2. **API Endpoint Migration**

#### **Legacy API Support (Temporary)**
```typescript
// Add to your CAM v2.0 configuration
const cam = new CompleteArbitrationMesh({
  apiKey: process.env.CAM_API_KEY,
  endpoint: 'https://api.complete-cam.com',
  legacyApiSupport: true  // Enable during migration
});

// This enables automatic translation of v1.x API calls
```

#### **Endpoint Mapping**
| v1.x Endpoint | v2.0 Endpoint | Status |
|---------------|---------------|---------|
| `POST /api/route` | `POST /api/routeRequest` | ✅ Mapped |
| `GET /api/providers` | `GET /api/getOptimalProvider` | ✅ Mapped |
| `POST /api/validate` | `POST /api/validatePolicy` | ✅ Mapped |
| `GET /api/metrics` | `GET /api/getMetrics` | ✅ Enhanced |
| `POST /api/config` | `POST /api/manageConfiguration` | ⚠️ Breaking |

---

## ⚙️ CONFIGURATION MIGRATION

### 1. **Environment Variables**

#### **Before (v1.x)**
```env
# v1.x configuration
CAM_API_KEY=your-api-key
CAM_ENDPOINT=https://api.cam-protocol.com
CAM_LOG_LEVEL=info
CAM_PROVIDER_OPENAI_KEY=sk-...
CAM_PROVIDER_ANTHROPIC_KEY=sk-ant-...
CAM_DATABASE_URL=postgresql://...
CAM_REDIS_URL=redis://...
```

#### **After (v2.0)**
```env
# v2.0 configuration
CAM_API_KEY=your-api-key
CAM_ENDPOINT=https://api.complete-cam.com
CAM_LOG_LEVEL=info
CAM_ENVIRONMENT=production

# Enhanced provider configuration
CAM_FASTPATH_ENABLED=true
CAM_COLLABORATION_ENABLED=true
CAM_LEGACY_API_SUPPORT=true  # Temporary during migration

# Database configuration
DATABASE_URL=postgresql://...
REDIS_URL=redis://...

# New v2.0 specific settings
CAM_JWT_SECRET=your-jwt-secret
CAM_TOKEN_EXPIRY=24h
CAM_STATE_MANAGER_ENABLED=true
```

### 2. **Configuration Migration Script**
```bash
#!/bin/bash
# config-migration.sh

echo "Migrating CAM configuration to v2.0..."

# Backup existing configuration
kubectl get configmap cam-config -o yaml > cam-v1-config-backup.yaml

# Create v2.0 configuration
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: cam-v2-config
data:
  environment: "production"
  logLevel: "info"
  legacyApiSupport: "true"
  fastpathEnabled: "true"
  collaborationEnabled: "true"
  migrationMode: "true"
  
  # Provider configurations
  providers: |
    {
      "openai": {
        "endpoint": "https://api.openai.com/v1",
        "models": ["gpt-4", "gpt-3.5-turbo"],
        "fastpath": true
      },
      "anthropic": {
        "endpoint": "https://api.anthropic.com",
        "models": ["claude-3-opus", "claude-3-sonnet"],
        "fastpath": true
      }
    }
EOF

echo "Configuration migration completed!"
```

---

## 🧪 TESTING & VALIDATION

### 1. **Migration Testing Script**
```bash
#!/bin/bash
# migration-test.sh

echo "=== CAM v2.0 Migration Testing ==="

API_V1="https://api.your-domain.com"
API_V2="https://api.your-domain.com:8081"

# Test 1: Health checks
echo "Testing health endpoints..."
curl -f "$API_V2/health" || exit 1
curl -f "$API_V2/ready" || exit 1

# Test 2: Legacy API compatibility
echo "Testing legacy API compatibility..."
curl -X POST "$API_V2/api/route" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $CAM_API_KEY" \
  -d '{"prompt": "Test migration", "provider": "auto"}' || exit 1

# Test 3: New v2.0 features
echo "Testing new v2.0 features..."
curl -X POST "$API_V2/api/routeRequest" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $CAM_API_KEY" \
  -d '{"prompt": "Test v2.0", "requirements": {"cost": "optimize"}}' || exit 1

# Test 4: Collaboration features
echo "Testing collaboration features..."
curl -X POST "$API_V2/api/initiateCollaboration" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $CAM_API_KEY" \
  -d '{"task": "Test collaboration", "requirements": ["test-agent"]}' || exit 1

echo "✅ All migration tests passed!"
```

### 2. **Performance Comparison**
```bash
#!/bin/bash
# performance-comparison.sh

echo "Running performance comparison..."

# Test v1.x performance
echo "Testing v1.x performance..."
ab -n 1000 -c 10 "$API_V1/api/route" > v1-performance.txt

# Test v2.0 performance  
echo "Testing v2.0 performance..."
ab -n 1000 -c 10 "$API_V2/api/routeRequest" > v2-performance.txt

# Compare results
echo "Performance comparison:"
echo "v1.x average response time: $(grep 'Time per request' v1-performance.txt | head -1)"
echo "v2.0 average response time: $(grep 'Time per request' v2-performance.txt | head -1)"
```

---

## 🚀 PRODUCTION CUTOVER

### 1. **Gradual Traffic Migration**

#### **Phase 1: 10% Traffic (Week 1)**
```bash
# Update ingress to route 10% traffic to v2.0
kubectl patch ingress cam-migration-ingress -p '{"metadata":{"annotations":{"nginx.ingress.kubernetes.io/canary-weight":"10"}}}'
```

#### **Phase 2: 25% Traffic (Week 2)**
```bash
kubectl patch ingress cam-migration-ingress -p '{"metadata":{"annotations":{"nginx.ingress.kubernetes.io/canary-weight":"25"}}}'
```

#### **Phase 3: 50% Traffic (Week 3)**
```bash
kubectl patch ingress cam-migration-ingress -p '{"metadata":{"annotations":{"nginx.ingress.kubernetes.io/canary-weight":"50"}}}'
```

#### **Phase 4: 100% Traffic (Week 4)**
```bash
# Remove canary and route all traffic to v2.0
kubectl delete ingress cam-legacy-ingress
kubectl patch ingress cam-migration-ingress -p '{"metadata":{"annotations":{"nginx.ingress.kubernetes.io/canary":"false"}}}'
```

### 2. **Rollback Procedure**
```bash
#!/bin/bash
# rollback.sh

echo "🚨 Initiating rollback to CAM v1.x..."

# Immediate traffic switch back to v1.x
kubectl patch ingress cam-migration-ingress -p '{"metadata":{"annotations":{"nginx.ingress.kubernetes.io/canary-weight":"0"}}}'

# Scale down v2.0
kubectl scale deployment cam-v2 --replicas=0 -n cam-v2

# Scale up v1.x
kubectl scale deployment cam-app --replicas=3 -n default

# Restore database if needed
# psql $DATABASE_URL < cam_v1_backup_YYYYMMDD_HHMMSS.sql

echo "✅ Rollback completed!"
```

---

## 📊 MONITORING MIGRATION

### 1. **Key Metrics to Monitor**
```yaml
# migration-monitoring.yaml
alerts:
  - name: "Migration Error Rate"
    expression: "rate(cam_v2_errors[5m]) > 0.01"
    description: "v2.0 error rate exceeding threshold"
    
  - name: "Migration Latency"
    expression: "cam_v2_response_time_p95 > cam_v1_response_time_p95 * 1.2"
    description: "v2.0 latency 20% higher than v1.x"
    
  - name: "Database Connection Pool"
    expression: "cam_db_connections_active / cam_db_connections_max > 0.8"
    description: "Database connection pool utilization high"
```

### 2. **Migration Dashboard**
Create a Grafana dashboard to monitor:
- Traffic split between v1.x and v2.0
- Error rates for both versions
- Response time comparison
- Database performance
- Resource utilization

---

## 🔍 POST-MIGRATION CLEANUP

### 1. **Cleanup Script**
```bash
#!/bin/bash
# post-migration-cleanup.sh

echo "Starting post-migration cleanup..."

# Remove v1.x deployment
kubectl delete deployment cam-app -n default
kubectl delete service cam-service -n default

# Remove legacy configuration
kubectl delete configmap cam-config -n default

# Clean up migration-specific resources
kubectl delete ingress cam-migration-ingress
kubectl patch configmap cam-v2-config -p '{"data":{"migrationMode":"false","legacyApiSupport":"false"}}'

# Remove temporary migration tables
psql $DATABASE_URL -c "DROP TABLE IF EXISTS migration_log;"

echo "✅ Cleanup completed!"
```

### 2. **Validation Checklist**
- [ ] All traffic routed to v2.0
- [ ] No errors in application logs
- [ ] Database migration completed
- [ ] All integrations working
- [ ] Performance within acceptable limits
- [ ] Monitoring and alerting configured
- [ ] Legacy resources cleaned up
- [ ] Documentation updated
- [ ] Team trained on new features

---

## 🆘 TROUBLESHOOTING

### Common Migration Issues

#### **Issue 1: Authentication Failures**
```bash
# Check JWT token format
kubectl logs deployment/cam-v2 | grep "authentication"

# Update token if needed
kubectl create secret generic cam-jwt-secret --from-literal=secret="your-new-jwt-secret"
```

#### **Issue 2: Database Connection Issues**
```bash
# Check database connectivity
kubectl exec deployment/cam-v2 -- psql $DATABASE_URL -c "SELECT 1;"

# Check connection pool
kubectl logs deployment/cam-v2 | grep "database"
```

#### **Issue 3: Provider Integration Issues**
```bash
# Test provider connectivity
kubectl exec deployment/cam-v2 -- curl -v "https://api.openai.com/v1/models"

# Check provider configuration
kubectl get configmap cam-v2-config -o yaml
```

#### **Issue 4: Performance Degradation**
```bash
# Check resource utilization
kubectl top pods -n cam-v2

# Check application metrics
curl "$API_V2/metrics"

# Review scaling configuration
kubectl get hpa -n cam-v2
```

---

## 📞 SUPPORT RESOURCES

### Documentation
- [Complete CAM v2.0 API Reference](docs/api-reference.md)
- [Architecture Guide](docs/architecture.md)  
- [Troubleshooting Guide](docs/troubleshooting.md)

### Support Channels
- **GitHub Issues**: [Technical issues and bugs](https://github.com/cam-protocol/complete-arbitration-mesh/issues)
- **GitHub Discussions**: [Migration questions and community support](https://github.com/cam-protocol/complete-arbitration-mesh/discussions)
- **Enterprise Support**: 24/7 support for Enterprise tier customers

### Migration Assistance
For complex migrations or enterprise deployments, contact our migration team for dedicated support.

---

**Successfully migrating to Complete CAM v2.0 unlocks powerful new collaboration capabilities while maintaining the robust routing performance you depend on.**