# Deployment Guide

Complete Arbitration Mesh supports multiple deployment patterns from development to enterprise-scale production environments.

## Deployment Options

1. **Standalone Deployment** - Single instance
2. **Docker Deployment** - Containerized single instance
3. **Kubernetes Deployment** - Orchestrated microservices
4. **Cloud Deployment** - AWS, Azure, GCP
5. **Hybrid Deployment** - Multi-cloud and edge

## Prerequisites

### System Requirements

**Minimum:**
- CPU: 2 cores
- RAM: 4GB
- Storage: 10GB
- Network: 100Mbps

**Recommended:**
- CPU: 4+ cores
- RAM: 8GB+
- Storage: 50GB+ SSD
- Network: 1Gbps+

**Production:**
- CPU: 8+ cores
- RAM: 16GB+
- Storage: 100GB+ SSD
- Network: 10Gbps+

### Software Dependencies

- Node.js 18+ (for Node.js deployment)
- Python 3.9+ (for Python deployment)
- Docker 20+ (for containerized deployment)
- Kubernetes 1.24+ (for K8s deployment)

## Standalone Deployment

### Node.js Deployment

```bash
# 1. Clone repository
git clone https://github.com/your-org/complete-arbitration-mesh
cd complete-arbitration-mesh

# 2. Install dependencies
npm install

# 3. Build application
npm run build

# 4. Configure environment
cp .env.example .env
# Edit .env with your configuration

# 5. Start application
npm start
```

### Python Deployment

```bash
# 1. Clone repository
git clone https://github.com/your-org/complete-arbitration-mesh
cd complete-arbitration-mesh

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env with your configuration

# 5. Start application
python main.py
```

### Process Management

#### Using PM2 (Node.js)

```bash
# Install PM2
npm install -g pm2

# Create ecosystem file
cat > ecosystem.config.js << EOF
module.exports = {
  apps: [{
    name: 'complete-arbitration-mesh',
    script: 'dist/index.js',
    instances: 'max',
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'production',
      PORT: 3000
    }
  }]
}
EOF

# Start with PM2
pm2 start ecosystem.config.js
pm2 save
pm2 startup
```

#### Using Systemd

```bash
# Create service file
sudo cat > /etc/systemd/system/cam.service << EOF
[Unit]
Description=Complete Arbitration Mesh
After=network.target

[Service]
Type=simple
User=cam
WorkingDirectory=/opt/cam
ExecStart=/usr/bin/node dist/index.js
Restart=always
RestartSec=10
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl enable cam
sudo systemctl start cam
```

## Docker Deployment

### Single Container

Create `Dockerfile`:

```dockerfile
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

EXPOSE 3000

USER node

CMD ["npm", "start"]
```

Build and run:

```bash
# Build image
docker build -t cam:latest .

# Run container
docker run -d \
  --name cam \
  -p 3000:3000 \
  -e OPENAI_API_KEY=your-key \
  -e JWT_SECRET=your-secret \
  cam:latest
```

### Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  cam:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - JWT_SECRET=${JWT_SECRET}
      - REDIS_URL=redis://redis:6379
      - DATABASE_URL=postgresql://postgres:password@postgres:5432/cam
    depends_on:
      - redis
      - postgres
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data
    restart: unless-stopped

  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=cam
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - cam
    restart: unless-stopped

volumes:
  redis_data:
  postgres_data:
```

Start services:

```bash
docker-compose up -d
```

## Kubernetes Deployment

### Namespace and ConfigMap

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: cam-system

---
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cam-config
  namespace: cam-system
data:
  config.yaml: |
    api:
      port: 3000
      host: "0.0.0.0"
    
    providers:
      openai:
        enabled: true
        baseUrl: "https://api.openai.com/v1"
      
      anthropic:
        enabled: true
        baseUrl: "https://api.anthropic.com"
    
    routing:
      defaultProvider: "openai"
      fallbackEnabled: true
    
    collaboration:
      enabled: true
    
    monitoring:
      enabled: true
      metrics:
        enabled: true
```

### Secrets

```yaml
# secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: cam-secrets
  namespace: cam-system
type: Opaque
data:
  openai-api-key: <base64-encoded-key>
  anthropic-api-key: <base64-encoded-key>
  jwt-secret: <base64-encoded-secret>
```

### Deployment

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cam-api
  namespace: cam-system
spec:
  replicas: 3
  selector:
    matchLabels:
      app: cam-api
  template:
    metadata:
      labels:
        app: cam-api
    spec:
      containers:
      - name: cam-api
        image: cam:latest
        ports:
        - containerPort: 3000
        env:
        - name: NODE_ENV
          value: "production"
        - name: OPENAI_API_KEY
          valueFrom:
            secretKeyRef:
              name: cam-secrets
              key: openai-api-key
        - name: ANTHROPIC_API_KEY
          valueFrom:
            secretKeyRef:
              name: cam-secrets
              key: anthropic-api-key
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: cam-secrets
              key: jwt-secret
        volumeMounts:
        - name: config
          mountPath: /app/config
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: config
        configMap:
          name: cam-config
```

### Service and Ingress

```yaml
# service.yaml
apiVersion: v1
kind: Service
metadata:
  name: cam-api-service
  namespace: cam-system
spec:
  selector:
    app: cam-api
  ports:
  - protocol: TCP
    port: 80
    targetPort: 3000
  type: ClusterIP

---
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cam-api-ingress
  namespace: cam-system
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
  - hosts:
    - api.your-domain.com
    secretName: cam-tls
  rules:
  - host: api.your-domain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: cam-api-service
            port:
              number: 80
```

### Deploy to Kubernetes

```bash
# Apply configurations
kubectl apply -f namespace.yaml
kubectl apply -f configmap.yaml
kubectl apply -f secrets.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
kubectl apply -f ingress.yaml

# Check deployment status
kubectl get pods -n cam-system
kubectl get services -n cam-system
kubectl get ingress -n cam-system
```

## Cloud Deployment

### AWS Deployment

#### ECS with Fargate

```json
{
  "family": "cam-task",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::account:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::account:role/ecsTaskRole",
  "containerDefinitions": [
    {
      "name": "cam-api",
      "image": "your-account.dkr.ecr.region.amazonaws.com/cam:latest",
      "portMappings": [
        {
          "containerPort": 3000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "NODE_ENV",
          "value": "production"
        }
      ],
      "secrets": [
        {
          "name": "OPENAI_API_KEY",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:cam/openai-key"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/cam",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

#### Terraform Configuration

```hcl
# main.tf
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# VPC
resource "aws_vpc" "cam_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "cam-vpc"
  }
}

# ECS Cluster
resource "aws_ecs_cluster" "cam_cluster" {
  name = "cam-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

# Application Load Balancer
resource "aws_lb" "cam_alb" {
  name               = "cam-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets           = aws_subnet.public_subnet[*].id

  enable_deletion_protection = false

  tags = {
    Name = "cam-alb"
  }
}

# ECS Service
resource "aws_ecs_service" "cam_service" {
  name            = "cam-service"
  cluster         = aws_ecs_cluster.cam_cluster.id
  task_definition = aws_ecs_task_definition.cam_task.arn
  desired_count   = 3
  launch_type     = "FARGATE"

  network_configuration {
    security_groups  = [aws_security_group.ecs_sg.id]
    subnets         = aws_subnet.private_subnet[*].id
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.cam_tg.arn
    container_name   = "cam-api"
    container_port   = 3000
  }

  depends_on = [aws_lb_listener.cam_listener]
}
```

### Azure Deployment

#### Container Instances

```yaml
# azure-container-instances.yaml
apiVersion: '2021-03-01'
location: eastus
name: cam-container-group
properties:
  containers:
  - name: cam-api
    properties:
      image: your-registry.azurecr.io/cam:latest
      resources:
        requests:
          cpu: 1
          memoryInGb: 2
      ports:
      - port: 3000
        protocol: TCP
      environmentVariables:
      - name: NODE_ENV
        value: production
      - name: OPENAI_API_KEY
        secureValue: your-openai-key
      - name: JWT_SECRET
        secureValue: your-jwt-secret
  osType: Linux
  restartPolicy: Always
  ipAddress:
    type: Public
    ports:
    - protocol: TCP
      port: 80
    - protocol: TCP
      port: 443
type: Microsoft.ContainerInstance/containerGroups
```

#### ARM Template

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "siteName": {
      "type": "string",
      "metadata": {
        "description": "Name of the web app"
      }
    }
  },
  "resources": [
    {
      "type": "Microsoft.Web/serverfarms",
      "apiVersion": "2021-02-01",
      "name": "[concat(parameters('siteName'), '-plan')]",
      "location": "[resourceGroup().location]",
      "sku": {
        "name": "P1V2",
        "tier": "PremiumV2"
      },
      "kind": "linux",
      "properties": {
        "reserved": true
      }
    },
    {
      "type": "Microsoft.Web/sites",
      "apiVersion": "2021-02-01",
      "name": "[parameters('siteName')]",
      "location": "[resourceGroup().location]",
      "dependsOn": [
        "[resourceId('Microsoft.Web/serverfarms', concat(parameters('siteName'), '-plan'))]"
      ],
      "properties": {
        "serverFarmId": "[resourceId('Microsoft.Web/serverfarms', concat(parameters('siteName'), '-plan'))]",
        "siteConfig": {
          "linuxFxVersion": "DOCKER|your-registry.azurecr.io/cam:latest",
          "appSettings": [
            {
              "name": "WEBSITES_ENABLE_APP_SERVICE_STORAGE",
              "value": "false"
            }
          ]
        }
      }
    }
  ]
}
```

### Google Cloud Deployment

#### Cloud Run

```yaml
# cloudrun.yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: cam-api
  annotations:
    run.googleapis.com/ingress: all
spec:
  template:
    metadata:
      annotations:
        autoscaling.knative.dev/maxScale: "10"
        run.googleapis.com/cpu-throttling: "false"
    spec:
      containerConcurrency: 100
      containers:
      - image: gcr.io/your-project/cam:latest
        ports:
        - containerPort: 3000
        env:
        - name: NODE_ENV
          value: production
        - name: OPENAI_API_KEY
          valueFrom:
            secretKeyRef:
              name: cam-secrets
              key: openai-api-key
        resources:
          requests:
            cpu: "1"
            memory: "2Gi"
          limits:
            cpu: "2"
            memory: "4Gi"
```

## Production Considerations

### Security

1. **TLS/SSL Configuration**
   ```nginx
   server {
       listen 443 ssl http2;
       server_name api.your-domain.com;
       
       ssl_certificate /etc/ssl/certs/your-domain.crt;
       ssl_certificate_key /etc/ssl/private/your-domain.key;
       
       ssl_protocols TLSv1.2 TLSv1.3;
       ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
       
       location / {
           proxy_pass http://cam-backend;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }
   ```

2. **Network Security**
   - Use VPC/VNet isolation
   - Configure security groups/NSGs
   - Implement WAF rules
   - Enable DDoS protection

3. **Secrets Management**
   - Use cloud secret managers
   - Rotate secrets regularly
   - Encrypt secrets at rest
   - Audit secret access

### Monitoring and Observability

1. **Metrics Collection**
   ```yaml
   monitoring:
     prometheus:
       enabled: true
       endpoint: "/metrics"
     
     grafana:
       enabled: true
       dashboards:
         - "cam-overview"
         - "provider-performance"
         - "collaboration-metrics"
   ```

2. **Logging**
   ```yaml
   logging:
     structured: true
     level: "info"
     outputs:
       - type: "elasticsearch"
         endpoint: "https://elasticsearch:9200"
       - type: "cloudwatch"
         group: "/aws/ecs/cam"
   ```

3. **Alerting**
   ```yaml
   alerts:
     - name: "high-error-rate"
       condition: "error_rate > 0.05"
       actions:
         - "slack"
         - "pagerduty"
     
     - name: "high-latency"
       condition: "p95_latency > 5000"
       actions:
         - "email"
   ```

### Performance Optimization

1. **Caching Strategy**
   - Implement Redis clustering
   - Use CDN for static assets
   - Cache provider responses
   - Implement request deduplication

2. **Connection Pooling**
   ```typescript
   const poolConfig = {
     maxConnections: 100,
     acquireTimeoutMillis: 30000,
     idleTimeoutMillis: 30000,
     reapIntervalMillis: 1000,
     createRetryIntervalMillis: 200
   };
   ```

3. **Auto-scaling**
   ```yaml
   autoscaling:
     enabled: true
     minReplicas: 2
     maxReplicas: 20
     targetCPUUtilizationPercentage: 70
     targetMemoryUtilizationPercentage: 80
   ```

### Backup and Recovery

1. **Database Backups**
   ```bash
   # Automated backup script
   #!/bin/bash
   timestamp=$(date +%Y%m%d_%H%M%S)
   pg_dump -h $DB_HOST -U $DB_USER cam > backup_$timestamp.sql
   aws s3 cp backup_$timestamp.sql s3://cam-backups/
   ```

2. **Configuration Backups**
   ```bash
   # Backup configuration
   kubectl get configmap cam-config -o yaml > config-backup.yaml
   kubectl get secret cam-secrets -o yaml > secrets-backup.yaml
   ```

3. **Disaster Recovery**
   - Multi-region deployment
   - Database replication
   - Configuration replication
   - Automated failover

### Compliance

1. **Data Protection**
   - Implement data encryption
   - Configure data retention policies
   - Enable audit logging
   - Implement data anonymization

2. **Access Control**
   - Role-based access control
   - Multi-factor authentication
   - API key management
   - Session management

3. **Compliance Frameworks**
   - SOC 2 Type II
   - GDPR compliance
   - HIPAA compliance
   - PCI DSS (if applicable)

## Troubleshooting

### Common Deployment Issues

1. **Container Won't Start**
   ```bash
   # Check logs
   docker logs cam-container
   kubectl logs -f deployment/cam-api -n cam-system
   ```

2. **Health Check Failures**
   ```bash
   # Test health endpoint
   curl -f http://localhost:3000/health
   ```

3. **Provider Connection Issues**
   ```bash
   # Test provider connectivity
   cam-cli test-providers --config ./config.yaml
   ```

4. **Memory/CPU Issues**
   ```bash
   # Monitor resource usage
   docker stats cam-container
   kubectl top pods -n cam-system
   ```

### Performance Debugging

1. **Enable Debug Logging**
   ```yaml
   monitoring:
     logging:
       level: "debug"
       loggers:
         - "router"
         - "providers"
         - "collaboration"
   ```

2. **Profile Application**
   ```bash
   # Node.js profiling
   node --prof app.js
   node --prof-process isolate-*.log > processed.txt
   ```

3. **Database Performance**
   ```sql
   -- Check slow queries
   SELECT query, mean_time, calls 
   FROM pg_stat_statements 
   ORDER BY mean_time DESC 
   LIMIT 10;
   ```
