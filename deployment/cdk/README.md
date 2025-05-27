# AWS CDK Deployment for Complete Arbitration Mesh

This directory contains AWS CDK (Cloud Development Kit) infrastructure-as-code for deploying the Complete Arbitration Mesh on AWS using modern TypeScript constructs.

## Architecture

The CDK deployment creates a production-ready infrastructure with:

### Infrastructure Stack (`CamInfrastructureStack`)
- **VPC**: Multi-AZ with public, private, and isolated subnets
- **ECS Cluster**: Fargate-enabled with Container Insights
- **RDS PostgreSQL**: Multi-AZ with automated backups and performance insights
- **ElastiCache Redis**: Encrypted at rest and in transit
- **Security Groups**: Least-privilege network access controls
- **IAM Roles**: Task execution and runtime roles with minimal permissions

### Application Stack (`CamApplicationStack`)
- **ECS Fargate Service**: Auto-scaling containerized application
- **Application Load Balancer**: HTTPS termination and health checks
- **Service Discovery**: Private DNS for service-to-service communication
- **Auto Scaling**: CPU and memory-based scaling policies
- **CloudWatch Logs**: Centralized application logging

### Monitoring Stack (`CamMonitoringStack`)
- **CloudWatch Dashboard**: Real-time metrics visualization
- **CloudWatch Alarms**: Proactive alerting for critical metrics
- **SNS Notifications**: Email alerts for operational issues
- **Custom Metrics**: Application-specific monitoring

## Prerequisites

1. **AWS CLI** configured with appropriate credentials
2. **Node.js 18+** and npm
3. **AWS CDK CLI** installed globally:
   ```bash
   npm install -g aws-cdk
   ```
4. **Docker** for building container images

## Configuration

### Environment Variables

Create environment-specific configuration:

```bash
# For development
export CDK_DEFAULT_ACCOUNT=123456789012
export CDK_DEFAULT_REGION=us-west-2

# For production
export CDK_DEFAULT_ACCOUNT=123456789012
export CDK_DEFAULT_REGION=us-west-2
```

### Context Configuration

The CDK uses context variables for environment-specific settings:

```bash
# Deploy to development
cdk deploy --context environment=dev

# Deploy to staging 
cdk deploy --context environment=staging

# Deploy to production
cdk deploy --context environment=prod
```

## Deployment

### 1. Install Dependencies

```bash
cd deployment/cdk
npm install
```

### 2. Bootstrap CDK (First Time Only)

```bash
cdk bootstrap
```

### 3. Build and Synthesize

```bash
npm run build
cdk synth
```

### 4. Deploy Stacks

#### Development Environment
```bash
npm run deploy:dev
```

#### Staging Environment
```bash
npm run deploy:staging
```

#### Production Environment
```bash
npm run deploy:prod
```

### 5. Verify Deployment

```bash
# Check stack status
cdk list

# View stack outputs
aws cloudformation describe-stacks --stack-name complete-arbitration-mesh-prod-infrastructure
```

## Stack Outputs

Each deployment provides essential outputs:

### Infrastructure Stack
- **VpcId**: VPC identifier for reference
- **ClusterName**: ECS cluster name
- **DatabaseEndpoint**: RDS endpoint URL
- **RedisEndpoint**: ElastiCache Redis endpoint

### Application Stack  
- **LoadBalancerDNS**: Application URL
- **ServiceName**: ECS service identifier
- **TaskDefinitionArn**: Task definition ARN

### Monitoring Stack
- **DashboardURL**: CloudWatch dashboard link
- **AlertTopicArn**: SNS topic for alerts

## Customization

### Environment-Specific Settings

Modify the stacks for different environments:

```typescript
// In cam-infrastructure-stack.ts
const instanceType = props.environment === 'prod' 
  ? ec2.InstanceType.of(ec2.InstanceClass.R6G, ec2.InstanceSize.XLARGE)
  : ec2.InstanceType.of(ec2.InstanceClass.T4G, ec2.InstanceSize.MEDIUM);
```

### Security Configuration

Update security groups and IAM policies:

```typescript
// Add custom security group rules
dbSecurityGroup.addIngressRule(
  ec2.Peer.ipv4('10.0.0.0/8'),
  ec2.Port.tcp(5432),
  'Allow internal network access'
);
```

### Monitoring Customization

Add custom CloudWatch metrics and alarms:

```typescript
// Custom application metric
const customMetric = new cloudwatch.Metric({
  namespace: 'CAM/Application',
  metricName: 'BusinessMetric',
  statistic: 'Average',
});
```

## Scaling Configuration

### Auto Scaling Policies

The application automatically scales based on:

- **CPU Utilization**: Target 70%, scale out after 2 minutes, scale in after 5 minutes
- **Memory Utilization**: Target 80%, scale out after 2 minutes, scale in after 5 minutes

### Manual Scaling

```bash
# Scale ECS service manually
aws ecs update-service \
  --cluster complete-arbitration-mesh-prod \
  --service complete-arbitration-mesh-prod \
  --desired-count 5
```

## Monitoring and Alerting

### CloudWatch Dashboard

Access the dashboard at: `https://console.aws.amazon.com/cloudwatch/dashboards`

### Email Alerts

Configure email notifications by updating the SNS subscription:

```typescript
this.alertTopic.addSubscription(
  new snsSubscriptions.EmailSubscription('your-email@domain.com')
);
```

### Custom Alerts

Add application-specific alarms:

```typescript
const customAlarm = new cloudwatch.Alarm(this, 'CustomAlarm', {
  alarmName: `${props.projectName}-${props.environment}-custom-metric`,
  metric: customMetric,
  threshold: 100,
  evaluationPeriods: 2,
});
```

## Security Best Practices

### Network Security
- Private subnets for application and database tiers
- Security groups with minimal required access
- VPC Flow Logs enabled for monitoring

### Data Protection
- RDS encryption at rest and in transit
- ElastiCache encryption enabled
- Secrets Manager for database credentials

### Access Control
- IAM roles with least-privilege principles
- ECS task execution roles with minimal permissions
- CloudWatch Logs encryption

## Disaster Recovery

### Automated Backups
- RDS automated backups with 30-day retention (production)
- Point-in-time recovery enabled
- Cross-region backup replication (optional)

### Multi-AZ Deployment
- RDS Multi-AZ for high availability
- ECS tasks distributed across multiple AZs
- Load balancer spans multiple AZs

## Cost Optimization

### Development Environment
- Single NAT Gateway
- Smaller instance types
- Shorter backup retention
- Reduced monitoring retention

### Production Environment
- Multi-AZ NAT Gateways for availability
- Right-sized instances based on load
- Extended backup retention
- Comprehensive monitoring

## Troubleshooting

### Common Issues

1. **CDK Bootstrap Required**
   ```bash
   cdk bootstrap aws://ACCOUNT-NUMBER/REGION
   ```

2. **Insufficient Permissions**
   - Ensure CDK execution role has required permissions
   - Check CloudFormation stack events for detailed errors

3. **Resource Limits**
   - Verify AWS service limits (VPC, ECS, RDS)
   - Request limit increases if needed

4. **Container Image Issues**
   - Ensure image exists in ECR or public registry
   - Verify image tag and permissions

### Debugging Commands

```bash
# View CDK diff
cdk diff --context environment=prod

# Check CloudFormation events
aws cloudformation describe-stack-events --stack-name complete-arbitration-mesh-prod-infrastructure

# View ECS service status
aws ecs describe-services --cluster complete-arbitration-mesh-prod --services complete-arbitration-mesh-prod
```

## Cleanup

### Destroy Stacks

```bash
# Destroy all stacks
cdk destroy --all

# Destroy specific environment
cdk destroy --all --context environment=dev
```

### Manual Cleanup

Some resources may require manual cleanup:
- RDS snapshots (if deletion protection enabled)
- S3 buckets with contents
- CloudWatch Log Groups with retention policies

## Support

For deployment issues:
1. Check AWS CloudFormation console for stack events
2. Review CloudWatch Logs for application issues
3. Verify AWS service limits and quotas
4. Consult AWS CDK documentation for construct-specific issues
