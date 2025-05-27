#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { CamInfrastructureStack } from './lib/cam-infrastructure-stack';
import { CamApplicationStack } from './lib/cam-application-stack';
import { CamMonitoringStack } from './lib/cam-monitoring-stack';

const app = new cdk.App();

// Environment configuration
const env = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION || 'us-west-2',
};

// Environment from context or default
const environment = app.node.tryGetContext('environment') || 'dev';
const projectName = app.node.tryGetContext('projectName') || 'complete-arbitration-mesh';

// Stack naming convention
const stackPrefix = `${projectName}-${environment}`;

// Infrastructure Stack - VPC, ECS Cluster, RDS, ElastiCache, etc.
const infraStack = new CamInfrastructureStack(app, `${stackPrefix}-infrastructure`, {
  env,
  environment,
  projectName,
  description: `Complete Arbitration Mesh Infrastructure - ${environment}`,
  tags: {
    Environment: environment,
    Project: projectName,
    ManagedBy: 'CDK',
    Component: 'Infrastructure',
  },
});

// Application Stack - ECS Services, ALB, etc.
const appStack = new CamApplicationStack(app, `${stackPrefix}-application`, {
  env,
  environment,
  projectName,
  vpc: infraStack.vpc,
  cluster: infraStack.cluster,
  database: infraStack.database,
  redis: infraStack.redis,
  description: `Complete Arbitration Mesh Application - ${environment}`,
  tags: {
    Environment: environment,
    Project: projectName,
    ManagedBy: 'CDK',
    Component: 'Application',
  },
});

// Monitoring Stack - CloudWatch Dashboards, Alarms, etc.
const monitoringStack = new CamMonitoringStack(app, `${stackPrefix}-monitoring`, {
  env,
  environment,
  projectName,
  cluster: infraStack.cluster,
  service: appStack.service,
  loadBalancer: appStack.loadBalancer,
  database: infraStack.database,
  description: `Complete Arbitration Mesh Monitoring - ${environment}`,
  tags: {
    Environment: environment,
    Project: projectName,
    ManagedBy: 'CDK',
    Component: 'Monitoring',
  },
});

// Dependencies
appStack.addDependency(infraStack);
monitoringStack.addDependency(appStack);

// Outputs
new cdk.CfnOutput(infraStack, 'VpcId', {
  value: infraStack.vpc.vpcId,
  description: 'VPC ID',
  exportName: `${stackPrefix}-vpc-id`,
});

new cdk.CfnOutput(infraStack, 'ClusterName', {
  value: infraStack.cluster.clusterName,
  description: 'ECS Cluster Name',
  exportName: `${stackPrefix}-cluster-name`,
});

new cdk.CfnOutput(appStack, 'LoadBalancerDNS', {
  value: appStack.loadBalancer.loadBalancerDnsName,
  description: 'Application Load Balancer DNS Name',
  exportName: `${stackPrefix}-alb-dns`,
});

new cdk.CfnOutput(appStack, 'ServiceName', {
  value: appStack.service.serviceName,
  description: 'ECS Service Name',
  exportName: `${stackPrefix}-service-name`,
});
