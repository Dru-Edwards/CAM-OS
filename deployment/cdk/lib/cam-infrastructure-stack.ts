import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as rds from 'aws-cdk-lib/aws-rds';
import * as elasticache from 'aws-cdk-lib/aws-elasticache';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import { Construct } from 'constructs';

export interface CamInfrastructureStackProps extends cdk.StackProps {
  environment: string;
  projectName: string;
}

export class CamInfrastructureStack extends cdk.Stack {
  public readonly vpc: ec2.Vpc;
  public readonly cluster: ecs.Cluster;
  public readonly database: rds.DatabaseInstance;
  public readonly redis: elasticache.CfnCacheCluster;
  public readonly databaseSecret: secretsmanager.Secret;

  constructor(scope: Construct, id: string, props: CamInfrastructureStackProps) {
    super(scope, id, props);

    // VPC with public and private subnets across 3 AZs
    this.vpc = new ec2.Vpc(this, 'CamVpc', {
      maxAzs: 3,
      natGateways: props.environment === 'prod' ? 3 : 1,
      subnetConfiguration: [
        {
          cidrMask: 24,
          name: 'Public',
          subnetType: ec2.SubnetType.PUBLIC,
        },
        {
          cidrMask: 24,
          name: 'Private',
          subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
        },
        {
          cidrMask: 28,
          name: 'Isolated',
          subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
        },
      ],
      enableDnsHostnames: true,
      enableDnsSupport: true,
    });

    // VPC Flow Logs for security monitoring
    new ec2.FlowLog(this, 'VpcFlowLog', {
      resourceType: ec2.FlowLogResourceType.fromVpc(this.vpc),
      destination: ec2.FlowLogDestination.toCloudWatchLogs(
        new logs.LogGroup(this, 'VpcFlowLogGroup', {
          retention: logs.RetentionDays.ONE_MONTH,
          removalPolicy: cdk.RemovalPolicy.DESTROY,
        })
      ),
    });

    // ECS Cluster with Container Insights
    this.cluster = new ecs.Cluster(this, 'CamCluster', {
      vpc: this.vpc,
      clusterName: `${props.projectName}-${props.environment}`,
      containerInsights: true,
      enableFargateCapacityProviders: true,
    });

    // Database subnet group
    const dbSubnetGroup = new rds.SubnetGroup(this, 'DatabaseSubnetGroup', {
      vpc: this.vpc,
      description: 'Subnet group for CAM database',
      vpcSubnets: {
        subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
      },
    });

    // Database credentials secret
    this.databaseSecret = new secretsmanager.Secret(this, 'DatabaseSecret', {
      description: 'CAM Database credentials',
      generateSecretString: {
        secretStringTemplate: JSON.stringify({ username: 'camadmin' }),
        generateStringKey: 'password',
        excludeCharacters: ' %+~`#$&*()|[]{}:;<>?!\'/@"\\',
        includeSpace: false,
        passwordLength: 32,
      },
    });

    // Database security group
    const dbSecurityGroup = new ec2.SecurityGroup(this, 'DatabaseSecurityGroup', {
      vpc: this.vpc,
      description: 'Security group for CAM database',
      allowAllOutbound: false,
    });

    // PostgreSQL RDS instance
    this.database = new rds.DatabaseInstance(this, 'CamDatabase', {
      engine: rds.DatabaseInstanceEngine.postgres({
        version: rds.PostgresEngineVersion.VER_15_4,
      }),
      instanceType: props.environment === 'prod' 
        ? ec2.InstanceType.of(ec2.InstanceClass.R6G, ec2.InstanceSize.XLARGE)
        : ec2.InstanceType.of(ec2.InstanceClass.T4G, ec2.InstanceSize.MEDIUM),
      vpc: this.vpc,
      subnetGroup: dbSubnetGroup,
      securityGroups: [dbSecurityGroup],
      credentials: rds.Credentials.fromSecret(this.databaseSecret),
      databaseName: 'camarbitration',
      allocatedStorage: props.environment === 'prod' ? 100 : 20,
      maxAllocatedStorage: props.environment === 'prod' ? 1000 : 100,
      deleteAutomatedBackups: props.environment !== 'prod',
      backupRetention: props.environment === 'prod' 
        ? cdk.Duration.days(30) 
        : cdk.Duration.days(7),
      deletionProtection: props.environment === 'prod',
      multiAz: props.environment === 'prod',
      monitoringInterval: cdk.Duration.seconds(60),
      enablePerformanceInsights: true,
      cloudwatchLogsExports: ['postgresql'],
      parameterGroup: new rds.ParameterGroup(this, 'DatabaseParameterGroup', {
        engine: rds.DatabaseInstanceEngine.postgres({
          version: rds.PostgresEngineVersion.VER_15_4,
        }),
        parameters: {
          'shared_preload_libraries': 'pg_stat_statements',
          'log_statement': 'all',
          'log_min_duration_statement': '100',
        },
      }),
    });

    // Redis subnet group
    const redisSubnetGroup = new elasticache.CfnSubnetGroup(this, 'RedisSubnetGroup', {
      description: 'Subnet group for CAM Redis cluster',
      subnetIds: this.vpc.isolatedSubnets.map(subnet => subnet.subnetId),
    });

    // Redis security group
    const redisSecurityGroup = new ec2.SecurityGroup(this, 'RedisSecurityGroup', {
      vpc: this.vpc,
      description: 'Security group for CAM Redis cluster',
      allowAllOutbound: false,
    });

    // Redis cache cluster
    this.redis = new elasticache.CfnCacheCluster(this, 'CamRedis', {
      cacheNodeType: props.environment === 'prod' ? 'cache.r7g.large' : 'cache.t4g.micro',
      engine: 'redis',
      numCacheNodes: 1,
      cacheSubnetGroupName: redisSubnetGroup.ref,
      vpcSecurityGroupIds: [redisSecurityGroup.securityGroupId],
      port: 6379,
      engineVersion: '7.0',
      transitEncryptionEnabled: true,
      atRestEncryptionEnabled: true,
    });

    // ECS Task Execution Role
    const taskExecutionRole = new iam.Role(this, 'EcsTaskExecutionRole', {
      assumedBy: new iam.ServicePrincipal('ecs-tasks.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AmazonECSTaskExecutionRolePolicy'),
      ],
    });

    // Grant task execution role access to secrets
    this.databaseSecret.grantRead(taskExecutionRole);

    // ECS Task Role
    const taskRole = new iam.Role(this, 'EcsTaskRole', {
      assumedBy: new iam.ServicePrincipal('ecs-tasks.amazonaws.com'),
      inlinePolicies: {
        CloudWatchLogs: new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: [
                'logs:CreateLogGroup',
                'logs:CreateLogStream',
                'logs:PutLogEvents',
              ],
              resources: ['*'],
            }),
          ],
        }),
      },
    });

    // Store task roles as stack exports
    new cdk.CfnOutput(this, 'TaskExecutionRoleArn', {
      value: taskExecutionRole.roleArn,
      exportName: `${props.projectName}-${props.environment}-task-execution-role`,
    });

    new cdk.CfnOutput(this, 'TaskRoleArn', {
      value: taskRole.roleArn,
      exportName: `${props.projectName}-${props.environment}-task-role`,
    });

    // Security group rules
    dbSecurityGroup.addIngressRule(
      ec2.Peer.securityGroupId(this.cluster.connections.securityGroups[0].securityGroupId),
      ec2.Port.tcp(5432),
      'Allow ECS tasks to connect to database'
    );

    redisSecurityGroup.addIngressRule(
      ec2.Peer.securityGroupId(this.cluster.connections.securityGroups[0].securityGroupId),
      ec2.Port.tcp(6379),
      'Allow ECS tasks to connect to Redis'
    );

    // Tags
    cdk.Tags.of(this).add('Project', props.projectName);
    cdk.Tags.of(this).add('Environment', props.environment);
    cdk.Tags.of(this).add('ManagedBy', 'CDK');
  }
}
