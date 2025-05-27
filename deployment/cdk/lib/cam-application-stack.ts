import * as cdk from 'aws-cdk-lib';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as servicediscovery from 'aws-cdk-lib/aws-servicediscovery';
import * as rds from 'aws-cdk-lib/aws-rds';
import * as elasticache from 'aws-cdk-lib/aws-elasticache';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as route53targets from 'aws-cdk-lib/aws-route53-targets';
import * as certificatemanager from 'aws-cdk-lib/aws-certificatemanager';
import { Construct } from 'constructs';

export interface CamApplicationStackProps extends cdk.StackProps {
  environment: string;
  projectName: string;
  vpc: ec2.Vpc;
  cluster: ecs.Cluster;
  database: rds.DatabaseInstance;
  redis: elasticache.CfnCacheCluster;
}

export class CamApplicationStack extends cdk.Stack {
  public readonly service: ecs.FargateService;
  public readonly loadBalancer: elbv2.ApplicationLoadBalancer;

  constructor(scope: Construct, id: string, props: CamApplicationStackProps) {
    super(scope, id, props);

    // Service Discovery Namespace
    const namespace = new servicediscovery.PrivateDnsNamespace(this, 'CamNamespace', {
      name: `${props.projectName}.local`,
      vpc: props.vpc,
      description: 'Service discovery namespace for CAM services',
    });

    // CloudWatch Log Group
    const logGroup = new logs.LogGroup(this, 'CamLogGroup', {
      logGroupName: `/ecs/${props.projectName}-${props.environment}`,
      retention: props.environment === 'prod' 
        ? logs.RetentionDays.ONE_MONTH 
        : logs.RetentionDays.ONE_WEEK,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // Task Definition
    const taskDefinition = new ecs.FargateTaskDefinition(this, 'CamTaskDefinition', {
      memoryLimitMiB: props.environment === 'prod' ? 2048 : 1024,
      cpu: props.environment === 'prod' ? 1024 : 512,
      executionRole: iam.Role.fromRoleArn(
        this,
        'TaskExecutionRole',
        cdk.Fn.importValue(`${props.projectName}-${props.environment}-task-execution-role`)
      ),
      taskRole: iam.Role.fromRoleArn(
        this,
        'TaskRole',
        cdk.Fn.importValue(`${props.projectName}-${props.environment}-task-role`)
      ),
    });

    // Container Definition
    const container = taskDefinition.addContainer('CamContainer', {
      image: ecs.ContainerImage.fromRegistry(`ghcr.io/cam-protocol/complete-arbitration-mesh:latest`),
      environment: {
        NODE_ENV: 'production',
        PORT: '3000',
        REDIS_HOST: props.redis.attrRedisEndpointAddress,
        REDIS_PORT: '6379',
        LOG_LEVEL: props.environment === 'prod' ? 'info' : 'debug',
      },
      secrets: {
        DATABASE_URL: ecs.Secret.fromSecretsManager(props.database.secret!, 'engine'),
      },
      logging: ecs.LogDrivers.awsLogs({
        streamPrefix: 'cam',
        logGroup,
      }),
      healthCheck: {
        command: ['CMD-SHELL', 'curl -f http://localhost:3000/health || exit 1'],
        interval: cdk.Duration.seconds(30),
        timeout: cdk.Duration.seconds(5),
        retries: 3,
        startPeriod: cdk.Duration.seconds(60),
      },
    });

    container.addPortMappings({
      containerPort: 3000,
      protocol: ecs.Protocol.TCP,
    });

    // Security Group for ECS Service
    const serviceSecurityGroup = new ec2.SecurityGroup(this, 'ServiceSecurityGroup', {
      vpc: props.vpc,
      description: 'Security group for CAM ECS service',
      allowAllOutbound: true,
    });

    // ECS Service
    this.service = new ecs.FargateService(this, 'CamService', {
      cluster: props.cluster,
      taskDefinition,
      serviceName: `${props.projectName}-${props.environment}`,
      desiredCount: props.environment === 'prod' ? 3 : 1,
      minHealthyPercent: props.environment === 'prod' ? 50 : 0,
      maxHealthyPercent: 200,
      securityGroups: [serviceSecurityGroup],
      vpcSubnets: {
        subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
      },
      cloudMapOptions: {
        name: 'cam-api',
        cloudMapNamespace: namespace,
        dnsRecordType: servicediscovery.DnsRecordType.A,
        dnsTtl: cdk.Duration.seconds(60),
      },
      enableExecuteCommand: props.environment !== 'prod',
    });

    // Auto Scaling
    const scalingTarget = this.service.autoScaleTaskCount({
      minCapacity: props.environment === 'prod' ? 2 : 1,
      maxCapacity: props.environment === 'prod' ? 10 : 3,
    });

    scalingTarget.scaleOnCpuUtilization('CpuScaling', {
      targetUtilizationPercent: 70,
      scaleInCooldown: cdk.Duration.minutes(5),
      scaleOutCooldown: cdk.Duration.minutes(2),
    });

    scalingTarget.scaleOnMemoryUtilization('MemoryScaling', {
      targetUtilizationPercent: 80,
      scaleInCooldown: cdk.Duration.minutes(5),
      scaleOutCooldown: cdk.Duration.minutes(2),
    });

    // Application Load Balancer
    this.loadBalancer = new elbv2.ApplicationLoadBalancer(this, 'CamLoadBalancer', {
      vpc: props.vpc,
      internetFacing: true,
      loadBalancerName: `${props.projectName}-${props.environment}-alb`,
      securityGroup: new ec2.SecurityGroup(this, 'LoadBalancerSecurityGroup', {
        vpc: props.vpc,
        description: 'Security group for CAM load balancer',
        allowAllOutbound: true,
      }),
    });

    // ALB Security Group Rules
    this.loadBalancer.securityGroup.addIngressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.tcp(80),
      'Allow HTTP traffic'
    );

    this.loadBalancer.securityGroup.addIngressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.tcp(443),
      'Allow HTTPS traffic'
    );

    // Service Security Group Rules
    serviceSecurityGroup.addIngressRule(
      ec2.Peer.securityGroupId(this.loadBalancer.securityGroup.securityGroupId),
      ec2.Port.tcp(3000),
      'Allow ALB to connect to service'
    );

    // Target Group
    const targetGroup = new elbv2.ApplicationTargetGroup(this, 'CamTargetGroup', {
      vpc: props.vpc,
      port: 3000,
      protocol: elbv2.ApplicationProtocol.HTTP,
      targetType: elbv2.TargetType.IP,
      healthCheck: {
        enabled: true,
        path: '/health',
        protocol: elbv2.Protocol.HTTP,
        port: '3000',
        healthyHttpCodes: '200',
        interval: cdk.Duration.seconds(30),
        timeout: cdk.Duration.seconds(5),
        healthyThresholdCount: 2,
        unhealthyThresholdCount: 5,
      },
      deregistrationDelay: cdk.Duration.seconds(30),
    });

    // Attach ECS service to target group
    this.service.attachToApplicationTargetGroup(targetGroup);

    // HTTP Listener (redirect to HTTPS)
    this.loadBalancer.addListener('HttpListener', {
      port: 80,
      protocol: elbv2.ApplicationProtocol.HTTP,
      defaultAction: elbv2.ListenerAction.redirect({
        protocol: 'HTTPS',
        port: '443',
        permanent: true,
      }),
    });

    // HTTPS Listener (conditionally with certificate)
    if (props.environment === 'prod') {
      // For production, you would typically have a certificate
      // This is a placeholder - replace with actual certificate ARN or create one
      const certificate = certificatemanager.Certificate.fromCertificateArn(
        this,
        'Certificate',
        'arn:aws:acm:region:account:certificate/certificate-id' // Replace with actual ARN
      );

      this.loadBalancer.addListener('HttpsListener', {
        port: 443,
        protocol: elbv2.ApplicationProtocol.HTTPS,
        certificates: [certificate],
        defaultTargetGroups: [targetGroup],
      });
    } else {
      // For dev/staging, use HTTP only
      this.loadBalancer.addListener('HttpListener2', {
        port: 8080,
        protocol: elbv2.ApplicationProtocol.HTTP,
        defaultTargetGroups: [targetGroup],
      });
    }

    // Route 53 (optional, for custom domain)
    if (props.environment === 'prod') {
      // This is optional - only if you have a hosted zone
      // const hostedZone = route53.HostedZone.fromLookup(this, 'HostedZone', {
      //   domainName: 'example.com',
      // });

      // new route53.ARecord(this, 'AliasRecord', {
      //   zone: hostedZone,
      //   recordName: 'api',
      //   target: route53.RecordTarget.fromAlias(
      //     new route53targets.LoadBalancerTarget(this.loadBalancer)
      //   ),
      // });
    }

    // Tags
    cdk.Tags.of(this).add('Project', props.projectName);
    cdk.Tags.of(this).add('Environment', props.environment);
    cdk.Tags.of(this).add('ManagedBy', 'CDK');
  }
}
