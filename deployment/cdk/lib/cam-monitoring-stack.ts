import * as cdk from 'aws-cdk-lib';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as rds from 'aws-cdk-lib/aws-rds';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as snsSubscriptions from 'aws-cdk-lib/aws-sns-subscriptions';
import * as actions from 'aws-cdk-lib/aws-cloudwatch-actions';
import { Construct } from 'constructs';

export interface CamMonitoringStackProps extends cdk.StackProps {
  environment: string;
  projectName: string;
  cluster: ecs.Cluster;
  service: ecs.FargateService;
  loadBalancer: elbv2.ApplicationLoadBalancer;
  database: rds.DatabaseInstance;
}

export class CamMonitoringStack extends cdk.Stack {
  public readonly dashboard: cloudwatch.Dashboard;
  public readonly alertTopic: sns.Topic;

  constructor(scope: Construct, id: string, props: CamMonitoringStackProps) {
    super(scope, id, props);

    // SNS Topic for alerts
    this.alertTopic = new sns.Topic(this, 'CamAlerts', {
      topicName: `${props.projectName}-${props.environment}-alerts`,
      displayName: `CAM ${props.environment} Alerts`,
    });

    // Add email subscription (replace with actual email)
    this.alertTopic.addSubscription(
      new snsSubscriptions.EmailSubscription('alerts@your-domain.com')
    );

    // Create CloudWatch Dashboard
    this.dashboard = new cloudwatch.Dashboard(this, 'CamDashboard', {
      dashboardName: `${props.projectName}-${props.environment}`,
    });

    // ECS Service Metrics
    const serviceWidget = new cloudwatch.GraphWidget({
      title: 'ECS Service Metrics',
      width: 12,
      height: 6,
      left: [
        new cloudwatch.Metric({
          namespace: 'AWS/ECS',
          metricName: 'CPUUtilization',
          dimensionsMap: {
            ServiceName: props.service.serviceName,
            ClusterName: props.cluster.clusterName,
          },
          statistic: 'Average',
        }),
        new cloudwatch.Metric({
          namespace: 'AWS/ECS',
          metricName: 'MemoryUtilization',
          dimensionsMap: {
            ServiceName: props.service.serviceName,
            ClusterName: props.cluster.clusterName,
          },
          statistic: 'Average',
        }),
      ],
      right: [
        new cloudwatch.Metric({
          namespace: 'AWS/ECS',
          metricName: 'RunningTaskCount',
          dimensionsMap: {
            ServiceName: props.service.serviceName,
            ClusterName: props.cluster.clusterName,
          },
          statistic: 'Average',
        }),
      ],
    });

    // ALB Metrics
    const albWidget = new cloudwatch.GraphWidget({
      title: 'Application Load Balancer Metrics',
      width: 12,
      height: 6,
      left: [
        new cloudwatch.Metric({
          namespace: 'AWS/ApplicationELB',
          metricName: 'RequestCount',
          dimensionsMap: {
            LoadBalancer: props.loadBalancer.loadBalancerFullName,
          },
          statistic: 'Sum',
        }),
        new cloudwatch.Metric({
          namespace: 'AWS/ApplicationELB',
          metricName: 'TargetResponseTime',
          dimensionsMap: {
            LoadBalancer: props.loadBalancer.loadBalancerFullName,
          },
          statistic: 'Average',
        }),
      ],
      right: [
        new cloudwatch.Metric({
          namespace: 'AWS/ApplicationELB',
          metricName: 'HTTPCode_Target_4XX_Count',
          dimensionsMap: {
            LoadBalancer: props.loadBalancer.loadBalancerFullName,
          },
          statistic: 'Sum',
        }),
        new cloudwatch.Metric({
          namespace: 'AWS/ApplicationELB',
          metricName: 'HTTPCode_Target_5XX_Count',
          dimensionsMap: {
            LoadBalancer: props.loadBalancer.loadBalancerFullName,
          },
          statistic: 'Sum',
        }),
      ],
    });

    // RDS Metrics
    const rdsWidget = new cloudwatch.GraphWidget({
      title: 'RDS Database Metrics',
      width: 12,
      height: 6,
      left: [
        new cloudwatch.Metric({
          namespace: 'AWS/RDS',
          metricName: 'CPUUtilization',
          dimensionsMap: {
            DBInstanceIdentifier: props.database.instanceIdentifier,
          },
          statistic: 'Average',
        }),
        new cloudwatch.Metric({
          namespace: 'AWS/RDS',
          metricName: 'DatabaseConnections',
          dimensionsMap: {
            DBInstanceIdentifier: props.database.instanceIdentifier,
          },
          statistic: 'Average',
        }),
      ],
      right: [
        new cloudwatch.Metric({
          namespace: 'AWS/RDS',
          metricName: 'FreeableMemory',
          dimensionsMap: {
            DBInstanceIdentifier: props.database.instanceIdentifier,
          },
          statistic: 'Average',
        }),
        new cloudwatch.Metric({
          namespace: 'AWS/RDS',
          metricName: 'FreeStorageSpace',
          dimensionsMap: {
            DBInstanceIdentifier: props.database.instanceIdentifier,
          },
          statistic: 'Average',
        }),
      ],
    });

    // Custom Application Metrics (assuming your app publishes custom metrics)
    const customWidget = new cloudwatch.GraphWidget({
      title: 'Application Metrics',
      width: 12,
      height: 6,
      left: [
        new cloudwatch.Metric({
          namespace: 'CAM/Application',
          metricName: 'RequestProcessingTime',
          statistic: 'Average',
        }),
        new cloudwatch.Metric({
          namespace: 'CAM/Application',
          metricName: 'ActiveConnections',
          statistic: 'Average',
        }),
      ],
      right: [
        new cloudwatch.Metric({
          namespace: 'CAM/Application',
          metricName: 'ErrorRate',
          statistic: 'Average',
        }),
        new cloudwatch.Metric({
          namespace: 'CAM/Application',
          metricName: 'ThroughputPerSecond',
          statistic: 'Sum',
        }),
      ],
    });

    // Add widgets to dashboard
    this.dashboard.addWidgets(
      serviceWidget,
      albWidget,
      rdsWidget,
      customWidget
    );

    // CloudWatch Alarms

    // High CPU Utilization Alarm
    const highCpuAlarm = new cloudwatch.Alarm(this, 'HighCpuAlarm', {
      alarmName: `${props.projectName}-${props.environment}-high-cpu`,
      alarmDescription: 'ECS service CPU utilization is high',
      metric: new cloudwatch.Metric({
        namespace: 'AWS/ECS',
        metricName: 'CPUUtilization',
        dimensionsMap: {
          ServiceName: props.service.serviceName,
          ClusterName: props.cluster.clusterName,
        },
        statistic: 'Average',
      }),
      threshold: 80,
      evaluationPeriods: 2,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    highCpuAlarm.addAlarmAction(new actions.SnsAction(this.alertTopic));

    // High Memory Utilization Alarm
    const highMemoryAlarm = new cloudwatch.Alarm(this, 'HighMemoryAlarm', {
      alarmName: `${props.projectName}-${props.environment}-high-memory`,
      alarmDescription: 'ECS service memory utilization is high',
      metric: new cloudwatch.Metric({
        namespace: 'AWS/ECS',
        metricName: 'MemoryUtilization',
        dimensionsMap: {
          ServiceName: props.service.serviceName,
          ClusterName: props.cluster.clusterName,
        },
        statistic: 'Average',
      }),
      threshold: 85,
      evaluationPeriods: 2,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    highMemoryAlarm.addAlarmAction(new actions.SnsAction(this.alertTopic));

    // High Error Rate Alarm
    const highErrorRateAlarm = new cloudwatch.Alarm(this, 'HighErrorRateAlarm', {
      alarmName: `${props.projectName}-${props.environment}-high-error-rate`,
      alarmDescription: 'Application error rate is high',
      metric: new cloudwatch.Metric({
        namespace: 'AWS/ApplicationELB',
        metricName: 'HTTPCode_Target_5XX_Count',
        dimensionsMap: {
          LoadBalancer: props.loadBalancer.loadBalancerFullName,
        },
        statistic: 'Sum',
      }),
      threshold: 10,
      evaluationPeriods: 2,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    highErrorRateAlarm.addAlarmAction(new actions.SnsAction(this.alertTopic));

    // Database CPU Alarm
    const dbHighCpuAlarm = new cloudwatch.Alarm(this, 'DatabaseHighCpuAlarm', {
      alarmName: `${props.projectName}-${props.environment}-db-high-cpu`,
      alarmDescription: 'Database CPU utilization is high',
      metric: new cloudwatch.Metric({
        namespace: 'AWS/RDS',
        metricName: 'CPUUtilization',
        dimensionsMap: {
          DBInstanceIdentifier: props.database.instanceIdentifier,
        },
        statistic: 'Average',
      }),
      threshold: 80,
      evaluationPeriods: 3,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    dbHighCpuAlarm.addAlarmAction(new actions.SnsAction(this.alertTopic));

    // Low Free Storage Alarm
    const lowStorageAlarm = new cloudwatch.Alarm(this, 'LowStorageAlarm', {
      alarmName: `${props.projectName}-${props.environment}-low-storage`,
      alarmDescription: 'Database free storage is low',
      metric: new cloudwatch.Metric({
        namespace: 'AWS/RDS',
        metricName: 'FreeStorageSpace',
        dimensionsMap: {
          DBInstanceIdentifier: props.database.instanceIdentifier,
        },
        statistic: 'Average',
      }),
      threshold: 2 * 1024 * 1024 * 1024, // 2 GB in bytes
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    lowStorageAlarm.addAlarmAction(new actions.SnsAction(this.alertTopic));

    // Service Running Tasks Alarm
    const lowTaskCountAlarm = new cloudwatch.Alarm(this, 'LowTaskCountAlarm', {
      alarmName: `${props.projectName}-${props.environment}-low-task-count`,
      alarmDescription: 'ECS service has too few running tasks',
      metric: new cloudwatch.Metric({
        namespace: 'AWS/ECS',
        metricName: 'RunningTaskCount',
        dimensionsMap: {
          ServiceName: props.service.serviceName,
          ClusterName: props.cluster.clusterName,
        },
        statistic: 'Average',
      }),
      threshold: props.environment === 'prod' ? 2 : 1,
      evaluationPeriods: 2,
      comparisonOperator: cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.BREACHING,
    });

    lowTaskCountAlarm.addAlarmAction(new actions.SnsAction(this.alertTopic));

    // Tags
    cdk.Tags.of(this).add('Project', props.projectName);
    cdk.Tags.of(this).add('Environment', props.environment);
    cdk.Tags.of(this).add('ManagedBy', 'CDK');
  }
}
