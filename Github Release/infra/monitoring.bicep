// Monitoring and alerting configuration for Complete Arbitration Mesh
// Creates alerts, dashboards, and monitoring rules

param location string = resourceGroup().location
param environmentName string
param resourceToken string
param applicationInsightsName string
param containerAppName string

// Variables
var prefix = '${environmentName}-${resourceToken}'
var tags = {
  'azd-env-name': environmentName
  'cam-service': 'complete-arbitration-mesh'
}

// Reference existing resources
resource applicationInsights 'Microsoft.Insights/components@2020-02-02' existing = {
  name: applicationInsightsName
}

resource containerApp 'Microsoft.App/containerApps@2024-03-01' existing = {
  name: containerAppName
}

// Action Group for alerts
resource actionGroup 'Microsoft.Insights/actionGroups@2023-01-01' = {
  name: '${prefix}-alerts'
  location: 'Global'
  tags: tags
  properties: {
    groupShortName: 'CAM-Alerts'
    enabled: true
    emailReceivers: [
      {
        name: 'Admin'
        emailAddress: 'admin@example.com'
        useCommonAlertSchema: true
      }
    ]
  }
}

// High CPU Alert
resource highCpuAlert 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: '${prefix}-high-cpu'
  location: 'Global'
  tags: tags
  properties: {
    description: 'Alert when CPU usage is high'
    severity: 2
    enabled: true
    scopes: [
      containerApp.id
    ]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'HighCpu'
          metricName: 'CpuPercentage'
          operator: 'GreaterThan'
          threshold: 80
          timeAggregation: 'Average'
          criterionType: 'StaticThresholdCriterion'
        }
      ]
    }
    actions: [
      {
        actionGroupId: actionGroup.id
      }
    ]
  }
}

// High Memory Alert
resource highMemoryAlert 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: '${prefix}-high-memory'
  location: 'Global'
  tags: tags
  properties: {
    description: 'Alert when memory usage is high'
    severity: 2
    enabled: true
    scopes: [
      containerApp.id
    ]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'HighMemory'
          metricName: 'MemoryPercentage'
          operator: 'GreaterThan'
          threshold: 85
          timeAggregation: 'Average'
          criterionType: 'StaticThresholdCriterion'
        }
      ]
    }
    actions: [
      {
        actionGroupId: actionGroup.id
      }
    ]
  }
}

// High Request Rate Alert
resource highRequestRateAlert 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: '${prefix}-high-requests'
  location: 'Global'
  tags: tags
  properties: {
    description: 'Alert when request rate is unusually high'
    severity: 3
    enabled: true
    scopes: [
      containerApp.id
    ]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'HighRequestRate'
          metricName: 'Requests'
          operator: 'GreaterThan'
          threshold: 1000
          timeAggregation: 'Total'
          criterionType: 'StaticThresholdCriterion'
        }
      ]
    }
    actions: [
      {
        actionGroupId: actionGroup.id
      }
    ]
  }
}

// Application Availability Alert
resource availabilityAlert 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: '${prefix}-availability'
  location: 'Global'
  tags: tags
  properties: {
    description: 'Alert when application availability drops'
    severity: 1
    enabled: true
    scopes: [
      applicationInsights.id
    ]
    evaluationFrequency: 'PT1M'
    windowSize: 'PT5M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'LowAvailability'
          metricName: 'availabilityResults/availabilityPercentage'
          operator: 'LessThan'
          threshold: 95
          timeAggregation: 'Average'
          criterionType: 'StaticThresholdCriterion'
        }
      ]
    }
    actions: [
      {
        actionGroupId: actionGroup.id
      }
    ]
  }
}

// Outputs
output actionGroupId string = actionGroup.id
output alertNames array = [
  highCpuAlert.name
  highMemoryAlert.name
  highRequestRateAlert.name
  availabilityAlert.name
]
