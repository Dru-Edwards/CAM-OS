# Complete Arbitration Mesh (CAM) Helm Chart

This Helm chart deploys the Complete Arbitration Mesh (CAM) on a Kubernetes cluster using the Helm package manager.

## Overview

The Complete Arbitration Mesh (CAM) is an advanced distributed system that provides cognitive arbitration capabilities with multi-agent collaboration. This chart deploys a production-ready CAM cluster with comprehensive monitoring, security, and scalability features.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.2.0+
- PV provisioner support in the underlying infrastructure (for persistent storage)

## Installing the Chart

To install the chart with the release name `cam`:

```bash
helm install cam ./cam-chart
```

The command deploys CAM on the Kubernetes cluster in the default configuration. The [Parameters](#parameters) section lists the parameters that can be configured during installation.

> **Tip**: List all releases using `helm list`

## Uninstalling the Chart

To uninstall/delete the `cam` deployment:

```bash
helm delete cam
```

The command removes all the Kubernetes components associated with the chart and deletes the release.

## Parameters

### Global parameters

| Name                      | Description                                     | Value |
| ------------------------- | ----------------------------------------------- | ----- |
| `global.imageRegistry`    | Global Docker image registry                    | `""`  |
| `global.imagePullSecrets` | Global Docker registry secret names as an array| `[]`  |
| `global.storageClass`     | Global StorageClass for Persistent Volume(s)   | `""`  |

### Common parameters

| Name                     | Description                                        | Value |
| ------------------------ | -------------------------------------------------- | ----- |
| `replicaCount`           | Number of CAM replicas to deploy                  | `3`   |
| `image.repository`       | CAM image repository                               | `cam/complete-arbitration-mesh` |
| `image.tag`              | CAM image tag (immutable tags are recommended)    | `""` |
| `image.pullPolicy`       | CAM image pull policy                              | `IfNotPresent` |
| `imagePullSecrets`       | CAM image pull secrets                             | `[]` |
| `nameOverride`           | String to partially override cam-chart.fullname   | `""` |
| `fullnameOverride`       | String to fully override cam-chart.fullname       | `""` |

### Service Account parameters

| Name                         | Description                                               | Value |
| ---------------------------- | --------------------------------------------------------- | ----- |
| `serviceAccount.create`      | Specifies whether a ServiceAccount should be created     | `true` |
| `serviceAccount.annotations` | Additional Service Account annotations                    | `{}` |
| `serviceAccount.name`        | The name of the ServiceAccount to use                    | `""` |

### RBAC parameters

| Name                              | Description                                    | Value |
| --------------------------------- | ---------------------------------------------- | ----- |
| `rbac.create`                     | Specifies whether RBAC resources should be created | `true` |
| `rbac.createCRDPermissions`       | Create permissions for Custom Resource Definitions | `false` |
| `rbac.createNamespaceRole`        | Create namespace-scoped role                   | `true` |
| `rbac.meshCoordination.enabled`   | Enable mesh coordination permissions          | `true` |

### Security Context parameters

| Name                    | Description                         | Value |
| ----------------------- | ----------------------------------- | ----- |
| `podSecurityContext`    | Set CAM pod's Security Context      | `{}` |
| `securityContext`       | Set CAM container's Security Context| `{}` |

### Service parameters

| Name                  | Description                               | Value        |
| --------------------- | ----------------------------------------- | ------------ |
| `service.type`        | CAM service type                          | `ClusterIP`  |
| `service.port`        | CAM service HTTP port                     | `80`         |
| `service.targetPort`  | CAM container HTTP port                   | `8080`       |
| `service.nodePort`    | Node port for the HTTP service           | `""`         |
| `service.annotations` | Additional custom annotations for service | `{}`         |

### Ingress parameters

| Name                  | Description                                             | Value   |
| --------------------- | ------------------------------------------------------- | ------- |
| `ingress.enabled`     | Enable ingress record generation for CAM               | `true`  |
| `ingress.className`   | IngressClass that will be used to implement the Ingress| `nginx` |
| `ingress.annotations` | Additional annotations for the Ingress resource        | `{}`    |
| `ingress.hosts`       | An array with hosts and paths                          | `[...]` |
| `ingress.tls`         | TLS configuration for the Ingress                     | `[]`    |

### Resource Limits parameters

| Name                     | Description                       | Value    |
| ------------------------ | --------------------------------- | -------- |
| `resources.limits`       | The resources limits for the CAM containers   | `{}`     |
| `resources.requests`     | The requested resources for the CAM containers| `{}`     |

### Health Check parameters

| Name                                    | Description                                                     | Value |
| --------------------------------------- | --------------------------------------------------------------- | ----- |
| `healthcheck.liveness.path`             | Liveness probe HTTP path                                        | `/health` |
| `healthcheck.liveness.initialDelaySeconds` | Initial delay seconds for liveness probe                    | `30`  |
| `healthcheck.liveness.periodSeconds`    | Period seconds for liveness probe                              | `10`  |
| `healthcheck.readiness.path`            | Readiness probe HTTP path                                       | `/ready` |
| `healthcheck.readiness.initialDelaySeconds` | Initial delay seconds for readiness probe                  | `5`   |

### CAM Configuration parameters

| Name                              | Description                                    | Value |
| --------------------------------- | ---------------------------------------------- | ----- |
| `cam.meshId`                      | CAM mesh identifier                            | `default-mesh` |
| `cam.nodeType`                    | CAM node type (arbitrator, participant)       | `arbitrator` |
| `cam.consensus.algorithm`         | Consensus algorithm (raft, pbft)              | `raft` |
| `cam.consensus.threshold`         | Consensus threshold (0.0-1.0)                 | `0.66` |
| `cam.arbitration.timeout`         | Arbitration timeout duration                   | `30s` |
| `cam.arbitration.maxParticipants` | Maximum arbitration participants              | `10` |

### Autoscaling parameters

| Name                                            | Description                                                                                                              | Value   |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ------- |
| `autoscaling.enabled`                           | Enable autoscaling for CAM                                                                                              | `true`  |
| `autoscaling.minReplicas`                       | Minimum number of CAM replicas                                                                                          | `3`     |
| `autoscaling.maxReplicas`                       | Maximum number of CAM replicas                                                                                          | `10`    |
| `autoscaling.targetCPUUtilizationPercentage`    | Target CPU utilization percentage                                                                                       | `70`    |
| `autoscaling.targetMemoryUtilizationPercentage` | Target Memory utilization percentage                                                                                    | `80`    |

### Monitoring parameters

| Name                              | Description                                    | Value |
| --------------------------------- | ---------------------------------------------- | ----- |
| `monitoring.enabled`              | Enable monitoring                              | `true` |
| `monitoring.serviceMonitor.enabled` | Enable Prometheus ServiceMonitor            | `true` |
| `monitoring.prometheusRule.enabled` | Enable Prometheus Rules                      | `true` |
| `metrics.enabled`                 | Enable metrics endpoint                        | `true` |
| `metrics.port`                    | Metrics port                                   | `9091` |
| `metrics.path`                    | Metrics endpoint path                          | `/metrics` |

### Persistence parameters

| Name                        | Description                                          | Value           |
| --------------------------- | ---------------------------------------------------- | --------------- |
| `persistence.enabled`       | Enable persistence using Persistent Volume Claims   | `true`          |
| `persistence.mountPath`     | Path to mount the volume at                         | `/data`         |
| `persistence.size`          | Persistent Volume size                               | `10Gi`          |
| `persistence.storageClass`  | Storage class of backing PVC                         | `""`            |
| `persistence.accessModes`   | Persistent Volume access modes                       | `[ReadWriteOnce]` |

### Database parameters

| Name                           | Description                     | Value |
| ------------------------------ | ------------------------------- | ----- |
| `postgresql.enabled`           | Switch to enable or disable PostgreSQL helm chart | `true` |
| `postgresql.auth.username`     | Name for a custom user to create | `cam` |
| `postgresql.auth.password`     | Password for the custom user to create | `changeme` |
| `postgresql.auth.database`     | Name for a custom database to create | `cam` |

### Cache parameters

| Name                    | Description                     | Value |
| ----------------------- | ------------------------------- | ----- |
| `redis.enabled`         | Switch to enable or disable Redis helm chart | `true` |
| `redis.auth.password`   | Redis password                  | `changeme` |

## Configuration and Installation Details

### Resource Requirements

The default configuration requests:
- CPU: 500m per pod
- Memory: 512Mi per pod

For production environments, consider adjusting these values based on your workload.

### High Availability

This chart deploys CAM in a highly available configuration by default:
- 3 replicas minimum
- Pod Disruption Budget configured
- Anti-affinity rules can be configured

### Security

The chart includes several security features:
- Non-root container execution
- Read-only root filesystem
- Network policies (optional)
- RBAC configurations
- Secret management for sensitive data

### Monitoring

The chart includes comprehensive monitoring capabilities:
- Prometheus metrics endpoint
- ServiceMonitor for automatic Prometheus discovery
- Predefined alerting rules
- Health check endpoints

### Backup and Recovery

The chart includes automated backup capabilities:
- Daily database backups via CronJob
- Configurable retention policies
- Persistent volume backup support

## Upgrading

To upgrade the CAM deployment:

```bash
helm upgrade cam ./cam-chart
```

## Customization

### Custom Values

Create a `custom-values.yaml` file to override default values:

```yaml
replicaCount: 5

cam:
  meshId: "production-mesh"
  consensus:
    algorithm: "pbft"

resources:
  limits:
    cpu: 2000m
    memory: 2Gi
  requests:
    cpu: 1000m
    memory: 1Gi

ingress:
  hosts:
    - host: cam.yourdomain.com
      paths:
        - path: /
          pathType: Prefix
```

Then install with:

```bash
helm install cam ./cam-chart -f custom-values.yaml
```

### Environment-Specific Configurations

The chart supports different environments through value overrides:

#### Development
```yaml
replicaCount: 1
autoscaling:
  enabled: false
persistence:
  enabled: false
```

#### Staging
```yaml
replicaCount: 2
cam:
  meshId: "staging-mesh"
```

#### Production
```yaml
replicaCount: 5
cam:
  meshId: "production-mesh"
resources:
  limits:
    cpu: 2000m
    memory: 2Gi
persistence:
  size: 100Gi
```

## Troubleshooting

### Common Issues

1. **Pods not starting**: Check resource constraints and node capacity
2. **Database connection issues**: Verify PostgreSQL configuration and secrets
3. **Ingress not working**: Check ingress controller and DNS configuration

### Debugging Commands

```bash
# Check pod status
kubectl get pods -l app.kubernetes.io/name=cam-chart

# View pod logs
kubectl logs -l app.kubernetes.io/name=cam-chart

# Check events
kubectl get events --sort-by=.metadata.creationTimestamp

# Test connectivity
helm test cam
```

## Development

### Testing Changes

```bash
# Lint the chart
helm lint ./cam-chart

# Template without installing
helm template cam ./cam-chart

# Dry run installation
helm install cam ./cam-chart --dry-run --debug
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This Helm chart is licensed under the MIT License. See the LICENSE file for details.

## Support

For support and questions:
- GitHub Issues: [Repository Issues](https://github.com/cam-protocol/Complete-Arbitration-Mesh-Final/issues)
- Documentation: [CAM Documentation](https://github.com/cam-protocol/Complete-Arbitration-Mesh-Final/docs)
- Community: [CAM Community](https://github.com/cam-protocol/Complete-Arbitration-Mesh-Final/discussions)
