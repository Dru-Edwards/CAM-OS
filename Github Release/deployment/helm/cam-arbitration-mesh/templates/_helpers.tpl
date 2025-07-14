{{/*
Expand the name of the chart.
*/}}
{{- define "cam-arbitration-mesh.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "cam-arbitration-mesh.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "cam-arbitration-mesh.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "cam-arbitration-mesh.labels" -}}
helm.sh/chart: {{ include "cam-arbitration-mesh.chart" . }}
{{ include "cam-arbitration-mesh.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "cam-arbitration-mesh.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cam-arbitration-mesh.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "cam-arbitration-mesh.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "cam-arbitration-mesh.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the secret to use
*/}}
{{- define "cam-arbitration-mesh.secretName" -}}
{{- if .Values.secrets.create }}
{{- printf "%s-secrets" (include "cam-arbitration-mesh.fullname" .) }}
{{- else }}
{{- .Values.secrets.existingSecret }}
{{- end }}
{{- end }}

{{/*
Create the name of the configmap to use
*/}}
{{- define "cam-arbitration-mesh.configMapName" -}}
{{- if .Values.configMap.create }}
{{- printf "%s-config" (include "cam-arbitration-mesh.fullname" .) }}
{{- else }}
{{- .Values.configMap.existingConfigMap }}
{{- end }}
{{- end }}

{{/*
Database host
*/}}
{{- define "cam-arbitration-mesh.databaseHost" -}}
{{- if .Values.postgresql.enabled }}
{{- printf "%s-postgresql" .Release.Name }}
{{- else }}
{{- .Values.externalDatabase.host }}
{{- end }}
{{- end }}

{{/*
Database port
*/}}
{{- define "cam-arbitration-mesh.databasePort" -}}
{{- if .Values.postgresql.enabled }}
{{- 5432 }}
{{- else }}
{{- .Values.externalDatabase.port }}
{{- end }}
{{- end }}

{{/*
Database name
*/}}
{{- define "cam-arbitration-mesh.databaseName" -}}
{{- if .Values.postgresql.enabled }}
{{- .Values.postgresql.auth.database }}
{{- else }}
{{- .Values.externalDatabase.database }}
{{- end }}
{{- end }}

{{/*
Database username
*/}}
{{- define "cam-arbitration-mesh.databaseUsername" -}}
{{- if .Values.postgresql.enabled }}
{{- .Values.postgresql.auth.username }}
{{- else }}
{{- .Values.externalDatabase.username }}
{{- end }}
{{- end }}

{{/*
Database password secret name
*/}}
{{- define "cam-arbitration-mesh.databasePasswordSecret" -}}
{{- if .Values.postgresql.enabled }}
{{- printf "%s-postgresql" .Release.Name }}
{{- else if .Values.externalDatabase.existingSecret }}
{{- .Values.externalDatabase.existingSecret }}
{{- else }}
{{- include "cam-arbitration-mesh.secretName" . }}
{{- end }}
{{- end }}

{{/*
Database password secret key
*/}}
{{- define "cam-arbitration-mesh.databasePasswordSecretKey" -}}
{{- if .Values.postgresql.enabled }}
{{- "password" }}
{{- else if .Values.externalDatabase.existingSecretPasswordKey }}
{{- .Values.externalDatabase.existingSecretPasswordKey }}
{{- else }}
{{- "database-password" }}
{{- end }}
{{- end }}

{{/*
Redis host
*/}}
{{- define "cam-arbitration-mesh.redisHost" -}}
{{- if .Values.redis.enabled }}
{{- printf "%s-redis-master" .Release.Name }}
{{- else }}
{{- .Values.externalRedis.host }}
{{- end }}
{{- end }}

{{/*
Redis port
*/}}
{{- define "cam-arbitration-mesh.redisPort" -}}
{{- if .Values.redis.enabled }}
{{- 6379 }}
{{- else }}
{{- .Values.externalRedis.port }}
{{- end }}
{{- end }}

{{/*
Redis password secret name
*/}}
{{- define "cam-arbitration-mesh.redisPasswordSecret" -}}
{{- if .Values.redis.enabled }}
{{- printf "%s-redis" .Release.Name }}
{{- else if .Values.externalRedis.existingSecret }}
{{- .Values.externalRedis.existingSecret }}
{{- else }}
{{- include "cam-arbitration-mesh.secretName" . }}
{{- end }}
{{- end }}

{{/*
Redis password secret key
*/}}
{{- define "cam-arbitration-mesh.redisPasswordSecretKey" -}}
{{- if .Values.redis.enabled }}
{{- "redis-password" }}
{{- else if .Values.externalRedis.existingSecretPasswordKey }}
{{- .Values.externalRedis.existingSecretPasswordKey }}
{{- else }}
{{- "redis-password" }}
{{- end }}
{{- end }}

{{/*
Image pull policy
*/}}
{{- define "cam-arbitration-mesh.imagePullPolicy" -}}
{{- .Values.app.image.pullPolicy | default "IfNotPresent" }}
{{- end }}

{{/*
Image repository
*/}}
{{- define "cam-arbitration-mesh.imageRepository" -}}
{{- if .Values.global.imageRegistry }}
{{- printf "%s/%s" .Values.global.imageRegistry .Values.app.image.repository }}
{{- else if .Values.app.image.registry }}
{{- printf "%s/%s" .Values.app.image.registry .Values.app.image.repository }}
{{- else }}
{{- .Values.app.image.repository }}
{{- end }}
{{- end }}

{{/*
Image tag
*/}}
{{- define "cam-arbitration-mesh.imageTag" -}}
{{- .Values.app.image.tag | default .Chart.AppVersion }}
{{- end }}

{{/*
Full image name
*/}}
{{- define "cam-arbitration-mesh.image" -}}
{{- printf "%s:%s" (include "cam-arbitration-mesh.imageRepository" .) (include "cam-arbitration-mesh.imageTag" .) }}
{{- end }}

{{/*
Image pull secrets
*/}}
{{- define "cam-arbitration-mesh.imagePullSecrets" -}}
{{- $secrets := list }}
{{- if .Values.global.imagePullSecrets }}
{{- $secrets = concat $secrets .Values.global.imagePullSecrets }}
{{- end }}
{{- if .Values.app.image.pullSecrets }}
{{- $secrets = concat $secrets .Values.app.image.pullSecrets }}
{{- end }}
{{- if $secrets }}
imagePullSecrets:
{{- range $secrets }}
  - name: {{ . }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Storage class
*/}}
{{- define "cam-arbitration-mesh.storageClass" -}}
{{- if .Values.global.storageClass }}
{{- .Values.global.storageClass }}
{{- else }}
{{- .Values.persistence.storageClass }}
{{- end }}
{{- end }}

{{/*
Database URL
*/}}
{{- define "cam-arbitration-mesh.databaseUrl" -}}
{{- printf "postgresql://%s:$(DATABASE_PASSWORD)@%s:%v/%s?sslmode=require" (include "cam-arbitration-mesh.databaseUsername" .) (include "cam-arbitration-mesh.databaseHost" .) (include "cam-arbitration-mesh.databasePort" .) (include "cam-arbitration-mesh.databaseName" .) }}
{{- end }}

{{/*
Redis URL
*/}}
{{- define "cam-arbitration-mesh.redisUrl" -}}
{{- if .Values.redis.auth.enabled }}
{{- printf "redis://:$(REDIS_PASSWORD)@%s:%v/0" (include "cam-arbitration-mesh.redisHost" .) (include "cam-arbitration-mesh.redisPort" .) }}
{{- else }}
{{- printf "redis://%s:%v/0" (include "cam-arbitration-mesh.redisHost" .) (include "cam-arbitration-mesh.redisPort" .) }}
{{- end }}
{{- end }}

{{/*
Pod Security Context
*/}}
{{- define "cam-arbitration-mesh.podSecurityContext" -}}
{{- if .Values.app.securityContext }}
{{- toYaml .Values.app.securityContext }}
{{- end }}
{{- end }}

{{/*
Container Security Context
*/}}
{{- define "cam-arbitration-mesh.containerSecurityContext" -}}
{{- if .Values.app.containerSecurityContext }}
{{- toYaml .Values.app.containerSecurityContext }}
{{- end }}
{{- end }}

{{/*
Resources
*/}}
{{- define "cam-arbitration-mesh.resources" -}}
{{- if .Values.app.resources }}
{{- toYaml .Values.app.resources }}
{{- end }}
{{- end }}

{{/*
Node selector
*/}}
{{- define "cam-arbitration-mesh.nodeSelector" -}}
{{- if .Values.app.nodeSelector }}
{{- toYaml .Values.app.nodeSelector }}
{{- end }}
{{- end }}

{{/*
Affinity
*/}}
{{- define "cam-arbitration-mesh.affinity" -}}
{{- if .Values.app.affinity }}
{{- toYaml .Values.app.affinity }}
{{- end }}
{{- end }}

{{/*
Tolerations
*/}}
{{- define "cam-arbitration-mesh.tolerations" -}}
{{- if .Values.app.tolerations }}
{{- toYaml .Values.app.tolerations }}
{{- end }}
{{- end }}

{{/*
Pod annotations
*/}}
{{- define "cam-arbitration-mesh.podAnnotations" -}}
{{- if .Values.app.podAnnotations }}
{{- toYaml .Values.app.podAnnotations }}
{{- end }}
{{- end }}

{{/*
Pod labels
*/}}
{{- define "cam-arbitration-mesh.podLabels" -}}
{{- if .Values.app.podLabels }}
{{- toYaml .Values.app.podLabels }}
{{- end }}
{{- end }}

{{/*
Service annotations
*/}}
{{- define "cam-arbitration-mesh.serviceAnnotations" -}}
{{- if .Values.service.annotations }}
{{- toYaml .Values.service.annotations }}
{{- end }}
{{- end }}

{{/*
Service labels
*/}}
{{- define "cam-arbitration-mesh.serviceLabels" -}}
{{- if .Values.service.labels }}
{{- toYaml .Values.service.labels }}
{{- end }}
{{- end }}

{{/*
Ingress annotations
*/}}
{{- define "cam-arbitration-mesh.ingressAnnotations" -}}
{{- if .Values.ingress.annotations }}
{{- toYaml .Values.ingress.annotations }}
{{- end }}
{{- end }}
