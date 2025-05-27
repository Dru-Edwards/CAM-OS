{{/*
Expand the name of the chart.
*/}}
{{- define "cam.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "cam.fullname" -}}
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
{{- define "cam.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "cam.labels" -}}
helm.sh/chart: {{ include "cam.chart" . }}
{{ include "cam.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "cam.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cam.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "cam.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "cam.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
PostgreSQL fullname
*/}}
{{- define "cam.postgresql.fullname" -}}
{{- if .Values.postgresql.enabled }}
{{- printf "%s-postgresql" .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- .Values.external.database.host }}
{{- end }}
{{- end }}

{{/*
Redis fullname
*/}}
{{- define "cam.redis.fullname" -}}
{{- if .Values.redis.enabled }}
{{- printf "%s-redis-master" .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- .Values.external.redis.host }}
{{- end }}
{{- end }}

{{/*
Database URL
*/}}
{{- define "cam.databaseUrl" -}}
{{- if .Values.postgresql.enabled }}
{{- printf "postgresql://%s:%s@%s:5432/%s" .Values.postgresql.auth.username .Values.postgresql.auth.password (include "cam.postgresql.fullname" .) .Values.postgresql.auth.database }}
{{- else }}
{{- printf "postgresql://%s:%s@%s:%d/%s" .Values.external.database.username .Values.external.database.password .Values.external.database.host (.Values.external.database.port | int) .Values.external.database.database }}
{{- end }}
{{- end }}

{{/*
Redis URL
*/}}
{{- define "cam.redisUrl" -}}
{{- if .Values.redis.enabled }}
{{- if .Values.redis.auth.enabled }}
{{- printf "redis://:%s@%s:6379" .Values.redis.auth.password (include "cam.redis.fullname" .) }}
{{- else }}
{{- printf "redis://%s:6379" (include "cam.redis.fullname" .) }}
{{- end }}
{{- else }}
{{- if .Values.external.redis.password }}
{{- printf "redis://:%s@%s:%d" .Values.external.redis.password .Values.external.redis.host (.Values.external.redis.port | int) }}
{{- else }}
{{- printf "redis://%s:%d" .Values.external.redis.host (.Values.external.redis.port | int) }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Image pull secrets
*/}}
{{- define "cam.imagePullSecrets" -}}
{{- if .Values.global.imagePullSecrets }}
imagePullSecrets:
{{- range .Values.global.imagePullSecrets }}
  - name: {{ . }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Storage class
*/}}
{{- define "cam.storageClass" -}}
{{- if .Values.global.storageClass }}
{{- .Values.global.storageClass }}
{{- else if .Values.persistence.storageClass }}
{{- .Values.persistence.storageClass }}
{{- end }}
{{- end }}

{{/*
Image registry
*/}}
{{- define "cam.imageRegistry" -}}
{{- if .Values.global.imageRegistry }}
{{- printf "%s/" .Values.global.imageRegistry }}
{{- end }}
{{- end }}

{{/*
Worker labels
*/}}
{{- define "cam.workerLabels" -}}
{{- $workerName := .workerName }}
{{- $root := .root }}
helm.sh/chart: {{ include "cam.chart" $root }}
app.kubernetes.io/name: {{ printf "%s-%s" (include "cam.name" $root) $workerName }}
app.kubernetes.io/instance: {{ $root.Release.Name }}
app.kubernetes.io/component: worker
app.kubernetes.io/part-of: {{ include "cam.name" $root }}
{{- if $root.Chart.AppVersion }}
app.kubernetes.io/version: {{ $root.Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ $root.Release.Service }}
{{- end }}

{{/*
Worker selector labels
*/}}
{{- define "cam.workerSelectorLabels" -}}
{{- $workerName := .workerName }}
{{- $root := .root }}
app.kubernetes.io/name: {{ printf "%s-%s" (include "cam.name" $root) $workerName }}
app.kubernetes.io/instance: {{ $root.Release.Name }}
app.kubernetes.io/component: worker
{{- end }}

{{/*
Security context
*/}}
{{- define "cam.securityContext" -}}
{{- if .Values.app.securityContext }}
{{- toYaml .Values.app.securityContext }}
{{- else }}
runAsNonRoot: true
runAsUser: 1000
fsGroup: 2000
capabilities:
  drop:
    - ALL
readOnlyRootFilesystem: true
allowPrivilegeEscalation: false
{{- end }}
{{- end }}

{{/*
Pod security context
*/}}
{{- define "cam.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 1000
fsGroup: 2000
{{- end }}

{{/*
Resource limits
*/}}
{{- define "cam.resources" -}}
{{- if .Values.app.resources }}
{{- toYaml .Values.app.resources }}
{{- else }}
limits:
  cpu: 1000m
  memory: 1Gi
requests:
  cpu: 500m
  memory: 512Mi
{{- end }}
{{- end }}

{{/*
Environment variables
*/}}
{{- define "cam.env" -}}
- name: DATABASE_URL
  value: {{ include "cam.databaseUrl" . | quote }}
- name: REDIS_URL
  value: {{ include "cam.redisUrl" . | quote }}
{{- if .Values.postgresql.enabled }}
- name: POSTGRES_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "cam.fullname" . }}-secrets
      key: postgres_password
{{- end }}
{{- if .Values.redis.enabled }}
- name: REDIS_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "cam.fullname" . }}-secrets
      key: redis_password
{{- end }}
- name: JWT_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ include "cam.fullname" . }}-secrets
      key: jwt_secret
- name: ENCRYPTION_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "cam.fullname" . }}-secrets
      key: encryption_key
{{- if .Values.app.env }}
{{- toYaml .Values.app.env }}
{{- end }}
{{- end }}
