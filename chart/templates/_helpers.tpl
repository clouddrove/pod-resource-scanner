{{/*
Expand the name of the chart.
*/}}
{{- define "pod-resource-scanner.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "pod-resource-scanner.fullname" -}}
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
{{- define "pod-resource-scanner.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels (Helm and Kubernetes best practices).
*/}}
{{- define "pod-resource-scanner.labels" -}}
helm.sh/chart: {{ include "pod-resource-scanner.chart" . }}
app.kubernetes.io/name: {{ include "pod-resource-scanner.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: scanner
{{- end }}

{{/*
Selector labels for CronJob/Job pods.
*/}}
{{- define "pod-resource-scanner.selectorLabels" -}}
app.kubernetes.io/name: {{ include "pod-resource-scanner.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ServiceAccount name (used by CronJob/Job).
*/}}
{{- define "pod-resource-scanner.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- include "pod-resource-scanner.fullname" . }}
{{- else }}
{{- .Values.serviceAccount.name | default "default" }}
{{- end }}
{{- end }}

{{/*
Image (repository:tag).
*/}}
{{- define "pod-resource-scanner.image" -}}
{{- $tag := .Values.imageTag | default .Values.image.tag | default .Chart.AppVersion }}
{{- printf "%s:%s" .Values.image.repository $tag }}
{{- end }}

{{/*
ConfigMap name for env vars.
*/}}
{{- define "pod-resource-scanner.configMapName" -}}
{{- include "pod-resource-scanner.fullname" . }}-config
{{- end }}

{{/*
PVC name for output.
*/}}
{{- define "pod-resource-scanner.pvcName" -}}
{{- include "pod-resource-scanner.fullname" . }}-output
{{- end }}
