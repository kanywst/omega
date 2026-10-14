{{/*
Expand the name of the chart.
*/}}
{{- define "omega.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "omega.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "omega.serverName" -}}
{{ include "omega.fullname" . }}-server
{{- end -}}

{{- define "omega.agentName" -}}
{{ include "omega.fullname" . }}-agent
{{- end -}}

{{- define "omega.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{ printf "%s:%s" .Values.image.repository $tag }}
{{- end -}}

{{- define "omega.commonLabels" -}}
app.kubernetes.io/name: {{ include "omega.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "omega.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{ include "omega.fullname" . }}
{{- else -}}
default
{{- end -}}
{{- end -}}

{{/*
The agent runs under its own ServiceAccount when the Kubernetes workload
attestor is on, so its cluster-wide pod read does not reach the server.
*/}}
{{- define "omega.agentServiceAccountName" -}}
{{- if .Values.agent.k8sWorkloadAttestor.enabled -}}
{{ include "omega.agentName" . }}
{{- else -}}
{{ include "omega.serviceAccountName" . }}
{{- end -}}
{{- end -}}
