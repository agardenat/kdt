{{- define "kdt-web.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "kdt-web.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "kdt-web.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "kdt-web.labels" -}}
app.kubernetes.io/name: {{ include "kdt-web.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "kdt-web.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kdt-web.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "kdt-web.serviceAccountName" -}}
{{- default (include "kdt-web.fullname" .) .Values.serviceAccount.name -}}
{{- end -}}

{{/*
  Refuse une combinaison de valeurs qui produirait un déploiement inerte : kdt-web démarrerait,
  redirigerait vers le portail, et le portail refuserait chaque retour sans que rien ne dise
  pourquoi.
*/}}
{{- define "kdt-web.validate" -}}
{{- $web := required "webUrl est obligatoire : l'adresse de retour du flow d'autorisation en découle, et le portail n'en accepte aucune autre" .Values.webUrl -}}
{{- if and (not (hasPrefix "https://" $web)) (not (hasPrefix "http://localhost" $web)) (not (hasPrefix "http://127.0.0.1" $web)) -}}
{{- fail "webUrl doit être en https : le cookie de session porte Secure, un navigateur ne le renverrait jamais sur du HTTP et kdt-web serait inutilisable" -}}
{{- end -}}
{{- if hasSuffix "/" $web -}}
{{- fail "webUrl ne se termine pas par un / : l'adresse de retour est comparée caractère par caractère à celle que le portail a déclarée" -}}
{{- end -}}
{{- $portal := required "portalUrl est obligatoire : sans portail, personne ne peut se connecter" .Values.portalUrl -}}
{{- if hasSuffix "/" $portal -}}
{{- fail "portalUrl ne se termine pas par un /" -}}
{{- end -}}
{{- if gt (int .Values.replicas) 1 -}}
{{- fail "replicas > 1 : les sessions vivent en mémoire du processus, et une requête sur deux tomberait sur la réplique qui ne connaît pas le visiteur" -}}
{{- end -}}
{{- end -}}
