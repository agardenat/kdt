#!/bin/sh
# Un caBundle qui expire dans sept jours, pour exercer le constat « caBundle expire dans {n} j ».
#
# En script et non en manifeste figé : un certificat écrit dans un YAML versionné serait périmé
# quelques jours plus tard, et la fixture testerait alors « expiré » sans qu'on l'ait demandé.
set -eu
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -days 7 \
  -keyout "$dir/key.pem" -out "$dir/cert.pem" -subj "/CN=kdt-hooks-expiring" >/dev/null 2>&1
ca=$(base64 -w0 < "$dir/cert.pem")

kubectl "$@" apply -f - <<YAML
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: kdt-hooks-ca-expiring
webhooks:
  - name: ca-expiring.kdt.test
    failurePolicy: Ignore
    sideEffects: None
    admissionReviewVersions: ["v1"]
    clientConfig:
      caBundle: ${ca}
      service:
        namespace: kdt-hooks-test
        name: nobody-listens-here
        path: /validate
    namespaceSelector:
      matchExpressions:
        - key: kubernetes.io/metadata.name
          operator: In
          values: ["kdt-hooks-test"]
    rules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["configmaps"]
        operations: ["CREATE"]
YAML
