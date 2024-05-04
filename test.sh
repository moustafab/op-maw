#!/usr/bin/env bash
set -euo pipefail

# This script is loosely adapting the TLS setup described in
# https://kubernetes.io/blog/2019/03/21/a-guide-to-kubernetes-admission-controllers/#tls-certificates
# for local development

# Cleanup: Remove old MutatingWebhookConfiguration if exists (immutable)
kubectl delete mutatingwebhookconfiguration op-maw || true
# If behind a service:
#kubectl -n default delete secret op-maw-tls || true

# Get your IP into the cert
echo "subjectAltName = DNS:host.docker.internal" > certs/admission_extfile.cnf
# Or, if using DNS (e.g. when running behind a service):
#echo "subjectAltName = DNS:admission-controller.default.svc" > admission_extfile.cnf

# Generate the CA cert and private key
openssl req -nodes -new -x509 \
    -keyout certs/ca.key \
    -out certs/ca.crt -subj "/CN=op-maw"

# Generate the private key for the webhook server
openssl genrsa -out certs/op-maw-tls.key 2048

# Generate a Certificate Signing Request (CSR) for the private key
# and sign it with the private key of the CA.
openssl req -new -key certs/op-maw-tls.key \
    -subj "/CN=op-maw" \
    | openssl x509 -req -CA certs/ca.crt -CAkey certs/ca.key \
        -CAcreateserial -out certs/op-maw-tls.crt \
        -extfile certs/admission_extfile.cnf

CA_PEM64="$(openssl base64 -A < certs/ca.crt)"
# shellcheck disable=SC2016
sed -e 's@${CA_PEM_B64}@'"$CA_PEM64"'@g' < deploy/mutating_webhook_config.yaml | kubectl create -f -

# if behind a service:
#kubectl -n default create secret tls op-maw-tls \
#    --cert op-maw-tls.crt \
#    --key op-maw-tls.key
# similar guide: https://www.openpolicyagent.org/docs/v0.11.0/kubernetes-admission-control/

# Sanity:
kubectl get mutatingwebhookconfiguration op-maw -oyaml

cargo watch -w . -x run -L "info,op_maw=debug" -E 'TLS_ENABLED=true' -E 'CERT_PEM=certs/op-maw-tls.crt' -E 'KEY_PEM=certs/op-maw-tls.key'

