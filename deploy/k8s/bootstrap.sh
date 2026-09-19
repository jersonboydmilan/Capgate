#!/bin/sh
# Generate the harness secrets and the agent's short-lived token, and load them
# into the cluster as Kubernetes Secrets. Mirrors the `bootstrap` and
# `agent-token` steps of the Docker deployment.
#
# The manifests reference these Secrets by name; they are created here (out of
# band, the idiomatic Kubernetes pattern — in production this is your secret
# manager / external-secrets / sealed-secrets) rather than by an in-cluster Job,
# so nothing in the cluster needs RBAC to mint Secrets. The agent pod mounts ONLY
# 'agent-token'; deploy/k8s/validate.py enforces that.
#
# Requires: docker (to run the capgate CLI from the built image) and kubectl.
#   docker build -t capgate-harness:local -f deploy/harness/Dockerfile .
#
# Usage: sh deploy/k8s/bootstrap.sh [namespace]   (default namespace: capgate)
set -eu

NS="${1:-capgate}"
IMG="${CAPGATE_HARNESS_IMAGE:-capgate-harness:local}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "generating harness secrets with $IMG…"
docker run --rm -v "$WORK:/out" "$IMG" \
  python3 -m capgate.cli bootstrap --secrets-dir /out --tool-credential /out/tool_credential >/dev/null

secret() {  # secret() NAME KEY FILE
  kubectl -n "$NS" create secret generic "$1" --from-file="$2=$3" \
    --dry-run=client -o yaml | kubectl apply -f -
}
secret harness-signing-key   signing_key     "$WORK/signing_key"
secret harness-token-keyring token_keyring   "$WORK/token_keyring"
secret tool-credential       tool_credential "$WORK/tool_credential"

echo "issuing the agent's 15-minute token…"
docker run --rm -v "$WORK:/out" "$IMG" \
  python3 -m capgate.cli token issue --keyring /out/token_keyring \
    --sub researcher --role agent --ttl 15m --max-ttl 15m > "$WORK/token"
secret agent-token token "$WORK/token"

echo "done. secrets in namespace '$NS': harness-signing-key, harness-token-keyring, tool-credential, agent-token"
