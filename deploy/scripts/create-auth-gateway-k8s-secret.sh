#!/usr/bin/env bash
# Create/update Kubernetes Secret for Auth Gateway from Server 3 env files.
#
# Usage (on Server 3):
#   sudo bash /opt/auth-gateway/scripts/create-auth-gateway-k8s-secret.sh
set -euo pipefail

NAMESPACE="${AUTH_GATEWAY_K8S_NAMESPACE:-auth-gateway}"
SECRET_NAME="${AUTH_GATEWAY_K8S_SECRET:-auth-gateway-env}"
COMMON_ENV="${AUTH_GATEWAY_COMMON_ENV:-/opt/shared/env/common.env}"
AUTH_ENV="${AUTH_GATEWAY_ENV_FILE:-/opt/shared/env/auth-gateway.env}"
MERGED_ENV="$(mktemp)"

cleanup() {
  rm -f "${MERGED_ENV}"
}
trap cleanup EXIT

if [[ ! -f "${COMMON_ENV}" ]]; then
  echo "ERROR: missing ${COMMON_ENV}" >&2
  exit 1
fi
if [[ ! -f "${AUTH_ENV}" ]]; then
  echo "ERROR: missing ${AUTH_ENV}" >&2
  exit 1
fi

cat "${COMMON_ENV}" "${AUTH_ENV}" | awk '
  /^[[:space:]]*#/ { next }
  /^[[:space:]]*$/ { next }
  {
    eq = index($0, "=")
    if (eq <= 1) next
    key = substr($0, 1, eq - 1)
    val = substr($0, eq + 1)
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
    if (key != "") values[key] = val
  }
  END {
    for (k in values) print k "=" values[k]
  }
' > "${MERGED_ENV}"

KUBECTL=(k3s kubectl)
if ! command -v k3s >/dev/null 2>&1; then
  KUBECTL=(kubectl)
fi

"${KUBECTL[@]}" create namespace "${NAMESPACE}" --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f -
"${KUBECTL[@]}" -n "${NAMESPACE}" create secret generic "${SECRET_NAME}" \
  --from-env-file="${MERGED_ENV}" \
  --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f -

echo "Secret ${SECRET_NAME} applied in namespace ${NAMESPACE}"
