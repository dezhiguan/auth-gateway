#!/usr/bin/env bash
# Deploy Auth Gateway on Server 3 k3s from a GitHub Actions release.
# Usage: deploy-from-github.sh <release-sha>
set -euo pipefail

if [[ "${#}" -ne 1 ]]; then
  echo "Usage: $0 <release-sha>"
  exit 1
fi

RELEASE_SHA="${1}"
SHORT_SHA="${RELEASE_SHA:0:12}"
RELEASE_DIR="/opt/auth-gateway/releases/${RELEASE_SHA}"
CURRENT_LINK="/opt/auth-gateway/current"
K8S_DIR="/opt/auth-gateway/deploy/k8s/auth-gateway"
NAMESPACE="${AUTH_GATEWAY_K8S_NAMESPACE:-auth-gateway}"
DEPLOYMENT="auth-gateway"
IMAGE="auth-gateway:${SHORT_SHA}"
IMAGE_TAR="/tmp/auth-gateway-${SHORT_SHA}.tar"
NODEPORT="${AUTH_GATEWAY_NODEPORT:-31091}"

wait_for_node_ready() {
  local attempts="${1:-60}"
  for _ in $(seq 1 "${attempts}"); do
    local ready
    ready="$(k3s kubectl get nodes -o jsonpath='{range .items[*]}{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}' 2>/dev/null || true)"
    if [[ "${ready}" == *"True"* ]] && [[ "${ready}" != *"False"* ]]; then
      return 0
    fi
    echo "[k8s] waiting for node Ready..."
    sleep 5
  done
  echo "ERROR: k3s node not Ready" >&2
  k3s kubectl get nodes -o wide || true
  return 1
}

wait_for_rollout() {
  if k3s kubectl -n "${NAMESPACE}" rollout status "deployment/${DEPLOYMENT}" --timeout=600s; then
    return 0
  fi
  echo "ERROR: rollout timed out for deployment/${DEPLOYMENT}" >&2
  k3s kubectl -n "${NAMESPACE}" get pods -l app=auth-gateway -o wide || true
  k3s kubectl -n "${NAMESPACE}" describe pods -l app=auth-gateway | tail -160 || true
  k3s kubectl -n "${NAMESPACE}" logs -l app=auth-gateway --tail=160 --all-containers=true || true
  return 1
}

wait_for_nodeport_health() {
  local max_attempts="${HEALTH_MAX_ATTEMPTS:-60}"
  local sleep_secs="${HEALTH_SLEEP_SECS:-3}"
  local url="http://127.0.0.1:${NODEPORT}/actuator/health"
  for attempt in $(seq 1 "${max_attempts}"); do
    if curl -fsS "${url}" | grep -q '"status":"UP"'; then
      echo "health ok: ${url}"
      return 0
    fi
    echo "attempt ${attempt}/${max_attempts}: ${url} not ready"
    sleep "${sleep_secs}"
  done
  echo "ERROR: health check timed out: ${url}" >&2
  return 1
}

PREVIOUS_RELEASE="$(readlink -f "${CURRENT_LINK}" 2>/dev/null || true)"

on_error() {
  echo "ERROR: k3s deployment failed for release ${RELEASE_SHA}" >&2
  if [[ -n "${PREVIOUS_RELEASE}" && -d "${PREVIOUS_RELEASE}" ]]; then
    echo "Previous release (for manual rollback): ${PREVIOUS_RELEASE}" >&2
    echo "Run: sudo bash /opt/auth-gateway/scripts/rollback-auth-gateway.sh '${PREVIOUS_RELEASE}'" >&2
  fi
}
trap on_error ERR

echo "[1/8] Validate release and server prerequisites"
for f in "${RELEASE_DIR}/app.jar" "${RELEASE_DIR}/Dockerfile" "${K8S_DIR}/namespace.yaml" "${K8S_DIR}/deployment.yaml" "${K8S_DIR}/service.yaml"; do
  if [[ ! -f "${f}" ]]; then
    echo "Missing ${f}" >&2
    exit 1
  fi
done
if [[ ! -f /opt/shared/env/common.env || ! -f /opt/shared/env/auth-gateway.env ]]; then
  echo "Missing shared env files: /opt/shared/env/common.env and /opt/shared/env/auth-gateway.env" >&2
  exit 1
fi
if [[ ! -f /opt/auth-gateway/keys/auth-active.pem ]]; then
  echo "Missing active private key: /opt/auth-gateway/keys/auth-active.pem" >&2
  exit 1
fi
if ! command -v k3s >/dev/null 2>&1; then
  echo "ERROR: k3s is not installed on Server 3" >&2
  exit 1
fi

echo "[2/8] Previous release: ${PREVIOUS_RELEASE:-<none>}"
ln -sfn "${RELEASE_DIR}" "${CURRENT_LINK}"

echo "[3/8] Build Docker image ${IMAGE}"
docker build --build-arg JAR_FILE=app.jar -t "${IMAGE}" -t auth-gateway:latest "${CURRENT_LINK}"

echo "[4/8] Import image into k3s containerd"
docker save "${IMAGE}" auth-gateway:latest -o "${IMAGE_TAR}"
k3s ctr -n k8s.io images import "${IMAGE_TAR}"
rm -f "${IMAGE_TAR}"

echo "[5/8] Create/update Kubernetes Secret"
bash /opt/auth-gateway/scripts/create-auth-gateway-k8s-secret.sh

echo "[6/8] Apply manifests"
wait_for_node_ready 24
k3s kubectl apply -f "${K8S_DIR}/namespace.yaml"
k3s kubectl apply -f "${K8S_DIR}/service.yaml"
k3s kubectl apply -f "${K8S_DIR}/deployment.yaml"
k3s kubectl -n "${NAMESPACE}" set image "deployment/${DEPLOYMENT}" "auth-gateway=${IMAGE}"

echo "[7/8] Wait for rollout"
wait_for_rollout

echo "[8/8] Verify NodePort health"
wait_for_nodeport_health
k3s kubectl -n "${NAMESPACE}" get pods -o wide
k3s kubectl -n "${NAMESPACE}" get svc,endpoints

echo "Deployment succeeded (Server 3 k3s auth-gateway)"
echo "  release: ${RELEASE_DIR}"
echo "  image: ${IMAGE}"
echo "  nodeport: http://172.25.90.184:${NODEPORT}"
if [[ -n "${PREVIOUS_RELEASE}" && "${PREVIOUS_RELEASE}" != "$(readlink -f "${CURRENT_LINK}")" ]]; then
  echo "  rollback: sudo bash /opt/auth-gateway/scripts/rollback-auth-gateway.sh '${PREVIOUS_RELEASE}'"
fi
