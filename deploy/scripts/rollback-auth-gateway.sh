#!/usr/bin/env bash
# Roll back Auth Gateway on Server 3 k3s to a previous release directory.
# Usage: rollback-auth-gateway.sh /opt/auth-gateway/releases/<sha>
set -euo pipefail

if [[ "${#}" -ne 1 ]]; then
  echo "Usage: $0 /opt/auth-gateway/releases/<release-sha>" >&2
  exit 1
fi

RELEASE_DIR="${1}"
RELEASE_SHA="$(basename "${RELEASE_DIR}")"
SHORT_SHA="${RELEASE_SHA:0:12}"
CURRENT_LINK="/opt/auth-gateway/current"
K8S_DIR="/opt/auth-gateway/deploy/k8s/auth-gateway"
NAMESPACE="${AUTH_GATEWAY_K8S_NAMESPACE:-auth-gateway}"
DEPLOYMENT="auth-gateway"
IMAGE="auth-gateway:${SHORT_SHA}"
IMAGE_TAR="/tmp/auth-gateway-${SHORT_SHA}.tar"
NODEPORT="${AUTH_GATEWAY_NODEPORT:-31091}"

wait_for_rollout() {
  k3s kubectl -n "${NAMESPACE}" rollout status "deployment/${DEPLOYMENT}" --timeout=600s
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

echo "[1/5] Validate release directory: ${RELEASE_DIR}"
for f in "${RELEASE_DIR}/app.jar" "${RELEASE_DIR}/Dockerfile" "${K8S_DIR}/deployment.yaml" "${K8S_DIR}/service.yaml"; do
  if [[ ! -f "${f}" ]]; then
    echo "Missing ${f}" >&2
    exit 1
  fi
done
if ! command -v k3s >/dev/null 2>&1; then
  echo "ERROR: k3s is not installed on Server 3" >&2
  exit 1
fi

echo "[2/5] Switch current symlink"
ln -sfn "${RELEASE_DIR}" "${CURRENT_LINK}"

echo "[3/5] Build and import image ${IMAGE}"
docker build --build-arg JAR_FILE=app.jar -t "${IMAGE}" -t auth-gateway:latest "${CURRENT_LINK}"
docker save "${IMAGE}" auth-gateway:latest -o "${IMAGE_TAR}"
k3s ctr -n k8s.io images import "${IMAGE_TAR}"
rm -f "${IMAGE_TAR}"

echo "[4/5] Apply rollback image"
bash /opt/auth-gateway/scripts/create-auth-gateway-k8s-secret.sh
k3s kubectl apply -f "${K8S_DIR}/namespace.yaml"
k3s kubectl apply -f "${K8S_DIR}/service.yaml"
k3s kubectl apply -f "${K8S_DIR}/deployment.yaml"
k3s kubectl -n "${NAMESPACE}" set image "deployment/${DEPLOYMENT}" "auth-gateway=${IMAGE}"
wait_for_rollout

echo "[5/5] Verify NodePort health"
wait_for_nodeport_health
k3s kubectl -n "${NAMESPACE}" get pods -o wide
k3s kubectl -n "${NAMESPACE}" get svc,endpoints

echo "Auth Gateway k3s rollback succeeded"
echo "  current: $(readlink -f "${CURRENT_LINK}")"
echo "  image: ${IMAGE}"
