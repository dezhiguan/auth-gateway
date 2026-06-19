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
APP_UID="${AUTH_GATEWAY_APP_UID:-10001}"
APP_GID="${AUTH_GATEWAY_APP_GID:-10001}"

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

env_file_value() {
  local key="$1"
  local file="$2"
  awk -F= -v key="${key}" '
    $0 !~ /^[[:space:]]*#/ && $1 == key {
      sub(/^[^=]*=/, "")
      gsub(/^["'\''"]|["'\''"]$/, "")
      print
      exit
    }
  ' "${file}"
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
ACTIVE_KEY_PATH="$(env_file_value JWKS_ACTIVE_PRIVATE_KEY_PATH /opt/shared/env/auth-gateway.env)"
ACTIVE_KEY_PATH="${ACTIVE_KEY_PATH:-/opt/auth-gateway/keys/auth-active.pem}"
if [[ ! -f "${ACTIVE_KEY_PATH}" ]]; then
  echo "Missing active private key: ${ACTIVE_KEY_PATH}" >&2
  exit 1
fi
if ! command -v k3s >/dev/null 2>&1; then
  echo "ERROR: k3s is not installed on Server 3" >&2
  exit 1
fi

echo "[2/8] Ensure container-readable key and log permissions"
mkdir -p /opt/auth-gateway/logs
chown -R "${APP_UID}:${APP_GID}" /opt/auth-gateway/keys /opt/auth-gateway/logs
chmod 750 /opt/auth-gateway/keys
find /opt/auth-gateway/keys -type f -name '*.pem' -exec chmod 640 {} \;
chmod 750 /opt/auth-gateway/logs

echo "[3/8] Previous release: ${PREVIOUS_RELEASE:-<none>}"

echo "[4/8] Switch current symlink"
ln -sfn "${RELEASE_DIR}" "${CURRENT_LINK}"

echo "[5/8] Build Docker image ${IMAGE}"
JAR_SHA="$(sha256sum "${RELEASE_DIR}/app.jar" | awk '{print $1}' | head -c 16)"
CACHE_TAG="auth-gateway:jar-${JAR_SHA}"
echo "  jar sha=${JAR_SHA} (cache tag: ${CACHE_TAG})"
DOCKER_CACHE_HIT=0
if docker image inspect "${CACHE_TAG}" >/dev/null 2>&1; then
  echo "  cache hit (docker): retag without rebuild"
  docker tag "${CACHE_TAG}" "${IMAGE}"
  docker tag "${CACHE_TAG}" auth-gateway:latest
  DOCKER_CACHE_HIT=1
else
  echo "  cache miss: building image"
  docker build --build-arg JAR_FILE=app.jar \
    -t "${IMAGE}" -t auth-gateway:latest -t "${CACHE_TAG}" \
    "${CURRENT_LINK}"
fi

echo "[6/8] Import image into k3s containerd"
CTR_CACHE_HIT=0
if [[ "${DOCKER_CACHE_HIT}" == "1" ]] \
   && k3s ctr -n k8s.io images ls 2>/dev/null | grep -F -q "${CACHE_TAG}"; then
  echo "  cache hit (containerd): tagging in-place (no save/import)"
  if k3s ctr -n k8s.io images tag --force \
        "docker.io/library/${CACHE_TAG}" \
        "docker.io/library/${IMAGE}" >/dev/null 2>&1 \
     && k3s ctr -n k8s.io images tag --force \
        "docker.io/library/${CACHE_TAG}" \
        "docker.io/library/auth-gateway:latest" >/dev/null 2>&1; then
    CTR_CACHE_HIT=1
  else
    echo "  ctr tag failed, falling back to save+import"
  fi
fi
if [[ "${CTR_CACHE_HIT}" != "1" ]]; then
  docker save -o "${IMAGE_TAR}" "${IMAGE}" auth-gateway:latest "${CACHE_TAG}"
  k3s ctr -n k8s.io images import "${IMAGE_TAR}"
  rm -f "${IMAGE_TAR}"
fi

echo "[7/8] Create/update Kubernetes Secret and apply manifests"
bash /opt/auth-gateway/scripts/create-auth-gateway-k8s-secret.sh

wait_for_node_ready 24
k3s kubectl apply -f "${K8S_DIR}/namespace.yaml"
k3s kubectl apply -f "${K8S_DIR}/service.yaml"
k3s kubectl apply -f "${K8S_DIR}/deployment.yaml"
k3s kubectl -n "${NAMESPACE}" set image "deployment/${DEPLOYMENT}" "auth-gateway=${IMAGE}"

echo "[8/8] Wait for rollout and verify NodePort health"
wait_for_rollout

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
