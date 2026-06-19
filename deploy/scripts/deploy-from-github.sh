#!/usr/bin/env bash
# Deploy Auth Gateway on Server 3 from a GitHub Actions release.
# Usage: deploy-from-github.sh <release-sha>
set -euo pipefail

if [[ "${#}" -ne 1 ]]; then
  echo "Usage: $0 <release-sha>"
  exit 1
fi

RELEASE_SHA="${1}"
RELEASE_DIR="/opt/auth-gateway/releases/${RELEASE_SHA}"
CURRENT_LINK="/opt/auth-gateway/current"
HEALTH_PORTS=(8090 8091 8092)
COMPOSE_FILE="/opt/auth-gateway/docker-compose.yml"
IMAGE_NAME="auth-gateway:latest"

wait_for_port_health() {
  local port="$1"
  local max_attempts="${HEALTH_MAX_ATTEMPTS:-60}"
  local sleep_secs="${HEALTH_SLEEP_SECS:-3}"
  local url="http://127.0.0.1:${port}/actuator/health"

  for attempt in $(seq 1 "${max_attempts}"); do
    if curl -fsS "${url}" | grep -q '"status":"UP"'; then
      echo "  health ok: ${url}"
      return 0
    fi
    echo "  attempt ${attempt}/${max_attempts}: ${url} not ready"
    sleep "${sleep_secs}"
  done

  echo "ERROR: health check timed out: ${url}" >&2
  return 1
}

PREVIOUS_RELEASE="$(readlink -f "${CURRENT_LINK}" 2>/dev/null || true)"

on_error() {
  echo "ERROR: deployment failed for release ${RELEASE_SHA}" >&2
  if [[ -n "${PREVIOUS_RELEASE}" ]]; then
    echo "Previous release (for manual rollback): ${PREVIOUS_RELEASE}" >&2
    echo "Run: sudo bash /opt/auth-gateway/scripts/rollback-auth-gateway.sh '${PREVIOUS_RELEASE}'" >&2
  fi
}
trap on_error ERR

echo "[1/6] Validate release directory: ${RELEASE_DIR}"
if [[ ! -d "${RELEASE_DIR}" ]]; then
  echo "Release directory not found: ${RELEASE_DIR}" >&2
  exit 1
fi
if [[ ! -f "${RELEASE_DIR}/app.jar" ]]; then
  echo "Missing ${RELEASE_DIR}/app.jar" >&2
  exit 1
fi
if [[ ! -f "${RELEASE_DIR}/Dockerfile" ]]; then
  echo "Missing ${RELEASE_DIR}/Dockerfile" >&2
  exit 1
fi
if [[ ! -f "${COMPOSE_FILE}" ]]; then
  echo "Missing ${COMPOSE_FILE}" >&2
  exit 1
fi
if [[ ! -f /opt/shared/env/common.env || ! -f /opt/shared/env/auth-gateway.env ]]; then
  echo "Missing shared env files: /opt/shared/env/common.env and /opt/shared/env/auth-gateway.env" >&2
  exit 1
fi
if [[ ! -f /opt/auth-gateway/keys/auth-active.pem ]]; then
  echo "Missing active private key: /opt/auth-gateway/keys/auth-active.pem" >&2
  exit 1
fi

echo "[2/6] Previous release: ${PREVIOUS_RELEASE:-<none>}"

echo "[3/6] Switch current symlink"
ln -sfn "${RELEASE_DIR}" "${CURRENT_LINK}"

echo "[4/6] Build image"
docker build --build-arg JAR_FILE=app.jar -t "${IMAGE_NAME}" "${CURRENT_LINK}"

echo "[5/6] Rolling restart containers"
services=(
  "auth-gateway-1:8090"
  "auth-gateway-2:8091"
  "auth-gateway-3:8092"
)
for item in "${services[@]}"; do
  service="${item%%:*}"
  port="${item##*:}"
  echo "  recreating ${service} on port ${port}..."
  docker compose -f "${COMPOSE_FILE}" up -d --force-recreate --no-deps "${service}"
  wait_for_port_health "${port}"
done
docker compose -f "${COMPOSE_FILE}" ps

echo "[6/6] Verify all health ports"
for port in "${HEALTH_PORTS[@]}"; do
  wait_for_port_health "${port}"
done

echo "Deployment succeeded (Server 3 auth-gateway)"
echo "  release: ${RELEASE_DIR}"
echo "  current: $(readlink -f "${CURRENT_LINK}")"
echo "  containers: auth-gateway-1 auth-gateway-2 auth-gateway-3"
if [[ -n "${PREVIOUS_RELEASE}" && "${PREVIOUS_RELEASE}" != "$(readlink -f "${CURRENT_LINK}")" ]]; then
  echo "  rollback: sudo bash /opt/auth-gateway/scripts/rollback-auth-gateway.sh '${PREVIOUS_RELEASE}'"
fi
