#!/usr/bin/env bash
# Roll back Auth Gateway on Server 3 to a previous release directory.
# Usage: rollback-auth-gateway.sh /opt/auth-gateway/releases/<sha>
set -euo pipefail

if [[ "${#}" -ne 1 ]]; then
  echo "Usage: $0 /opt/auth-gateway/releases/<release-sha>"
  exit 1
fi

RELEASE_DIR="${1}"
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

echo "[1/4] Validate release directory: ${RELEASE_DIR}"
if [[ ! -d "${RELEASE_DIR}" ]]; then
  echo "Release directory not found: ${RELEASE_DIR}" >&2
  exit 1
fi
if [[ ! -f "${RELEASE_DIR}/app.jar" || ! -f "${RELEASE_DIR}/Dockerfile" ]]; then
  echo "Release must contain app.jar and Dockerfile" >&2
  exit 1
fi
if [[ ! -f "${COMPOSE_FILE}" ]]; then
  echo "Missing ${COMPOSE_FILE}" >&2
  exit 1
fi

echo "[2/4] Switch current symlink"
ln -sfn "${RELEASE_DIR}" "${CURRENT_LINK}"

echo "[3/4] Build image and rolling-restart containers"
docker build --build-arg JAR_FILE=app.jar -t "${IMAGE_NAME}" "${CURRENT_LINK}"
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

echo "[4/4] Verify all health ports"
for port in "${HEALTH_PORTS[@]}"; do
  wait_for_port_health "${port}"
done

echo "Auth Gateway rollback succeeded"
echo "  current: $(readlink -f "${CURRENT_LINK}")"
