#!/usr/bin/env bash
set -euo pipefail

PHONE="${1:?phone required}"
CODE="${2:?code required}"
SCENE="${3:?scene required}"

DB_HOST="${AUTH_DB_HOST:-localhost}"
DB_PORT="${AUTH_DB_PORT:-5432}"
DB_NAME="${AUTH_DB_NAME:-authdb}"
DB_USER="${AUTH_DB_USERNAME:-auth}"
PEPPER="${AUTH_SMS_PHONE_HASH_PEPPER:-auth-gateway-dev-pepper}"
PSQL="${PSQL:-/Applications/Postgres.app/Contents/Versions/latest/bin/psql}"

if [[ ! -x "${PSQL}" ]]; then
  PSQL="psql"
fi

read -r PHONE_HASH CODE_HASH NORMALIZED_SCENE < <(PHONE="${PHONE}" CODE="${CODE}" SCENE="${SCENE}" PEPPER="${PEPPER}" node <<'NODE'
const crypto = require('crypto');

function normalizePhone(phone) {
  let value = String(phone || '').trim().replaceAll(' ', '').replaceAll('-', '');
  if (value.startsWith('+86')) value = value.slice(3);
  if (value.startsWith('86') && value.length === 13) value = value.slice(2);
  return value;
}

function normalizeScene(scene) {
  const value = String(scene || '').trim().toLowerCase();
  if (value === 'mobile_login') return 'login';
  if (value === 'password_reset') return 'reset';
  return value;
}

function sha256Hex(input) {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

const phone = normalizePhone(process.env.PHONE);
const code = process.env.CODE;
const pepper = process.env.PEPPER;
console.log([
  sha256Hex(`${phone}:${pepper}`),
  sha256Hex(`${code}:code:${pepper}`),
  normalizeScene(process.env.SCENE)
].join(' '));
NODE
)

"${PSQL}" -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" \
  -v ON_ERROR_STOP=1 \
  -c "INSERT INTO sms_codes(phone_hash, code_hash, scene, expires_at) VALUES ('${PHONE_HASH}', '${CODE_HASH}', '${NORMALIZED_SCENE}', now() + interval '5 minutes');"

echo "Seeded SMS code for ${PHONE} scene=${NORMALIZED_SCENE}"
