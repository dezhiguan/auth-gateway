#!/usr/bin/env bash
set -euo pipefail

CLIENT_ID="${1:?client_id required}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PRIVATE_KEY="${CLIENT_ASSERTION_KEY:-${ROOT_DIR}/config/keys/auth-active.pem}"
KID="${CLIENT_ASSERTION_KID:-auth-active}"
AUD="${AUTH_TOKEN_ENDPOINT_AUDIENCE:-https://auth.careermate.cn/oauth/token}"

if [[ ! -f "${PRIVATE_KEY}" ]]; then
  echo "missing private key: ${PRIVATE_KEY}" >&2
  exit 1
fi

CLIENT_ID="${CLIENT_ID}" PRIVATE_KEY="${PRIVATE_KEY}" KID="${KID}" AUD="${AUD}" node <<'NODE'
const crypto = require('crypto');
const fs = require('fs');

function base64url(input) {
  return Buffer.from(input).toString('base64url');
}

const now = Math.floor(Date.now() / 1000);
const header = { alg: 'RS256', typ: 'JWT', kid: process.env.KID };
const payload = {
  iss: process.env.CLIENT_ID,
  sub: process.env.CLIENT_ID,
  aud: process.env.AUD,
  jti: `ca_${crypto.randomUUID()}`,
  iat: now,
  exp: now + 600
};

const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`;
const signature = crypto
  .createSign('RSA-SHA256')
  .update(signingInput)
  .end()
  .sign(fs.readFileSync(process.env.PRIVATE_KEY), 'base64url');

process.stdout.write(`${signingInput}.${signature}`);
NODE
