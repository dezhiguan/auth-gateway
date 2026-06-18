#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${AUTH_BASE_URL:-http://127.0.0.1:8090}"
CLIENT_ID="${AUTH_CLIENT_ID:-ragforge-admin-backend}"
TARGET_AUD="${AUTH_TARGET_AUD:-ragforge-admin-api}"
ACCOUNT="${AUTH_TEST_ACCOUNT:-admin}"
PASSWORD="${AUTH_TEST_PASSWORD:-Admin123!}"
ASSERTION_TYPE="urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

json_field() {
  node -e "let s='';process.stdin.on('data',d=>s+=d);process.stdin.on('end',()=>{const o=JSON.parse(s); const v=o[process.argv[1]]; if (v === undefined || v === null) process.exit(2); console.log(v);});" "$1"
}

client_assertion() {
  scripts/gen-client-assertion.sh "$CLIENT_ID" "$BASE_URL/auth/token"
}

post_refresh() {
  local refresh_token="$1"
  local assertion
  assertion="$(client_assertion)"
  curl -s -w '\n%{http_code}' \
    -X POST "$BASE_URL/auth/token/refresh" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "refresh_token=$refresh_token" \
    --data-urlencode "client_id=$CLIENT_ID" \
    --data-urlencode "client_assertion_type=$ASSERTION_TYPE" \
    --data-urlencode "client_assertion=$assertion"
}

login_assertion="$(client_assertion)"
login_response="$(curl -s -w '\n%{http_code}' \
  -X POST "$BASE_URL/auth/login/password" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "account=$ACCOUNT" \
  --data-urlencode "password=$PASSWORD" \
  --data-urlencode "target_aud=$TARGET_AUD" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "client_assertion_type=$ASSERTION_TYPE" \
  --data-urlencode "client_assertion=$login_assertion")"

login_status="$(printf '%s' "$login_response" | tail -n 1)"
login_body="$(printf '%s' "$login_response" | sed '$d')"
if [[ "$login_status" != "200" ]]; then
  echo "login_status=$login_status"
  echo "$login_body"
  exit 1
fi

old_refresh="$(printf '%s' "$login_body" | json_field refresh_token)"
first_refresh_response="$(post_refresh "$old_refresh")"
first_refresh_status="$(printf '%s' "$first_refresh_response" | tail -n 1)"
first_refresh_body="$(printf '%s' "$first_refresh_response" | sed '$d')"
if [[ "$first_refresh_status" != "200" ]]; then
  echo "first_refresh_status=$first_refresh_status"
  echo "$first_refresh_body"
  exit 1
fi

new_refresh="$(printf '%s' "$first_refresh_body" | json_field refresh_token)"
replay_response="$(post_refresh "$old_refresh")"
replay_status="$(printf '%s' "$replay_response" | tail -n 1)"
new_after_replay_response="$(post_refresh "$new_refresh")"
new_after_replay_status="$(printf '%s' "$new_after_replay_response" | tail -n 1)"

echo "login_status=$login_status"
echo "first_refresh_status=$first_refresh_status"
echo "old_refresh_replay_status=$replay_status"
echo "new_refresh_after_family_revoke_status=$new_after_replay_status"

if [[ "$replay_status" != "401" || "$new_after_replay_status" != "401" ]]; then
  echo "refresh replay detection failed"
  exit 1
fi
