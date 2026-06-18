#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${AUTH_BASE_URL:-http://127.0.0.1:8090}"
CLIENT_ID="${AUTH_CLIENT_ID:-ragforge-admin-backend}"
TARGET_AUD="${AUTH_TARGET_AUD:-ragforge-admin-api}"
ACCOUNT="${AUTH_RESET_ACCOUNT:-+8613800000000}"
CODE="${AUTH_RESET_CODE:-123456}"
NEW_PASSWORD="${AUTH_RESET_NEW_PASSWORD:-Admin123!}"
ASSERTION_TYPE="urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

json_field() {
  node -e "let s='';process.stdin.on('data',d=>s+=d);process.stdin.on('end',()=>{const o=JSON.parse(s); const v=o[process.argv[1]]; if (v === undefined || v === null) process.exit(2); console.log(v);});" "$1"
}

post_json() {
  local path="$1"
  local body="$2"
  curl -s -w '\n%{http_code}' \
    -X POST "$BASE_URL$path" \
    -H 'Content-Type: application/json' \
    -d "$body"
}

client_assertion() {
  scripts/gen-client-assertion.sh "$CLIENT_ID" "$BASE_URL/auth/token"
}

existing_init="$(post_json /auth/password/reset/init "{\"account\":\"$ACCOUNT\"}")"
existing_init_status="$(printf '%s' "$existing_init" | tail -n 1)"
existing_init_body="$(printf '%s' "$existing_init" | sed '$d')"

missing_init="$(post_json /auth/password/reset/init '{"account":"+8613999999999"}')"
missing_init_status="$(printf '%s' "$missing_init" | tail -n 1)"
missing_init_body="$(printf '%s' "$missing_init" | sed '$d')"

verify_response="$(post_json /auth/password/reset/verify "{\"account\":\"$ACCOUNT\",\"code\":\"$CODE\"}")"
verify_status="$(printf '%s' "$verify_response" | tail -n 1)"
verify_body="$(printf '%s' "$verify_response" | sed '$d')"

if [[ "$verify_status" != "200" ]]; then
  echo "init_existing_status=$existing_init_status"
  echo "init_missing_status=$missing_init_status"
  echo "verify_status=$verify_status"
  echo "$verify_body"
  exit 1
fi

reset_ticket="$(printf '%s' "$verify_body" | json_field reset_ticket)"
assertion="$(client_assertion)"
confirm_body="$(RESET_TICKET="$reset_ticket" NEW_PASSWORD="$NEW_PASSWORD" TARGET_AUD="$TARGET_AUD" CLIENT_ID="$CLIENT_ID" ASSERTION_TYPE="$ASSERTION_TYPE" CLIENT_ASSERTION="$assertion" node -e '
const body = {
  reset_ticket: process.env.RESET_TICKET,
  new_password: process.env.NEW_PASSWORD,
  target_aud: process.env.TARGET_AUD,
  client_id: process.env.CLIENT_ID,
  client_assertion_type: process.env.ASSERTION_TYPE,
  client_assertion: process.env.CLIENT_ASSERTION
};
console.log(JSON.stringify(body));
' )"
confirm_response="$(post_json /auth/password/reset/confirm "$confirm_body")"
confirm_status="$(printf '%s' "$confirm_response" | tail -n 1)"
confirm_body_text="$(printf '%s' "$confirm_response" | sed '$d')"

echo "init_existing_status=$existing_init_status"
echo "init_missing_status=$missing_init_status"
echo "init_responses_equal=$([[ "$existing_init_body" == "$missing_init_body" ]] && echo true || echo false)"
echo "verify_status=$verify_status"
echo "confirm_status=$confirm_status"

if [[ "$existing_init_status" != "200" || "$missing_init_status" != "200" ]]; then
  exit 1
fi
if [[ "$existing_init_body" != "$missing_init_body" ]]; then
  echo "existing_init_body=$existing_init_body"
  echo "missing_init_body=$missing_init_body"
  exit 1
fi
if [[ "$confirm_status" != "200" ]]; then
  echo "$confirm_body_text"
  exit 1
fi
printf '%s' "$confirm_body_text" | json_field access_token >/dev/null
printf '%s' "$confirm_body_text" | json_field refresh_token >/dev/null
