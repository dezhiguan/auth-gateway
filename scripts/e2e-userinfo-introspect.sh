#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${AUTH_BASE_URL:-http://127.0.0.1:8090}"
CLIENT_ID="${AUTH_CLIENT_ID:-ragforge-admin-backend}"
TARGET_AUD="${AUTH_TARGET_AUD:-ragforge-admin-api}"
ACCOUNT="${AUTH_TEST_ACCOUNT:-admin}"
PASSWORD="${AUTH_TEST_PASSWORD:-Admin123!}"
ASSERTION_TYPE="urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

json_field() {
  node -e "let s='';process.stdin.on('data',d=>s+=d);process.stdin.on('end',()=>{const o=JSON.parse(s); const v=o[process.argv[1]]; if (v === undefined || v === null) process.exit(2); console.log(Array.isArray(v) ? JSON.stringify(v) : v);});" "$1"
}

client_assertion() {
  scripts/gen-client-assertion.sh "$CLIENT_ID"
}

assertion="$(client_assertion)"
login_response="$(curl -s -w '\n%{http_code}' \
  -X POST "$BASE_URL/auth/login/password" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "account=$ACCOUNT" \
  --data-urlencode "password=$PASSWORD" \
  --data-urlencode "target_aud=$TARGET_AUD" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "client_assertion_type=$ASSERTION_TYPE" \
  --data-urlencode "client_assertion=$assertion")"
login_status="$(printf '%s' "$login_response" | tail -n 1)"
login_body="$(printf '%s' "$login_response" | sed '$d')"
if [[ "$login_status" != "200" ]]; then
  echo "login_status=$login_status"
  echo "$login_body"
  exit 1
fi

access_token="$(printf '%s' "$login_body" | json_field access_token)"
userinfo_response="$(curl -s -w '\n%{http_code}' "$BASE_URL/userinfo" -H "Authorization: Bearer $access_token")"
userinfo_status="$(printf '%s' "$userinfo_response" | tail -n 1)"
userinfo_body="$(printf '%s' "$userinfo_response" | sed '$d')"
userinfo_user_id="$(printf '%s' "$userinfo_body" | json_field user_id)"

introspection_assertion="$(client_assertion)"
introspect_response="$(curl -s -w '\n%{http_code}' \
  -X POST "$BASE_URL/oauth/introspect" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "token=$access_token" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "client_assertion_type=$ASSERTION_TYPE" \
  --data-urlencode "client_assertion=$introspection_assertion")"
introspect_status="$(printf '%s' "$introspect_response" | tail -n 1)"
introspect_body="$(printf '%s' "$introspect_response" | sed '$d')"
introspect_active="$(printf '%s' "$introspect_body" | json_field active)"

echo "login_status=$login_status"
echo "userinfo_status=$userinfo_status"
echo "userinfo_user_id=$userinfo_user_id"
echo "introspect_status=$introspect_status"
echo "introspect_active=$introspect_active"

if [[ "$userinfo_status" != "200" || "$userinfo_user_id" != "1" ]]; then
  echo "$userinfo_body"
  exit 1
fi
if [[ "$introspect_status" != "200" || "$introspect_active" != "true" ]]; then
  echo "$introspect_body"
  exit 1
fi
