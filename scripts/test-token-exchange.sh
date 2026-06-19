#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${AUTH_BASE_URL:-http://127.0.0.1:8090}"
CLIENT_ID="${AUTH_CLIENT_ID:-careermate-backend}"
DENIED_CLIENT_ID="${AUTH_DENIED_CLIENT_ID:-ragforge-admin-backend}"
SOURCE_AUD="${AUTH_SOURCE_AUD:-careermate-api}"
REQUESTED_AUD="${AUTH_REQUESTED_AUD:-ragforge-api}"
REQUESTED_SCOPES="${AUTH_REQUESTED_SCOPES:-rag:search}"
ACCOUNT="${AUTH_TEST_ACCOUNT:-admin}"
PASSWORD="${AUTH_TEST_PASSWORD:-Admin123!}"
ASSERTION_TYPE="urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
GRANT_TYPE="urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE="urn:ietf:params:oauth:token-type:access_token"

json_field() {
  node -e "let s='';process.stdin.on('data',d=>s+=d);process.stdin.on('end',()=>{const o=JSON.parse(s); const v=o[process.argv[1]]; if (v === undefined || v === null) process.exit(2); console.log(v);});" "$1"
}

client_assertion() {
  scripts/gen-client-assertion.sh "$1"
}

login_assertion="$(client_assertion "$CLIENT_ID")"
login_response="$(curl -s -w '\n%{http_code}' \
  -X POST "$BASE_URL/auth/login/password" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "account=$ACCOUNT" \
  --data-urlencode "password=$PASSWORD" \
  --data-urlencode "target_aud=$SOURCE_AUD" \
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
subject_token="$(printf '%s' "$login_body" | json_field access_token)"

missing_assertion_response="$(curl -s -w '\n%{http_code}' \
  -X POST "$BASE_URL/oauth/token-exchange" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=$GRANT_TYPE" \
  --data-urlencode "subject_token=$subject_token" \
  --data-urlencode "subject_token_type=$ACCESS_TOKEN_TYPE" \
  --data-urlencode "requested_audience=$REQUESTED_AUD" \
  --data-urlencode "requested_scopes=$REQUESTED_SCOPES" \
  --data-urlencode "client_id=$CLIENT_ID")"
missing_assertion_status="$(printf '%s' "$missing_assertion_response" | tail -n 1)"

denied_assertion="$(client_assertion "$DENIED_CLIENT_ID")"
denied_response="$(curl -s -w '\n%{http_code}' \
  -X POST "$BASE_URL/oauth/token-exchange" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=$GRANT_TYPE" \
  --data-urlencode "subject_token=$subject_token" \
  --data-urlencode "subject_token_type=$ACCESS_TOKEN_TYPE" \
  --data-urlencode "requested_audience=$REQUESTED_AUD" \
  --data-urlencode "requested_scopes=$REQUESTED_SCOPES" \
  --data-urlencode "client_id=$DENIED_CLIENT_ID" \
  --data-urlencode "client_assertion_type=$ASSERTION_TYPE" \
  --data-urlencode "client_assertion=$denied_assertion")"
denied_status="$(printf '%s' "$denied_response" | tail -n 1)"

exchange_assertion="$(client_assertion "$CLIENT_ID")"
exchange_response="$(curl -s -w '\n%{http_code}' \
  -X POST "$BASE_URL/oauth/token-exchange" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=$GRANT_TYPE" \
  --data-urlencode "subject_token=$subject_token" \
  --data-urlencode "subject_token_type=$ACCESS_TOKEN_TYPE" \
  --data-urlencode "requested_audience=$REQUESTED_AUD" \
  --data-urlencode "requested_scopes=$REQUESTED_SCOPES" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "client_assertion_type=$ASSERTION_TYPE" \
  --data-urlencode "client_assertion=$exchange_assertion")"
exchange_status="$(printf '%s' "$exchange_response" | tail -n 1)"
exchange_body="$(printf '%s' "$exchange_response" | sed '$d')"

echo "login_status=$login_status"
echo "missing_client_assertion_status=$missing_assertion_status"
echo "denied_client_status=$denied_status"
echo "exchange_status=$exchange_status"

if [[ "$missing_assertion_status" != "401" || "$denied_status" != "403" || "$exchange_status" != "200" ]]; then
  echo "$exchange_body"
  exit 1
fi
printf '%s' "$exchange_body" | json_field access_token >/dev/null
