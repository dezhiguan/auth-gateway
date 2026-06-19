#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${AUTH_BASE_URL:-http://127.0.0.1:8090}"
USER_CLIENT_ID="${AUTH_USER_CLIENT_ID:-ragforge-admin-backend}"
AGENT_CLIENT_ID="${AUTH_AGENT_CLIENT_ID:-careermate-backend}"
USER_AUD="${AUTH_USER_AUD:-ragforge-admin-api}"
REQUESTED_AUD="${AUTH_REQUESTED_AUD:-ragforge-api}"
REQUESTED_SCOPES="${AUTH_REQUESTED_SCOPES:-rag:search}"
ACCOUNT="${AUTH_TEST_ACCOUNT:-admin}"
PASSWORD="${AUTH_TEST_PASSWORD:-Admin123!}"
ASSERTION_TYPE="urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

json_field() {
  node -e "let s='';process.stdin.on('data',d=>s+=d);process.stdin.on('end',()=>{const o=JSON.parse(s); const v=o[process.argv[1]]; if (v === undefined || v === null) process.exit(2); console.log(v);});" "$1"
}

client_assertion() {
  scripts/gen-client-assertion.sh "$1"
}

login_assertion="$(client_assertion "$USER_CLIENT_ID")"
login_response="$(curl -s -w '\n%{http_code}' \
  -X POST "$BASE_URL/auth/login/password" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "account=$ACCOUNT" \
  --data-urlencode "password=$PASSWORD" \
  --data-urlencode "target_aud=$USER_AUD" \
  --data-urlencode "client_id=$USER_CLIENT_ID" \
  --data-urlencode "client_assertion_type=$ASSERTION_TYPE" \
  --data-urlencode "client_assertion=$login_assertion")"
login_status="$(printf '%s' "$login_response" | tail -n 1)"
login_body="$(printf '%s' "$login_response" | sed '$d')"
if [[ "$login_status" != "200" ]]; then
  echo "login_status=$login_status"
  echo "$login_body"
  exit 1
fi
access_token="$(printf '%s' "$login_body" | json_field access_token)"

create_body="$(AGENT_CLIENT_ID="$AGENT_CLIENT_ID" REQUESTED_SCOPES="$REQUESTED_SCOPES" node -e "console.log(JSON.stringify({client_principal_id: process.env.AGENT_CLIENT_ID, scopes: [process.env.REQUESTED_SCOPES], allowed_kb_ids: [101,102], expires_in_seconds: 3600}))" )"
create_response="$(curl -s -w '\n%{http_code}' \
  -X POST "$BASE_URL/oauth/consents" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $access_token" \
  -d "$create_body")"
create_status="$(printf '%s' "$create_response" | tail -n 1)"
create_response_body="$(printf '%s' "$create_response" | sed '$d')"
if [[ "$create_status" != "200" ]]; then
  echo "create_status=$create_status"
  echo "$create_response_body"
  exit 1
fi
consent_id="$(printf '%s' "$create_response_body" | json_field consent_id)"

list_response="$(curl -s -w '\n%{http_code}' "$BASE_URL/oauth/consents" -H "Authorization: Bearer $access_token")"
list_status="$(printf '%s' "$list_response" | tail -n 1)"

delegation_assertion="$(client_assertion "$AGENT_CLIENT_ID")"
delegation_response="$(curl -s -w '\n%{http_code}' \
  -X POST "$BASE_URL/oauth/delegation-token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "consent_id=$consent_id" \
  --data-urlencode "requested_audience=$REQUESTED_AUD" \
  --data-urlencode "requested_scopes=$REQUESTED_SCOPES" \
  --data-urlencode "client_id=$AGENT_CLIENT_ID" \
  --data-urlencode "client_assertion_type=$ASSERTION_TYPE" \
  --data-urlencode "client_assertion=$delegation_assertion")"
delegation_status="$(printf '%s' "$delegation_response" | tail -n 1)"
delegation_body="$(printf '%s' "$delegation_response" | sed '$d')"

revoke_response="$(curl -s -w '\n%{http_code}' \
  -X POST "$BASE_URL/oauth/consents/$consent_id/revoke" \
  -H "Authorization: Bearer $access_token")"
revoke_status="$(printf '%s' "$revoke_response" | tail -n 1)"

revoked_assertion="$(client_assertion "$AGENT_CLIENT_ID")"
revoked_delegation_response="$(curl -s -w '\n%{http_code}' \
  -X POST "$BASE_URL/oauth/delegation-token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "consent_id=$consent_id" \
  --data-urlencode "requested_audience=$REQUESTED_AUD" \
  --data-urlencode "requested_scopes=$REQUESTED_SCOPES" \
  --data-urlencode "client_id=$AGENT_CLIENT_ID" \
  --data-urlencode "client_assertion_type=$ASSERTION_TYPE" \
  --data-urlencode "client_assertion=$revoked_assertion")"
revoked_delegation_status="$(printf '%s' "$revoked_delegation_response" | tail -n 1)"

echo "login_status=$login_status"
echo "create_consent_status=$create_status"
echo "list_consents_status=$list_status"
echo "delegation_token_status=$delegation_status"
echo "revoke_consent_status=$revoke_status"
echo "revoked_delegation_status=$revoked_delegation_status"

if [[ "$list_status" != "200" || "$delegation_status" != "200" || "$revoke_status" != "200" || "$revoked_delegation_status" != "401" ]]; then
  echo "$delegation_body"
  exit 1
fi
printf '%s' "$delegation_body" | json_field access_token >/dev/null
