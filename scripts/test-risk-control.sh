#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${AUTH_BASE_URL:-http://127.0.0.1:8090}"
ACCOUNT="${AUTH_RISK_ACCOUNT:-+8613800000000}"
IP="${AUTH_RISK_IP:-127.0.0.1}"

json_field() {
  node -e "let s='';process.stdin.on('data',d=>s+=d);process.stdin.on('end',()=>{const o=JSON.parse(s); const v=o[process.argv[1]]; if (v === undefined || v === null) process.exit(2); console.log(v);});" "$1"
}

last_body=""
last_status=""
for _ in 1 2 3 4 5; do
  response="$(curl -s -w '\n%{http_code}' \
    -X POST "$BASE_URL/risk/login-failure" \
    -H 'Content-Type: application/json' \
    -d "{\"account\":\"$ACCOUNT\",\"ip\":\"$IP\"}")"
  last_status="$(printf '%s' "$response" | tail -n 1)"
  last_body="$(printf '%s' "$response" | sed '$d')"
done

location_response="$(curl -s -w '\n%{http_code}' \
  -X POST "$BASE_URL/risk/location-warning" \
  -H 'Content-Type: application/json' \
  -d '{"user_id":1,"last_region":"CN-GD","current_region":"US-CA"}')"
location_status="$(printf '%s' "$location_response" | tail -n 1)"
location_body="$(printf '%s' "$location_response" | sed '$d')"

captcha_required="$(printf '%s' "$last_body" | json_field captcha_required)"
unusual_location="$(printf '%s' "$location_body" | json_field unusual_location)"

echo "risk_failure_status=$last_status"
echo "captcha_required_after_5=$captcha_required"
echo "location_warning_status=$location_status"
echo "unusual_location=$unusual_location"

if [[ "$last_status" != "200" || "$captcha_required" != "true" ]]; then
  echo "$last_body"
  exit 1
fi
if [[ "$location_status" != "200" || "$unusual_location" != "true" ]]; then
  echo "$location_body"
  exit 1
fi
