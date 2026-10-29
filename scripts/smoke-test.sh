#!/usr/bin/env bash

set -euo pipefail

PROXY="${1:-http://localhost:10000}"

request() {
  local body="$1"
  curl --silent --show-error \
    --output "$response_body" \
    --write-out '%{http_code}' \
    --header 'Content-Type: application/json' \
    --data "$body" \
    "$PROXY"
}

assert_request() {
  local name="$1"
  local expected_status="$2"
  local expected_text="$3"
  local body="$4"
  local status

  status=$(request "$body")
  if [[ "$status" != "$expected_status" ]]; then
    echo "FAIL: $name returned HTTP $status, expected $expected_status" >&2
    cat "$response_body" >&2
    exit 1
  fi
  if ! grep -Fq "$expected_text" "$response_body"; then
    echo "FAIL: $name response did not contain $expected_text" >&2
    cat "$response_body" >&2
    exit 1
  fi
  echo "PASS: $name (HTTP $status)"
}

response_body=$(mktemp)
trap 'rm -f "$response_body"' EXIT

if ! curl --silent --show-error "$PROXY" >/dev/null; then
  echo "FAIL: Envoy is not reachable at $PROXY" >&2
  exit 1
fi

assert_request \
  "allowed operation" \
  200 \
  '"result"' \
  '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}'

assert_request \
  "blocked namespace" \
  403 \
  '"code":-32601' \
  '{"jsonrpc":"2.0","id":2,"method":"debug_traceTransaction","params":["0x0"]}'

assert_request \
  "malformed request" \
  400 \
  '"code":-32600' \
  'not json'

assert_request \
  "empty request" \
  400 \
  '"code":-32600' \
  ''

oversized_body=$(head -c 65537 /dev/zero | tr '\0' a)
assert_request \
  "oversized request" \
  413 \
  '"code":-32600' \
  "$oversized_body"

assert_request \
  "unsupported batch" \
  400 \
  '"code":-32600' \
  '[{"jsonrpc":"2.0","id":3,"method":"eth_chainId","params":[]}]'
