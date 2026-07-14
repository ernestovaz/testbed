#!/usr/bin/env bash
# Really simplistic smoke test: sends a few JSON-RPC requests through the filter.
# TODO: move this to python or something
# Usage: ./scripts/smoke-test.sh [proxy_url]

set -euo pipefail

PROXY="${1:-http://localhost:10000}"

echo "=== Smoke Test ==="
echo "Target: $PROXY"
echo ""

rpc() {
  local method="$1"
  local params="${2:-[]}"
  local id="${3:-1}"
  local body="{\"jsonrpc\":\"2.0\",\"id\":${id},\"method\":\"${method}\",\"params\":${params}}"

  echo -n "  ${method} ... "
  local response
  response=$(curl -s -w "\n%{http_code}" -X POST "$PROXY" \
    -H "Content-Type: application/json" \
    -d "$body")

  local http_code
  http_code=$(echo "$response" | tail -1)
  local body_response
  body_response=$(echo "$response" | sed '$d')

  if [ "$http_code" -eq 200 ]; then
    echo "OK (200) -> $(echo "$body_response" | head -c 80)"
  elif [ "$http_code" -eq 403 ]; then
    echo "BLOCKED (403) -> $(echo "$body_response" | head -c 80)"
  else
    echo "HTTP $http_code -> $(echo "$body_response" | head -c 80)"
  fi
}

echo "--- Methods that SHOULD pass ---"
rpc "eth_blockNumber"
rpc "eth_chainId"
rpc "eth_getBalance" '["0x0000000000000000000000000000000000000000","latest"]'
rpc "eth_call" '[{"to":"0x0000000000000000000000000000000000000000","data":"0x"},"latest"]'
rpc "net_version"
rpc "web3_clientVersion"

echo ""
echo "--- Methods that SHOULD be blocked ---"
rpc "personal_unlockAccount" '["0x0","password",300]'
rpc "admin_addPeer" '["enode://abc@1.2.3.4:30303"]'
rpc "miner_start" '[1]'
rpc "debug_setHead" '["0x0"]'

echo ""
echo "=== Done ==="
