#!/usr/bin/env bash

set -euo pipefail

PROXY_BASE_URL="${PROXY_BASE_URL:-http://localhost:8090}"
PROXY_MCP_URL="${PROXY_BASE_URL%/}/mcp"
PHASE4_BASE_URL="${PHASE4_BASE_URL:-http://localhost:8082}"
PROXY_API_KEY="$(tools/mcp_api_key.sh --proxy)"
HUNT_IOC="${HUNT_IOC:-203.0.113.10}"
HUNT_QUERY="${HUNT_QUERY:-src_ip:${HUNT_IOC}}"

require_cmd() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "ERROR: required command not found: ${cmd}" >&2
    exit 2
  fi
}

proxy_rpc() {
  local payload="$1"
  curl -sS \
    --retry 3 \
    --retry-delay 1 \
    --retry-all-errors \
    -H "Authorization: Bearer ${PROXY_API_KEY}" \
    -H "Content-Type: application/json" \
    "${PROXY_MCP_URL}" \
    -d "${payload}"
}

phase4_post() {
  local path="$1"
  local payload="$2"
  curl -sS \
    --retry 3 \
    --retry-delay 1 \
    --retry-all-errors \
    --connect-timeout 5 \
    --max-time 90 \
    -H 'Content-Type: application/json' \
    -d "${payload}" \
    "${PHASE4_BASE_URL%/}${path}"
}

require_cmd curl
require_cmd jq

echo "=== Autonomous Hunt via MCP Security Proxy ==="
echo "Proxy:  ${PROXY_MCP_URL}"
echo "Phase4: ${PHASE4_BASE_URL%/}"

read_payload="{\"jsonrpc\":\"2.0\",\"id\":\"hunt-read-1\",\"method\":\"tools/call\",\"params\":{\"name\":\"search_security_events\",\"arguments\":{\"query\":\"${HUNT_QUERY}\",\"limit\":50}}}"
read_resp="$(proxy_rpc "${read_payload}")"

if echo "${read_resp}" | jq -e '.result.isError == false' >/dev/null 2>&1; then
  echo "[OK] Evidence collection via MCP proxy succeeded"
else
  echo "[ERR] Evidence collection failed"
  echo "${read_resp}" | jq '.'
  exit 1
fi

soc_ioc_payload="{\"ioc_value\":\"${HUNT_IOC}\",\"ioc_type\":\"auto\",\"include_llm\":true,\"time_range\":\"24h\",\"min_level\":5,\"limit\":30,\"max_hops\":5,\"include_opencti\":true,\"include_neo4j\":true}"
ioc_resp="$(phase4_post '/soc/ioc-pivot' "${soc_ioc_payload}")"

echo "[INFO] IOC pivot response summary:"
echo "${ioc_resp}" | jq '{status: (.status // "ok"), verdict: (.data.verdict // .verdict // "n/a"), baseline: (.data.deterministic_baseline.verdict // "n/a")}'

mitre_payload="{\"time_range\":\"24h\",\"min_level\":5,\"limit\":20,\"include_llm\":true,\"query\":\"${HUNT_QUERY}\",\"srcip\":\"${HUNT_IOC}\"}"
mitre_resp="$(phase4_post '/soc/mitre-map' "${mitre_payload}")"

echo "[INFO] MITRE mapping response summary:"
echo "${mitre_resp}" | jq '{status: (.status // "ok"), techniques: (.techniques // .data.techniques // [])}'

echo "[INFO] Proxy metrics (top):"
curl -sS "${PROXY_BASE_URL%/}/metrics" | grep -E '^mcp_security_proxy_' | head -n 30

echo "=== Hunt cycle completed ==="
