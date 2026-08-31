#!/usr/bin/env bash

# Demo script for Phase 4 Tool Intent rollout controls.
# Mirrors UI flow: score-only -> observe -> tune thresholds -> optional enforce -> disable.
set -euo pipefail

PHASE4_BASE_URL="${PHASE4_BASE_URL:-http://localhost:8082}"
PROXY_BASE_URL="${PROXY_BASE_URL:-http://localhost:8090}"
PROXY_MCP_URL="${PROXY_BASE_URL%/}/mcp"
PROXY_API_KEY="$(tools/mcp_api_key.sh --proxy)"

ENABLE_ENFORCE="${ENABLE_ENFORCE:-0}"
RUN_TRAFFIC="${RUN_TRAFFIC:-1}"

MONITOR_SCORE="${MONITOR_SCORE:-0.45}"
CHALLENGE_SCORE="${CHALLENGE_SCORE:-0.65}"
DENY_SCORE="${DENY_SCORE:-0.82}"

require_cmd() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "ERROR: missing required command: ${cmd}" >&2
    exit 2
  fi
}

get_json() {
  local path="$1"
  curl -sS "${PHASE4_BASE_URL%/}${path}"
}

post_json() {
  local path="$1"
  local payload="$2"
  curl -sS -H "Content-Type: application/json" -X POST -d "${payload}" "${PHASE4_BASE_URL%/}${path}"
}

print_cfg() {
  local json="$1"
  echo "status=$(echo "${json}" | jq -r '.status // "n/a"') enabled=$(echo "${json}" | jq -r '.tool_intent.enabled // "n/a"') enforce=$(echo "${json}" | jq -r '.tool_intent.enforce // "n/a"') monitor=$(echo "${json}" | jq -r '.tool_intent.min_monitor_score // "n/a"') challenge=$(echo "${json}" | jq -r '.tool_intent.min_challenge_score // "n/a"') deny=$(echo "${json}" | jq -r '.tool_intent.min_deny_score // "n/a"')"
}

probe_observability() {
  local json
  json="$(get_json "/soc/proxy-tool-intent-observability")"
  echo "status=$(echo "${json}" | jq -r '.status // "n/a"') metrics_found=$(echo "${json}" | jq -r '.metrics_found // false') sample_lines=$(echo "${json}" | jq -r '.sample_lines | length')"
}

send_proxy_call() {
  local intent="$1"
  local rpc_payload
  rpc_payload="$(cat <<JSON
{
  "jsonrpc": "2.0",
  "id": "tool-intent-demo",
  "method": "tools/call",
  "params": {
    "name": "get_wazuh_alerts",
    "metadata": {
      "intent": "${intent}"
    },
    "arguments": {
      "time_range": "24h",
      "min_level": 10,
      "limit": 5
    }
  }
}
JSON
)"

  curl -sS \
    -H "Authorization: Bearer ${PROXY_API_KEY}" \
    -H "Content-Type: application/json" \
    -X POST \
    -d "${rpc_payload}" \
    "${PROXY_MCP_URL}" >/dev/null
}

restore_safe_state() {
  post_json "/soc/proxy-tool-intent-config" '{"tool_intent":{"enabled":false,"enforce":false}}' >/dev/null || true
}

main() {
  require_cmd curl
  require_cmd jq

  echo "Phase4 URL: ${PHASE4_BASE_URL}"
  echo "Proxy URL : ${PROXY_BASE_URL}"

  echo
  echo "[0] Current config"
  cfg="$(get_json "/soc/proxy-tool-intent-config")"
  print_cfg "${cfg}"

  echo
  echo "[1] Enable score-only"
  cfg="$(post_json "/soc/proxy-tool-intent-config" '{"tool_intent":{"enabled":true,"enforce":false}}')"
  print_cfg "${cfg}"

  if [[ "${RUN_TRAFFIC}" == "1" ]]; then
    echo
    echo "[2] Generate traffic for telemetry"
    send_proxy_call "Review recent high severity detections for SOC triage"
    send_proxy_call "Review recent high severity detections for SOC triage"
  fi

  echo
  echo "[3] Observe tool intent metrics"
  probe_observability

  echo
  echo "[4] Save thresholds"
  cfg="$(post_json "/soc/proxy-tool-intent-config" "{\"tool_intent\":{\"min_monitor_score\":${MONITOR_SCORE},\"min_challenge_score\":${CHALLENGE_SCORE},\"min_deny_score\":${DENY_SCORE}}}")"
  print_cfg "${cfg}"

  if [[ "${ENABLE_ENFORCE}" == "1" ]]; then
    echo
    echo "[5] Enable enforcement"
    cfg="$(post_json "/soc/proxy-tool-intent-config" '{"tool_intent":{"enabled":true,"enforce":true}}')"
    print_cfg "${cfg}"
  else
    echo
    echo "[5] Enforcement skipped (ENABLE_ENFORCE=0)"
  fi

  echo
  echo "[6] Disable all (safe restore)"
  cfg="$(post_json "/soc/proxy-tool-intent-config" '{"tool_intent":{"enabled":false,"enforce":false}}')"
  print_cfg "${cfg}"

  echo
  echo "Done."
}

main "$@"
