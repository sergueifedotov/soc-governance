#!/usr/bin/env bash

# Validates tool-intent verification in score-only and optional enforce mode.
set -euo pipefail

PROXY_BASE_URL="${PROXY_BASE_URL:-http://localhost:8090}"
PROXY_MCP_URL="${PROXY_BASE_URL%/}/mcp"
PROXY_ADMIN_URL="${PROXY_BASE_URL%/}/admin/tool-intent-config"
PROXY_API_KEY="$(tools/mcp_api_key.sh --proxy)"
ENFORCE_MODE="${ENFORCE_MODE:-0}"  # 0=score-only, 1=enforce

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
    --retry 2 \
    --retry-delay 1 \
    --retry-all-errors \
    -H "Authorization: Bearer ${PROXY_API_KEY}" \
    -H "Content-Type: application/json" \
    -X POST \
    -d "${payload}" \
    "${PROXY_MCP_URL}"
}

set_tool_intent_cfg() {
  local enforce_bool="$1"
  curl -sS \
    -H "Authorization: Bearer ${PROXY_API_KEY}" \
    -H "Content-Type: application/json" \
    -X POST \
    -d "{\"tool_intent\":{\"enabled\":true,\"enforce\":${enforce_bool}}}" \
    "${PROXY_ADMIN_URL}" | jq . >/dev/null
}

run_safe_intent_call() {
  local payload
  payload='{
    "jsonrpc": "2.0",
    "id": "intent-safe-call",
    "method": "tools/call",
    "params": {
      "name": "get_wazuh_alerts",
      "metadata": {
        "intent": "Review recent high severity detections for SOC triage"
      },
      "arguments": {
        "time_range": "24h",
        "min_level": 10,
        "limit": 10
      }
    }
  }'

  echo
  echo "== SAFE INTENT CALL =="
  local resp
  resp="$(proxy_rpc "${payload}")"
  if echo "${resp}" | jq -e '.error' >/dev/null 2>&1; then
    echo "[FAIL] Safe intent call returned error"
    echo "${resp}" | jq '.error'
    return 1
  fi
  echo "[PASS] Safe intent call succeeded"
  return 0
}

run_mismatch_call() {
  local payload
  payload='{
    "jsonrpc": "2.0",
    "id": "intent-mismatch-call",
    "method": "tools/call",
    "params": {
      "name": "get_wazuh_alerts",
      "metadata": {
        "intent": "Isolate compromised endpoints and terminate malicious processes immediately"
      },
      "arguments": {
        "time_range": "24h",
        "min_level": 10,
        "limit": 10
      }
    }
  }'

  echo
  echo "== INTENT MISMATCH CALL =="
  local resp
  resp="$(proxy_rpc "${payload}")"

  if [[ "${ENFORCE_MODE}" == "1" ]]; then
    if echo "${resp}" | jq -e '.error' >/dev/null 2>&1; then
      local reason
      reason="$(echo "${resp}" | jq -r '.error.data.reason // .error.message // "denied"')"
      echo "[PASS] Mismatch call denied in enforce mode: ${reason}"
      echo "${resp}" | jq '.error'
      return 0
    fi
    echo "[FAIL] Mismatch call was not denied in enforce mode"
    echo "${resp}" | jq '.'
    return 1
  fi

  if echo "${resp}" | jq -e '.error' >/dev/null 2>&1; then
    echo "[WARN] Mismatch call denied in score-only mode (policy may already enforce elsewhere)"
    echo "${resp}" | jq '.error'
  else
    echo "[PASS] Mismatch call completed in score-only mode (check metrics/logs for tool_intent signal)"
  fi
  return 0
}

main() {
  require_cmd curl
  require_cmd jq

  echo "Proxy MCP URL : ${PROXY_MCP_URL}"
  echo "Admin URL     : ${PROXY_ADMIN_URL}"
  echo "Enforce mode  : ${ENFORCE_MODE}"

  if [[ "${ENFORCE_MODE}" == "1" ]]; then
    set_tool_intent_cfg true
  else
    set_tool_intent_cfg false
  fi

  run_safe_intent_call
  run_mismatch_call

  echo
  echo "== SUMMARY =="
  if [[ "${ENFORCE_MODE}" == "1" ]]; then
    echo "Tool-intent verification enforce mode validated."
  else
    echo "Tool-intent verification score-only path validated."
  fi
}

main "$@"
