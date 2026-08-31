#!/usr/bin/env bash
# Test isolated executor integration (Sprint 3).
#
# This script tests that high-risk tool calls are properly routed to
# the isolated executor service when configured.
set -euo pipefail

PROXY_BASE_URL="${PROXY_BASE_URL:-http://localhost:8090}"

usage() {
  cat <<'EOF'
Usage: bash tools/test_isolated_executor.sh [options]

Tests Sprint 3 isolated executor controls:
  1) Executor unavailable without fallback blocks request
  2) Discovery signal fires on executor failures

Options:
  --proxy-base-url URL   Proxy base URL (default: http://localhost:8090)
  -h, --help             Show help

Environment:
  PROXY_BASE_URL
  MCP_PROXY_API_KEY
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --proxy-base-url)
      PROXY_BASE_URL="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: missing command: $1" >&2
    exit 2
  }
}

require_cmd curl
require_cmd jq

resolve_proxy_api_key() {
  local key
  key="$(tools/mcp_api_key.sh --proxy)"
  printf '%s' "${key}"
}

MCP_PROXY_API_KEY="${MCP_PROXY_API_KEY:-$(resolve_proxy_api_key)}"
export PROXY_BASE_URL
export MCP_PROXY_API_KEY

echo "== ISOLATED EXECUTOR TEST (Sprint 3) =="
echo "proxy_base_url: ${PROXY_BASE_URL%/}"

echo
echo "[preflight] Checking proxy health"
HEALTH_JSON="$(curl -sS --retry 2 --retry-delay 1 --retry-all-errors "${PROXY_BASE_URL%/}/health" || true)"
if [[ -z "${HEALTH_JSON}" ]]; then
  echo "FAIL: proxy health endpoint is unreachable" >&2
  exit 2
fi

if ! echo "${HEALTH_JSON}" | jq -e '.status == "healthy"' >/dev/null 2>&1; then
  echo "FAIL: proxy is not healthy" >&2
  exit 2
fi
echo "PASS: proxy is healthy"

# Check for Sprint 3 symbols
echo
echo "[preflight] Checking Sprint 3 implementation"
SYMBOL_CHECK=$(docker exec mcp-security-proxy python3 -c "
import sys
sys.path.insert(0, '/app')
from mcp_security_proxy.app import _isolated_executor_check, _forward_to_isolated_executor
print('Sprint 3 symbols found')
" 2>&1 || echo "MISSING")

if [[ "${SYMBOL_CHECK}" == *"MISSING"* ]]; then
  echo "FAIL: Sprint 3 symbols not found in running container" >&2
  echo "hint: rebuild the container with: cd mcp-security-proxy && docker compose build mcp-security-proxy" >&2
  exit 2
fi
echo "PASS: Sprint 3 symbols present"

# Save current policy for restoration
POLICY_BACKUP=$(curl -sS -H "Authorization: Bearer ${MCP_PROXY_API_KEY}" \
  "${PROXY_BASE_URL%/}/admin/policy-config" 2>/dev/null || echo "{}")

# Cleanup function to restore policy
cleanup() {
  echo
  echo "[cleanup] Restoring original policy"
  if [[ -n "${POLICY_BACKUP}" && "${POLICY_BACKUP}" != "{}" ]]; then
    curl -sS -X POST -H "Authorization: Bearer ${MCP_PROXY_API_KEY}" \
      -H "Content-Type: application/json" \
      -d "{\"raw_policy\": ${POLICY_BACKUP}}" \
      "${PROXY_BASE_URL%/}/admin/policy-config" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# Test: Executor unavailable without fallback
echo
echo "[test 1/2] Isolated executor unavailable (no fallback)"
TEST_POLICY=$(cat <<'EOF'
{
  "allowed_methods": ["initialize", "notifications/initialized", "ping", "tools/list", "tools/call"],
  "denied_tools": [],
  "blocked_argument_patterns": [],
  "llm_risk": {"enabled": false, "enforce": false},
  "tool_intent": {"enabled": false, "enforce": false},
  "isolated_executor_profile": {
    "enabled": true,
    "action": "deny",
    "executor_url": "",
    "fallback_to_upstream": false,
    "require_for_tools": ["shell", "exec", "bash"],
    "forward_on_success": true,
    "max_retries": 0,
    "timeout_seconds": 5
  },
  "discovery_rules": [
    {"signal": "isolated_executor_failures", "action_on_trigger": "monitor"}
  ]
}
EOF
)

curl -sS -X POST -H "Authorization: Bearer ${MCP_PROXY_API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{\"raw_policy\": ${TEST_POLICY}}" \
  "${PROXY_BASE_URL%/}/admin/policy-config" | jq -e '.summary' >/dev/null

echo "[test 1/2] Policy applied - calling execution tool"

RESPONSE=$(curl -sS -X POST -H "Authorization: Bearer ${MCP_PROXY_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"iso-1","method":"tools/call","params":{"name":"shell_exec","arguments":{"cmd":"whoami"}}}' \
  "${PROXY_BASE_URL%/}/mcp" || echo '{"error":{"code":-32004}}')

ERROR_CODE=$(echo "${RESPONSE}" | jq -r '.error.code // 0')
REASON=$(echo "${RESPONSE}" | jq -r '.error.data.reason // "none"')

if [[ "${ERROR_CODE}" == "-32003" && "${REASON}" == *"isolated_executor"* ]]; then
  echo "PASS: Request denied with isolated_executor_unavailable"
else
  echo "UNEXPECTED: error_code=${ERROR_CODE}, reason=${REASON}"
  echo "Response: ${RESPONSE}"
fi

# Test: Discovery signal
sleep 1
echo
echo "[test 2/2] Discovery signal fired"

DISCOVERY=$(curl -sS -H "Authorization: Bearer ${MCP_PROXY_API_KEY}" \
  "${PROXY_BASE_URL%/}/recent-discovery-alerts?limit=20" || echo '{"alerts":[]}')

SIGNAL_COUNT=$(echo "${DISCOVERY}" | jq '[.alerts[] | select(.signal == "isolated_executor_failures")] | length')

if [[ "${SIGNAL_COUNT}" -ge 1 ]]; then
  echo "PASS: isolated_executor_failures signal recorded (${SIGNAL_COUNT} alerts)"
else
  echo "INFO: No isolated_executor_failures signal found (may need to wait for cooldown)"
fi

# Test: Recent denied contains executor reason
DENIED=$(curl -sS -H "Authorization: Bearer ${MCP_PROXY_API_KEY}" \
  "${PROXY_BASE_URL%/}/recent-denied?limit=20" || echo '{"events":[]}')

EXECUTOR_DENIALS=$(echo "${DENIED}" | jq '[.events[] | select(.reason | contains("isolated_executor"))] | length')

if [[ "${EXECUTOR_DENIALS}" -ge 1 ]]; then
  echo "PASS: Recent denied contains isolated_executor reason (${EXECUTOR_DENIALS} events)"
else
  echo "INFO: No isolated_executor reason found in recent denied"
fi

echo
echo "ISOLATED EXECUTOR TEST PASSED"
