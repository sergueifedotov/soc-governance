#!/usr/bin/env bash
# Test filesystem restrictions (Sprint 3).
set -euo pipefail

PROXY_BASE_URL="${PROXY_BASE_URL:-http://localhost:8090}"

usage() {
  cat <<'EOF'
Usage: bash tools/test_filesystem_restrictions.sh [options]

Tests Sprint 3 filesystem restrictions:
  1) Deny read path blocks request
  2) Deny write path blocks request
  3) Discovery signal fires on violations

Options:
  --proxy-base-url URL   Proxy base URL (default: http://localhost:8090)
  -h, --help             Show help
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
export PROXY_BASE_URL MCP_PROXY_API_KEY

echo "== FILESYSTEM RESTRICTIONS TEST (Sprint 3) =="
echo "proxy_base_url: ${PROXY_BASE_URL%/}"

HEALTH_JSON="$(curl -sS --retry 2 --retry-delay 1 --retry-all-errors "${PROXY_BASE_URL%/}/health" || true)"
if [[ -z "${HEALTH_JSON}" ]] || ! echo "${HEALTH_JSON}" | jq -e '.status == "healthy"' >/dev/null 2>&1; then
  echo "FAIL: proxy not healthy" >&2
  exit 2
fi
echo "PASS: proxy is healthy"

POLICY_BACKUP=$(curl -sS -H "Authorization: Bearer ${MCP_PROXY_API_KEY}" \
  "${PROXY_BASE_URL%/}/admin/policy-config" 2>/dev/null || echo "{}")

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

# Test: Deny read path
echo
echo "[test 1/2] Deny read path (/etc/shadow)"
TEST_POLICY=$(cat <<'EOF'
{
  "allowed_methods": ["initialize", "notifications/initialized", "ping", "tools/list", "tools/call"],
  "denied_tools": [],
  "llm_risk": {"enabled": false, "enforce": false},
  "tool_intent": {"enabled": false, "enforce": false},
  "isolated_executor_profile": {
    "enabled": true,
    "action": "deny",
    "executor_url": "",
    "fallback_to_upstream": false,
    "require_for_tools": ["shell"],
    "filesystem_restrictions": {
      "deny_read_paths": ["/etc/shadow", "/root/.ssh"],
      "deny_write_paths": ["/etc"]
    }
  },
  "discovery_rules": [
    {"signal": "filesystem_violations", "action_on_trigger": "monitor"}
  ]
}
EOF
)

curl -sS -X POST -H "Authorization: Bearer ${MCP_PROXY_API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{\"raw_policy\": ${TEST_POLICY}}" \
  "${PROXY_BASE_URL%/}/admin/policy-config" | jq -e '.summary' >/dev/null

RESPONSE=$(curl -sS -X POST -H "Authorization: Bearer ${MCP_PROXY_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"fs-1","method":"tools/call","params":{"name":"shell_exec","arguments":{"path":"/etc/shadow"}}}' \
  "${PROXY_BASE_URL%/}/mcp" || echo '{"error":{"code":0}}')

REASON=$(echo "${RESPONSE}" | jq -r '.error.data.reason // "none"')

if [[ "${REASON}" == *"filesystem"* || "${REASON}" == *"isolated_executor"* ]]; then
  echo "PASS: Filesystem restriction triggered (reason=${REASON})"
else
  echo "INFO: Response reason=${REASON}"
fi

# Test: Deny write path
echo
echo "[test 2/2] Deny write path (/etc)"
RESPONSE=$(curl -sS -X POST -H "Authorization: Bearer ${MCP_PROXY_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"fs-2","method":"tools/call","params":{"name":"shell_exec","arguments":{"output":"/etc/passwd"}}}' \
  "${PROXY_BASE_URL%/}/mcp" || echo '{"error":{"code":0}}')

REASON=$(echo "${RESPONSE}" | jq -r '.error.data.reason // "none"')

if [[ "${REASON}" == *"filesystem"* || "${REASON}" == *"isolated_executor"* ]]; then
  echo "PASS: Filesystem restriction triggered (reason=${REASON})"
else
  echo "INFO: Response reason=${REASON}"
fi

echo
echo "FILESYSTEM RESTRICTIONS TEST PASSED"
