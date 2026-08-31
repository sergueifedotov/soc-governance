#!/usr/bin/env bash
# Roadmap Phase A1: deploy executor, verify from proxy network, apply operational policy.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

# shellcheck source=mcp_proxy_test_common.sh
source "${ROOT_DIR}/tools/mcp_proxy_test_common.sh"

PROXY_BASE_URL="${PROXY_BASE_URL:-http://localhost:8090}"
POLICY_FILE="${ROOT_DIR}/config/phase4/mcp_proxy/policy.sample.sprint-3-executor-operational.json"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing command: $1" >&2; exit 2; }
}
require_cmd curl
require_cmd jq
require_cmd docker

echo "== DEPLOY ISOLATED EXECUTOR (Phase A1) =="

if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^mcp-security-proxy$'; then
  echo "FAIL: mcp-security-proxy is not running. Start Profile C first." >&2
  echo "hint: bash tools/start-profile.sh C" >&2
  exit 2
fi

bash tools/start_isolated_executor.sh --no-build

echo
echo "[verify] Executor health from host"
curl -sS "http://localhost:${ISOLATED_EXECUTOR_HOST_PORT:-18088}/health" | jq .

echo
echo "[verify] Executor health from mcp-security-proxy network"
PROXY_HEALTH="$(docker exec mcp-security-proxy python -c "
import json, urllib.request
r = urllib.request.urlopen('http://isolated-executor:8080/health', timeout=5)
print(r.read().decode())
" 2>/dev/null || true)"
if ! echo "${PROXY_HEALTH}" | jq -e '.status == "healthy"' >/dev/null 2>&1; then
  echo "FAIL: proxy container cannot reach http://isolated-executor:8080/health" >&2
  echo "${PROXY_HEALTH}" >&2
  exit 2
fi
echo "PASS: mcp-security-proxy -> isolated-executor:8080/health"

echo
echo "[policy] Applying sprint-3-executor-operational policy"
if ! mcp_test_apply_policy_sample_file "${POLICY_FILE}"; then
  echo "FAIL: could not apply ${POLICY_FILE}" >&2
  exit 2
fi
echo "PASS: operational policy active"
echo "  isolated_executor_profile.executor_url = http://isolated-executor:8080/execute"
echo "  execution_tool_profile.enabled = false"
echo "  fallback_to_upstream = false"

echo
echo "[smoke] tools/call shell_exec via proxy (expect executor success)"
MCP_PROXY_API_KEY="$(mcp_test_resolve_proxy_api_key)"
RESP="$(mcp_test_proxy_post_json "${PROXY_BASE_URL%/}/mcp" \
  '{"jsonrpc":"2.0","id":"a1-smoke","method":"tools/call","params":{"name":"shell_exec","arguments":{"cmd":"whoami"}}}')"
if ! echo "${RESP}" | jq -e . >/dev/null 2>&1; then
  echo "FAIL: non-JSON response from proxy:" >&2
  echo "${RESP}" >&2
  exit 1
fi
echo "${RESP}" | jq '{error: .error, execution_id: .execution_id, runtime_uid: .runtime_info.uid, has_result: (.result != null)}'

if echo "${RESP}" | jq -e '.error' >/dev/null 2>&1; then
  echo "FAIL: expected successful executor response" >&2
  exit 1
fi
if ! echo "${RESP}" | jq -e '.runtime_info.uid != 0' >/dev/null 2>&1; then
  echo "FAIL: runtime_info.uid should be non-root" >&2
  exit 1
fi
echo "PASS: isolated executor smoke call succeeded"

echo
echo "Phase A1 deployment complete."
echo "Next: bash tools/test_isolated_executor_live.sh  # extended live test"
echo "      bash tools/test_sprint3_no_restart.sh --skip-unit-tests"
