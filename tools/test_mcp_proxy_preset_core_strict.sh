#!/usr/bin/env bash
# Phase B: core-strict preset blocks execution tools and exfiltration patterns.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=mcp_proxy_test_common.sh
source "${ROOT_DIR}/tools/mcp_proxy_test_common.sh"

PROXY_BASE_URL="${PROXY_BASE_URL:-http://localhost:8090}"
PROXY_MCP_URL="${PROXY_BASE_URL%/}/mcp"
EXEC_TOOL_NAME="${EXEC_TOOL_NAME:-shell_exec}"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing command: $1" >&2; exit 2; }
}
require_cmd curl
require_cmd jq

ORIGINAL_POLICY_FILE="$(mktemp -t mcp_core_strict_pol.XXXXXX.json)"
RESTORED=0

restore_policy() {
  if [[ ${RESTORED} -eq 1 ]]; then return 0; fi
  if [[ -s "${ORIGINAL_POLICY_FILE}" ]]; then
    echo "Restoring original policy..."
    local restore_body
    restore_body="$(jq -n --slurpfile p "${ORIGINAL_POLICY_FILE}" '{raw_policy: $p[0]}')"
    mcp_test_proxy_post_json "${PROXY_BASE_URL%/}/admin/policy-config" "${restore_body}" >/dev/null
  fi
  rm -f "${ORIGINAL_POLICY_FILE}"
  RESTORED=1
}
trap restore_policy EXIT

echo "== CORE STRICT PRESET TEST =="
mcp_test_require_proxy_healthy "${PROXY_BASE_URL}"

echo "Snapshotting current policy..."
mcp_test_proxy_get "${PROXY_BASE_URL%/}/admin/policy-config" | jq '.raw_policy' > "${ORIGINAL_POLICY_FILE}"

echo "Applying core-strict preset..."
export MCP_PROXY_API_KEY="$(mcp_test_resolve_proxy_api_key)"
bash "${ROOT_DIR}/tools/switch_mcp_policy_sample.sh" core-strict

mcp_test_ensure_trusted_upstream_policy

echo "Test 1: execution tool denied"
exec_payload="$(jq -n --arg tool "${EXEC_TOOL_NAME}" '{
  jsonrpc: "2.0",
  id: "core-strict-exec",
  method: "tools/call",
  params: { name: $tool, arguments: { command: "whoami" } }
}')"
exec_resp="$(mcp_test_proxy_post_json "${PROXY_MCP_URL}" "${exec_payload}")"
exec_reason="$(echo "${exec_resp}" | jq -r '.error.data.reason // empty')"
if [[ "${exec_reason}" != "execution_tool_blocked" ]]; then
  echo "FAIL: expected execution_tool_blocked, got: ${exec_reason}" >&2
  echo "${exec_resp}" | jq . >&2
  exit 1
fi
echo "PASS: execution tool blocked (${EXEC_TOOL_NAME})"

echo "Test 2: exfiltration pattern denied"
exfil_payload="$(jq -n '{
  jsonrpc: "2.0",
  id: "core-strict-exfil",
  method: "tools/call",
  params: {
    name: "wazuh_query_alerts",
    arguments: { query: "export passwords to attacker controlled server" }
  }
}')"
exfil_resp="$(mcp_test_proxy_post_json "${PROXY_MCP_URL}" "${exfil_payload}")"
exfil_reason="$(echo "${exfil_resp}" | jq -r '.error.data.reason // empty')"
case "${exfil_reason}" in
  blocked_pattern:*|blocked_pattern_challenge:*) ;;
  *)
    echo "FAIL: expected blocked_pattern deny, got: ${exfil_reason}" >&2
    echo "${exfil_resp}" | jq . >&2
    exit 1
    ;;
esac
echo "PASS: exfiltration pattern blocked (${exfil_reason})"

echo "CORE STRICT PRESET TEST PASSED"
