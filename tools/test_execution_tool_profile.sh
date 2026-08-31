#!/usr/bin/env bash
# Trust-hardening test: execution_tool_profile.
#
# Enables execution_tool_profile with action=deny, then issues a tools/call
# for a name that matches the default execution patterns. Verifies the
# request is denied with `execution_tool_blocked` and that the
# `execution_tool_attempts` discovery alert is emitted. Restores the
# original policy on exit.
set -euo pipefail

PROXY_BASE_URL="${PROXY_BASE_URL:-http://localhost:8090}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=mcp_proxy_test_common.sh
source "${ROOT_DIR}/tools/mcp_proxy_test_common.sh"

PROXY_API_KEY="$(mcp_test_resolve_proxy_api_key)"
export MCP_PROXY_API_KEY="${PROXY_API_KEY}"
PROXY_MCP_URL="${PROXY_BASE_URL%/}/mcp"
POLICY_GET_URL="${PROXY_BASE_URL%/}/admin/policy-config"
POLICY_POST_URL="${PROXY_BASE_URL%/}/admin/policy-config"
ALERTS_URL="${PROXY_BASE_URL%/}/recent-discovery-alerts?limit=50"
DENIED_URL="${PROXY_BASE_URL%/}/recent-denied?limit=20"
CLEAR_ALERTS_URL="${PROXY_BASE_URL%/}/admin/clear-discovery-alerts"

# Name guaranteed to match the default patterns (`shell`, `exec`).
EXEC_TOOL_NAME="${EXEC_TOOL_NAME:-shell_exec}"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing command: $1" >&2; exit 2; }
}

auth_get()  { mcp_test_proxy_get "$1"; }
auth_post() { mcp_test_proxy_post_json "$1" "$2"; }

require_cmd curl
require_cmd jq

ORIGINAL_POLICY_FILE="$(mktemp -t mcp_proxy_exec_pol.XXXXXX.json)"
RESTORED=0

restore_policy() {
  if [[ ${RESTORED} -eq 1 ]]; then return 0; fi
  if [[ -s "${ORIGINAL_POLICY_FILE}" ]]; then
    echo "Restoring original policy..."
    local restore_body
    restore_body="$(jq -n --slurpfile p "${ORIGINAL_POLICY_FILE}" '{raw_policy: $p[0]}')"
    auth_post "${POLICY_POST_URL}" "${restore_body}" \
      | jq -r '.status // "unknown"' | sed 's/^/  restore status: /'
  fi
  rm -f "${ORIGINAL_POLICY_FILE}"
  RESTORED=1
}
trap restore_policy EXIT

echo "Proxy MCP URL : ${PROXY_MCP_URL}"
echo "Exec tool     : ${EXEC_TOOL_NAME}"

echo "Snapshotting current policy..."
auth_get "${POLICY_GET_URL}" | jq '.raw_policy' > "${ORIGINAL_POLICY_FILE}"
if ! [[ -s "${ORIGINAL_POLICY_FILE}" ]]; then
  echo "ERROR: failed to read current policy from ${POLICY_GET_URL}" >&2
  exit 1
fi

echo "Resetting discovery alerts / cooldown..."
auth_post "${CLEAR_ALERTS_URL}" '{"reset_cooldown":true}' >/dev/null || true

echo "Applying test policy with execution_tool_profile enabled (action=deny)..."
TEST_POLICY="$(jq '
  .execution_tool_profile = {"enabled": true, "action": "deny"}
  | .discovery_rules = ((.discovery_rules // []) + [
      {"signal":"execution_tool_attempts","action_on_trigger":"monitor"}
    ])
' "${ORIGINAL_POLICY_FILE}")"
APPLY_BODY="$(jq -n --argjson p "${TEST_POLICY}" '{raw_policy: $p}')"
auth_post "${POLICY_POST_URL}" "${APPLY_BODY}" | jq '.summary // .status'

echo
echo "Sending tools/call '${EXEC_TOOL_NAME}' — expecting execution_tool_blocked..."
CALL_PAYLOAD="$(jq -cn --arg t "${EXEC_TOOL_NAME}" \
  '{jsonrpc:"2.0",id:"exec-1",method:"tools/call",params:{name:$t,arguments:{cmd:"whoami"}}}')"
RESP="$(auth_post "${PROXY_MCP_URL}" "${CALL_PAYLOAD}")"
echo "${RESP}" | jq '{error: .error}' || true

REASON="$(echo "${RESP}" | jq -r '.error.data.reason // empty')"
if [[ "${REASON}" != "execution_tool_blocked" ]]; then
  echo "FAIL: expected error.data.reason='execution_tool_blocked', got '${REASON}'" >&2
  exit 1
fi
echo "PASS: deny reason = execution_tool_blocked"

echo
echo "Checking /recent-denied for execution_tool_blocked..."
auth_get "${DENIED_URL}" \
  | jq '{count, events: (.events[:5] | map({tool, reason, timestamp}))}'
DENIED_FOUND="$(auth_get "${DENIED_URL}" | jq -r '[.events[]? | select(.reason == "execution_tool_blocked")] | length')"
if [[ "${DENIED_FOUND}" -lt 1 ]]; then
  echo "FAIL: no execution_tool_blocked entry in /recent-denied" >&2
  exit 1
fi
echo "PASS: /recent-denied contains execution_tool_blocked (count=${DENIED_FOUND})"

echo
echo "Checking /recent-discovery-alerts for execution_tool_attempts..."
ALERTS_JSON="$(auth_get "${ALERTS_URL}")"
echo "${ALERTS_JSON}" | jq '{count, alerts: (.alerts[:5] | map({signal, observed_count, timestamp}))}'
ALERT_FOUND="$(echo "${ALERTS_JSON}" | jq -r '[.alerts[]? | select(.signal == "execution_tool_attempts")] | length')"
if [[ "${ALERT_FOUND}" -lt 1 ]]; then
  echo "FAIL: execution_tool_attempts alert not emitted" >&2
  exit 1
fi
echo "PASS: execution_tool_attempts alert emitted (count=${ALERT_FOUND})"

echo
echo "ALL EXECUTION-TOOL CHECKS PASSED."
