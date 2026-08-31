#!/usr/bin/env bash
# Trust-hardening test: tool_descriptor_hashes / descriptor_drift.
#
# 1. Snapshots the current policy.
# 2. Calls tools/list to discover a real tool name (or uses DRIFT_TARGET_TOOL).
# 3. Pins a *deliberately wrong* sha256 for that tool in
#    tool_descriptor_hashes (descriptor_drift_action=deny).
# 4. Calls tools/list again and verifies drift handling + telemetry.
# 5. Restores the original policy on exit.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=mcp_proxy_test_common.sh
source "${ROOT_DIR}/tools/mcp_proxy_test_common.sh"

PROXY_BASE_URL="${PROXY_BASE_URL:-http://localhost:8090}"
PROXY_API_KEY="$(mcp_test_resolve_proxy_api_key)"
export MCP_PROXY_API_KEY="${PROXY_API_KEY}"

PROXY_MCP_URL="${PROXY_BASE_URL%/}/mcp"
POLICY_GET_URL="${PROXY_BASE_URL%/}/admin/policy-config"
POLICY_POST_URL="${PROXY_BASE_URL%/}/admin/policy-config"
ALERTS_URL="${PROXY_BASE_URL%/}/recent-discovery-alerts?limit=50"
DENIED_URL="${PROXY_BASE_URL%/}/recent-denied?limit=20"
CLEAR_ALERTS_URL="${PROXY_BASE_URL%/}/admin/clear-discovery-alerts"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing command: $1" >&2; exit 2; }
}

auth_get()  { mcp_test_proxy_get "$1"; }
auth_post() { mcp_test_proxy_post_json "$1" "$2"; }

require_cmd curl
require_cmd jq

ORIGINAL_POLICY_FILE="$(mktemp -t mcp_proxy_drift_pol.XXXXXX.json)"
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

echo "Preflight: proxy -> upstream MCP path..."
mcp_test_preflight_upstream_mcp "descriptor-drift"

echo "Snapshotting current policy..."
auth_get "${POLICY_GET_URL}" | jq '.raw_policy' > "${ORIGINAL_POLICY_FILE}"
if ! [[ -s "${ORIGINAL_POLICY_FILE}" ]]; then
  echo "ERROR: failed to read current policy from ${POLICY_GET_URL}" >&2
  exit 1
fi

TARGET_TOOL="${DRIFT_TARGET_TOOL:-}"
if [[ -z "${TARGET_TOOL}" ]]; then
  echo "Discovering a tool name via tools/list..."
  TARGET_TOOL="$(mcp_test_tools_list_names | head -n1 || true)"
fi
if [[ -z "${TARGET_TOOL}" ]]; then
  echo "ERROR: could not determine a tool name (set DRIFT_TARGET_TOOL or fix upstream MCP auth)" >&2
  exit 1
fi
echo "Target tool   : ${TARGET_TOOL}"

# Deliberately wrong hash: sha256("descriptor-drift-test").
WRONG_HASH="$(printf '%s' 'descriptor-drift-test' | shasum -a 256 | awk '{print $1}')"
echo "Pinned hash   : ${WRONG_HASH} (intentionally wrong)"

echo "Resetting discovery alerts / cooldown..."
auth_post "${CLEAR_ALERTS_URL}" '{"reset_cooldown":true}' >/dev/null || true

echo "Applying test policy with descriptor_drift_action=deny..."
TEST_POLICY="$(jq \
  --arg tool "${TARGET_TOOL}" \
  --arg h "${WRONG_HASH}" '
    .tool_descriptor_hashes = ((.tool_descriptor_hashes // {}) + {($tool): $h})
    | .descriptor_drift_action = "deny"
    | .discovery_rules = ((.discovery_rules // []) + [
        {"signal":"descriptor_drift_events","action_on_trigger":"monitor"}
      ])
' "${ORIGINAL_POLICY_FILE}")"
APPLY_BODY="$(jq -n --argjson p "${TEST_POLICY}" '{raw_policy: $p}')"
auth_post "${POLICY_POST_URL}" "${APPLY_BODY}" | jq '.summary // .status'

echo
echo "Re-running tools/list (drift should be detected)..."
LIST_PAYLOAD='{"jsonrpc":"2.0","id":"drift-discover","method":"tools/list","params":{}}'
RESP="$(auth_post "${PROXY_MCP_URL}" "${LIST_PAYLOAD}")"
DRIFT_COUNT="$(echo "${RESP}" | jq --arg t "${TARGET_TOOL}" '[.result._descriptor_drift[]? | select(.tool == $t)] | length')"
STILL_PRESENT="$(echo "${RESP}" | jq --arg t "${TARGET_TOOL}" '[.result.tools[]? | select(.name == $t)] | length')"

echo "${RESP}" | jq '{tools_count: (.result.tools | length // 0), drift: (.result._descriptor_drift // [])}'

if [[ "${DRIFT_COUNT}" -lt 1 ]]; then
  echo "FAIL: _descriptor_drift did not contain tool '${TARGET_TOOL}'" >&2
  exit 1
fi
if [[ "${STILL_PRESENT}" -ne 0 ]]; then
  echo "FAIL: tool '${TARGET_TOOL}' should have been filtered out of result.tools" >&2
  exit 1
fi
echo "PASS: tool '${TARGET_TOOL}' filtered + _descriptor_drift finding present"

echo
echo "Checking /recent-denied for descriptor_drift..."
DENIED_FOUND="$(auth_get "${DENIED_URL}" | jq -r '[.events[]? | select(.reason == "descriptor_drift")] | length')"
if [[ "${DENIED_FOUND}" -lt 1 ]]; then
  echo "FAIL: no descriptor_drift entry in /recent-denied" >&2
  exit 1
fi
echo "PASS: /recent-denied contains descriptor_drift (count=${DENIED_FOUND})"

echo
echo "Checking /recent-discovery-alerts for descriptor_drift_events..."
ALERTS_JSON="$(auth_get "${ALERTS_URL}")"
echo "${ALERTS_JSON}" | jq '{count, alerts: (.alerts[:5] | map({signal, observed_count, timestamp}))}'
ALERT_FOUND="$(echo "${ALERTS_JSON}" | jq -r '[.alerts[]? | select(.signal == "descriptor_drift_events")] | length')"
if [[ "${ALERT_FOUND}" -lt 1 ]]; then
  echo "FAIL: descriptor_drift_events alert not emitted" >&2
  exit 1
fi
echo "PASS: descriptor_drift_events alert emitted (count=${ALERT_FOUND})"

echo
echo "ALL DESCRIPTOR-DRIFT CHECKS PASSED."
