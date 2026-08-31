#!/usr/bin/env bash
# Trust-hardening test: trusted_servers gate.
#
# Snapshots the active proxy policy, sets trusted_servers to a value that
# does NOT match the configured MCP_PROXY_UPSTREAM_URL, sends a tools/list
# request, and verifies that the proxy responded with an `untrusted_server`
# deny and emitted an `untrusted_server_calls` discovery alert. Restores the
# original policy on exit (even on failure).
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

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing command: $1" >&2; exit 2; }
}

auth_get()  { mcp_test_proxy_get "$1"; }
auth_post() { mcp_test_proxy_post_json "$1" "$2"; }

require_cmd curl
require_cmd jq

ORIGINAL_POLICY_FILE="$(mktemp -t mcp_proxy_trust_pol.XXXXXX.json)"
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

echo "Snapshotting current policy..."
auth_get "${POLICY_GET_URL}" | jq '.raw_policy' > "${ORIGINAL_POLICY_FILE}"
if ! [[ -s "${ORIGINAL_POLICY_FILE}" ]]; then
  echo "ERROR: failed to read current policy from ${POLICY_GET_URL}" >&2
  exit 1
fi

echo "Resetting discovery alerts / cooldown..."
auth_post "${CLEAR_ALERTS_URL}" '{"reset_cooldown":true}' >/dev/null || true

echo "Applying test policy (trusted_servers does NOT match upstream)..."
TEST_POLICY="$(jq '
  .trusted_servers = ["https://trusted.invalid.example/mcp"]
  | .untrusted_server_action = "deny"
  | .discovery_rules = ((.discovery_rules // []) + [
      {"signal":"untrusted_server_calls","action_on_trigger":"monitor"}
    ])
' "${ORIGINAL_POLICY_FILE}")"
APPLY_BODY="$(jq -n --argjson p "${TEST_POLICY}" '{raw_policy: $p}')"
auth_post "${POLICY_POST_URL}" "${APPLY_BODY}" | jq '.summary // .status'

echo
echo "Sending tools/list — expecting untrusted_server deny..."
LIST_PAYLOAD='{"jsonrpc":"2.0","id":"trust-1","method":"tools/list","params":{}}'
RESP="$(auth_post "${PROXY_MCP_URL}" "${LIST_PAYLOAD}")"
echo "${RESP}" | jq '{error: .error}' || true

REASON="$(echo "${RESP}" | jq -r '.error.data.reason // empty')"
if [[ "${REASON}" != "untrusted_server" ]]; then
  echo "FAIL: expected error.data.reason='untrusted_server', got '${REASON}'" >&2
  exit 1
fi
echo "PASS: deny reason = untrusted_server"

echo
echo "Checking /recent-denied for untrusted_server..."
auth_get "${DENIED_URL}" \
  | jq '{count, events: (.events[:5] | map({tool, reason, timestamp}))}'
DENIED_FOUND="$(auth_get "${DENIED_URL}" | jq -r '[.events[]? | select(.reason == "untrusted_server")] | length')"
if [[ "${DENIED_FOUND}" -lt 1 ]]; then
  echo "FAIL: no untrusted_server entry in /recent-denied" >&2
  exit 1
fi
echo "PASS: /recent-denied contains untrusted_server (count=${DENIED_FOUND})"

echo
echo "Checking /recent-discovery-alerts for untrusted_server_calls..."
ALERTS_JSON="$(auth_get "${ALERTS_URL}")"
echo "${ALERTS_JSON}" | jq '{count, alerts: (.alerts[:5] | map({signal, observed_count, timestamp}))}'
ALERT_FOUND="$(echo "${ALERTS_JSON}" | jq -r '[.alerts[]? | select(.signal == "untrusted_server_calls")] | length')"
if [[ "${ALERT_FOUND}" -lt 1 ]]; then
  echo "FAIL: untrusted_server_calls alert not emitted" >&2
  exit 1
fi
echo "PASS: untrusted_server_calls alert emitted (count=${ALERT_FOUND})"

echo
echo "ALL TRUST-SERVER CHECKS PASSED."
