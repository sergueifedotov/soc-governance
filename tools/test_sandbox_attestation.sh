#!/usr/bin/env bash
# Sprint 2 containment test: sandbox attestation gate.
#
# Enables sandbox_attestation_profile with action=deny for execution-like tools,
# then issues tools/call without attestation evidence. Verifies deny reason
# `sandbox_attestation_missing` and discovery signal `sandbox_attestation_failures`.
# Restores original policy on exit.
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
DENIED_URL="${PROXY_BASE_URL%/}/recent-denied?limit=30"
CLEAR_ALERTS_URL="${PROXY_BASE_URL%/}/admin/clear-discovery-alerts"

EXEC_TOOL_NAME="${EXEC_TOOL_NAME:-shell_exec}"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing command: $1" >&2; exit 2; }
}

auth_get()  { mcp_test_proxy_get "$1"; }
auth_post() { mcp_test_proxy_post_json "$1" "$2"; }

require_cmd curl
require_cmd jq

preflight_runtime_support() {
  # Best-effort stale-image detection when the proxy is running in Docker.
  if ! command -v docker >/dev/null 2>&1; then
    return 0
  fi
  if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^mcp-security-proxy$'; then
    return 0
  fi
  local has_sandbox
  has_sandbox="$(docker exec mcp-security-proxy sh -lc "python - <<'PY'
import mcp_security_proxy.app as app
print('1' if hasattr(app, '_sandbox_attestation_check') else '0')
PY" 2>/dev/null | tr -d '\r' | tail -n1 || true)"
  if [[ "${has_sandbox}" != "1" ]]; then
    echo "FAIL: running mcp-security-proxy container does not include Sprint 2 sandbox attestation code." >&2
    echo "hint: rebuild/restart proxy from local source:" >&2
    echo "  cd mcp-security-proxy && docker compose -f docker-compose.yml -f docker-compose.phase4.yml build mcp-security-proxy && docker compose -f docker-compose.yml -f docker-compose.phase4.yml up -d mcp-security-proxy" >&2
    exit 2
  fi
}

preflight_runtime_support

ORIGINAL_POLICY_FILE="$(mktemp -t mcp_proxy_attestation_pol.XXXXXX.json)"
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

echo "Applying test policy with sandbox attestation gate (deny)..."
TEST_POLICY="$(jq --arg exec_tool "${EXEC_TOOL_NAME}" '
  .sandbox_attestation_profile = {
    "enabled": true,
    "action": "deny",
    "require_for_tools": [$exec_tool, "shell", "exec", "python_repl", "bash", "powershell"],
    "trusted_issuers": ["trusted-attestor"],
    "allowed_modes": ["isolated"],
    "allow_missing_expiry": false,
    "max_age_seconds": 900,
    "require_pass": true
  }
  | .tool_intent.enforce = false
  | .tool_intent.require_intent_metadata = false
  | .execution_tool_profile = ((.execution_tool_profile // {}) + {"enabled": false})
  | .discovery_rules = ((.discovery_rules // []) + [
      {"signal":"sandbox_attestation_failures","action_on_trigger":"monitor"}
    ])
' "${ORIGINAL_POLICY_FILE}")"
APPLY_BODY="$(jq -n --argjson p "${TEST_POLICY}" '{raw_policy: $p}')"
auth_post "${POLICY_POST_URL}" "${APPLY_BODY}" | jq '.summary // .status'

echo
echo "Sending tools/call '${EXEC_TOOL_NAME}' without attestation — expecting sandbox_attestation_missing..."
CALL_PAYLOAD="$(jq -cn --arg t "${EXEC_TOOL_NAME}" \
  '{jsonrpc:"2.0",id:"att-1",method:"tools/call",params:{name:$t,tool:$t,arguments:{cmd:"whoami"}}}')"
RESP="$(auth_post "${PROXY_MCP_URL}" "${CALL_PAYLOAD}")"
echo "${RESP}" | jq '{error: .error}' || true

REASON="$(echo "${RESP}" | jq -r '.error.data.reason // empty')"
if [[ "${REASON}" != "sandbox_attestation_missing" ]]; then
  echo "FAIL: expected error.data.reason='sandbox_attestation_missing', got '${REASON}'" >&2
  exit 1
fi
echo "PASS: deny reason = sandbox_attestation_missing"

echo
echo "Checking /recent-denied for sandbox_attestation_*..."
auth_get "${DENIED_URL}" \
  | jq '{count, events: (.events[:8] | map({tool, reason, timestamp}))}'
DENIED_FOUND="$(auth_get "${DENIED_URL}" | jq -r '[.events[]? | select(.reason | startswith("sandbox_attestation"))] | length')"
if [[ "${DENIED_FOUND}" -lt 1 ]]; then
  echo "FAIL: no sandbox_attestation* entry in /recent-denied" >&2
  exit 1
fi
echo "PASS: /recent-denied contains sandbox_attestation* reason(s) (count=${DENIED_FOUND})"

echo
echo "Checking /recent-discovery-alerts for sandbox_attestation_failures..."
ALERTS_JSON="$(auth_get "${ALERTS_URL}")"
echo "${ALERTS_JSON}" | jq '{count, alerts: (.alerts[:8] | map({signal, observed_count, timestamp}))}'
ALERT_FOUND="$(echo "${ALERTS_JSON}" | jq -r '[.alerts[]? | select(.signal == "sandbox_attestation_failures")] | length')"
if [[ "${ALERT_FOUND}" -lt 1 ]]; then
  echo "FAIL: sandbox_attestation_failures alert not emitted" >&2
  exit 1
fi
echo "PASS: sandbox_attestation_failures alert emitted (count=${ALERT_FOUND})"

echo
echo "ALL SANDBOX ATTESTATION CHECKS PASSED."
