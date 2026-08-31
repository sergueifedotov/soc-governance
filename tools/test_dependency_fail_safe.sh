#!/usr/bin/env bash
# Sprint 2 fail-safe test: required dependency health checks.
#
# Enables llm_risk enforcement and dependency_fail_safe_profile. Points base_url
# to an unreachable endpoint to trigger fail-closed behavior. Verifies deny reason
# `dependency_health_failed` and discovery signal `dependency_health_failures`.
# Restores original policy on exit.
set -euo pipefail

PROXY_BASE_URL="${PROXY_BASE_URL:-http://localhost:8090}"

resolve_proxy_api_key() {
  local container_key=""
  if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^mcp-security-proxy$'; then
    container_key="$(docker exec mcp-security-proxy printenv MCP_PROXY_API_KEY 2>/dev/null || true)"
    if [[ -n "${container_key}" ]]; then
      printf '%s' "${container_key}"
      return 0
    fi
  fi
  if [[ -n "${MCP_PROXY_API_KEY:-}" ]]; then
    printf '%s' "${MCP_PROXY_API_KEY}"
    return 0
  fi
  if source "tools/mcp_api_key.sh" --quiet >/dev/null 2>&1 && [[ -n "${MCP_PROXY_API_KEY:-}" ]]; then
    printf '%s' "${MCP_PROXY_API_KEY}"
    return 0
  fi
  printf '%s' "mcp_proxy_local_demo_change_me"
}

PROXY_API_KEY="$(resolve_proxy_api_key)"
PROXY_MCP_URL="${PROXY_BASE_URL%/}/mcp"
POLICY_GET_URL="${PROXY_BASE_URL%/}/admin/policy-config"
POLICY_POST_URL="${PROXY_BASE_URL%/}/admin/policy-config"
ALERTS_URL="${PROXY_BASE_URL%/}/recent-discovery-alerts?limit=50"
DENIED_URL="${PROXY_BASE_URL%/}/recent-denied?limit=30"
CLEAR_ALERTS_URL="${PROXY_BASE_URL%/}/admin/clear-discovery-alerts"

UNREACHABLE_BASE_URL="${UNREACHABLE_BASE_URL:-http://127.0.0.1:9}"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing command: $1" >&2; exit 2; }
}

auth_get()  { curl -sS -H "Authorization: Bearer ${PROXY_API_KEY}" "$1"; }
auth_post() { curl -sS -H "Authorization: Bearer ${PROXY_API_KEY}" -H "Content-Type: application/json" -X POST -d "$2" "$1"; }

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
  local has_failsafe
  has_failsafe="$(docker exec mcp-security-proxy sh -lc "python - <<'PY'
import mcp_security_proxy.app as app
print('1' if hasattr(app, '_dependency_fail_safe_check') else '0')
PY" 2>/dev/null | tr -d '\r' | tail -n1 || true)"
  if [[ "${has_failsafe}" != "1" ]]; then
    echo "FAIL: running mcp-security-proxy container does not include Sprint 2 dependency fail-safe code." >&2
    echo "hint: rebuild/restart proxy from local source:" >&2
    echo "  cd mcp-security-proxy && docker compose -f docker-compose.yml -f docker-compose.phase4.yml build mcp-security-proxy && docker compose -f docker-compose.yml -f docker-compose.phase4.yml up -d mcp-security-proxy" >&2
    exit 2
  fi
}

preflight_runtime_support

ORIGINAL_POLICY_FILE="$(mktemp -t mcp_proxy_failsafe_pol.XXXXXX.json)"
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

echo "Proxy MCP URL      : ${PROXY_MCP_URL}"
echo "Unreachable base URL: ${UNREACHABLE_BASE_URL}"

echo "Snapshotting current policy..."
auth_get "${POLICY_GET_URL}" | jq '.raw_policy' > "${ORIGINAL_POLICY_FILE}"
if ! [[ -s "${ORIGINAL_POLICY_FILE}" ]]; then
  echo "ERROR: failed to read current policy from ${POLICY_GET_URL}" >&2
  exit 1
fi

echo "Resetting discovery alerts / cooldown..."
auth_post "${CLEAR_ALERTS_URL}" '{"reset_cooldown":true}' >/dev/null || true

echo "Applying test policy with dependency fail-safe enabled (deny)..."
TEST_POLICY="$(jq --arg bad_url "${UNREACHABLE_BASE_URL}" '
  .llm_risk = ((.llm_risk // {}) + {
    "enabled": true,
    "enforce": true,
    "provider": "langchain",
    "base_url": $bad_url,
    "timeout_seconds": 1
  })
  | .dependency_fail_safe_profile = {
      "enabled": true,
      "action": "deny",
      "required_controls": ["llm_risk"],
      "require_network_reachability": true,
      "health_cache_ttl_seconds": 1,
      "prevent_silent_bypass": true
    }
  | .discovery_rules = ((.discovery_rules // []) + [
      {"signal":"dependency_health_failures","action_on_trigger":"monitor"}
    ])
' "${ORIGINAL_POLICY_FILE}")"
APPLY_BODY="$(jq -n --argjson p "${TEST_POLICY}" '{raw_policy: $p}')"
auth_post "${POLICY_POST_URL}" "${APPLY_BODY}" | jq '.summary // .status'

echo
echo "Sending tools/call under enforcing mode with failed dependency — expecting dependency_health_failed..."
CALL_PAYLOAD="$(jq -cn \
  '{jsonrpc:"2.0",id:"dep-1",method:"tools/call",params:{name:"wazuh_lookup_alert",arguments:{alert_id:"123"}}}')"
RESP="$(auth_post "${PROXY_MCP_URL}" "${CALL_PAYLOAD}")"
echo "${RESP}" | jq '{error: .error}' || true

REASON="$(echo "${RESP}" | jq -r '.error.data.reason // empty')"
if [[ "${REASON}" != "dependency_health_failed" ]]; then
  echo "FAIL: expected error.data.reason='dependency_health_failed', got '${REASON}'" >&2
  exit 1
fi
echo "PASS: deny reason = dependency_health_failed"

echo
echo "Checking /recent-denied for dependency_health_*..."
auth_get "${DENIED_URL}" \
  | jq '{count, events: (.events[:8] | map({tool, reason, timestamp}))}'
DENIED_FOUND="$(auth_get "${DENIED_URL}" | jq -r '[.events[]? | select(.reason | startswith("dependency_health"))] | length')"
if [[ "${DENIED_FOUND}" -lt 1 ]]; then
  echo "FAIL: no dependency_health* entry in /recent-denied" >&2
  exit 1
fi
echo "PASS: /recent-denied contains dependency_health* reason(s) (count=${DENIED_FOUND})"

echo
echo "Checking /recent-discovery-alerts for dependency_health_failures..."
ALERTS_JSON="$(auth_get "${ALERTS_URL}")"
echo "${ALERTS_JSON}" | jq '{count, alerts: (.alerts[:8] | map({signal, observed_count, timestamp}))}'
ALERT_FOUND="$(echo "${ALERTS_JSON}" | jq -r '[.alerts[]? | select(.signal == "dependency_health_failures")] | length')"
if [[ "${ALERT_FOUND}" -lt 1 ]]; then
  echo "FAIL: dependency_health_failures alert not emitted" >&2
  exit 1
fi
echo "PASS: dependency_health_failures alert emitted (count=${ALERT_FOUND})"

echo
echo "ALL DEPENDENCY FAIL-SAFE CHECKS PASSED."
