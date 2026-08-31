#!/usr/bin/env bash
# Phase B: metering, entitlements, and tier limit enforcement.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=mcp_proxy_test_common.sh
source "${ROOT_DIR}/tools/mcp_proxy_test_common.sh"

PROXY_BASE_URL="${PROXY_BASE_URL:-http://localhost:8090}"
PROXY_MCP_URL="${PROXY_BASE_URL%/}/mcp"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing command: $1" >&2; exit 2; }
}
require_cmd curl
require_cmd jq

ORIGINAL_POLICY_FILE="$(mktemp -t mcp_phase_b_meter.XXXXXX.json)"
RESTORED=0

restore_policy() {
  if [[ ${RESTORED} -eq 1 ]]; then return 0; fi
  if [[ -s "${ORIGINAL_POLICY_FILE}" ]]; then
    local restore_body
    restore_body="$(jq -n --slurpfile p "${ORIGINAL_POLICY_FILE}" '{raw_policy: $p[0]}')"
    mcp_test_proxy_post_json "${PROXY_BASE_URL%/}/admin/policy-config" "${restore_body}" >/dev/null
  fi
  rm -f "${ORIGINAL_POLICY_FILE}"
  RESTORED=1
}
trap restore_policy EXIT

echo "== PHASE B METERING TEST =="
mcp_test_require_proxy_healthy "${PROXY_BASE_URL}"

mcp_test_proxy_get "${PROXY_BASE_URL%/}/admin/policy-config" | jq '.raw_policy' > "${ORIGINAL_POLICY_FILE}"

echo "Test 1: usage and entitlements endpoints"
usage_resp="$(mcp_test_proxy_get "${PROXY_BASE_URL%/}/admin/usage")"
ent_resp="$(mcp_test_proxy_get "${PROXY_BASE_URL%/}/admin/entitlements")"
tier="$(echo "${usage_resp}" | jq -r '.usage.tier // empty')"
if [[ -z "${tier}" ]]; then
  echo "FAIL: /admin/usage missing tier" >&2
  exit 1
fi
if ! echo "${ent_resp}" | jq -e '.entitlements.features' >/dev/null 2>&1; then
  echo "FAIL: /admin/entitlements missing features" >&2
  exit 1
fi
echo "PASS: usage tier=${tier}"

echo "Test 2: policy_bundles gated for core tier"
bundle_body='{"policy_bundle":{"denied_tools":["wazuh_block_ip"]},"dry_run":true}'
bundle_code="$(curl -sS -o /tmp/mcp_bundle_resp.json -w '%{http_code}' \
  -H "$(mcp_test_proxy_auth_header)" \
  -H "Content-Type: application/json" \
  -X POST \
  -d "${bundle_body}" \
  "${PROXY_BASE_URL%/}/admin/apply-policy-bundle")"
if [[ "${bundle_code}" != "403" ]]; then
  echo "FAIL: expected 403 for policy_bundles on core, got ${bundle_code}" >&2
  cat /tmp/mcp_bundle_resp.json >&2
  exit 1
fi
echo "PASS: policy_bundles returns 403 for core tier"

echo "Test 3: core tier hard deny on MCP call limit"
limited_policy="$(jq '.commercial.tier = "core" | .commercial.limits.max_mcp_calls_per_day = 1' "${ORIGINAL_POLICY_FILE}")"
limited_body="$(jq -n --argjson p "${limited_policy}" '{raw_policy: $p}')"
mcp_test_proxy_post_json "${PROXY_BASE_URL%/}/admin/policy-config" "${limited_body}" >/dev/null

ping_payload='{"jsonrpc":"2.0","id":"meter-1","method":"ping"}'
mcp_test_proxy_post_json "${PROXY_MCP_URL}" "${ping_payload}" >/dev/null
limit_resp="$(mcp_test_proxy_post_json "${PROXY_MCP_URL}" "${ping_payload}")"
limit_reason="$(echo "${limit_resp}" | jq -r '.error.data.reason // empty')"
if [[ "${limit_reason}" != "tier_limit_exceeded" ]]; then
  echo "FAIL: expected tier_limit_exceeded on second call, got: ${limit_reason}" >&2
  echo "${limit_resp}" | jq . >&2
  exit 1
fi
echo "PASS: core tier denies when MCP daily limit exceeded"

echo "PHASE B METERING TEST PASSED"
