#!/usr/bin/env bash
# Phase C / Sprint 4: RBAC role enforcement on admin routes.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=mcp_proxy_test_common.sh
source "${ROOT_DIR}/tools/mcp_proxy_test_common.sh"

PROXY_BASE_URL="${PROXY_BASE_URL:-http://localhost:8090}"
OPERATOR_TOKEN="${MCP_PROXY_OPERATOR_TOKEN:-mcp_proxy_operator_demo_change_me}"
AUDITOR_TOKEN="${MCP_PROXY_AUDITOR_TOKEN:-mcp_proxy_auditor_demo_change_me}"

mcp_test_proxy_get_with_token() {
  local url="$1"
  local token="$2"
  curl -sS -H "Authorization: Bearer ${token}" "${url}"
}

mcp_test_proxy_post_json_with_token() {
  local url="$1"
  local token="$2"
  local body="$3"
  curl -sS \
    -H "Authorization: Bearer ${token}" \
    -H "Content-Type: application/json" \
    -X POST \
    -d "${body}" \
    "${url}"
}

echo "== PHASE C RBAC TEST =="
mcp_test_require_proxy_healthy "${PROXY_BASE_URL}"

echo "Test 1: auditor can read policy"
code="$(curl -sS -o /tmp/mcp_rbac_aud_read.json -w '%{http_code}' \
  -H "Authorization: Bearer ${AUDITOR_TOKEN}" \
  "${PROXY_BASE_URL%/}/admin/policy-config")"
if [[ "${code}" != "200" ]]; then
  echo "FAIL: auditor policy read expected 200, got ${code}" >&2
  exit 1
fi
echo "PASS: auditor policy:read"

echo "Test 2: auditor denied policy write"
code="$(curl -sS -o /tmp/mcp_rbac_aud_write.json -w '%{http_code}' \
  -H "Authorization: Bearer ${AUDITOR_TOKEN}" \
  -H "Content-Type: application/json" \
  -X POST \
  -d "$(jq -n --argjson p "$(cat /tmp/mcp_rbac_aud_read.json | jq '.raw_policy')" '{raw_policy: $p}')" \
  "${PROXY_BASE_URL%/}/admin/policy-config")"
if [[ "${code}" != "403" ]]; then
  echo "FAIL: auditor policy write expected 403, got ${code}" >&2
  exit 1
fi
echo "PASS: auditor policy write forbidden"

echo "Test 3: operator write queues proposal when approval required"
policy="$(mcp_test_proxy_get_with_token "${PROXY_BASE_URL%/}/admin/policy-config" "${OPERATOR_TOKEN}" | jq -c '.raw_policy')"
mutated="$(echo "${policy}" | jq -c '.denied_tools += ["phase_c_rbac_marker_tool"]')"
resp="$(mcp_test_proxy_post_json_with_token \
  "${PROXY_BASE_URL%/}/admin/policy-config" \
  "${OPERATOR_TOKEN}" \
  "$(jq -n --argjson p "${mutated}" '{raw_policy: $p, reason: "phase c rbac test"}')")"
status="$(echo "${resp}" | jq -r '.status // empty')"
if [[ "${status}" != "pending_approval" ]]; then
  echo "FAIL: operator write expected pending_approval, got: ${status}" >&2
  echo "${resp}" | jq . >&2 || true
  exit 1
fi
echo "PASS: operator proposal queued"

echo "Test 4: admin auth/me exposes role"
me="$(mcp_test_proxy_get_with_token "${PROXY_BASE_URL%/}/admin/auth/me" "${OPERATOR_TOKEN}")"
role="$(echo "${me}" | jq -r '.principal.role // empty')"
if [[ "${role}" != "operator" ]]; then
  echo "FAIL: expected operator role, got ${role}" >&2
  exit 1
fi
echo "PASS: auth/me role=${role}"

echo "PHASE C RBAC TEST PASSED"
