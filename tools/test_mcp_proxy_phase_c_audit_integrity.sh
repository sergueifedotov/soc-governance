#!/usr/bin/env bash
# Phase C / Sprint 4: tamper-evident audit hash chain.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=mcp_proxy_test_common.sh
source "${ROOT_DIR}/tools/mcp_proxy_test_common.sh"

PROXY_BASE_URL="${PROXY_BASE_URL:-http://localhost:8090}"
PROXY_MCP_URL="${PROXY_BASE_URL%/}/mcp"

echo "== PHASE C AUDIT INTEGRITY TEST =="
mcp_test_require_proxy_healthy "${PROXY_BASE_URL}"

echo "Test 0: purge stale runtime history for a clean chain baseline"
purge_resp="$(mcp_test_proxy_post_json \
  "${PROXY_BASE_URL%/}/admin/purge-runtime-history" \
  "$(jq -n '{clear_runtime_buffers: true}')")"
if [[ "$(echo "${purge_resp}" | jq -r '.status // empty')" != "ok" ]]; then
  echo "FAIL: could not purge runtime history before audit integrity test" >&2
  echo "${purge_resp}" | jq . >&2 || true
  exit 1
fi
echo "PASS: runtime history purged"

echo "Test 1: generate denied event with audit chain"
deny_payload="$(jq -n '{
  jsonrpc: "2.0",
  id: "phase-c-audit-chain",
  method: "tools/call",
  params: { name: "wazuh_block_ip", arguments: { ip: "203.0.113.9" } }
}')"
deny_resp="$(mcp_test_proxy_post_json "${PROXY_MCP_URL}" "${deny_payload}")"
deny_reason="$(echo "${deny_resp}" | jq -r '.error.data.reason // empty')"
if [[ "${deny_reason}" != "tool_denied" ]]; then
  echo "FAIL: expected tool_denied, got ${deny_reason}" >&2
  exit 1
fi
echo "PASS: denied event generated"

echo "Test 2: audit integrity endpoint"
integrity="$(mcp_test_proxy_get "${PROXY_BASE_URL%/}/admin/audit-integrity")"
enabled="$(echo "${integrity}" | jq -r '.integrity.audit_chain_enabled // false')"
valid="$(echo "${integrity}" | jq -r '.integrity.verification.valid // false')"
chained="$(echo "${integrity}" | jq -r '.integrity.chained_event_count // 0')"
if [[ "${enabled}" != "true" ]]; then
  echo "FAIL: audit chain not enabled in governance policy" >&2
  exit 1
fi
if [[ "${chained}" -lt 1 || "${valid}" != "true" ]]; then
  echo "FAIL: chain invalid or empty (chained=${chained}, valid=${valid})" >&2
  echo "${integrity}" | jq . >&2 || true
  exit 1
fi
echo "PASS: audit chain valid (events=${chained})"

echo "Test 3: audit export includes integrity block"
export_resp="$(mcp_test_proxy_get "${PROXY_BASE_URL%/}/admin/audit-export?format=json")"
export_valid="$(echo "${export_resp}" | jq -r '.audit.integrity.verification.valid // false')"
if [[ "${export_valid}" != "true" ]]; then
  echo "FAIL: audit export integrity verification not valid" >&2
  exit 1
fi
echo "PASS: audit export integrity embedded"

echo "PHASE C AUDIT INTEGRITY TEST PASSED"
