#!/usr/bin/env bash
# Phase B: audit export API and runtime history survival across proxy restart.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=mcp_proxy_test_common.sh
source "${ROOT_DIR}/tools/mcp_proxy_test_common.sh"

PROXY_BASE_URL="${PROXY_BASE_URL:-http://localhost:8090}"
PROXY_MCP_URL="${PROXY_BASE_URL%/}/mcp"
CONTAINER_NAME="${MCP_PROXY_CONTAINER:-mcp-security-proxy}"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing command: $1" >&2; exit 2; }
}
require_cmd curl
require_cmd jq
require_cmd docker

echo "== PHASE B AUDIT BASELINE TEST =="
mcp_test_require_proxy_healthy "${PROXY_BASE_URL}"

if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${CONTAINER_NAME}$"; then
  echo "FAIL: ${CONTAINER_NAME} is not running (required for restart survival test)" >&2
  exit 2
fi

echo "Test 1: generate denied event"
deny_payload="$(jq -n '{
  jsonrpc: "2.0",
  id: "audit-deny-test",
  method: "tools/call",
  params: { name: "wazuh_block_ip", arguments: { ip: "203.0.113.1" } }
}')"
deny_resp="$(mcp_test_proxy_post_json "${PROXY_MCP_URL}" "${deny_payload}")"
deny_reason="$(echo "${deny_resp}" | jq -r '.error.data.reason // empty')"
if [[ "${deny_reason}" != "tool_denied" ]]; then
  echo "FAIL: expected tool_denied, got: ${deny_reason}" >&2
  exit 1
fi
echo "PASS: denied event generated (${deny_reason})"

echo "Test 2: audit export API"
export_resp="$(mcp_test_proxy_get "${PROXY_BASE_URL%/}/admin/audit-export?format=json")"
denied_count="$(echo "${export_resp}" | jq -r '.audit.counts.denied_events // 0')"
if [[ "${denied_count}" -lt 1 ]]; then
  echo "FAIL: audit export shows no denied events" >&2
  exit 1
fi
ndjson_resp="$(mcp_test_proxy_get "${PROXY_BASE_URL%/}/admin/audit-export?format=ndjson")"
if [[ -z "${ndjson_resp}" ]]; then
  echo "FAIL: ndjson audit export empty" >&2
  exit 1
fi
echo "PASS: audit export json + ndjson (denied_events=${denied_count})"

history_before="$(mcp_test_proxy_get "${PROXY_BASE_URL%/}/admin/runtime-history")"
file_exists_before="$(echo "${history_before}" | jq -r '.history_file_exists')"
if [[ "${file_exists_before}" != "true" ]]; then
  echo "FAIL: runtime history file not persisted before restart" >&2
  exit 1
fi

echo "Test 3: restart proxy and verify history restored"
docker restart "${CONTAINER_NAME}" >/dev/null
for _ in $(seq 1 30); do
  if mcp_test_proxy_get "${PROXY_BASE_URL%/}/health" 2>/dev/null | jq -e '.status == "healthy"' >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
mcp_test_require_proxy_healthy "${PROXY_BASE_URL}"

export_after="$(mcp_test_proxy_get "${PROXY_BASE_URL%/}/admin/audit-export?format=json")"
denied_after="$(echo "${export_after}" | jq -r '.audit.counts.denied_events // 0')"
if [[ "${denied_after}" -lt 1 ]]; then
  echo "FAIL: denied events not restored after restart (count=${denied_after})" >&2
  exit 1
fi
echo "PASS: audit history survived restart (denied_events=${denied_after})"

echo "PHASE B AUDIT BASELINE TEST PASSED"
