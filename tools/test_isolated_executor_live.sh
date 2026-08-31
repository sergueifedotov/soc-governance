#!/usr/bin/env bash
# Live integration test: requires running isolated-executor + mcp-security-proxy.
#
# Interpreting output (field-by-field): docs/MCP_PROXY_PHASE_A1_DEPLOY.md
#   section "Interpreting isolated executor test results"
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=mcp_proxy_test_common.sh
source "${ROOT_DIR}/tools/mcp_proxy_test_common.sh"

PROXY_BASE_URL="${PROXY_BASE_URL:-http://localhost:8090}"
POLICY_FILE="${POLICY_FILE:-${ROOT_DIR}/config/phase4/mcp_proxy/policy.sample.sprint-3-executor-operational.json}"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing command: $1" >&2; exit 2; }
}

require_cmd curl
require_cmd jq
require_cmd docker

echo "== ISOLATED EXECUTOR LIVE TEST =="

if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^isolated-executor$'; then
  echo "FAIL: isolated-executor container not running" >&2
  echo "hint: bash tools/start_isolated_executor.sh" >&2
  exit 2
fi

mcp_test_require_upstream_api_key_alignment
mcp_test_apply_policy_sample_file "${POLICY_FILE}"

PAYLOAD='{"jsonrpc":"2.0","id":"live-1","method":"tools/call","params":{"name":"shell_exec","arguments":{"cmd":"whoami"}}}'
RESP="$(mcp_test_proxy_post_json "${PROXY_BASE_URL%/}/mcp" "${PAYLOAD}")"

echo "${RESP}" | jq '.'

if echo "${RESP}" | jq -e '.error' >/dev/null 2>&1; then
  echo "FAIL: tools/call returned error" >&2
  exit 1
fi

if ! echo "${RESP}" | jq -e '.runtime_info and .execution_id' >/dev/null 2>&1; then
  echo "FAIL: missing executor evidence in response" >&2
  exit 1
fi

DENIED="$(mcp_test_proxy_get "${PROXY_BASE_URL%/}/recent-denied?limit=10")"
if echo "${DENIED}" | jq -e '[.events[]? | select(.tool == "shell_exec" and (.reason | startswith("isolated_executor")))] | length > 0' >/dev/null; then
  echo "WARN: recent denied contains isolated_executor* for shell_exec (unexpected on success)"
fi

echo "PASS: live isolated executor integration"
