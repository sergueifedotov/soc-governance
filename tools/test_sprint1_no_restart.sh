#!/usr/bin/env bash
# Sprint 1 trust-hardening all-in-one verification (no profile restart).
#
# This script intentionally does NOT stop/start profile C. It assumes
# mcp-security-proxy is already running and reachable.
set -euo pipefail

PROXY_BASE_URL="${PROXY_BASE_URL:-http://localhost:8090}"
RUN_UNIT_TESTS=1

usage() {
  cat <<'EOF'
Usage: bash tools/test_sprint1_no_restart.sh [options]

Runs Sprint 1 trust-hardening verification without restarting profile C:
  1) trusted upstream gate
  2) descriptor drift gate
  3) execution-tool profile gate
  4) (optional) unit tests
  5) telemetry summary

Options:
  --proxy-base-url URL   Proxy base URL (default: http://localhost:8090)
  --skip-unit-tests      Skip pytest step
  -h, --help             Show help

Environment:
  PROXY_BASE_URL
  MCP_PROXY_API_KEY
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --proxy-base-url)
      PROXY_BASE_URL="$2"
      shift 2
      ;;
    --skip-unit-tests)
      RUN_UNIT_TESTS=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: missing command: $1" >&2
    exit 2
  }
}

require_cmd curl
require_cmd jq

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=mcp_proxy_test_common.sh
source "${ROOT_DIR}/tools/mcp_proxy_test_common.sh"

MCP_PROXY_API_KEY="$(mcp_test_resolve_proxy_api_key)"
export PROXY_BASE_URL
export MCP_PROXY_API_KEY

echo "== SPRINT 1 VERIFICATION (NO RESTART) =="
echo "proxy_base_url: ${PROXY_BASE_URL%/}"

SPRINT1_POLICY="${ROOT_DIR}/config/phase4/mcp_proxy/policy.sample.sprint-1-trust-hardening.json"
echo
echo "[preflight] Applying sprint-1 policy baseline (trusted_servers + drift/execution gates)"
if ! mcp_test_apply_policy_sample_file "${SPRINT1_POLICY}"; then
  echo "FAIL: could not apply ${SPRINT1_POLICY}" >&2
  exit 2
fi
echo "PASS: sprint-1 policy active"

echo
echo "[preflight] Upstream API key alignment (proxy -> wazuh-mcp-server)"
mcp_test_require_upstream_api_key_alignment

echo
echo "[preflight] Proxy and upstream MCP (required for descriptor drift tools/list)"
mcp_test_preflight_upstream_mcp "sprint1"

echo
echo "[preflight] Checking proxy health"
HEALTH_JSON="$(curl -sS --retry 2 --retry-delay 1 --retry-all-errors "${PROXY_BASE_URL%/}/health" || true)"
if [[ -z "${HEALTH_JSON}" ]]; then
  echo "FAIL: proxy health endpoint is unreachable: ${PROXY_BASE_URL%/}/health" >&2
  echo "hint: start profile C manually first (example: bash tools/start-profile.sh C)" >&2
  exit 2
fi

if ! echo "${HEALTH_JSON}" | jq -e '.status == "healthy"' >/dev/null 2>&1; then
  echo "FAIL: proxy is not healthy" >&2
  echo "${HEALTH_JSON}" | jq '.' 2>/dev/null || echo "${HEALTH_JSON}" >&2
  exit 2
fi
echo "PASS: proxy is healthy"

echo
echo "[1/5] Trusted upstream gate"
bash tools/test_trusted_servers.sh

echo
echo "[2/5] Descriptor drift gate"
bash tools/test_descriptor_drift.sh

echo
echo "[3/5] Execution-tool profile gate"
bash tools/test_execution_tool_profile.sh

if [[ ${RUN_UNIT_TESTS} -eq 1 ]]; then
  echo
  echo "[4/5] Unit tests"
  .venv/bin/python -m pytest mcp-security-proxy/tests/test_app.py -q
else
  echo
  echo "[4/5] Unit tests skipped (--skip-unit-tests)"
fi

echo
echo "[5/5] Telemetry summary"
curl -sS -H "Authorization: Bearer ${MCP_PROXY_API_KEY}" \
  "${PROXY_BASE_URL%/}/recent-denied?limit=100" \
  | jq '{count, reasons: ([.events[]?.reason] | unique)}'

curl -sS -H "Authorization: Bearer ${MCP_PROXY_API_KEY}" \
  "${PROXY_BASE_URL%/}/recent-discovery-alerts?limit=100" \
  | jq '{count, signals: ([.alerts[]?.signal] | unique)}'

echo
echo "SPRINT 1 VERIFICATION PASSED"