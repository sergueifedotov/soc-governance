#!/usr/bin/env bash
# Sprint 2 containment and fail-safe all-in-one verification (no profile restart).
#
# This script does NOT stop/start profile C. It assumes mcp-security-proxy is
# already running and reachable.
set -euo pipefail

PROXY_BASE_URL="${PROXY_BASE_URL:-http://localhost:8090}"
RUN_UNIT_TESTS=1

usage() {
  cat <<'EOF'
Usage: bash tools/test_sprint2_no_restart.sh [options]

Runs Sprint 2 verification without restarting profile C:
  1) sandbox attestation gate
  2) dependency fail-safe gate
  3) (optional) unit tests
  4) telemetry summary

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

echo "== SPRINT 2 VERIFICATION (NO RESTART) =="
echo "proxy_base_url: ${PROXY_BASE_URL%/}"

SPRINT2_POLICY="${ROOT_DIR}/config/phase4/mcp_proxy/policy.sample.sprint-2-containment-failsafe.json"
echo
echo "[preflight] Applying sprint-2 policy baseline"
if ! mcp_test_apply_policy_sample_file "${SPRINT2_POLICY}"; then
  echo "FAIL: could not apply ${SPRINT2_POLICY}" >&2
  exit 2
fi
echo "PASS: sprint-2 policy active"

echo
echo "[preflight] Upstream API key alignment (proxy -> wazuh-mcp-server)"
mcp_test_require_upstream_api_key_alignment

echo
echo "[preflight] Checking proxy health"
HEALTH_JSON="$(mcp_test_proxy_get "${PROXY_BASE_URL%/}/health" || true)"
if [[ -z "${HEALTH_JSON}" ]] || ! echo "${HEALTH_JSON}" | jq -e '.status == "healthy"' >/dev/null 2>&1; then
  echo "FAIL: proxy is not healthy" >&2
  echo "${HEALTH_JSON}" | jq '.' 2>/dev/null || echo "${HEALTH_JSON}" >&2
  echo "hint: start profile C manually first (example: bash tools/start-profile.sh C)" >&2
  exit 2
fi
echo "PASS: proxy is healthy"

echo
echo "[1/4] Sandbox attestation gate"
bash tools/test_sandbox_attestation.sh

echo
echo "[2/4] Dependency fail-safe gate"
bash tools/test_dependency_fail_safe.sh

if [[ ${RUN_UNIT_TESTS} -eq 1 ]]; then
  echo
  echo "[3/4] Unit tests"
  .venv/bin/python -m pytest mcp-security-proxy/tests/test_app.py -q
else
  echo
  echo "[3/4] Unit tests skipped (--skip-unit-tests)"
fi

echo
echo "[4/4] Telemetry summary"
mcp_test_proxy_get "${PROXY_BASE_URL%/}/recent-denied?limit=100" \
  | jq '{count, reasons: ([.events[]?.reason] | unique)}'

mcp_test_proxy_get "${PROXY_BASE_URL%/}/recent-discovery-alerts?limit=100" \
  | jq '{count, signals: ([.alerts[]?.signal] | unique)}'

echo
echo "SPRINT 2 VERIFICATION PASSED"
