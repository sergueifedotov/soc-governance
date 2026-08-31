#!/usr/bin/env bash
# Phase A4: keys and deployment hygiene verification (no profile restart).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=mcp_proxy_test_common.sh
source "${ROOT_DIR}/tools/mcp_proxy_test_common.sh"

PROXY_BASE_URL="${PROXY_BASE_URL:-http://localhost:8090}"
SKIP_TOOLS_LIST=0
SKIP_ALIGN=0

usage() {
  cat <<'EOF'
Usage: bash tools/test_mcp_proxy_phase_a4.sh [options]

Verifies Phase A4 hygiene:
  1) Key report (.env, wazuh, proxy upstream + client bearer)
  2) Upstream + client bearer alignment with wazuh-mcp-server
  3) Proxy health
  4) Upstream MCP ping via proxy
  5) tools/list via proxy (discovery path)

Options:
  --proxy-base-url URL   Proxy base URL (default: http://localhost:8090)
  --skip-tools-list      Skip tools/list check
  --skip-align-hint      Do not fail when keys mismatch (report only)
  -h, --help             Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --proxy-base-url)
      PROXY_BASE_URL="$2"
      shift 2
      ;;
    --skip-tools-list)
      SKIP_TOOLS_LIST=1
      shift
      ;;
    --skip-align-hint)
      SKIP_ALIGN=1
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
  command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing command: $1" >&2; exit 2; }
}
require_cmd curl
require_cmd jq
require_cmd docker

echo "== MCP PROXY PHASE A4 (keys and deployment hygiene) =="
echo "proxy_base_url: ${PROXY_BASE_URL%/}"

if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^mcp-security-proxy$'; then
  echo "FAIL: mcp-security-proxy is not running" >&2
  echo "hint: bash tools/start-profile.sh C" >&2
  exit 2
fi

echo
echo "[1/5] Key report"
mcp_test_print_key_report | jq .

if [[ -f "${ROOT_DIR}/.env" ]]; then
  if grep -qE '^[[:space:]]*MCP_API_KEY=' "${ROOT_DIR}/.env" 2>/dev/null; then
    echo "PASS: repo .env defines MCP_API_KEY"
  else
    echo "WARN: .env exists but MCP_API_KEY is not set (set before Profile C start)"
  fi
else
  echo "WARN: ${ROOT_DIR}/.env not found — copy from .env.example and set MCP_API_KEY before Profile C"
fi

echo
echo "[2/5] Container key alignment"
if [[ "${SKIP_ALIGN}" -eq 1 ]]; then
  mcp_test_require_upstream_api_key_alignment || true
else
  mcp_test_require_upstream_api_key_alignment
fi

echo
echo "[3/5] Proxy health"
mcp_test_require_proxy_healthy "${PROXY_BASE_URL}"
echo "PASS: proxy healthy"

echo
echo "[4/5] Upstream MCP ping via proxy"
mcp_test_preflight_upstream_mcp "a4-preflight"

echo
echo "[5/5] Admin API auth (policy-config)"
POLICY_RESP="$(mcp_test_proxy_get "${PROXY_BASE_URL%/}/admin/policy-config")"
if echo "${POLICY_RESP}" | jq -e '.raw_policy // .allowed_methods' >/dev/null 2>&1; then
  echo "PASS: admin policy-config reachable with proxy bearer token"
else
  echo "FAIL: admin policy-config failed" >&2
  echo "${POLICY_RESP}" | jq '.' >&2 || echo "${POLICY_RESP}" >&2
  exit 1
fi

if [[ "${SKIP_TOOLS_LIST}" -eq 0 ]]; then
  echo
  echo "[5b] tools/list via proxy"
  TOOL_COUNT="$(mcp_test_tools_list_names | wc -l | tr -d ' ')"
  if [[ "${TOOL_COUNT}" -ge 1 ]]; then
    echo "PASS: tools/list returned ${TOOL_COUNT} tool(s)"
  else
    echo "FAIL: tools/list returned no tools" >&2
    exit 1
  fi
fi

echo
echo "PHASE A4 KEYS AND HYGIENE TEST PASSED"
