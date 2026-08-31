#!/usr/bin/env bash
# Roadmap Phase A4: align API keys, verify deployment hygiene, optional proxy rebuild.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

REBUILD_PROXY=0
SKIP_ALIGN=0
SKIP_TOOLS_LIST=0
SYNC_ENV_HINT=0

usage() {
  cat <<'EOF'
Usage: bash tools/apply_mcp_proxy_phase_a4.sh [options]

Phase A4 — keys and deployment hygiene:
  - Report .env / container API keys
  - Align MCP_PROXY_UPSTREAM_API_KEY and MCP_PROXY_API_KEY with wazuh-mcp-server
  - Verify health, upstream ping, tools/list

Prerequisites: Profile C (mcp-security-proxy + wazuh-mcp-server running).

Options:
  --rebuild-proxy        Rebuild mcp-security-proxy image before recreate
  --no-align             Skip align step (verify only)
  --skip-tools-list      Skip tools/list in verification
  --print-env-sync       Print export lines to sync repo .env from wazuh (no write)
  -h, --help             Show help

Before first Profile C start, set MCP_API_KEY in repo .env (see .env.example).
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rebuild-proxy)
      REBUILD_PROXY=1
      shift
      ;;
    --no-align)
      SKIP_ALIGN=1
      shift
      ;;
    --skip-tools-list)
      SKIP_TOOLS_LIST=1
      shift
      ;;
    --print-env-sync)
      SYNC_ENV_HINT=1
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
require_cmd bash
require_cmd docker
require_cmd jq
require_cmd curl

echo "== MCP PROXY PHASE A4 (keys and deployment hygiene) =="

if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^wazuh-mcp-server$'; then
  echo "FAIL: wazuh-mcp-server is not running. Start Profile C first." >&2
  echo "hint: bash tools/start-profile.sh C" >&2
  exit 2
fi

if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^mcp-security-proxy$'; then
  echo "FAIL: mcp-security-proxy is not running. Start Profile C first." >&2
  exit 2
fi

WAZUH_KEY="$(docker exec wazuh-mcp-server printenv MCP_API_KEY 2>/dev/null || true)"
if [[ -z "${WAZUH_KEY}" ]]; then
  echo "FAIL: wazuh-mcp-server MCP_API_KEY is empty" >&2
  exit 2
fi

echo
echo "[report] Key summary"
# shellcheck source=mcp_proxy_test_common.sh
source "${ROOT_DIR}/tools/mcp_proxy_test_common.sh"
mcp_test_print_key_report | jq .

if [[ "${SYNC_ENV_HINT}" -eq 1 || ! -f "${ROOT_DIR}/.env" ]] || ! grep -qE '^[[:space:]]*MCP_API_KEY=' "${ROOT_DIR}/.env" 2>/dev/null; then
  echo
  echo "[hint] Sync repo .env before the next Profile C recreate (do not commit secrets):"
  echo "  export MCP_API_KEY='$(printf '%s' "${WAZUH_KEY}" | sed "s/'/'\\\\''/g")'"
  echo "  export MCP_PROXY_API_KEY=\"\${MCP_API_KEY}\""
  echo "  # Add the same lines to ${ROOT_DIR}/.env"
fi

MCP_COMPOSE=(
  -f mcp-security-proxy/docker-compose.yml
  -f mcp-security-proxy/docker-compose.phase4.yml
)

if [[ "${REBUILD_PROXY}" -eq 1 ]]; then
  echo
  echo "[rebuild] mcp-security-proxy image"
  docker compose "${MCP_COMPOSE[@]}" build mcp-security-proxy
fi

if [[ "${SKIP_ALIGN}" -eq 0 ]]; then
  echo
  echo "[align] Recreate proxy with wazuh MCP_API_KEY (upstream + client bearer)"
  bash tools/align_mcp_proxy_upstream_key.sh
else
  echo
  echo "[align] Skipped (--no-align)"
fi

echo
echo "[verify] Phase A4 gates"
if [[ "${SKIP_TOOLS_LIST}" -eq 1 ]]; then
  bash tools/test_mcp_proxy_phase_a4.sh --skip-tools-list
else
  bash tools/test_mcp_proxy_phase_a4.sh
fi

echo
echo "Phase A4 complete."
echo "  Runbook: docs/MCP_PROXY_PHASE_A4.md"
echo "  Next: Phase A5 regression — bash tools/apply_mcp_proxy_phase_a5.sh"
