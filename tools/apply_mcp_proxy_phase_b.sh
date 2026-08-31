#!/usr/bin/env bash
# Roadmap Phase B: Phase 1 commercialization (MVP deploy + verify).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

WITH_EXECUTOR=0
SKIP_START=0
SKIP_ALIGN=0
SKIP_VERIFY=0
PRESET="${MCP_PROXY_B_PRESET:-core-balanced}"

usage() {
  cat <<'EOF'
Usage: bash tools/apply_mcp_proxy_phase_b.sh [options]

Phase B — Phase 1 commercialization (MVP):
  - Start Profile C (unless --skip-start)
  - Align API keys
  - Apply Core MVP preset (default: core-balanced)
  - Optional isolated executor
  - Run Phase B verification

Prerequisites: Docker, jq, curl. Set MCP_API_KEY in repo .env before first Profile C start.

Options:
  --with-executor      Deploy isolated executor after proxy is up
  --preset NAME        Policy preset (core-balanced, core-strict, core-observe)
  --skip-start         Skip bash tools/start-profile.sh C
  --skip-align         Skip key alignment
  --skip-verify        Skip Phase B test suite
  -h, --help           Show help

Default:
  bash tools/apply_mcp_proxy_phase_b.sh
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-executor) WITH_EXECUTOR=1; shift ;;
    --preset)
      PRESET="$2"
      shift 2
      ;;
    --skip-start) SKIP_START=1; shift ;;
    --skip-align) SKIP_ALIGN=1; shift ;;
    --skip-verify) SKIP_VERIFY=1; shift ;;
    -h|--help) usage; exit 0 ;;
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

echo "== MCP PROXY PHASE B (Phase 1 commercialization) =="
echo "preset: ${PRESET}"

if [[ "${SKIP_START}" -eq 0 ]]; then
  echo
  echo "[start] Profile C"
  bash tools/start-profile.sh C
else
  echo
  echo "[start] Skipped (--skip-start)"
fi

if [[ "${SKIP_ALIGN}" -eq 0 ]]; then
  echo
  echo "[align] API keys"
  bash tools/align_mcp_proxy_upstream_key.sh
else
  echo
  echo "[align] Skipped (--skip-align)"
fi

echo
echo "[preset] Applying ${PRESET}"
export MCP_PROXY_API_KEY="$(bash tools/mcp_api_key.sh --proxy)"
bash tools/switch_mcp_policy_sample.sh "${PRESET}"

if [[ "${WITH_EXECUTOR}" -eq 1 ]]; then
  echo
  echo "[executor] Deploy isolated executor (optional)"
  bash tools/deploy_isolated_executor_a1.sh || {
    echo "WARN: executor deploy failed; continuing without live executor" >&2
  }
fi

# shellcheck source=mcp_proxy_test_common.sh
source "${ROOT_DIR}/tools/mcp_proxy_test_common.sh"
mcp_test_require_proxy_healthy
mcp_test_ensure_trusted_upstream_policy

echo
echo "[health] Proxy ready"
curl -sS -H "$(mcp_test_proxy_auth_header)" "${PROXY_BASE_URL:-http://localhost:8090}/admin/entitlements" | jq '{
  tier: .entitlements.tier,
  features: .entitlements.features
}'

if [[ "${SKIP_VERIFY}" -eq 0 ]]; then
  echo
  echo "[verify] Phase B gates"
  bash tools/test_mcp_proxy_phase_b.sh
else
  echo
  echo "[verify] Skipped (--skip-verify)"
fi

echo
echo "Phase B deploy complete."
echo "  Runbook: docs/MCP_PROXY_PHASE_B.md"
echo "  UI: http://localhost:8090/ui"
echo "  Presets: docs/MCP_PROXY_PRESETS.md"
