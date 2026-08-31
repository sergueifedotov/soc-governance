#!/usr/bin/env bash
# Phase C / Sprint 4: apply enterprise governance preset and verify.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

WITH_PROXY_REBUILD=0

usage() {
  cat <<'EOF'
Usage: bash tools/apply_mcp_proxy_phase_c.sh [options]

Applies Sprint 4 governance policy (sprint-4-governance), reloads proxy, runs Phase C tests.

Prerequisites: Profile C running (bash tools/start-profile.sh C).

Options:
  --rebuild-proxy   Rebuild mcp-security-proxy image before apply
  -h, --help        Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rebuild-proxy) WITH_PROXY_REBUILD=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "ERROR: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

echo "== APPLY MCP PROXY PHASE C (Sprint 4) =="

if [[ "${WITH_PROXY_REBUILD}" -eq 1 ]]; then
  echo "Rebuilding mcp-security-proxy..."
  docker compose -f compose.phase4.yml build mcp-security-proxy
  docker compose -f compose.phase4.yml up -d mcp-security-proxy
fi

bash tools/switch_mcp_policy_sample.sh sprint-4-governance

echo "Running Phase C verification..."
bash tools/test_mcp_proxy_phase_c.sh

echo "Phase C deploy complete."
