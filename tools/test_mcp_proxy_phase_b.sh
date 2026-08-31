#!/usr/bin/env bash
# Phase B: commercialization verification (presets, metering, audit).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

SKIP_PRESET=0
SKIP_METERING=0
SKIP_AUDIT=0

usage() {
  cat <<'EOF'
Usage: bash tools/test_mcp_proxy_phase_b.sh [options]

Verifies Phase B commercialization:
  1) core-strict preset (execution + exfiltration deny)
  2) metering / entitlements / tier limits
  3) audit export + restart survival

Prerequisites: Profile C, mcp-security-proxy running.

Options:
  --skip-preset    Skip core-strict preset test
  --skip-metering  Skip metering test
  --skip-audit     Skip audit baseline test (includes container restart)
  -h, --help       Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-preset) SKIP_PRESET=1; shift ;;
    --skip-metering) SKIP_METERING=1; shift ;;
    --skip-audit) SKIP_AUDIT=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "ERROR: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

echo "== MCP PROXY PHASE B (commercialization verification) =="

if [[ "${SKIP_PRESET}" -eq 0 ]]; then
  bash tools/test_mcp_proxy_preset_core_strict.sh
fi

if [[ "${SKIP_METERING}" -eq 0 ]]; then
  bash tools/test_mcp_proxy_phase_b_metering.sh
fi

if [[ "${SKIP_AUDIT}" -eq 0 ]]; then
  bash tools/test_mcp_proxy_phase_b_audit.sh
fi

echo "PHASE B COMMERCIALIZATION PASSED"
