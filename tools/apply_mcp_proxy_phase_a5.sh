#!/usr/bin/env bash
# Roadmap Phase A5: full post-operational regression after Phases A1–A4.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

MODE="fast"
WITH_SMOKE=0
SMOKE_ONLY=0
SKIP_A4=0
SKIP_LIVE=0
ALIGN_KEYS=0

usage() {
  cat <<'EOF'
Usage: bash tools/apply_mcp_proxy_phase_a5.sh [options]

Runs Phase A5 regression after operational rollout (A1–A4):
  - Sprint 1, 2, 3 E2E (no profile restart)
  - Optional live executor + smoke
  - Restores sprint-3-a3-deny policy when done

Prerequisites: Profile C, Phases A1–A4 complete.

Options:
  --full                 Include unit tests in each sprint script
  --with-unit-tests      Also run pytest mcp-security-proxy/tests/test_app.py
  --with-smoke           Also run tools/smoke_mcp_proxy.sh
  --smoke-only           Run consolidated smoke only (skip sprint wrappers)
  --skip-a4-preflight    Skip embedded A4 key check
  --skip-live-executor   Skip live executor test
  --align-keys-first     Run tools/align_mcp_proxy_upstream_key.sh before tests
  -h, --help             Show help

Default (fast):
  bash tools/test_mcp_proxy_phase_a5.sh   # sprints with --skip-unit-tests

Full regression:
  bash tools/apply_mcp_proxy_phase_a5.sh --full --with-unit-tests --with-smoke
EOF
}

A5_FULL=0
A5_WITH_UNIT=0
A5_WITH_SMOKE=0
A5_SMOKE_ONLY=0
A5_SKIP_A4=0
A5_SKIP_LIVE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --full)
      MODE="full"
      A5_FULL=1
      shift
      ;;
    --with-unit-tests)
      A5_WITH_UNIT=1
      shift
      ;;
    --with-smoke)
      WITH_SMOKE=1
      A5_WITH_SMOKE=1
      shift
      ;;
    --smoke-only)
      SMOKE_ONLY=1
      A5_SMOKE_ONLY=1
      shift
      ;;
    --skip-a4-preflight)
      SKIP_A4=1
      A5_SKIP_A4=1
      shift
      ;;
    --skip-live-executor)
      SKIP_LIVE=1
      A5_SKIP_LIVE=1
      shift
      ;;
    --align-keys-first)
      ALIGN_KEYS=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
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

echo "== MCP PROXY PHASE A5 (apply regression validation) =="
echo "mode: ${MODE}"

if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^mcp-security-proxy$'; then
  echo "FAIL: mcp-security-proxy is not running. Start Profile C first." >&2
  exit 2
fi

if [[ "${ALIGN_KEYS}" -eq 1 ]]; then
  echo
  echo "[preflight] Align API keys (Phase A4)"
  bash tools/align_mcp_proxy_upstream_key.sh
fi

echo
echo "[run] Phase A5 test suite"
A5_CMD=(bash tools/test_mcp_proxy_phase_a5.sh)
[[ "${A5_FULL}" -eq 1 ]] && A5_CMD+=(--full)
[[ "${A5_WITH_UNIT}" -eq 1 ]] && A5_CMD+=(--with-unit-tests)
[[ "${A5_WITH_SMOKE}" -eq 1 ]] && A5_CMD+=(--with-smoke)
[[ "${A5_SMOKE_ONLY}" -eq 1 ]] && A5_CMD+=(--smoke-only)
[[ "${A5_SKIP_A4}" -eq 1 ]] && A5_CMD+=(--skip-a4-preflight)
[[ "${A5_SKIP_LIVE}" -eq 1 ]] && A5_CMD+=(--skip-live-executor)
"${A5_CMD[@]}"

echo
echo "Phase A5 complete."
echo "  Runbook: docs/MCP_PROXY_PHASE_A5.md"
echo "  Operational policy restored: sprint-3-a3-deny (unless --no-restore-policy on test script)"
