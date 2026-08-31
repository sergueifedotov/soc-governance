#!/usr/bin/env bash
# Roadmap Phase A3: staged enforcement rollout (monitor -> challenge -> deny).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

STAGE="all"
SKIP_LIVE=0

usage() {
  cat <<'EOF'
Usage: bash tools/apply_mcp_proxy_phase_a3.sh [monitor|challenge|deny|all] [options]

Applies sprint-3-a3-* policy samples and verifies staged enforcement behavior.
Prerequisites: Phase A1 + A2 (Profile C, isolated-executor).

Stages:
  monitor    — observe violations without executor pre-check deny
  challenge  — return challenge reasons on violations
  deny       — fail-closed; includes live whoami smoke unless --skip-live-test
  all        — run monitor, challenge, deny in sequence (default)

Options:
  --skip-live-test   Skip live executor test on deny stage
  -h, --help         Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-live-test)
      SKIP_LIVE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    monitor|challenge|deny|all)
      STAGE="$1"
      shift
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
require_cmd jq

echo "== MCP PROXY PHASE A3 (staged enforcement) =="
echo "stage: ${STAGE}"

if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^mcp-security-proxy$'; then
  echo "FAIL: mcp-security-proxy is not running. Start Profile C first." >&2
  echo "hint: bash tools/start-profile.sh C" >&2
  exit 2
fi

if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^isolated-executor$'; then
  echo "WARN: isolated-executor not running; starting sidecar..."
  bash tools/start_isolated_executor.sh --no-build
fi

echo
echo "[preflight] Align upstream API key"
bash tools/align_mcp_proxy_upstream_key.sh

export SKIP_LIVE_TEST="${SKIP_LIVE}"
bash tools/test_mcp_proxy_phase_a3.sh "${STAGE}"

echo
echo "Phase A3 complete (stage=${STAGE})."
echo "  Active policy after test: see last stage applied (deny when stage=all)"
echo "  Production policy: bash tools/switch_mcp_policy_sample.sh sprint-3-a3-deny"
echo "  Runbook: docs/MCP_PROXY_PHASE_A3.md"
echo "  Next: Phase A4 / A5 — docs/MCP_PROXY_NEXT_STEPS.md"
