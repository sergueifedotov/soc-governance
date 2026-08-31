#!/usr/bin/env bash
# Phase A5: post-operational regression (Sprints 1–3, optional smoke, live executor).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

# shellcheck source=mcp_proxy_test_common.sh
source "${ROOT_DIR}/tools/mcp_proxy_test_common.sh"

PROXY_BASE_URL="${PROXY_BASE_URL:-http://localhost:8090}"
SKIP_A4=0
SKIP_UNIT_TESTS=1
WITH_UNIT_TESTS=0
WITH_SMOKE=0
SMOKE_ONLY=0
WITH_LIVE_EXECUTOR=1
RESTORE_POLICY="sprint-3-a3-deny"

usage() {
  cat <<'EOF'
Usage: bash tools/test_mcp_proxy_phase_a5.sh [options]

Phase A5 regression (no Profile C restart):
  1) Optional A4 key/hygiene preflight
  2) Sprint 1, 2, 3 E2E wrappers (default: --skip-unit-tests each)
  3) Optional pytest suite
  4) Optional isolated-executor live test
  5) Optional consolidated smoke
  6) Restore operational policy (default: sprint-3-a3-deny)

Options:
  --proxy-base-url URL     Proxy base URL
  --skip-a4-preflight      Skip Phase A4 key checks
  --full                   Run unit tests inside each sprint script
  --with-unit-tests        Run pytest once after sprints (in addition to --full)
  --with-smoke             Also run tools/smoke_mcp_proxy.sh --with-isolated-executor
  --smoke-only             Skip sprint wrappers; run smoke only
  --skip-live-executor     Skip test_isolated_executor_live.sh
  --no-restore-policy      Do not switch policy sample at end
  --restore-policy NAME    Policy alias to restore (default: sprint-3-a3-deny)
  -h, --help               Show help

Prerequisites: Profile C up (mcp-security-proxy, wazuh-mcp-server).
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --proxy-base-url)
      PROXY_BASE_URL="$2"
      shift 2
      ;;
    --skip-a4-preflight)
      SKIP_A4=1
      shift
      ;;
    --full)
      SKIP_UNIT_TESTS=0
      shift
      ;;
    --with-unit-tests)
      WITH_UNIT_TESTS=1
      shift
      ;;
    --with-smoke)
      WITH_SMOKE=1
      shift
      ;;
    --smoke-only)
      SMOKE_ONLY=1
      shift
      ;;
    --skip-live-executor)
      WITH_LIVE_EXECUTOR=0
      shift
      ;;
    --no-restore-policy)
      RESTORE_POLICY=""
      shift
      ;;
    --restore-policy)
      RESTORE_POLICY="$2"
      shift 2
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
require_cmd curl
require_cmd jq

export PROXY_BASE_URL

echo "== MCP PROXY PHASE A5 (regression validation) =="
echo "proxy_base_url: ${PROXY_BASE_URL%/}"

if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^mcp-security-proxy$'; then
  echo "FAIL: mcp-security-proxy is not running" >&2
  echo "hint: bash tools/start-profile.sh C" >&2
  exit 2
fi

mcp_test_require_proxy_healthy "${PROXY_BASE_URL}"

if [[ "${SKIP_A4}" -eq 0 ]]; then
  echo
  echo "[preflight] Phase A4 key alignment"
  bash tools/test_mcp_proxy_phase_a4.sh
fi

run_sprint() {
  local n="$1"
  local script="${ROOT_DIR}/tools/test_sprint${n}_no_restart.sh"
  local extra=()
  echo
  echo "========================================"
  if [[ "${SKIP_UNIT_TESTS}" -eq 1 ]]; then
    bash "${script}" --skip-unit-tests
  else
    bash "${script}"
  fi
}

if [[ "${SMOKE_ONLY}" -eq 0 ]]; then
  run_sprint 1
  run_sprint 2
  run_sprint 3
else
  echo
  echo "[skip] Sprint 1–3 wrappers (--smoke-only)"
fi

if [[ "${WITH_UNIT_TESTS}" -eq 1 ]]; then
  echo
  echo "========================================"
  echo "[pytest] mcp-security-proxy unit tests"
  if [[ -x "${ROOT_DIR}/.venv/bin/python" ]]; then
    "${ROOT_DIR}/.venv/bin/python" -m pytest mcp-security-proxy/tests/test_app.py -q
  else
    python3 -m pytest mcp-security-proxy/tests/test_app.py -q
  fi
fi

if [[ "${WITH_LIVE_EXECUTOR}" -eq 1 ]]; then
  if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^isolated-executor$'; then
    echo
    echo "========================================"
    echo "[live] isolated executor under operational deny policy"
    POLICY_FILE="${ROOT_DIR}/config/phase4/mcp_proxy/policy.sample.sprint-3-a3-deny.json" \
      bash "${ROOT_DIR}/tools/test_isolated_executor_live.sh"
  else
    echo
    echo "WARN: isolated-executor not running — skip live test (bash tools/start_isolated_executor.sh)"
  fi
fi

if [[ "${WITH_SMOKE}" -eq 1 || "${SMOKE_ONLY}" -eq 1 ]]; then
  echo
  echo "========================================"
  echo "[smoke] consolidated MCP proxy smoke"
  if [[ "${SMOKE_ONLY}" -eq 1 ]]; then
    bash "${ROOT_DIR}/tools/smoke_mcp_proxy.sh" --with-isolated-executor --skip-sprints
  else
    bash "${ROOT_DIR}/tools/smoke_mcp_proxy.sh" --with-isolated-executor
  fi
fi

if [[ -n "${RESTORE_POLICY}" ]]; then
  echo
  echo "[restore] Operational policy: ${RESTORE_POLICY}"
  bash tools/switch_mcp_policy_sample.sh "${RESTORE_POLICY}"
fi

echo
echo "========================================"
echo "Telemetry snapshot (proxy)"
curl -sS -H "Authorization: Bearer $(tools/mcp_api_key.sh --proxy)" \
  "${PROXY_BASE_URL%/}/recent-denied?limit=15" 2>/dev/null \
  | jq '{count, recent_reasons: [.events[0:5][]?.reason]}' 2>/dev/null || echo '{"note":"recent-denied unavailable"}'

echo
echo "PHASE A5 REGRESSION VALIDATION PASSED"
echo "  Review: http://localhost:8090/ui → Tuning Studio → Evidence and Decisions"
