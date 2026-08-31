#!/usr/bin/env bash
# Roadmap Phase A2: apply tuned runtime/filesystem/provenance policy and verify gates.
# Prerequisites: Phase A1 complete (Profile C, mcp-security-proxy, isolated-executor).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

# shellcheck source=mcp_proxy_test_common.sh
source "${ROOT_DIR}/tools/mcp_proxy_test_common.sh"

PROXY_BASE_URL="${PROXY_BASE_URL:-http://localhost:8090}"
POLICY_FILE="${ROOT_DIR}/config/phase4/mcp_proxy/policy.sample.sprint-3-a2-operational.json"
SKIP_LIVE_TEST=0

usage() {
  cat <<'EOF'
Usage: bash tools/apply_mcp_proxy_phase_a2.sh [options]

Applies sprint-3-a2-operational policy (runtime limits, filesystem, provenance),
runs Sprint 3 sub-gate tests, and confirms live executor routing still works.

Options:
  --skip-live-test   Skip test_isolated_executor_live.sh
  -h, --help         Show help

Prerequisites:
  bash tools/deploy_isolated_executor_a1.sh   # or Profile C + executor up
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-live-test)
      SKIP_LIVE_TEST=1
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

echo "== MCP PROXY PHASE A2 (runtime / filesystem / provenance) =="

if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^mcp-security-proxy$'; then
  echo "FAIL: mcp-security-proxy is not running. Start Profile C first." >&2
  echo "hint: bash tools/start-profile.sh C" >&2
  exit 2
fi

HEALTH_JSON="$(curl -sS --retry 2 --retry-delay 1 "${PROXY_BASE_URL%/}/health" || true)"
if ! echo "${HEALTH_JSON}" | jq -e '.status == "healthy"' >/dev/null 2>&1; then
  echo "FAIL: proxy not healthy at ${PROXY_BASE_URL}" >&2
  exit 2
fi
echo "PASS: proxy is healthy"

if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^isolated-executor$'; then
  echo "WARN: isolated-executor not running; starting sidecar..."
  bash tools/start_isolated_executor.sh --no-build
fi

echo
echo "[policy] Applying sprint-3-a2-operational to disk and proxy"
bash tools/switch_mcp_policy_sample.sh sprint-3-a2

echo
echo "[policy] Verify A2 profiles active"
curl -sS -H "Authorization: Bearer $(tools/mcp_api_key.sh --proxy)" \
  "${PROXY_BASE_URL%/}/admin/policy-config" | jq '{
    isolated_executor_enabled: (.raw_policy.isolated_executor_profile.enabled // false),
    executor_url: (.raw_policy.isolated_executor_profile.executor_url // ""),
    runtime_limits: (.raw_policy.isolated_executor_profile.runtime_limits // {}),
    filesystem_deny_read_count: (.raw_policy.isolated_executor_profile.filesystem_restrictions.deny_read_paths | length),
    upstream_provenance_enabled: (.raw_policy.upstream_provenance_profile.enabled // false),
    upstream_allowed_count: (.raw_policy.upstream_provenance_profile.allowed_destinations | length)
  }'

echo
echo "[keys] Align proxy upstream API key"
bash tools/align_mcp_proxy_upstream_key.sh

echo
echo "[1/4] Runtime limits gate"
bash tools/test_runtime_limits.sh

echo
echo "[2/4] Filesystem restrictions gate"
bash tools/test_filesystem_restrictions.sh

echo
echo "[3/4] Upstream provenance gate"
bash tools/test_upstream_provenance.sh

if [[ "${SKIP_LIVE_TEST}" -eq 0 ]]; then
  echo
  echo "[4/4] Live executor under A2 policy"
  POLICY_FILE="${POLICY_FILE}" bash tools/test_isolated_executor_live.sh
else
  echo
  echo "[4/4] Skipped live executor test (--skip-live-test)"
fi

echo
echo "Phase A2 complete."
echo "  Active policy: config/phase4/mcp_proxy/policy.json (sprint-3-a2-operational)"
echo "  Runbook: docs/MCP_PROXY_PHASE_A2.md"
echo "  Next: Phase A3 staged rollout (monitor -> challenge -> deny) — docs/MCP_PROXY_NEXT_STEPS.md"
echo "  UI: http://localhost:8090/ui → Tuning Studio"
