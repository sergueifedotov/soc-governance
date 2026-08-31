#!/usr/bin/env bash
# Phase A3: verify monitor / challenge / deny enforcement stages (no profile restart).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=mcp_proxy_test_common.sh
source "${ROOT_DIR}/tools/mcp_proxy_test_common.sh"

PROXY_BASE_URL="${PROXY_BASE_URL:-http://localhost:8090}"
STAGE="${1:-all}"
SKIP_LIVE_TEST="${SKIP_LIVE_TEST:-0}"

usage() {
  cat <<'EOF'
Usage: bash tools/test_mcp_proxy_phase_a3.sh [monitor|challenge|deny|all]

Exercises staged enforcement for isolated_executor_profile.action:
  monitor   — violations recorded; tools/call not blocked by executor pre-check
  challenge — violations return *challenge* reasons
  deny      — violations return deny reasons (runtime_limits / filesystem / etc.)

Requires mcp-security-proxy healthy. Does not restart Profile C.
EOF
}

mcp_call_shell_exec() {
  local id="$1"
  local args_json="$2"
  mcp_test_proxy_post_json "${PROXY_BASE_URL%/}/mcp" "$(jq -n \
    --arg id "${id}" \
    --argjson args "${args_json}" \
    '{jsonrpc:"2.0",id:$id,method:"tools/call",params:{name:"shell_exec",arguments:$args}}')"
}

apply_stage_policy() {
  local stage="$1"
  bash "${ROOT_DIR}/tools/switch_mcp_policy_sample.sh" "sprint-3-a3-${stage}"
}

verify_stage() {
  local stage="$1"
  echo
  echo "== A3 stage: ${stage} =="

  apply_stage_policy "${stage}"

  local action
  action="$(mcp_test_proxy_get "${PROXY_BASE_URL%/}/admin/policy-config" \
    | jq -r '.raw_policy.isolated_executor_profile.action // "unknown"')"
  if [[ "${action}" != "${stage}" ]]; then
    echo "FAIL: expected isolated_executor_profile.action=${stage}, got ${action}" >&2
    return 1
  fi
  echo "PASS: isolated_executor_profile.action=${action}"

  local resp reason has_error
  resp="$(mcp_call_shell_exec "a3-${stage}-limits" '{"memory_mb":9999}')"
  has_error="$(echo "${resp}" | jq -r 'if .error then "yes" else "no" end')"
  reason="$(echo "${resp}" | jq -r '.error.data.reason // "none"')"

  case "${stage}" in
    monitor)
      if [[ "${has_error}" == "yes" ]] && [[ "${reason}" == *"runtime_limits"* || "${reason}" == *"filesystem"* ]]; then
        echo "FAIL: monitor stage blocked request (reason=${reason})" >&2
        return 1
      fi
      echo "PASS: monitor stage did not hard-deny limits probe (has_error=${has_error}, reason=${reason})"
      ;;
    challenge)
      if [[ "${has_error}" != "yes" ]] || [[ "${reason}" != *"challenge"* ]]; then
        echo "FAIL: challenge stage expected *challenge* deny (has_error=${has_error}, reason=${reason})" >&2
        return 1
      fi
      echo "PASS: challenge stage triggered (reason=${reason})"
      ;;
    deny)
      if [[ "${has_error}" != "yes" ]] || [[ "${reason}" != *"runtime_limits"* && "${reason}" != *"filesystem"* && "${reason}" != *"isolated_executor"* ]]; then
        echo "FAIL: deny stage expected enforcement deny (has_error=${has_error}, reason=${reason})" >&2
        return 1
      fi
      echo "PASS: deny stage triggered (reason=${reason})"
      ;;
    *)
      echo "FAIL: unknown stage ${stage}" >&2
      return 1
      ;;
  esac

  if [[ "${stage}" == "deny" && "${SKIP_LIVE_TEST}" -eq 0 ]]; then
    echo
    echo "[live] whoami under deny stage (must still route to executor)"
    POLICY_FILE="${ROOT_DIR}/config/phase4/mcp_proxy/policy.sample.sprint-3-a3-deny.json" \
      bash "${ROOT_DIR}/tools/test_isolated_executor_live.sh"
  fi
}

case "${STAGE}" in
  -h|--help)
    usage
    exit 0
    ;;
  monitor|challenge|deny)
    mcp_test_require_proxy_healthy "${PROXY_BASE_URL}"
    verify_stage "${STAGE}"
    ;;
  all)
    mcp_test_require_proxy_healthy "${PROXY_BASE_URL}"
    verify_stage monitor
    verify_stage challenge
    verify_stage deny
    ;;
  *)
    echo "ERROR: unknown stage: ${STAGE}" >&2
    usage >&2
    exit 2
    ;;
esac

echo
echo "PHASE A3 STAGED ENFORCEMENT TEST PASSED (${STAGE})"
