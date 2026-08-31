#!/usr/bin/env bash
# Consolidated smoke test for MCP Security Proxy — feature regression (Sprints 1–3,
# tool-intent, LLM risk, discovery, optional live executor). Does NOT run Phase B
# (presets, metering, audit) or full Phase A apply flows (A2–A5).
#
# Full documentation (check catalog, overlap with Phase A/B, CI):
#   docs/MCP_PROXY_SMOKE_TEST.md
#
# Quick start:
#   bash tools/start-profile.sh C
#   bash tools/align_mcp_proxy_upstream_key.sh
#   bash tools/smoke_mcp_proxy.sh --with-isolated-executor
#
# After smoke, also run Phase B when commercial paths changed:
#   bash tools/test_mcp_proxy_phase_b.sh
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

PROXY_BASE_URL="${PROXY_BASE_URL:-http://localhost:8090}"
PHASE4_BASE_URL="${PHASE4_BASE_URL:-http://localhost:8082}"
MCP_URL="${MCP_URL:-http://localhost:3000/mcp}"

RUN_UNIT_TESTS=0
SKIP_SPRINTS=0
OUTPUT_JSON=false
FAIL_FAST=false

ISOLATED_EXECUTOR_MODE="auto"   # auto|on|off
PHASE4_INTEGRATION_MODE="auto"  # auto|on|off — llm_risk + tool-intent sanity
REVERSE_FLOW_MODE="auto"        # auto|on|off — direct upstream MCP tools

TOTAL=0
PASSED=0
FAILED=0
SKIPPED=0

TMPDIR_SMOKE=""

usage() {
  cat <<'EOF'
Usage: bash tools/smoke_mcp_proxy.sh [options]

Runs a consolidated smoke suite for MCP Security Proxy features (Sprints 1–3,
tool-intent, LLM risk, discovery, optional isolated-executor live test).

Options:
  --proxy-base-url URL          Proxy base URL (default: http://localhost:8090)
  --phase4-base-url URL         Phase 4 API for SOC config bridges (default: http://localhost:8082)
  --mcp-url URL                 Upstream Wazuh MCP URL for reverse-flow (default: http://localhost:3000/mcp)
  --skip-sprints                Skip sprint 1/2/3 wrapper scripts (core + intent + discovery only)
  --with-unit-tests             Run pytest mcp-security-proxy/tests/test_app.py at end
  --with-isolated-executor      Require isolated-executor live test
  --no-isolated-executor        Skip isolated-executor live test
  --with-phase4-integration     Require Phase 4-backed tests (llm_risk, tool-intent sanity)
  --no-phase4-integration       Skip Phase 4-backed tests
  --with-reverse-flow           Require upstream MCP reverse-flow test
  --no-reverse-flow             Skip reverse-flow test
  --fail-fast                   Exit on first failed check (default: run all, summarize)
  --json                        Print JSON summary at end
  -h, --help                    Show help

Environment:
  PROXY_BASE_URL, PHASE4_BASE_URL, MCP_URL, MCP_PROXY_API_KEY, MCP_API_KEY

Typical run (stack already up):
  bash tools/start-profile.sh C
  bash tools/align_mcp_proxy_upstream_key.sh
  bash tools/smoke_mcp_proxy.sh

With live executor:
  bash tools/start_isolated_executor.sh
  bash tools/smoke_mcp_proxy.sh --with-isolated-executor

Documentation:
  docs/MCP_PROXY_SMOKE_TEST.md
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --proxy-base-url)
      PROXY_BASE_URL="$2"
      shift 2
      ;;
    --phase4-base-url)
      PHASE4_BASE_URL="$2"
      shift 2
      ;;
    --mcp-url)
      MCP_URL="$2"
      shift 2
      ;;
    --skip-sprints)
      SKIP_SPRINTS=1
      shift
      ;;
    --with-unit-tests)
      RUN_UNIT_TESTS=1
      shift
      ;;
    --with-isolated-executor)
      ISOLATED_EXECUTOR_MODE="on"
      shift
      ;;
    --no-isolated-executor)
      ISOLATED_EXECUTOR_MODE="off"
      shift
      ;;
    --with-phase4-integration)
      PHASE4_INTEGRATION_MODE="on"
      shift
      ;;
    --no-phase4-integration)
      PHASE4_INTEGRATION_MODE="off"
      shift
      ;;
    --with-reverse-flow)
      REVERSE_FLOW_MODE="on"
      shift
      ;;
    --no-reverse-flow)
      REVERSE_FLOW_MODE="off"
      shift
      ;;
    --fail-fast)
      FAIL_FAST=true
      shift
      ;;
    --json)
      OUTPUT_JSON=true
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
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "ERROR: required command not found: ${cmd}" >&2
    exit 2
  fi
}

cleanup() {
  if [[ -n "${TMPDIR_SMOKE}" && -d "${TMPDIR_SMOKE}" ]]; then
    rm -rf "${TMPDIR_SMOKE}"
  fi
}

log_pass() {
  TOTAL=$((TOTAL + 1))
  PASSED=$((PASSED + 1))
  echo "PASS ${1}"
}

log_fail() {
  TOTAL=$((TOTAL + 1))
  FAILED=$((FAILED + 1))
  echo "FAIL ${1}: ${2}"
  if [[ "${FAIL_FAST}" == "true" ]]; then
    echo "ABORT fail-fast enabled"
    exit 1
  fi
}

log_skip() {
  SKIPPED=$((SKIPPED + 1))
  echo "SKIP ${1}: ${2}"
}

record_check() {
  local name="$1"
  local ok="$2"
  local details="$3"
  if [[ "${ok}" == "true" ]]; then
    log_pass "${name}"
  else
    log_fail "${name}" "${details}"
  fi
}

phase4_healthy() {
  local health_file="${1}"
  local code
  code="$(curl -sS -o "${health_file}" -w '%{http_code}' "${PHASE4_BASE_URL%/}/health" 2>/dev/null || echo "000")"
  [[ "${code}" == "200" ]] && jq -e '.status == "healthy"' "${health_file}" >/dev/null 2>&1
}

proxy_healthy() {
  local health_file="${1}"
  local code
  code="$(curl -sS -o "${health_file}" -w '%{http_code}' "${PROXY_BASE_URL%/}/health" 2>/dev/null || echo "000")"
  [[ "${code}" == "200" ]] && jq -e '.status == "healthy"' "${health_file}" >/dev/null 2>&1
}

soc_integration_available() {
  local health_file="${TMPDIR_SMOKE}/soc_integration_health.json"
  if phase4_healthy "${health_file}"; then
    return 0
  fi
  proxy_healthy "${TMPDIR_SMOKE}/proxy_soc_health.json"
}

isolated_executor_running() {
  command -v docker >/dev/null 2>&1 \
    && docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^isolated-executor$'
}

upstream_mcp_reachable() {
  local key
  key="$(bash tools/mcp_api_key.sh 2>/dev/null || echo "${MCP_API_KEY:-}")"
  [[ -n "${key}" ]] || return 1
  local resp
  resp="$(curl -sS -m 5 \
    -H "Authorization: Bearer ${key}" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":"smoke-ping","method":"ping"}' \
    "${MCP_URL}" 2>/dev/null || true)"
  [[ -n "${resp}" ]] && ! echo "${resp}" | jq -e '.error' >/dev/null 2>&1
}

should_run_mode() {
  local mode="$1"      # auto|on|off
  local available="$2" # true|false
  case "${mode}" in
    on) [[ "${available}" == "true" ]] ;;
    off) false ;;
    auto) [[ "${available}" == "true" ]] ;;
    *) false ;;
  esac
}

# Phase 4 may return HTTP 410 for retired /soc/* wrappers; use proxy direct URLs instead.
resolve_soc_config_base() {
  local probe_file="${TMPDIR_SMOKE}/soc_probe.json"
  local code
  code="$(curl -sS -o "${probe_file}" -w '%{http_code}' \
    "${PHASE4_BASE_URL%/}/soc/proxy-llm-risk-config" 2>/dev/null || echo "000")"
  if [[ "${code}" == "200" ]]; then
    printf '%s' "${PHASE4_BASE_URL%/}"
    return 0
  fi
  if [[ "${code}" == "410" || "${code}" == "404" ]]; then
    printf '%s' "${PROXY_BASE_URL%/}"
    return 0
  fi
  printf '%s' "${PHASE4_BASE_URL%/}"
}

wazuh_upstream_api_key() {
  if command -v docker >/dev/null 2>&1 \
    && docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^wazuh-mcp-server$'; then
    docker exec wazuh-mcp-server printenv MCP_API_KEY 2>/dev/null || true
    return 0
  fi
  bash "${ROOT_DIR}/tools/mcp_api_key.sh" 2>/dev/null || true
}

run_bash_script() {
  local name="$1"
  local script_path="$2"
  shift 2

  if [[ ! -f "${script_path}" ]]; then
    record_check "${name}" "false" "missing script: ${script_path}"
    return 0
  fi

  local out_file="${TMPDIR_SMOKE}/${name//[^a-zA-Z0-9._-]/_}.out"
  set +e
  env \
    PROXY_BASE_URL="${PROXY_BASE_URL}" \
    PHASE4_BASE_URL="${PHASE4_BASE_URL}" \
    MCP_URL="${MCP_URL}" \
    MCP_API_KEY="${MCP_API_KEY:-}" \
    MCP_PROXY_API_KEY="${MCP_PROXY_API_KEY:-}" \
    bash "${script_path}" "$@" >"${out_file}" 2>&1
  local rc=$?
  set -e

  local summary
  summary="$(tail -n 5 "${out_file}" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g' | sed 's/^ //;s/ $//')"
  if [[ -z "${summary}" ]]; then
    summary="$(head -n 3 "${out_file}" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')"
  fi

  if [[ "${rc}" -eq 0 ]]; then
    record_check "${name}" "true" "${summary}"
    return 0
  fi

  # Reverse-flow: Neo4j/OpenCTI optional in Profile C — do not fail full smoke when core MCP works.
  if [[ "${name}" == "upstream.reverse_flow" ]] \
    && grep -qiE 'Neo4j unreachable|Connection refused' "${out_file}" 2>/dev/null \
    && grep -q 'PASS:' "${out_file}" 2>/dev/null; then
    log_skip "${name}" "optional Neo4j/OpenCTI dependency unavailable"
    return 0
  fi

  record_check "${name}" "false" "exit=${rc} ${summary}"
}

run_preflight() {
  echo
  echo "== PREFLIGHT =="
  echo "proxy:  ${PROXY_BASE_URL%/}"
  echo "phase4: ${PHASE4_BASE_URL%/}"
  echo "mcp:    ${MCP_URL}"

  local health_file="${TMPDIR_SMOKE}/proxy_health.json"
  if ! proxy_healthy "${health_file}"; then
    record_check "preflight.proxy_reachable" "false" \
      "proxy not healthy at ${PROXY_BASE_URL%/}/health — run: bash tools/start-profile.sh C"
    if [[ "${FAIL_FAST}" == "true" ]]; then
      exit 1
    fi
    return 0
  fi

  record_check "preflight.proxy_reachable" "true" "healthy"

  # shellcheck source=mcp_proxy_test_common.sh
  source "${ROOT_DIR}/tools/mcp_proxy_test_common.sh"
  export PROXY_BASE_URL
  if mcp_test_require_upstream_api_key_alignment; then
    record_check "preflight.upstream_api_key" "true" "aligned"
  else
    record_check "preflight.upstream_api_key" "false" \
      "run: bash tools/align_mcp_proxy_upstream_key.sh"
  fi
}

run_core_checks() {
  echo
  echo "== CORE GATEWAY =="

  local health_file="${TMPDIR_SMOKE}/core_health.json"
  if proxy_healthy "${health_file}"; then
    record_check "core.health" "true" "$(jq -c '{status, upstream}' "${health_file}" 2>/dev/null || echo ok)"
  else
    record_check "core.health" "false" "unhealthy"
  fi

  local metrics_file="${TMPDIR_SMOKE}/metrics.txt"
  local metrics_code
  metrics_code="$(curl -sS -o "${metrics_file}" -w '%{http_code}' "${PROXY_BASE_URL%/}/metrics" 2>/dev/null || echo "000")"
  if [[ "${metrics_code}" == "200" ]] && grep -q 'mcp_security_proxy_' "${metrics_file}" 2>/dev/null; then
    record_check "core.metrics" "true" "Prometheus metrics present"
  else
    record_check "core.metrics" "false" "status=${metrics_code} or missing mcp_proxy metrics"
  fi

  local api_key
  api_key="$(bash tools/mcp_api_key.sh --proxy 2>/dev/null || true)"
  if [[ -z "${api_key}" ]]; then
    record_check "core.mcp_ping" "false" "could not resolve proxy API key"
    return 0
  fi

  local ping_resp
  ping_resp="$(curl -sS -m 10 \
    -H "Authorization: Bearer ${api_key}" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":"smoke-core-ping","method":"ping"}' \
    "${PROXY_BASE_URL%/}/mcp" 2>/dev/null || true)"

  if [[ -n "${ping_resp}" ]] && ! echo "${ping_resp}" | jq -e '.error' >/dev/null 2>&1; then
    record_check "core.mcp_ping" "true" "ping via /mcp"
  else
    local detail
    detail="$(echo "${ping_resp}" | jq -c '.error // .detail // .' 2>/dev/null | head -c 200 || echo empty)"
    record_check "core.mcp_ping" "false" "${detail}"
  fi

  local policy_code
  policy_code="$(curl -sS -o "${TMPDIR_SMOKE}/policy.json" -w '%{http_code}' \
    -H "Authorization: Bearer ${api_key}" \
    "${PROXY_BASE_URL%/}/admin/policy-config" 2>/dev/null || echo "000")"
  if [[ "${policy_code}" == "200" ]] && jq -e '.raw_policy // .policy' "${TMPDIR_SMOKE}/policy.json" >/dev/null 2>&1; then
    record_check "core.admin_policy" "true" "policy-config readable"
  else
    record_check "core.admin_policy" "false" "status=${policy_code}"
  fi
}

apply_discovery_baseline_policy() {
  # shellcheck source=mcp_proxy_test_common.sh
  source "${ROOT_DIR}/tools/mcp_proxy_test_common.sh"
  export PROXY_BASE_URL
  local baseline="${ROOT_DIR}/config/phase4/mcp_proxy/policy.sample.sprint-2-containment-failsafe.json"
  if ! mcp_test_apply_policy_sample_file "${baseline}"; then
    echo "WARN: could not apply discovery baseline policy" >&2
    return 1
  fi
  echo "INFO discovery baseline policy applied (sprint-2 sample)"

  local policy_resp merged body
  policy_resp="$(mcp_test_proxy_get "${PROXY_BASE_URL%/}/admin/policy-config" || true)"
  merged="$(echo "${policy_resp}" | jq -c '
    (.raw_policy // {}) as $p
    | ($p.discovery_rules // []) as $rules
    | if ([$rules[]? | select((.signal // "") == "write_tool_abuse")] | length) >= 1 then $p
      else $p + {
          discovery_rules: (
            $rules + [{
              signal: "write_tool_abuse",
              threshold: "3 events in 5 minutes",
              action_on_trigger: "monitor"
            }]
          )
        }
      end
  ' 2>/dev/null || true)"
  if [[ -n "${merged}" && "${merged}" != "null" ]]; then
    body="$(jq -n --argjson p "${merged}" '{raw_policy: $p}')"
    mcp_test_proxy_post_json "${PROXY_BASE_URL%/}/admin/policy-config" "${body}" >/dev/null || true
    echo "INFO ensured write_tool_abuse discovery rule"
  fi
  return 0
}

run_sprint_suite() {
  if [[ "${SKIP_SPRINTS}" -eq 1 ]]; then
    log_skip "sprints.all" "--skip-sprints"
    return 0
  fi

  echo
  echo "== SPRINT 1 — TRUST HARDENING =="
  run_bash_script "sprint1.trust_hardening" "tools/test_sprint1_no_restart.sh" \
    --proxy-base-url "${PROXY_BASE_URL}" --skip-unit-tests

  echo
  echo "== SPRINT 2 — CONTAINMENT / FAIL-SAFE =="
  run_bash_script "sprint2.containment_failsafe" "tools/test_sprint2_no_restart.sh" \
    --proxy-base-url "${PROXY_BASE_URL}" --skip-unit-tests

  echo
  echo "== SPRINT 3 — ISOLATED EXECUTION (POLICY GATES) =="
  run_bash_script "sprint3.isolated_execution" "tools/test_sprint3_no_restart.sh" \
    --proxy-base-url "${PROXY_BASE_URL}" --skip-unit-tests
}

run_isolated_executor_live() {
  echo
  echo "== PHASE A1 — ISOLATED EXECUTOR LIVE =="

  local available="false"
  if isolated_executor_running; then
    available="true"
  fi

  if ! should_run_mode "${ISOLATED_EXECUTOR_MODE}" "${available}"; then
    if [[ "${ISOLATED_EXECUTOR_MODE}" == "on" ]]; then
      record_check "executor.live_integration" "false" \
        "isolated-executor container not running — bash tools/start_isolated_executor.sh"
    else
      log_skip "executor.live_integration" "container not running (auto)"
    fi
    return 0
  fi

  run_bash_script "executor.live_integration" "tools/test_isolated_executor_live.sh"
}

run_tool_intent_suite() {
  echo
  echo "== TOOL-INTENT VERIFICATION =="

  run_bash_script "tool_intent.verification" "tools/test_tool_intent_verification.sh"

  local soc_ok="false"
  if soc_integration_available; then
    soc_ok="true"
  fi

  if should_run_mode "${PHASE4_INTEGRATION_MODE}" "${soc_ok}"; then
    local soc_base prev_phase4
    soc_base="$(resolve_soc_config_base)"
    prev_phase4="${PHASE4_BASE_URL}"
    PHASE4_BASE_URL="${soc_base}"
    run_bash_script "tool_intent.sanity_mismatch" "tools/sanity_tool_intent_mismatch.sh"
    PHASE4_BASE_URL="${prev_phase4}"
  elif [[ "${PHASE4_INTEGRATION_MODE}" == "on" ]]; then
    record_check "tool_intent.sanity_mismatch" "false" \
      "proxy/Phase 4 SOC integration not available"
  else
    log_skip "tool_intent.sanity_mismatch" "Phase 4 not available (auto)"
  fi

  run_bash_script "tool_intent.misc_mismatch" "tools/test_tool_intent_mismatch_misc.sh"
}

run_llm_risk_suite() {
  echo
  echo "== LLM RISK ENFORCEMENT =="

  local soc_ok="false"
  if soc_integration_available; then
    soc_ok="true"
  fi

  if should_run_mode "${PHASE4_INTEGRATION_MODE}" "${soc_ok}"; then
    local soc_base prev_phase4
    soc_base="$(resolve_soc_config_base)"
    prev_phase4="${PHASE4_BASE_URL}"
    PHASE4_BASE_URL="${soc_base}"
    MCP_PROXY_API_KEY="$(bash "${ROOT_DIR}/tools/mcp_api_key.sh" --proxy 2>/dev/null || true)"
    export MCP_PROXY_API_KEY
    SOC_API_KEY="${MCP_PROXY_API_KEY}"
    run_bash_script "llm_risk.enforcement_smoke" "tools/smoke_llm_risk_enforcement.sh"
    PHASE4_BASE_URL="${prev_phase4}"
  elif [[ "${PHASE4_INTEGRATION_MODE}" == "on" ]]; then
    record_check "llm_risk.enforcement_smoke" "false" \
      "proxy/Phase 4 SOC integration not available"
  else
    log_skip "llm_risk.enforcement_smoke" "Phase 4 not available (auto)"
  fi
}

run_discovery_suite() {
  echo
  echo "== DISCOVERY ALERTS =="

  apply_discovery_baseline_policy || true

  run_bash_script "discovery.attack_pattern_denials" \
    "tools/test_discovery_attack_pattern_denials.sh"

  run_bash_script "discovery.write_tool_abuse" \
    "tools/test_discovery_write_tool_abuse.sh"
}

run_reverse_flow() {
  echo
  echo "== UPSTREAM MCP REVERSE-FLOW =="

  local available="false"
  if upstream_mcp_reachable; then
    available="true"
  fi

  if ! should_run_mode "${REVERSE_FLOW_MODE}" "${available}"; then
    if [[ "${REVERSE_FLOW_MODE}" == "on" ]]; then
      record_check "upstream.reverse_flow" "false" \
        "upstream MCP not reachable at ${MCP_URL}"
    else
      log_skip "upstream.reverse_flow" "upstream MCP not reachable (auto)"
    fi
    return 0
  fi

  local wazuh_key
  wazuh_key="$(wazuh_upstream_api_key)"
  if [[ -z "${wazuh_key}" ]]; then
    record_check "upstream.reverse_flow" "false" "could not resolve wazuh-mcp-server MCP_API_KEY"
    return 0
  fi
  MCP_API_KEY="${wazuh_key}" MCP_KEY="${wazuh_key}" \
    run_bash_script "upstream.reverse_flow" "tools/test_mcp_reverse_flow.sh"
}

run_unit_tests() {
  if [[ "${RUN_UNIT_TESTS}" -ne 1 ]]; then
    return 0
  fi

  echo
  echo "== UNIT TESTS (pytest) =="

  local pytest_bin=""
  for candidate in "${ROOT_DIR}/.venv/bin/python" python3; do
    if [[ "${candidate}" == "python3" ]]; then
      command -v python3 >/dev/null 2>&1 || continue
    elif [[ ! -x "${candidate}" ]]; then
      continue
    fi
    pytest_bin="${candidate}"
    break
  done

  if [[ -z "${pytest_bin}" ]]; then
    record_check "unit.mcp_security_proxy" "false" "no python interpreter found"
    return 0
  fi

  local out_file="${TMPDIR_SMOKE}/pytest.out"
  set +e
  "${pytest_bin}" -m pytest mcp-security-proxy/tests/test_app.py -q >"${out_file}" 2>&1
  local rc=$?
  set -e
  local summary
  summary="$(tail -n 3 "${out_file}" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')"
  if [[ "${rc}" -eq 0 ]]; then
    record_check "unit.mcp_security_proxy" "true" "${summary}"
  else
    record_check "unit.mcp_security_proxy" "false" "exit=${rc} ${summary}"
  fi
}

# --- main ---

require_cmd bash
require_cmd curl
require_cmd jq

TMPDIR_SMOKE="$(mktemp -d "${TMPDIR:-/tmp}/smoke-mcp-proxy.XXXXXX")"
trap cleanup EXIT

echo "== MCP SECURITY PROXY — CONSOLIDATED SMOKE =="

run_preflight

# If proxy is completely down, remaining checks are noise unless we already aborted
if [[ "${FAILED}" -gt 0 ]] && ! proxy_healthy "${TMPDIR_SMOKE}/recheck_health.json"; then
  echo
  echo "SUMMARY total=${TOTAL} passed=${PASSED} failed=${FAILED} skipped=${SKIPPED}"
  echo "hint: bash tools/start-profile.sh C && bash tools/align_mcp_proxy_upstream_key.sh"
  exit 1
fi

run_core_checks
run_discovery_suite
run_tool_intent_suite
run_llm_risk_suite
run_sprint_suite
run_isolated_executor_live
run_reverse_flow
run_unit_tests

echo
echo "SUMMARY total=${TOTAL} passed=${PASSED} failed=${FAILED} skipped=${SKIPPED}"

if [[ "${OUTPUT_JSON}" == "true" ]]; then
  jq -n \
    --argjson total "${TOTAL}" \
    --argjson passed "${PASSED}" \
    --argjson failed "${FAILED}" \
    --argjson skipped "${SKIPPED}" \
    '{total: $total, passed: $passed, failed: $failed, skipped: $skipped}'
fi

if [[ "${FAILED}" -gt 0 ]]; then
  exit 1
fi

exit 0
