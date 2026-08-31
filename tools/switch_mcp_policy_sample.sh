#!/usr/bin/env bash

# Switches active MCP proxy policy.json to one of the saved sample profiles
# and optionally reloads the running proxy policy via admin endpoint.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POLICY_DIR="${ROOT_DIR}/config/phase4/mcp_proxy"
ACTIVE_POLICY="${POLICY_DIR}/policy.json"

PROXY_BASE_URL="${PROXY_BASE_URL:-http://localhost:8090}"
if [[ -z "${MCP_PROXY_API_KEY:-}" ]]; then
  MCP_PROXY_API_KEY="$("${ROOT_DIR}/tools/mcp_api_key.sh" --proxy)"
fi
DEFAULT_PROFILE="${DEFAULT_PROFILE:-llm-challenge-first-template}"

reload_proxy_policy() {
  local url="${PROXY_BASE_URL%/}/admin/reload-policy"
  local attempt=1
  local max_attempts=5
  local body http_code

  echo "Reloading policy via ${url} ..."
  while [[ ${attempt} -le ${max_attempts} ]]; do
    body="$(curl -sS -X POST "${url}" \
      -H "Authorization: Bearer ${MCP_PROXY_API_KEY}" \
      -w $'\n__HTTP_CODE__:%{http_code}')" || body=""
    http_code="${body##*$'\n'__HTTP_CODE__:}"
    body="${body%$'\n'__HTTP_CODE__:*}"

    if [[ "${http_code}" == "200" ]] && echo "${body}" | jq -e . >/dev/null 2>&1; then
      echo "${body}" | jq .
      return 0
    fi

    if [[ ${attempt} -lt ${max_attempts} ]]; then
      echo "WARN: reload attempt ${attempt}/${max_attempts} failed (http=${http_code:-unknown}); retrying..." >&2
      sleep 2
    else
      echo "ERROR: policy reload failed after ${max_attempts} attempts (http=${http_code:-unknown})" >&2
      if [[ -n "${body}" ]]; then
        echo "Response body:" >&2
        echo "${body}" >&2
      fi
      return 1
    fi
    attempt=$((attempt + 1))
  done
}

print_usage() {
  cat <<'USAGE'
Usage:
  bash tools/switch_mcp_policy_sample.sh [profile] [--dry-run] [--no-reload]
  bash tools/switch_mcp_policy_sample.sh --list

If profile is omitted, default is: llm-challenge-first-template

LLM / rollout profiles:
  llm-challenge-first-template -> policy.template.llm-challenge-first.json
  llm-challenge-first   -> policy.sample.llm-challenge-first.json
  pattern-first-strict  -> policy.sample.pattern-first-strict.json
  balanced-challenge    -> policy.sample.balanced-challenge.json
  observe-only          -> policy.sample.observe-only.json

Sprint trust / containment / execution test baselines:
  sprint-1-trust-hardening   (alias: sprint-1)
    Sprint 1: trusted_servers, descriptor drift, execution_tool_profile
    Use before: tools/test_sprint1_no_restart.sh, test_trusted_servers.sh,
                test_descriptor_drift.sh, test_execution_tool_profile.sh
  sprint-2-containment-failsafe (alias: sprint-2)
    Sprint 1 + sandbox_attestation_profile + dependency_fail_safe_profile
    Use before: tools/test_sprint2_no_restart.sh, test_sandbox_attestation.sh,
                test_dependency_fail_safe.sh
  sprint-3-isolated-execution   (alias: sprint-3)
    Sprint 2 + isolated_executor_profile + upstream_provenance_profile
    Use before: tools/test_sprint3_no_restart.sh, test_isolated_executor.sh,
                test_runtime_limits.sh, test_filesystem_restrictions.sh,
                test_upstream_provenance.sh
  sprint-3-executor-operational (alias: sprint-3-executor)
    Sprint 3 with live isolated-executor sidecar (execution_tool_profile off)
    Use after: bash tools/start_isolated_executor.sh
                bash tools/deploy_isolated_executor_a1.sh
  sprint-3-a2-operational (alias: sprint-3-a2)
    Phase A2: A1 + tighter runtime_limits, filesystem, upstream provenance
    Use: bash tools/apply_mcp_proxy_phase_a2.sh
  sprint-3-a3-monitor (alias: sprint-3-a3-monitor)
    Phase A3 monitor stage (observe, do not deny on executor pre-check)
  sprint-3-a3-challenge (alias: sprint-3-a3-challenge)
    Phase A3 challenge stage
  sprint-3-a3-deny (alias: sprint-3-a3-deny)
    Phase A3 production deny stage
    Use: bash tools/apply_mcp_proxy_phase_a3.sh

Phase B Core MVP presets:
  core-observe
    Trial tier, monitor-only LLM/tool-intent enforce=false
  core-balanced (default Phase B deploy preset)
    Balanced challenge + Sprint 1 trust controls + core tier metering
  core-strict
    Pattern-first strict deny + Sprint 1 trust + execution-tool deny

Phase C Sprint 4 governance:
  sprint-4-governance (alias: sprint-4)
    Enterprise tier + RBAC tokens + policy lifecycle + signed bundles + audit chain
    Use: bash tools/apply_mcp_proxy_phase_c.sh

Options:
  --list      Show available profiles and exit.
  --dry-run   Print planned actions, do not copy/reload.
  --no-reload Copy file but skip POST /admin/reload-policy.
  -h, --help  Show this help.

Environment:
  PROXY_BASE_URL   Default: http://localhost:8090
  MCP_PROXY_API_KEY Default: from tools/mcp_api_key.sh --proxy
USAGE
}

list_profiles() {
  cat <<'LIST'
Available profiles:

LLM / rollout:
  llm-challenge-first-template
  llm-challenge-first
  pattern-first-strict
  balanced-challenge
  observe-only

Sprint test baselines:
  sprint-1-trust-hardening   (alias: sprint-1)
  sprint-2-containment-failsafe (alias: sprint-2)
  sprint-3-isolated-execution   (alias: sprint-3)
  sprint-3-executor-operational (alias: sprint-3-executor)
  sprint-3-a2-operational (alias: sprint-3-a2)
  sprint-3-a3-monitor
  sprint-3-a3-challenge
  sprint-3-a3-deny

Phase B Core MVP:
  core-observe
  core-balanced
  core-strict

Phase C Sprint 4:
  sprint-4-governance (alias: sprint-4)
LIST
}

resolve_sample_file() {
  local profile="$1"
  case "${profile}" in
    llm-challenge-first-template)
      echo "${POLICY_DIR}/policy.template.llm-challenge-first.json"
      ;;
    llm-challenge-first)
      echo "${POLICY_DIR}/policy.sample.llm-challenge-first.json"
      ;;
    pattern-first-strict)
      echo "${POLICY_DIR}/policy.sample.pattern-first-strict.json"
      ;;
    balanced-challenge)
      echo "${POLICY_DIR}/policy.sample.balanced-challenge.json"
      ;;
    observe-only)
      echo "${POLICY_DIR}/policy.sample.observe-only.json"
      ;;
    sprint-1|sprint-1-trust-hardening)
      echo "${POLICY_DIR}/policy.sample.sprint-1-trust-hardening.json"
      ;;
    sprint-2|sprint-2-containment-failsafe)
      echo "${POLICY_DIR}/policy.sample.sprint-2-containment-failsafe.json"
      ;;
    sprint-3|sprint-3-isolated-execution)
      echo "${POLICY_DIR}/policy.sample.sprint-3-isolated-execution.json"
      ;;
    sprint-3-executor|sprint-3-executor-operational)
      echo "${POLICY_DIR}/policy.sample.sprint-3-executor-operational.json"
      ;;
    sprint-3-a2|sprint-3-a2-operational)
      echo "${POLICY_DIR}/policy.sample.sprint-3-a2-operational.json"
      ;;
    sprint-3-a3-monitor)
      echo "${POLICY_DIR}/policy.sample.sprint-3-a3-monitor.json"
      ;;
    sprint-3-a3-challenge)
      echo "${POLICY_DIR}/policy.sample.sprint-3-a3-challenge.json"
      ;;
    sprint-3-a3-deny)
      echo "${POLICY_DIR}/policy.sample.sprint-3-a3-deny.json"
      ;;
    core-observe)
      echo "${POLICY_DIR}/policy.sample.core-observe.json"
      ;;
    core-balanced|core-mvp)
      echo "${POLICY_DIR}/policy.sample.core-balanced.json"
      ;;
    core-strict)
      echo "${POLICY_DIR}/policy.sample.core-strict.json"
      ;;
    sprint-4|sprint-4-governance)
      echo "${POLICY_DIR}/policy.sample.sprint-4-governance.json"
      ;;
    *)
      return 1
      ;;
  esac
}

main() {
  local profile=""
  local dry_run=0
  local no_reload=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --list)
        list_profiles
        exit 0
        ;;
      --dry-run)
        dry_run=1
        shift
        ;;
      --no-reload)
        no_reload=1
        shift
        ;;
      -h|--help)
        print_usage
        exit 0
        ;;
      -* )
        echo "ERROR: Unknown option: $1" >&2
        print_usage
        exit 1
        ;;
      *)
        if [[ -n "${profile}" ]]; then
          echo "ERROR: Multiple profiles provided: '${profile}' and '$1'" >&2
          print_usage
          exit 1
        fi
        profile="$1"
        shift
        ;;
    esac
  done

  if [[ -z "${profile}" ]]; then
    profile="${DEFAULT_PROFILE}"
  fi

  local sample_file
  if ! sample_file="$(resolve_sample_file "${profile}")"; then
    echo "ERROR: Unknown profile '${profile}'" >&2
    list_profiles
    exit 1
  fi

  if [[ ! -f "${sample_file}" ]]; then
    echo "ERROR: Sample file not found: ${sample_file}" >&2
    exit 1
  fi

  if ! jq . "${sample_file}" >/dev/null 2>&1; then
    echo "ERROR: Sample JSON is invalid: ${sample_file}" >&2
    exit 1
  fi

  echo "Profile      : ${profile}"
  echo "Sample file  : ${sample_file}"
  echo "Target file  : ${ACTIVE_POLICY}"

  if [[ ${dry_run} -eq 1 ]]; then
    echo "DRY RUN: would copy sample to active policy and reload=${no_reload}"
    exit 0
  fi

  cp "${sample_file}" "${ACTIVE_POLICY}"
  echo "Copied sample to active policy."

  if [[ ${no_reload} -eq 1 ]]; then
    echo "Skipped proxy reload (--no-reload)."
    exit 0
  fi

  reload_proxy_policy
}

main "$@"
