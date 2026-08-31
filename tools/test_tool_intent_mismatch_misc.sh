#!/usr/bin/env bash

# Generates miscellaneous tool-intent mismatch cases for SOC Report Step 2.
# Focus: missing/invalid intent metadata and contradictory intent/tool pairings.
set -euo pipefail

PHASE4_BASE_URL="${PHASE4_BASE_URL:-http://localhost:8082}"
PROXY_BASE_URL="${PROXY_BASE_URL:-http://localhost:8090}"
PROXY_MCP_URL="${PROXY_BASE_URL%/}/mcp"
PROXY_API_KEY="$(tools/mcp_api_key.sh --proxy)"

ENFORCE_MODE="${ENFORCE_MODE:-1}"
RESTORE_ON_EXIT="${RESTORE_ON_EXIT:-1}"

MONITOR_SCORE="${MONITOR_SCORE:-0.30}"
CHALLENGE_SCORE="${CHALLENGE_SCORE:-0.45}"
DENY_SCORE="${DENY_SCORE:-0.60}"

ORIG_ENABLED=""
ORIG_ENFORCE=""
ORIG_REQUIRE_METADATA=""
ORIG_MONITOR=""
ORIG_CHALLENGE=""
ORIG_DENY=""

ORIG_FAILSAFE_ENABLED=""
ORIG_FAILSAFE_REQUIRED_CONTROLS=""

require_cmd() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "ERROR: required command not found: ${cmd}" >&2
    exit 2
  fi
}

phase4_get() {
  local path="$1"
  curl -sS "${PHASE4_BASE_URL%/}${path}"
}

phase4_post() {
  local path="$1"
  local payload="$2"
  curl -sS -H "Content-Type: application/json" -X POST -d "${payload}" "${PHASE4_BASE_URL%/}${path}"
}

proxy_post() {
  local payload="$1"
  curl -sS \
    -H "Authorization: Bearer ${PROXY_API_KEY}" \
    -H "Content-Type: application/json" \
    -X POST \
    -d "${payload}" \
    "${PROXY_MCP_URL}"
}

proxy_recent_denied() {
  curl -sS -H "Authorization: Bearer ${PROXY_API_KEY}" "${PROXY_BASE_URL%/}/recent-denied?limit=40"
}

proxy_get_soc() {
  local path="$1"
  curl -sS -H "Authorization: Bearer ${PROXY_API_KEY}" "${PROXY_BASE_URL%/}${path}"
}

proxy_post_soc() {
  local path="$1"
  local payload="$2"
  curl -sS \
    -H "Authorization: Bearer ${PROXY_API_KEY}" \
    -H "Content-Type: application/json" \
    -X POST \
    -d "${payload}" \
    "${PROXY_BASE_URL%/}${path}"
}

snapshot_current_cfg() {
  local current
  current="$(proxy_get_soc "/soc/proxy-tool-intent-config")"
  ORIG_ENABLED="$(echo "${current}" | jq -r '.tool_intent.enabled // false')"
  ORIG_ENFORCE="$(echo "${current}" | jq -r '.tool_intent.enforce // false')"
  ORIG_REQUIRE_METADATA="$(echo "${current}" | jq -r '.tool_intent.require_intent_metadata // false')"
  ORIG_MONITOR="$(echo "${current}" | jq -r '.tool_intent.min_monitor_score // 0.30')"
  ORIG_CHALLENGE="$(echo "${current}" | jq -r '.tool_intent.min_challenge_score // 0.45')"
  ORIG_DENY="$(echo "${current}" | jq -r '.tool_intent.min_deny_score // 0.60')"

  local policy
  policy="$(proxy_get_soc "/soc/proxy-policy-config")"
  ORIG_FAILSAFE_ENABLED="$(echo "${policy}" | jq -r '.raw_policy.dependency_fail_safe_profile.enabled // true')"
  ORIG_FAILSAFE_REQUIRED_CONTROLS="$(echo "${policy}" | jq -r '.raw_policy.dependency_fail_safe_profile.required_controls // ["llm_risk","tool_intent"] | @json')"
}

restore_cfg() {
  if [[ "${RESTORE_ON_EXIT}" != "1" ]]; then
    return
  fi
  if [[ -z "${ORIG_ENABLED}" ]]; then
    return
  fi

  # Restore dependency fail-safe config first (merge into current policy)
  if [[ -n "${ORIG_FAILSAFE_ENABLED}" ]]; then
    local full_policy
    full_policy="$(proxy_get_soc "/soc/proxy-policy-config")"
    local restored_policy
    restored_policy="$(echo "${full_policy}" | jq --arg enabled "${ORIG_FAILSAFE_ENABLED}" --argjson controls "${ORIG_FAILSAFE_REQUIRED_CONTROLS}" '.raw_policy | .dependency_fail_safe_profile.enabled = ($enabled == "true") | .dependency_fail_safe_profile.required_controls = $controls')"
    proxy_post_soc "/soc/proxy-policy-config" "{\"policy\":${restored_policy}}" >/dev/null || true
  fi

  # Restore tool-intent config
  proxy_post_soc "/soc/proxy-tool-intent-config" "{\"tool_intent\":{\"enabled\":${ORIG_ENABLED},\"enforce\":${ORIG_ENFORCE},\"require_intent_metadata\":${ORIG_REQUIRE_METADATA},\"min_monitor_score\":${ORIG_MONITOR},\"min_challenge_score\":${ORIG_CHALLENGE},\"min_deny_score\":${ORIG_DENY}}}" >/dev/null || true
}

set_mismatch_mode() {
  local enforce_json
  if [[ "${ENFORCE_MODE}" == "1" ]]; then
    enforce_json="true"
  else
    enforce_json="false"
  fi
  proxy_post_soc "/soc/proxy-tool-intent-config" "{\"tool_intent\":{\"enabled\":true,\"enforce\":${enforce_json},\"require_intent_metadata\":true,\"min_monitor_score\":${MONITOR_SCORE},\"min_challenge_score\":${CHALLENGE_SCORE},\"min_deny_score\":${DENY_SCORE}}}" \
    | jq -c '{status, tool_intent: {enabled: .tool_intent.enabled, enforce: .tool_intent.enforce, require_intent_metadata: .tool_intent.require_intent_metadata, min_monitor_score: .tool_intent.min_monitor_score, min_challenge_score: .tool_intent.min_challenge_score, min_deny_score: .tool_intent.min_deny_score}}'
}

disable_fail_safe() {
  # Disable dependency fail-safe to allow testing without LLM provider being available
  # Need to fetch full policy first since /soc/proxy-policy-config replaces entire policy
  local full_policy
  full_policy="$(proxy_get_soc "/soc/proxy-policy-config")"
  # Merge the fail-safe change into the existing policy
  local merged_policy
  merged_policy="$(echo "${full_policy}" | jq '.raw_policy | .dependency_fail_safe_profile.enabled = false')"
  proxy_post_soc "/soc/proxy-policy-config" "{\"policy\":${merged_policy}}" >/dev/null || true
}

print_case_result() {
  local label="$1"
  local payload="$2"
  local resp
  resp="$(proxy_post "${payload}")"

  echo ""
  echo "== ${label} =="
  echo "${resp}" | jq -c '{id, has_error: (.error != null), reason: (.error.data.reason // null), decision_hint: (.error.data.decision_hint // null), intent_score: (.error.data.intent_score // .error.data.score // null), labels: (.error.data.labels // null), rationale: (.error.data.rationale // null), result_is_error: (.result.isError // null)}'
}

main() {
  require_cmd curl
  require_cmd jq

  local run_start_iso
  run_start_iso="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  echo "== Misc Tool-Intent Mismatch Use Cases =="
  echo "PHASE4_BASE_URL=${PHASE4_BASE_URL}"
  echo "PROXY_MCP_URL=${PROXY_MCP_URL}"
  echo "RUN_START_ISO=${run_start_iso}"

  snapshot_current_cfg
  trap restore_cfg EXIT

  echo ""
  echo "[1/4] Enable tool_intent mismatch mode"
  set_mismatch_mode

  echo ""
  echo "[2/4] Disable dependency fail-safe (to allow testing without LLM provider)"
  disable_fail_safe

  echo ""
  echo "[3/4] Run miscellaneous mismatch cases"

  print_case_result "no metadata object" '{"jsonrpc":"2.0","id":"misc-no-metadata","method":"tools/call","params":{"name":"get_wazuh_alerts","arguments":{"time_range":"24h","min_level":10,"limit":5}}}'

  print_case_result "empty metadata.intent" '{"jsonrpc":"2.0","id":"misc-empty-intent","method":"tools/call","params":{"name":"get_wazuh_alerts","metadata":{"intent":"","source":"misc-test"},"arguments":{"time_range":"24h","min_level":10,"limit":5}}}'

  print_case_result "whitespace metadata.intent" '{"jsonrpc":"2.0","id":"misc-whitespace-intent","method":"tools/call","params":{"name":"get_wazuh_alerts","metadata":{"intent":"   ","source":"misc-test"},"arguments":{"time_range":"24h","min_level":10,"limit":5}}}'

  print_case_result "unrecognized metadata key only" '{"jsonrpc":"2.0","id":"misc-goal-only","method":"tools/call","params":{"name":"get_wazuh_alerts","metadata":{"goal":"isolate compromised endpoints now","source":"misc-test"},"arguments":{"time_range":"24h","min_level":10,"limit":5}}}'

  print_case_result "intent provided in arguments only (benign text)" '{"jsonrpc":"2.0","id":"misc-arg-intent-only","method":"tools/call","params":{"name":"get_wazuh_alerts","metadata":{"source":"misc-test"},"arguments":{"intent":"Review high-severity endpoint alerts from the last day for triage context","time_range":"24h","min_level":10,"limit":5}}}'

  print_case_result "contradictory high-risk intent text" '{"jsonrpc":"2.0","id":"misc-contradictory-intent","method":"tools/call","params":{"name":"get_wazuh_alerts","metadata":{"intent":"Isolate compromised endpoints and kill malicious processes immediately","source":"misc-test"},"arguments":{"time_range":"24h","min_level":10,"limit":5}}}'

  print_case_result "declared_intent mismatch alias" '{"jsonrpc":"2.0","id":"misc-declared-intent","method":"tools/call","params":{"name":"get_wazuh_alerts","metadata":{"declared_intent":"Block attacker IPs at firewall and quarantine hosts","source":"misc-test"},"arguments":{"time_range":"24h","min_level":10,"limit":5}}}'

  echo ""
  echo "[4/4] Recent llm_intent denied/challenge events since run start"
  proxy_recent_denied | jq -c --arg run_start "${run_start_iso}" '{count, events: [(.events // [])[0:40][] | select(type == "object" and (.timestamp // "") >= $run_start and ((.reason // "") | test("llm_intent"))) | {timestamp, reason, tool, metadata}]}'

  echo ""
  echo "Done. Refresh SOC Report -> Tool Intent Step 2 to view new mismatch rows."
}

main "$@"