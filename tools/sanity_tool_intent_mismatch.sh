#!/usr/bin/env bash

# End-to-end sanity check for tool-intent mismatch traffic.
# Flow: monitor mode -> matched+mismatched calls -> observability+metrics -> enforce mismatch -> recent-denied -> safe restore.
set -euo pipefail

PHASE4_BASE_URL="${PHASE4_BASE_URL:-http://localhost:8082}"
PROXY_BASE_URL="${PROXY_BASE_URL:-http://localhost:8090}"
MCP_PROXY_API_KEY="$(tools/mcp_api_key.sh --proxy)"

MONITOR_SCORE="${MONITOR_SCORE:-0.30}"
CHALLENGE_SCORE="${CHALLENGE_SCORE:-0.45}"
DENY_SCORE="${DENY_SCORE:-0.60}"
STRICT_MODE="${STRICT_MODE:-0}"          # 1 = retry mismatched calls until llm_intent event appears
MAX_ATTEMPTS="${MAX_ATTEMPTS:-12}"       # used only in STRICT_MODE
RETRY_DELAY_SECONDS="${RETRY_DELAY_SECONDS:-1}"
STRICT_FORCE_MISSING_INTENT="${STRICT_FORCE_MISSING_INTENT:-1}"  # 1 = omit metadata.intent during strict retries to force deterministic llm_intent_challenge

MATCHED_INTENT="${MATCHED_INTENT:-Review recent high severity detections for SOC triage}"
MISMATCH_INTENT="${MISMATCH_INTENT:-Isolate compromised endpoints and terminate malicious processes immediately}"
SECOND_MISMATCH_INTENT="${SECOND_MISMATCH_INTENT:-Block attacker IP addresses at firewall level now}"

require_cmd() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "ERROR: required command not found: ${cmd}" >&2
    exit 2
  fi
}

post_phase4() {
  local path="$1"
  local payload="$2"
  curl -sS -X POST -H "Content-Type: application/json" -d "${payload}" "${PHASE4_BASE_URL%/}${path}"
}

get_phase4() {
  local path="$1"
  curl -sS "${PHASE4_BASE_URL%/}${path}"
}

post_proxy() {
  local payload="$1"
  curl -sS -X POST \
    -H "Authorization: Bearer ${MCP_PROXY_API_KEY}" \
    -H "Content-Type: application/json" \
    -d "${payload}" \
    "${PROXY_BASE_URL%/}/mcp"
}

get_proxy_metrics() {
  curl -sS "${PROXY_BASE_URL%/}/metrics"
}

get_recent_denied() {
  curl -sS \
    -H "Authorization: Bearer ${MCP_PROXY_API_KEY}" \
    "${PROXY_BASE_URL%/}/recent-denied?limit=10"
}

build_call_payload() {
  local id="$1"
  local intent="$2"
  local tool_name="${3:-get_wazuh_alerts}"
  local include_intent_metadata="${4:-1}"
  local intent_variant="${5:-full}"

  if [[ "${intent_variant}" == "empty_intent_value" ]]; then
    cat <<JSON
{
  "jsonrpc": "2.0",
  "id": "${id}",
  "method": "tools/call",
  "params": {
    "name": "${tool_name}",
    "metadata": {
      "intent": "",
      "payload_variant": "empty_intent_value"
    },
    "arguments": {
      "time_range": "24h",
      "min_level": 10,
      "limit": 5
    }
  }
}
JSON
    return
  fi

  if [[ "${intent_variant}" == "unrecognized_intent_keys" ]]; then
    cat <<JSON
{
  "jsonrpc": "2.0",
  "id": "${id}",
  "method": "tools/call",
  "params": {
    "name": "${tool_name}",
    "metadata": {
      "goal": "${intent}",
      "payload_variant": "unrecognized_intent_keys"
    },
    "arguments": {
      "time_range": "24h",
      "min_level": 10,
      "limit": 5
    }
  }
}
JSON
    return
  fi

  if [[ "${include_intent_metadata}" != "1" ]]; then
    cat <<JSON
{
  "jsonrpc": "2.0",
  "id": "${id}",
  "method": "tools/call",
  "params": {
    "name": "${tool_name}",
    "metadata": {
      "payload_variant": "no_metadata"
    },
    "arguments": {
      "time_range": "24h",
      "min_level": 10,
      "limit": 5
    }
  }
}
JSON
    return
  fi

  cat <<JSON
{
  "jsonrpc": "2.0",
  "id": "${id}",
  "method": "tools/call",
  "params": {
    "name": "${tool_name}",
    "metadata": {
      "intent": "${intent}",
      "payload_variant": "${intent_variant}"
    },
    "arguments": {
      "time_range": "24h",
      "min_level": 10,
      "limit": 5
    }
  }
}
JSON
}

summarize_call_result() {
  local payload="$1"
  local tool_name="$2"
  local mismatch_class="$3"
  local payload_variant="${4:-full}"
  echo "${payload}" | jq -c --arg tool_name "${tool_name}" --arg mismatch_class "${mismatch_class}" --arg payload_variant "${payload_variant}" '{id, tool_name: $tool_name, mismatch_class: $mismatch_class, payload_variant: $payload_variant, has_error: (.error != null), error_message: (.error.message // null), reason: (.error.data.reason // null), score: ((.error.data.score // .error.data.intent_score) // null), labels: (.error.data.labels // null), rationale: (.error.data.rationale // null)}'
}

restore_safe_state() {
  post_phase4 "/soc/proxy-tool-intent-config" '{"tool_intent":{"enabled":false,"enforce":false}}' >/dev/null || true
}

print_llm_intent_recent_denied() {
  local raw
  raw="$(get_recent_denied || true)"
  if ! echo "${raw}" | jq -e '.events? | type == "array"' >/dev/null 2>&1; then
    echo '{"count":0,"events":[],"warning":"recent-denied unavailable or non-array events"}'
    return
  fi
  echo "${raw}" | jq -c '{count, events: [(.events // [])[0:10][] | select(type == "object" and ((.reason // "") | test("llm_intent"))) | {timestamp, reason, tool, metadata}]}'
}

enforce_config_payload() {
  if [[ "${STRICT_MODE}" == "1" && "${STRICT_FORCE_MISSING_INTENT}" == "1" ]]; then
    echo "{\"tool_intent\":{\"enabled\":true,\"enforce\":true,\"require_intent_metadata\":true,\"min_monitor_score\":${MONITOR_SCORE},\"min_challenge_score\":${CHALLENGE_SCORE},\"min_deny_score\":${DENY_SCORE}}}"
  else
    echo "{\"tool_intent\":{\"enabled\":true,\"enforce\":true,\"min_monitor_score\":${MONITOR_SCORE},\"min_challenge_score\":${CHALLENGE_SCORE},\"min_deny_score\":${DENY_SCORE}}}"
  fi
}

llm_intent_event_count() {
  local run_start_iso="$1"
  get_recent_denied | jq -r --arg run_start "${run_start_iso}" '(.events // []) | map(select(type == "object" and ((.reason // "") | test("llm_intent")) and ((.timestamp // "") >= $run_start))) | length'
}

filter_recent_denied_since_run_start() {
  local run_start_iso="$1"
  get_recent_denied | jq -c --arg run_start "${run_start_iso}" '{count, events: [(.events // [])[0:10][] | select(type == "object" and ((.reason // "") | test("llm_intent")) and ((.timestamp // "") >= $run_start)) | {timestamp, reason, tool, metadata}]}'
}

main() {
  require_cmd curl
  require_cmd jq

  RUN_START_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  echo "== Tool Intent Mismatch Sanity Check =="
  echo "PHASE4_BASE_URL=${PHASE4_BASE_URL}"
  echo "PROXY_BASE_URL=${PROXY_BASE_URL}"
  echo "RUN_START_ISO=${RUN_START_ISO}"

  echo
  echo "[1/7] Enable score-only mode"
  post_phase4 "/soc/proxy-tool-intent-config" "{\"tool_intent\":{\"enabled\":true,\"enforce\":false,\"min_monitor_score\":${MONITOR_SCORE},\"min_challenge_score\":${CHALLENGE_SCORE},\"min_deny_score\":${DENY_SCORE}}}" \
    | jq -c '{status, tool_intent: {enabled: .tool_intent.enabled, enforce: .tool_intent.enforce, min_monitor_score: .tool_intent.min_monitor_score, min_challenge_score: .tool_intent.min_challenge_score, min_deny_score: .tool_intent.min_deny_score}}'

  echo
  echo "[2/7] Send matched call (monitor mode)"
  matched_resp="$(post_proxy "$(build_call_payload "matched-ui-check" "${MATCHED_INTENT}" "get_wazuh_alerts")")"
  echo "REQUEST VARIANT: matched_read"
  summarize_call_result "${matched_resp}" "get_wazuh_alerts" "matched_read" "full"

  echo
  echo "[3/7] Send mismatched call (monitor mode)"
  mismatch_monitor_resp="$(post_proxy "$(build_call_payload "mismatch-ui-check" "${MISMATCH_INTENT}" "get_wazuh_alerts" "0")")"
  echo "REQUEST VARIANT: no_metadata"
  summarize_call_result "${mismatch_monitor_resp}" "get_wazuh_alerts" "intent_metadata_missing_or_drift" "no_metadata"

  echo
  echo "[3b/7] Send alternate missing-intent call (monitor mode)"
  second_mismatch_monitor_resp="$(post_proxy "$(build_call_payload "mismatch-ui-check-2" "${SECOND_MISMATCH_INTENT}" "get_wazuh_alerts" "0" "empty_intent_value")")"
  echo "REQUEST VARIANT: empty_intent_value"
  summarize_call_result "${second_mismatch_monitor_resp}" "get_wazuh_alerts" "intent_metadata_missing_or_empty" "empty_intent_value"

  echo
  echo "[3c/7] Send policy-denied tool call (monitor mode)"
  policy_denied_monitor_resp="$(post_proxy "$(build_call_payload "mismatch-ui-check-3" "${SECOND_MISMATCH_INTENT}" "search_security_events")")"
  echo "REQUEST VARIANT: policy_denied_tool"
  summarize_call_result "${policy_denied_monitor_resp}" "search_security_events" "policy_denied_tool" "full"

  echo
  echo "[4/7] Observability snapshot"
  obs="$(get_phase4 "/soc/proxy-tool-intent-observability")"
  echo "${obs}" | jq -c '{status, metrics_found, sample_lines_count: (.sample_lines | length), sample_lines: (.sample_lines[0:8])}'

  echo
  echo "[5/7] Tool-intent metrics slice"
  get_proxy_metrics | rg "mcp_security_proxy_tool_intent_calls_total|mcp_security_proxy_tool_intent_score_count|mcp_security_proxy_tool_intent_score_sum|mcp_security_proxy_tool_intent_score_bucket|mcp_security_proxy_denied_total" || true

  echo
  echo "[6/7] Enable enforce=true then re-send mismatched call"
  post_phase4 "/soc/proxy-tool-intent-config" "$(enforce_config_payload)" \
    | jq -c '{status, tool_intent: {enabled: .tool_intent.enabled, enforce: .tool_intent.enforce}}'

  mismatch_enforce_resp="$(post_proxy "$(build_call_payload "mismatch-ui-report" "${MISMATCH_INTENT}" "get_wazuh_alerts")")"
  echo "REQUEST VARIANT: no_metadata"
  mismatch_enforce_summary="$(summarize_call_result "${mismatch_enforce_resp}" "get_wazuh_alerts" "intent_metadata_missing_or_drift" "no_metadata")"
  echo "${mismatch_enforce_summary}"

  second_mismatch_enforce_resp="$(post_proxy "$(build_call_payload "mismatch-ui-report-2" "${SECOND_MISMATCH_INTENT}" "get_wazuh_alerts" "0" "empty_intent_value")")"
  echo "REQUEST VARIANT: empty_intent_value"
  second_mismatch_enforce_summary="$(summarize_call_result "${second_mismatch_enforce_resp}" "get_wazuh_alerts" "intent_metadata_missing_or_empty" "empty_intent_value")"
  echo "${second_mismatch_enforce_summary}"

  policy_denied_enforce_resp="$(post_proxy "$(build_call_payload "mismatch-ui-report-3" "${SECOND_MISMATCH_INTENT}" "search_security_events")")"
  echo "REQUEST VARIANT: policy_denied_tool"
  policy_denied_enforce_summary="$(summarize_call_result "${policy_denied_enforce_resp}" "search_security_events" "policy_denied_tool" "full")"
  echo "${policy_denied_enforce_summary}"

  echo
  echo "Mismatch call summaries (no metadata vs empty intent value vs policy-denied tool)"
  printf '%s\n' "${mismatch_enforce_summary}" "${second_mismatch_enforce_summary}" "${policy_denied_enforce_summary}" | jq -r '. as $row | "REQUEST VARIANT: \($row.payload_variant) | tool=\($row.tool_name) | mismatch_class=\($row.mismatch_class) | has_error=\($row.has_error) | reason=\($row.reason // "—") | labels=\(($row.labels // []) | join(", ")) | rationale=\($row.rationale // "—")"'

  if [[ "${STRICT_MODE}" == "1" ]]; then
    echo
    echo "Strict mode enabled: waiting for two llm_intent denied events (max attempts=${MAX_ATTEMPTS})"
    attempt=1
    found=0
    while (( attempt <= MAX_ATTEMPTS )); do
      count_now="$(llm_intent_event_count "${RUN_START_ISO}")"
      if [[ "${count_now}" =~ ^[0-9]+$ ]] && (( count_now >= 2 )); then
        echo "llm_intent events detected after attempt ${attempt}: ${count_now}"
        found=1
        break
      fi
      if (( attempt % 2 == 1 )); then
        # First sample: omit metadata entirely for a deterministic challenge row.
        post_proxy "$(build_call_payload "mismatch-ui-report-${attempt}" "${MISMATCH_INTENT}" "get_wazuh_alerts" "0" "no_metadata")" >/dev/null || true
      else
        # Second sample: include an empty intent value so the payload still looks like a missing-intent case, but not the same shape.
        post_proxy "$(build_call_payload "mismatch-ui-report-${attempt}" "${SECOND_MISMATCH_INTENT}" "get_wazuh_alerts" "0" "empty_intent_value")" >/dev/null || true
      fi
      sleep "${RETRY_DELAY_SECONDS}"
      ((attempt++))
    done
    if (( found == 0 )); then
      echo "ERROR: strict mode failed to produce two llm_intent denied/challenge events" >&2
      print_llm_intent_recent_denied
      exit 1
    fi
  fi

  echo
  echo "Recent denied llm_intent events"
  filter_recent_denied_since_run_start "${RUN_START_ISO}"

  echo
  echo "[7/7] Restore safe state"
  restore_safe_state
  get_phase4 "/soc/proxy-tool-intent-config" | jq -c '{status, tool_intent: {enabled: .tool_intent.enabled, enforce: .tool_intent.enforce}}'

  echo
  echo "Sanity check complete."
}

trap restore_safe_state EXIT
main "$@"
