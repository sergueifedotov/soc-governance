#!/usr/bin/env bash

# Trigger and verify discovery rule: write_tool_abuse.
set -euo pipefail

PROXY_BASE_URL="${PROXY_BASE_URL:-http://localhost:8090}"
PROXY_MCP_URL="${PROXY_BASE_URL%/}/mcp"
PROXY_API_KEY="$(tools/mcp_api_key.sh --proxy)"
ALERTS_URL="${PROXY_BASE_URL%/}/recent-discovery-alerts?limit=50"
DENIED_URL="${PROXY_BASE_URL%/}/recent-denied?limit=20"
CLEAR_ALERTS_URL="${PROXY_BASE_URL%/}/admin/clear-discovery-alerts"
RESET_DISCOVERY_STATE="${RESET_DISCOVERY_STATE:-1}"

require_cmd() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "ERROR: required command not found: ${cmd}" >&2
    exit 2
  fi
}

proxy_rpc() {
  local payload="$1"
  curl -sS \
    --retry 2 \
    --retry-delay 1 \
    --retry-all-errors \
    -H "Authorization: Bearer ${PROXY_API_KEY}" \
    -H "Content-Type: application/json" \
    -X POST \
    -d "${payload}" \
    "${PROXY_MCP_URL}"
}

proxy_get() {
  local url="$1"
  curl -sS \
    --retry 2 \
    --retry-delay 1 \
    --retry-all-errors \
    -H "Authorization: Bearer ${PROXY_API_KEY}" \
    "${url}"
}

proxy_post_json() {
  local url="$1"
  local payload="$2"
  curl -sS \
    --retry 2 \
    --retry-delay 1 \
    --retry-all-errors \
    -H "Authorization: Bearer ${PROXY_API_KEY}" \
    -H "Content-Type: application/json" \
    -X POST \
    -d "${payload}" \
    "${url}"
}

run_denied_write_call() {
  local call_id="$1"
  local tool_name="$2"

  local payload
  payload="$(jq -cn \
    --arg id "${call_id}" \
    --arg tool "${tool_name}" \
    '{jsonrpc:"2.0",id:$id,method:"tools/call",params:{name:$tool,arguments:{agent_id:"001",src_ip:"198.51.100.77",duration:60,reason:"discovery-write-tool-abuse-test"}}}')"

  local resp
  if ! resp="$(proxy_rpc "${payload}")"; then
    echo "[ERROR] ${call_id} (${tool_name}): proxy unreachable"
    return 1
  fi

  if echo "${resp}" | jq -e '.error' >/dev/null 2>&1; then
    local reason
    reason="$(echo "${resp}" | jq -r '.error.data.reason // .error.message // "denied"')"
    echo "[DENY] ${call_id} (${tool_name}): ${reason}"
    return 0
  fi

  echo "[WARN] ${call_id} (${tool_name}): call was not denied"
  return 1
}

main() {
  require_cmd curl
  require_cmd jq

  local start_ts
  start_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  echo "Proxy MCP URL : ${PROXY_MCP_URL}"
  echo "Alerts URL    : ${ALERTS_URL}"
  echo "Start (UTC)   : ${start_ts}"

  if [[ "${RESET_DISCOVERY_STATE}" == "1" ]]; then
    echo "Resetting discovery alerts/cooldown before test..."
    if ! proxy_post_json "${CLEAR_ALERTS_URL}" '{"reset_cooldown":true}' | jq -e '.status == "ok" or .cleared == true' >/dev/null 2>&1; then
      echo "WARN: could not confirm discovery-state reset via ${CLEAR_ALERTS_URL}; continuing." >&2
    fi
  fi

  local baseline_alerts_json baseline_observed_max
  if ! baseline_alerts_json="$(proxy_get "${ALERTS_URL}")"; then
    echo "ERROR: proxy unreachable while reading baseline discovery alerts" >&2
    exit 1
  fi
  baseline_observed_max="$(echo "${baseline_alerts_json}" | jq -r '
    [ .alerts[]? | select(.signal == "write_tool_abuse") | (.observed_count // 0) ]
    | if length == 0 then 0 else max end
  ')"
  echo "Baseline write_tool_abuse max observed_count: ${baseline_observed_max}"

  local failures=0

  # 3 denied write/response tool calls to satisfy write_tool_abuse threshold.
  if ! run_denied_write_call "write-abuse-1" "wazuh_block_ip"; then failures=$((failures + 1)); fi
  if ! run_denied_write_call "write-abuse-2" "wazuh_isolate_host"; then failures=$((failures + 1)); fi
  if ! run_denied_write_call "write-abuse-3" "wazuh_kill_process"; then failures=$((failures + 1)); fi

  if [[ ${failures} -gt 0 ]]; then
    echo "ERROR: ${failures} write-tool calls were not denied; threshold validation may be unreliable." >&2
    exit 1
  fi

  echo
  echo "Recent denied sample:"
  if ! proxy_get "${DENIED_URL}" | jq '{count, events: (.events[:6] | map({tool, reason, timestamp}))}'; then
    echo "ERROR: proxy unreachable while reading recent denied sample" >&2
    exit 1
  fi

  echo
  echo "Checking discovery alerts for write_tool_abuse since ${start_ts}..."
  local alerts_json
  if ! alerts_json="$(proxy_get "${ALERTS_URL}")"; then
    echo "ERROR: proxy unreachable while reading discovery alerts" >&2
    exit 1
  fi

  echo "${alerts_json}" | jq '{count, alerts: (.alerts[:8] | map({signal, action_on_trigger, observed_count, threshold, tool, timestamp}))}'

  local matched post_observed_max
  post_observed_max="$(echo "${alerts_json}" | jq -r '
    [ .alerts[]? | select(.signal == "write_tool_abuse") | (.observed_count // 0) ]
    | if length == 0 then 0 else max end
  ')"

  # Some deployments deduplicate alerts inside the active threshold window,
  # so a freshly triggered condition may keep the original alert timestamp.
  matched="$(echo "${alerts_json}" | jq -r --arg start "${start_ts}" --argjson baseline "${baseline_observed_max}" '
    [
      .alerts[]?
      | select(.signal == "write_tool_abuse")
      | select(
          # Preferred: a newly emitted alert at/after this run start.
          ((.timestamp // "") >= $start and ((.observed_count // 0) >= 3))
          or
          # Fallback: an existing deduplicated alert still within the same
          # 5-minute window relative to this run start, with qualifying count.
          (
            ((.observed_count // 0) >= 3)
            and ((.timestamp // "") != "")
            and ((.timestamp | fromdateiso8601) >= (($start | fromdateiso8601) - 300))
          )
          or
          # Additional fallback: in some cooldown/dedup implementations,
          # timestamp may stay old while observed_count keeps increasing.
          (
            ((.observed_count // 0) >= 3)
            and ((.observed_count // 0) > $baseline)
          )
        )
    ]
    | length
  ')"

  if [[ "${matched}" -ge 1 ]]; then
    echo "PASS: write_tool_abuse triggered with observed_count >= 3 (baseline=${baseline_observed_max}, post_max=${post_observed_max})."
    exit 0
  fi

  echo "FAIL: no qualifying write_tool_abuse alert was found (new, active-window, or increased observed_count). baseline=${baseline_observed_max}, post_max=${post_observed_max}" >&2
  exit 1
}

main "$@"
