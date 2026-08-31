#!/usr/bin/env bash

set -euo pipefail

PHASE4_BASE_URL="${PHASE4_BASE_URL:-http://localhost:8082}"
HEALTH_RETRIES="${HEALTH_RETRIES:-30}"
HEALTH_DELAY_SECONDS="${HEALTH_DELAY_SECONDS:-2}"
RUN_UI_CHECK=false

usage() {
  cat <<'EOF'
Usage: bash tools/retest_write_tool_abuse_accept_flow.sh [options]

Re-tests the write_tool_abuse Accept auto-apply flow end-to-end:
1) wait for phase4 health
2) remove write_tool_abuse from active policy
3) verify rule is missing
4) call /soc/policy-recommendations-action with apply_if_missing=true
5) verify rule is re-added

Options:
  --base-url URL         Phase 4 base URL (default: http://localhost:8082)
  --ui-check             Also check /ui availability and print manual UI steps
  --health-retries N     Health poll retries (default: 30)
  --health-delay SEC     Delay between health retries in seconds (default: 2)
  -h, --help             Show help

Environment:
  PHASE4_BASE_URL
  HEALTH_RETRIES
  HEALTH_DELAY_SECONDS
EOF
}

require_cmd() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "ERROR: required command not found: ${cmd}" >&2
    exit 2
  fi
}

wait_for_health() {
  local i
  for ((i=1; i<=HEALTH_RETRIES; i++)); do
    if curl -sS "${PHASE4_BASE_URL%/}/health" >/dev/null 2>&1; then
      echo "INFO: phase4 health is ready"
      return 0
    fi
    echo "INFO: waiting for phase4 health (${i}/${HEALTH_RETRIES})"
    sleep "${HEALTH_DELAY_SECONDS}"
  done
  echo "ERROR: phase4 health did not become ready" >&2
  return 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base-url)
      PHASE4_BASE_URL="$2"
      shift 2
      ;;
    --ui-check)
      RUN_UI_CHECK=true
      shift
      ;;
    --health-retries)
      HEALTH_RETRIES="$2"
      shift 2
      ;;
    --health-delay)
      HEALTH_DELAY_SECONDS="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

require_cmd curl
require_cmd jq

echo "INFO: re-test started"
echo "INFO: base_url=${PHASE4_BASE_URL%/}"

wait_for_health
curl -sS "${PHASE4_BASE_URL%/}/health" | jq .

echo "INFO: removing write_tool_abuse from active policy"
SNAP="$(curl -sS "${PHASE4_BASE_URL%/}/soc/proxy-policy-config")"
RAW="$(echo "${SNAP}" | jq '.raw_policy')"
MOD="$(echo "${RAW}" | jq '(.discovery_rules // []) as $rules | .discovery_rules = [ $rules[] | select((.signal // "") != "write_tool_abuse") ]')"
UPDATE_PAYLOAD="$(jq -cn --argjson p "${MOD}" '{raw_policy:$p}')"

curl -sS -X POST "${PHASE4_BASE_URL%/}/soc/proxy-policy-config" \
  -H 'Content-Type: application/json' \
  -d "${UPDATE_PAYLOAD}" | jq '{status, summary: .result.summary}'

MISSING_COUNT="$(curl -sS "${PHASE4_BASE_URL%/}/soc/proxy-policy-config" | jq '[.raw_policy.discovery_rules[]? | select(.signal=="write_tool_abuse")] | length')"
echo "INFO: missing_count=${MISSING_COUNT}"
if [[ "${MISSING_COUNT}" != "0" ]]; then
  echo "ERROR: write_tool_abuse still present after removal" >&2
  exit 1
fi

echo "INFO: submitting Accept action with apply_if_missing=true"
REC='{"type":"discovery","signal":"write_tool_abuse","threshold":"3 denials in 5 minutes","action_on_trigger":"challenge","tool_scope":["wazuh_block_ip","wazuh_isolate_host","wazuh_kill_process","wazuh_disable_user","wazuh_quarantine_file","wazuh_active_response","wazuh_firewall_drop","wazuh_host_deny","wazuh_restart","wazuh_unisolate_host","wazuh_enable_user","wazuh_restore_file","wazuh_firewall_allow","wazuh_host_allow"],"confidence":0.7,"rationale":"Tool search_security_events has highest deny rate; recommend challenge rule for repeated attempts","source":"policy_tuning_change_bundle"}'
ACTION_PAYLOAD="$(jq -cn --argjson rec "${REC}" '{recommendation_index:0, action:"accept", apply_if_missing:true, recommendation_data:$rec}')"

curl -sS -X POST "${PHASE4_BASE_URL%/}/soc/policy-recommendations-action" \
  -H 'Content-Type: application/json' \
  -d "${ACTION_PAYLOAD}" | jq .

echo "INFO: verifying write_tool_abuse was re-added"
VERIFY="$(curl -sS "${PHASE4_BASE_URL%/}/soc/proxy-policy-config" | jq '[.raw_policy.discovery_rules[]? | select(.signal=="write_tool_abuse")]')"
echo "${VERIFY}" | jq .
COUNT="$(echo "${VERIFY}" | jq 'length')"

echo "INFO: readded_count=${COUNT}"
if [[ "${COUNT}" -lt 1 ]]; then
  echo "ERROR: write_tool_abuse was not re-added via approval flow" >&2
  exit 1
fi

if [[ "${RUN_UI_CHECK}" == "true" ]]; then
  echo "INFO: checking UI endpoint"
  UI_CODE="$(curl -sS -o /dev/null -w '%{http_code}' "${PHASE4_BASE_URL%/}/ui")"
  if [[ "${UI_CODE}" != "200" ]]; then
    echo "ERROR: UI endpoint check failed (status=${UI_CODE})" >&2
    exit 1
  fi

  cat <<EOF
UI Manual Re-Test Steps:
1) Open ${PHASE4_BASE_URL%/}/ui
2) Go to Policy Tuning tab
3) Generate discovery recommendations
4) Accept a write_tool_abuse recommendation
5) Confirm toast indicates auto-apply result
6) Refresh Current Proxy Policy snapshot and verify discovery_rules contains write_tool_abuse
EOF
fi

echo "PASS: write_tool_abuse Accept auto-apply re-test succeeded"
