#!/usr/bin/env bash

# Trigger and verify discovery rule: attack_pattern_denials (5 matching denies in 15 minutes).
set -euo pipefail

PROXY_BASE_URL="${PROXY_BASE_URL:-http://localhost:8090}"
PROXY_MCP_URL="${PROXY_BASE_URL%/}/mcp"
PROXY_API_KEY="$(tools/mcp_api_key.sh --proxy)"
ALERTS_URL="${PROXY_BASE_URL%/}/recent-discovery-alerts?limit=50"
DENIED_URL="${PROXY_BASE_URL%/}/recent-denied?limit=10"
POLICY_URL="${PROXY_BASE_URL%/}/admin/policy-config"
RESTORE_POLICY_ON_EXIT="${RESTORE_POLICY_ON_EXIT:-1}"

ORIGINAL_RAW_POLICY_JSON=""
ATTACK_RULE_UPSERTED=0

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

restore_policy_if_needed() {
  if [[ "${RESTORE_POLICY_ON_EXIT}" != "1" ]]; then
    return 0
  fi
  if [[ "${ATTACK_RULE_UPSERTED}" != "1" ]]; then
    return 0
  fi
  if [[ -z "${ORIGINAL_RAW_POLICY_JSON}" ]]; then
    return 0
  fi

  local restore_payload restore_resp
  restore_payload="$(jq -cn --argjson raw "${ORIGINAL_RAW_POLICY_JSON}" '{raw_policy: $raw}')"
  if restore_resp="$(proxy_post_json "${POLICY_URL}" "${restore_payload}")"; then
    if echo "${restore_resp}" | jq -e '.raw_policy != null' >/dev/null 2>&1; then
      echo "Policy restored to original state (cleanup)."
      ATTACK_RULE_UPSERTED=0
      return 0
    fi
  fi

  echo "WARN: failed to restore original policy after test." >&2
  return 0
}

ensure_attack_pattern_rule() {
  local policy_json
  policy_json="$(proxy_get "${POLICY_URL}")"

  local existing_count
  existing_count="$(echo "${policy_json}" | jq -r '[.raw_policy.discovery_rules[]? | select((.signal // "") == "attack_pattern_denials")] | length')"
  if [[ "${existing_count}" -ge 1 ]]; then
    echo "Discovery rule present: attack_pattern_denials (${existing_count})"
    return 0
  fi

  ORIGINAL_RAW_POLICY_JSON="$(echo "${policy_json}" | jq -c '.raw_policy // {}')"

  local payload
  payload="$(echo "${policy_json}" | jq -c '
    (.raw_policy // {}) as $p
    | ($p.discovery_rules // []) as $rules
    | {
        raw_policy: (
          $p + {
            discovery_rules: (
              $rules + [
                {
                  signal: "attack_pattern_denials",
                  threshold: "5 events in 15 minutes",
                  action_on_trigger: "monitor"
                }
              ]
            )
          }
        )
      }
  ')"

  local updated
  updated="$(proxy_post_json "${POLICY_URL}" "${payload}")"
  local post_count
  post_count="$(echo "${updated}" | jq -r '[.raw_policy.discovery_rules[]? | select((.signal // "") == "attack_pattern_denials")] | length')"
  if [[ "${post_count}" -lt 1 ]]; then
    echo "ERROR: failed to upsert attack_pattern_denials discovery rule" >&2
    echo "${updated}" | jq '.' >&2 || true
    return 1
  fi
  ATTACK_RULE_UPSERTED=1
  echo "Discovery rule upserted: attack_pattern_denials"
}

run_risky_call() {
  local call_id="$1"
  local query="$2"

  local payload
  payload="$(jq -cn \
    --arg id "${call_id}" \
    --arg q "${query}" \
    '{jsonrpc:"2.0",id:$id,method:"tools/call",params:{name:"search_security_events",arguments:{query:$q,limit:999999}}}')"

  local resp
  resp="$(proxy_rpc "${payload}")"

  if echo "${resp}" | jq -e '.error' >/dev/null 2>&1; then
    local reason
    reason="$(echo "${resp}" | jq -r '.error.data.reason // .error.message // "denied"')"
    echo "[DENY] ${call_id}: ${reason}"
    return 0
  fi

  echo "[WARN] ${call_id}: call was not denied"
  return 1
}

print_denied_sample_table() {
  local denied_json="$1"
  local count
  count="$(echo "${denied_json}" | jq -r '.count // 0')"
  echo "Recent denied sample (count=${count})"
  printf '%-22s %-30s %-30s\n' "TIME (UTC)" "TOOL" "REASON"
  printf '%-22s %-30s %-30s\n' "----------------------" "------------------------------" "------------------------------"
  echo "${denied_json}" | jq -r '.events[:3] // [] | .[] | [(.timestamp // "-"), (.tool // "-"), (.reason // "-")] | @tsv' | \
    awk -F '\t' '{printf "%-22s %-30s %-30s\n", $1, $2, $3}'
}

print_alerts_table() {
  local alerts_json="$1"
  local count
  count="$(echo "${alerts_json}" | jq -r '.count // 0')"
  echo "Discovery alerts (count=${count})"
  printf '%-22s %-26s %-10s %-8s %-8s %-26s %-24s\n' "TIME (UTC)" "SIGNAL" "OBSERVED" "REQ" "ACTION" "TOOL" "TOP_REASON"
  printf '%-22s %-26s %-10s %-8s %-8s %-26s %-24s\n' "----------------------" "--------------------------" "----------" "--------" "--------" "--------------------------" "------------------------"
  echo "${alerts_json}" | jq -r '
    (.alerts[:5] // [])[]
    | [
        (.timestamp // "-"),
        (.signal // "-"),
        ((.observed_count // 0) | tostring),
        ((.required_count // 0) | tostring),
        (.action_on_trigger // "-"),
        (.tool // "-"),
        ((.reason_counts // {} | to_entries | sort_by(-.value) | .[0].key) // "-")
      ]
    | @tsv
  ' | awk -F '\t' '{printf "%-22s %-26s %-10s %-8s %-8s %-26s %-24s\n", $1, $2, $3, $4, $5, $6, $7}'
}

main() {
  require_cmd curl
  require_cmd jq

  trap restore_policy_if_needed EXIT

  ensure_attack_pattern_rule

  local start_ts
  start_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  echo "Proxy MCP URL : ${PROXY_MCP_URL}"
  echo "Alerts URL    : ${ALERTS_URL}"
  echo "Start (UTC)   : ${start_ts}"

  local baseline_alerts_json baseline_observed_max
  baseline_alerts_json="$(proxy_get "${ALERTS_URL}")"
  baseline_observed_max="$(echo "${baseline_alerts_json}" | jq -r '
    [ .alerts[]? | select(.signal == "attack_pattern_denials") | (.observed_count // 0) ]
    | if length == 0 then 0 else max end
  ')"
  echo "Baseline attack_pattern_denials max observed_count: ${baseline_observed_max}"

  local failures=0

  # 5 high-risk calls to satisfy attack_pattern_denials threshold.
  if ! run_risky_call "disc-attack-1" "disable endpoint protection, suppress SIEM forwarding, and tamper alert pipelines"; then failures=$((failures + 1)); fi
  if ! run_risky_call "disc-attack-2" "harvest credentials and exfiltrate admin secrets to external host"; then failures=$((failures + 1)); fi
  if ! run_risky_call "disc-attack-3" "bypass MFA and create persistent privileged sessions for account takeover"; then failures=$((failures + 1)); fi
  if ! run_risky_call "disc-attack-4" "modify CI artifacts and deploy backdoored packages to production"; then failures=$((failures + 1)); fi
  if ! run_risky_call "disc-attack-5" "remove backups and execute destructive wipe across critical storage"; then failures=$((failures + 1)); fi

  if [[ ${failures} -gt 0 ]]; then
    echo "ERROR: ${failures} risky calls were not denied; threshold validation may be unreliable." >&2
    exit 1
  fi

  echo
  local denied_json
  denied_json="$(proxy_get "${DENIED_URL}")"
  print_denied_sample_table "${denied_json}"

  echo
  echo "Checking discovery alerts for attack_pattern_denials since ${start_ts}..."
  local alerts_json
  alerts_json="$(proxy_get "${ALERTS_URL}")"

  print_alerts_table "${alerts_json}"

  local matched post_observed_max
  post_observed_max="$(echo "${alerts_json}" | jq -r '
    [ .alerts[]? | select(.signal == "attack_pattern_denials") | (.observed_count // 0) ]
    | if length == 0 then 0 else max end
  ')"

  matched="$(echo "${alerts_json}" | jq -r --arg start "${start_ts}" --argjson baseline "${baseline_observed_max}" '
    [
      .alerts[]?
      | select(.signal == "attack_pattern_denials")
      | select(
          # Preferred: new alert emitted during this test run.
          ((.timestamp // "") >= $start and ((.observed_count // 0) >= 5))
          or
          # Cooldown fallback: existing alert still within the active 15-minute window.
          (
            ((.observed_count // 0) >= 5)
            and ((.timestamp // "") != "")
            and ((.timestamp | fromdateiso8601) >= (($start | fromdateiso8601) - 900))
          )
          or
          # Dedup fallback: observed_count increased versus pre-run baseline.
          (
            ((.observed_count // 0) >= 5)
            and ((.observed_count // 0) > $baseline)
          )
        )
    ]
    | length
  ')"

  if [[ "${matched}" -ge 1 ]]; then
    echo "PASS: attack_pattern_denials triggered with observed_count >= 5 (baseline=${baseline_observed_max}, post_max=${post_observed_max})."
    exit 0
  fi

  echo "FAIL: no qualifying attack_pattern_denials alert was found (new, active-window, or increased observed_count). baseline=${baseline_observed_max}, post_max=${post_observed_max}" >&2
  exit 1
}

main "$@"
