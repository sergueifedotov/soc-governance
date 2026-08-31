#!/bin/bash
# Quick smoke tests for Adaptive Masking recommendation endpoint

set -euo pipefail

PHASE4_BASE_URL="${PHASE4_BASE_URL:-http://localhost:8082}"
TIME_RANGE="${TIME_RANGE:-24h}"
LIMIT="${LIMIT:-100}"
MODE="${MODE:-monitor}"
TOOL_FILTER="${TOOL_FILTER:-write_alert,bulk_operation}"
APPLY_CHANGES="${APPLY_CHANGES:-0}"

if ! command -v jq >/dev/null 2>&1; then
  echo "Error: jq is required but not installed." >&2
  exit 1
fi

echo "Adaptive Masking Recommendation — Smoke Test"
echo "==========================================="
echo "PHASE4_BASE_URL: ${PHASE4_BASE_URL}"
echo "TIME_RANGE:      ${TIME_RANGE}"
echo "LIMIT:           ${LIMIT}"
echo "MODE:            ${MODE}"
echo "TOOL_FILTER:     ${TOOL_FILTER}"
echo "APPLY_CHANGES:   ${APPLY_CHANGES}"
echo

# Build JSON array from comma-separated TOOL_FILTER
TOOL_FILTER_JSON="[]"
if [[ -n "${TOOL_FILTER}" ]]; then
  TOOL_FILTER_JSON="$(printf '%s' "${TOOL_FILTER}" | jq -Rc 'split(",") | map(gsub("^\\s+|\\s+$"; "")) | map(select(length > 0))')"
fi

post_json() {
  local url="$1"
  local data="$2"
  curl -sS -w '\n%{http_code}' -X POST "${url}" \
    -H 'Content-Type: application/json' \
    -d "${data}"
}

split_body_and_status() {
  local response="$1"
  HTTP_STATUS="$(printf '%s' "${response}" | tail -n1)"
  HTTP_BODY="$(printf '%s' "${response}" | sed '$d')"
}

assert_ok_shape() {
  local body="$1"
  printf '%s' "${body}" | jq -e '
    .status == "ok" and
    (.summary | type == "object") and
    (.recommendations | type == "array") and
    (.human_review_required == true) and
    (.safety_model | type == "string")
  ' >/dev/null
}

assert_action_ok_shape() {
  local body="$1"
  local expected_action="$2"
  printf '%s' "${body}" | jq -e --arg expected_action "${expected_action}" '
    .status == "ok" and
    (.action_recorded == true) and
    (.action == $expected_action) and
    (.recommendation_index | type == "number") and
    (.timestamp | type == "string")
  ' >/dev/null
}

assert_apply_ok_shape() {
  local body="$1"
  printf '%s' "${body}" | jq -e '
    .status == "ok" and
    (.result | type == "object")
  ' >/dev/null
}

echo "Test 1: monitor mode baseline"
echo "-----------------------------"
RESP1="$(post_json "${PHASE4_BASE_URL}/soc/proxy-adaptive-masking-recommendations" "{
  \"time_range\": \"${TIME_RANGE}\",
  \"limit\": ${LIMIT},
  \"mode\": \"${MODE}\",
  \"run_llm\": true
}")"
split_body_and_status "${RESP1}"

if [[ "${HTTP_STATUS}" != "200" ]]; then
  echo "FAIL: expected HTTP 200, got ${HTTP_STATUS}" >&2
  printf '%s\n' "${HTTP_BODY}" | jq '.' || printf '%s\n' "${HTTP_BODY}"
  exit 1
fi

assert_ok_shape "${HTTP_BODY}"
printf '%s\n' "${HTTP_BODY}" | jq '{status, summary, recommendations_count: (.recommendations | length), human_review_required, safety_model}'
echo "PASS"
echo

echo "Test 2: review mode with tool filter"
echo "------------------------------------"
RESP2="$(post_json "${PHASE4_BASE_URL}/soc/proxy-adaptive-masking-recommendations" "{
  \"time_range\": \"${TIME_RANGE}\",
  \"limit\": ${LIMIT},
  \"mode\": \"review\",
  \"tool_filter\": ${TOOL_FILTER_JSON},
  \"run_llm\": true
}")"
split_body_and_status "${RESP2}"

if [[ "${HTTP_STATUS}" != "200" ]]; then
  echo "FAIL: expected HTTP 200, got ${HTTP_STATUS}" >&2
  printf '%s\n' "${HTTP_BODY}" | jq '.' || printf '%s\n' "${HTTP_BODY}"
  exit 1
fi

assert_ok_shape "${HTTP_BODY}"
printf '%s\n' "${HTTP_BODY}" | jq '{status, mode: .summary.mode, tool_filter: .summary.tool_filter, recommendations_count: (.recommendations | length)}'
REVIEW_BODY="${HTTP_BODY}"
echo "PASS"
echo

echo "Test 3: invalid mode (expect 400)"
echo "---------------------------------"
RESP3="$(post_json "${PHASE4_BASE_URL}/soc/proxy-adaptive-masking-recommendations" "{
  \"time_range\": \"${TIME_RANGE}\",
  \"limit\": ${LIMIT},
  \"mode\": \"invalid_mode\",
  \"run_llm\": true
}")"
split_body_and_status "${RESP3}"

if [[ "${HTTP_STATUS}" != "400" ]]; then
  echo "FAIL: expected HTTP 400, got ${HTTP_STATUS}" >&2
  printf '%s\n' "${HTTP_BODY}" | jq '.' || printf '%s\n' "${HTTP_BODY}"
  exit 1
fi

printf '%s\n' "${HTTP_BODY}" | jq '{detail}'
echo "PASS"
echo

ACTION_REC_JSON="$(printf '%s' "${REVIEW_BODY}" | jq -c '(.recommendations[0] // {tool:"*",argument_path:"arguments[*]",recommended_mode:"redact",confidence:0.5,rationale:"fallback"})')"
ADAPTIVE_BUNDLE_JSON="$(jq -cn --argjson rec "${ACTION_REC_JSON}" '
{
  artifact_version: "1.0",
  artifact_type: "adaptive_masking_change_bundle",
  source: {
    generated_at: (now | todateiso8601),
    source: "adaptive_smoke_test",
    feature: "adaptive_masking"
  },
  accepted_count: 1,
  accepted_recommendations: [
    {
      recommendation_index: 0,
      accepted_at: (now | todateiso8601),
      recommendation: $rec
    }
  ],
  policy_patch_preview: {
    masking_updates: [
      {
        recommendation_index: 0,
        target: ($rec.argument_path // "arguments[*]"),
        mode: ($rec.recommended_mode // "redact"),
        tool_scope: (if (($rec.tool // "*") == "*") then [] else [($rec.tool // "*")] end),
        confidence: ($rec.confidence // 0.5),
        rationale: ($rec.rationale // "adaptive smoke fallback"),
        source: "adaptive_masking_accept"
      }
    ],
    discovery_updates: []
  },
  next_action: "Apply via controlled policy update workflow"
}
')"

echo "Test 4: action endpoint accept"
echo "------------------------------"
RESP4="$(post_json "${PHASE4_BASE_URL}/soc/adaptive-masking-recommendations-action" "{
  \"recommendation_index\": 0,
  \"action\": \"accept\",
  \"recommendation_data\": ${ACTION_REC_JSON},
  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
}")"
split_body_and_status "${RESP4}"

if [[ "${HTTP_STATUS}" != "200" ]]; then
  echo "FAIL: expected HTTP 200, got ${HTTP_STATUS}" >&2
  printf '%s\n' "${HTTP_BODY}" | jq '.' || printf '%s\n' "${HTTP_BODY}"
  exit 1
fi

assert_action_ok_shape "${HTTP_BODY}" "accept"
printf '%s\n' "${HTTP_BODY}" | jq '{status, action_recorded, action, recommendation_index, detail, timestamp}'
echo "PASS"
echo

echo "Test 5: action endpoint reject"
echo "------------------------------"
RESP5="$(post_json "${PHASE4_BASE_URL}/soc/adaptive-masking-recommendations-action" "{
  \"recommendation_index\": 0,
  \"action\": \"reject\",
  \"recommendation_data\": ${ACTION_REC_JSON},
  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
}")"
split_body_and_status "${RESP5}"

if [[ "${HTTP_STATUS}" != "200" ]]; then
  echo "FAIL: expected HTTP 200, got ${HTTP_STATUS}" >&2
  printf '%s\n' "${HTTP_BODY}" | jq '.' || printf '%s\n' "${HTTP_BODY}"
  exit 1
fi

assert_action_ok_shape "${HTTP_BODY}" "reject"
printf '%s\n' "${HTTP_BODY}" | jq '{status, action_recorded, action, recommendation_index, detail, timestamp}'
echo "PASS"
echo

echo "Test 6: adaptive bundle dry-run apply"
echo "-------------------------------------"
RESP6="$(post_json "${PHASE4_BASE_URL}/soc/proxy-policy-bundle-apply" "{
  \"policy_bundle\": ${ADAPTIVE_BUNDLE_JSON},
  \"dry_run\": true
}")"
split_body_and_status "${RESP6}"

if [[ "${HTTP_STATUS}" != "200" ]]; then
  echo "FAIL: expected HTTP 200, got ${HTTP_STATUS}" >&2
  printf '%s\n' "${HTTP_BODY}" | jq '.' || printf '%s\n' "${HTTP_BODY}"
  exit 1
fi

assert_apply_ok_shape "${HTTP_BODY}"
printf '%s\n' "${HTTP_BODY}" | jq '{status, result: {summary: .result.summary, changed: .result.changed, backup_file: .result.backup_file}}'
echo "PASS"
echo

if [[ "${APPLY_CHANGES}" == "1" ]]; then
  echo "Test 7: adaptive bundle real apply"
  echo "----------------------------------"
  RESP7="$(post_json "${PHASE4_BASE_URL}/soc/proxy-policy-bundle-apply" "{
  \"policy_bundle\": ${ADAPTIVE_BUNDLE_JSON},
  \"dry_run\": false
}")"
  split_body_and_status "${RESP7}"

  if [[ "${HTTP_STATUS}" != "200" ]]; then
    echo "FAIL: expected HTTP 200, got ${HTTP_STATUS}" >&2
    printf '%s\n' "${HTTP_BODY}" | jq '.' || printf '%s\n' "${HTTP_BODY}"
    exit 1
  fi

  assert_apply_ok_shape "${HTTP_BODY}"
  printf '%s\n' "${HTTP_BODY}" | jq '{status, result: {summary: .result.summary, changed: .result.changed, backup_file: .result.backup_file}}'
  echo "PASS"
  echo
else
  echo "Test 7: adaptive bundle real apply"
  echo "----------------------------------"
  echo "SKIP: set APPLY_CHANGES=1 to enable non-dry-run policy apply in this smoke script."
  echo
fi

echo "All adaptive masking smoke tests passed."
