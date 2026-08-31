#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PHASE3_BASE_URL="${PHASE3_BASE_URL:-http://localhost:8081}"
MCP_BASE_URL="${MCP_BASE_URL:-http://localhost:3000}"
PHASE3_DEMO_AGENT_ID="${PHASE3_DEMO_AGENT_ID:-}"
PHASE3_STRICT_AGENT_ID="${PHASE3_STRICT_AGENT_ID:-false}"

is_http_endpoint_reachable() {
  local url="$1"
  local code

  code="$(curl -sS -o /dev/null --max-time 3 -w '%{http_code}' "${url}" 2>/dev/null || true)"
  [[ "${code}" != "000" ]]
}

preflight_service_checks() {
  local warned=false

  if ! is_http_endpoint_reachable "${MCP_BASE_URL%/}/"; then
    echo "WARN: MCP endpoint is not reachable at ${MCP_BASE_URL%/}/" >&2
    warned=true
  fi

  if ! is_http_endpoint_reachable "${PHASE3_BASE_URL%/}/health"; then
    echo "WARN: Phase3 endpoint is not reachable at ${PHASE3_BASE_URL%/}/health" >&2
    warned=true
  fi

  if [[ "${warned}" == "true" ]]; then
    echo "WARN: Preflight detected connectivity issues. Scenario execution will continue and report per-scenario failures." >&2
  fi
}

usage() {
  cat <<'EOF'
Usage: tools/demo_phase3_langgraph.sh [scenario]

Scenarios:
  low-readonly         Low-risk read-only flow (no write action)
  medium-block         Medium risk block IP with approval
  high-isolate         High risk host isolation with approval
  critical-rollback    Critical quarantine with forced verify failure -> rollback
  critical-parallel    Critical scenario with parallel actions (isolate_host + block_ip + disable_user)
  all                  Run all scenarios (default)

Environment:
  PHASE3_BASE_URL    LangGraph service URL (default: http://localhost:8081)
  MCP_BASE_URL       MCP server URL for agent discovery (default: http://localhost:3000)
  PHASE3_DEMO_AGENT_ID  Force agent id for write scenarios (default: auto-detect active agent)
  PHASE3_STRICT_AGENT_ID  If true, fail when PHASE3_DEMO_AGENT_ID is not active (default: false)
EOF
}

scenario="${1:-all}"

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

preflight_service_checks

resolve_mcp_api_key() {
  if [[ -n "${MCP_API_KEY:-}" ]]; then
    echo "${MCP_API_KEY}"
    return 0
  fi

  if [[ -f "${REPO_ROOT}/.env" ]]; then
    grep '^MCP_API_KEY=' "${REPO_ROOT}/.env" | cut -d= -f2- | head -n1
    return 0
  fi

  echo ""
}

discover_active_agent_id() {
  local mcp_key
  local payload
  mcp_key="$(resolve_mcp_api_key)"

  if [[ -z "${mcp_key}" ]]; then
    echo "WARN: MCP_API_KEY is unavailable; defaulting to agent_id=002 for write scenarios" >&2
    echo "002"
    return 0
  fi

  payload='{"jsonrpc":"2.0","id":"phase3-demo-agent","method":"tools/call","params":{"name":"get_wazuh_running_agents","arguments":{}}}'

  local response
  if ! response="$(curl -fsS --max-time 20 "${MCP_BASE_URL%/}/" \
    -H "Authorization: Bearer ${mcp_key}" \
    -H "Content-Type: application/json" \
    -d "${payload}")"; then
    echo "WARN: Unable to query running agents; defaulting to agent_id=002" >&2
    echo "002"
    return 0
  fi

  local selected
  selected="$(echo "${response}" | python3 -c '
import json, re, sys
obj = json.load(sys.stdin)
text = ((obj.get("result", {}).get("content") or [{}])[0].get("text", ""))
match = re.search(r"\{[\s\S]*\}\s*$", text)
if not match:
    print("")
    raise SystemExit(0)
payload = json.loads(match.group(0))
items = (payload.get("data", {}) or {}).get("affected_items", []) or []
non_manager = [a.get("id") for a in items if a.get("status") == "active" and a.get("id") and a.get("id") != "000"]
if non_manager:
    print(non_manager[0])
    raise SystemExit(0)
active_any = [a.get("id") for a in items if a.get("status") == "active" and a.get("id")]
print(active_any[0] if active_any else "")
')"

  if [[ -z "${selected}" ]]; then
    echo "WARN: No active agents found; defaulting to agent_id=002" >&2
    echo "002"
    return 0
  fi

  echo "${selected}"
}

is_agent_active() {
  local agent_id="$1"
  local mcp_key
  local payload
  mcp_key="$(resolve_mcp_api_key)"

  if [[ -z "${mcp_key}" ]]; then
    return 2
  fi

  payload='{"jsonrpc":"2.0","id":"phase3-demo-agent-check","method":"tools/call","params":{"name":"get_wazuh_running_agents","arguments":{}}}'

  local response
  if ! response="$(curl -fsS --max-time 20 "${MCP_BASE_URL%/}/" \
    -H "Authorization: Bearer ${mcp_key}" \
    -H "Content-Type: application/json" \
    -d "${payload}")"; then
    return 2
  fi

  # Returns "active:<numeric_id>" when found by name, "active" when found by id,
  # "missing" or "inactive" otherwise.
  local status
  status="$(echo "${response}" | python3 -c '
import json, re, sys
target = sys.argv[1]
obj = json.load(sys.stdin)
text = ((obj.get("result", {}).get("content") or [{}])[0].get("text", ""))
match = re.search(r"\{[\s\S]*\}\s*$", text)
if not match:
    print("unknown")
    raise SystemExit(0)
payload = json.loads(match.group(0))
items = (payload.get("data", {}) or {}).get("affected_items", []) or []
# Match by numeric id first, then by name
record = next((a for a in items if str(a.get("id", "")) == target), None)
if not record:
    record = next((a for a in items if str(a.get("name", "")) == target), None)
    if record and record.get("status") == "active":
        print("active:" + str(record.get("id", "")))
        raise SystemExit(0)
if not record:
    print("missing")
elif record.get("status") == "active":
    print("active")
else:
    print(str(record.get("status", "inactive")))
' "${agent_id}")"

  # If matched by name, status is "active:<numeric_id>" — export the resolved ID
  if [[ "${status}" == active:* ]]; then
    PHASE3_RESOLVED_NUMERIC_ID="${status#active:}"
    return 0
  fi
  PHASE3_RESOLVED_NUMERIC_ID=""
  [[ "${status}" == "active" ]]
}

resolve_demo_agent_id() {
  if [[ -n "${PHASE3_DEMO_AGENT_ID}" ]]; then
    PHASE3_RESOLVED_NUMERIC_ID=""
    if is_agent_active "${PHASE3_DEMO_AGENT_ID}"; then
      # If value looked like a name and was resolved to a numeric ID, use that
      if [[ -n "${PHASE3_RESOLVED_NUMERIC_ID}" ]]; then
        echo "INFO: PHASE3_DEMO_AGENT_ID='${PHASE3_DEMO_AGENT_ID}' resolved by name to numeric id=${PHASE3_RESOLVED_NUMERIC_ID}" >&2
        echo "${PHASE3_RESOLVED_NUMERIC_ID}"
      else
        echo "${PHASE3_DEMO_AGENT_ID}"
      fi
      return 0
    fi

    if [[ "${PHASE3_STRICT_AGENT_ID}" == "true" ]]; then
      echo "ERROR: PHASE3_DEMO_AGENT_ID=${PHASE3_DEMO_AGENT_ID} is not active (or could not be validated)." >&2
      echo "ERROR: Use an active non-manager agent, or unset PHASE3_DEMO_AGENT_ID to auto-discover." >&2
      exit 2
    fi

    echo "WARN: PHASE3_DEMO_AGENT_ID=${PHASE3_DEMO_AGENT_ID} is not active (or could not be validated). Falling back to auto-discovered active agent." >&2
  fi

  discover_active_agent_id
}

DEMO_AGENT_ID="$(resolve_demo_agent_id)"

if [[ "${DEMO_AGENT_ID}" == "000" ]]; then
  echo "WARN: Only manager agent 000 is active. Active-response actions are not available for manager; medium/high/critical scenarios are expected to return completed_action_failed." >&2
fi

echo "Using demo action agent_id=${DEMO_AGENT_ID}" >&2

TOTAL_SCENARIOS=0
FAILED_SCENARIOS=0
PASSED_SCENARIOS=0

run_case_collect() {
  local name="$1"
  local payload="$2"

  TOTAL_SCENARIOS=$((TOTAL_SCENARIOS + 1))
  if run_case "${name}" "${payload}"; then
    PASSED_SCENARIOS=$((PASSED_SCENARIOS + 1))
  else
    FAILED_SCENARIOS=$((FAILED_SCENARIOS + 1))
    echo "Scenario failed: ${name}" >&2
  fi
}

run_case() {
  local name="$1"
  local payload="$2"
  local response
  local http_code
  local body
  local stderr_file

  echo "\n=== ${name} ==="
  stderr_file="$(mktemp)"
  if ! response="$(curl -sS --max-time 180 -w $'\n%{http_code}' "${PHASE3_BASE_URL}/phase3/run" \
    -H "Content-Type: application/json" \
    -d "${payload}" 2>"${stderr_file}")"; then
    echo "Request failed for scenario: ${name}" >&2
    if [[ -s "${stderr_file}" ]]; then
      cat "${stderr_file}" >&2
    fi
    rm -f "${stderr_file}"
    return 1
  fi
  rm -f "${stderr_file}"

  http_code="${response##*$'\n'}"
  body="${response%$'\n'*}"

  if [[ ! "${http_code}" =~ ^2[0-9][0-9]$ ]]; then
    echo "Scenario ${name} returned HTTP ${http_code}" >&2
    if [[ -n "${body}" ]]; then
      echo "${body}" >&2
    fi
    return 1
  fi

  if [[ -z "${body}" ]]; then
    echo "Scenario ${name} returned an empty response body" >&2
    return 1
  fi

  if ! echo "${body}" | python3 tools/format_phase3_output.py; then
    echo "Formatter failed for scenario: ${name}. Raw response follows:" >&2
    echo "${body}" >&2
    return 1
  fi
}

case "${scenario}" in
  low-readonly)
    run_case "LOW READ-ONLY" '{"incident_id":"INC-low-001","risk_tier":"low","use_case":"block_ip","time_range":"1h","query":"scan","auto_approve":false,"approval_decision":"rejected"}'
    ;;
  medium-block)
    run_case "MEDIUM BLOCK IP" "{\"incident_id\":\"INC-med-002\",\"risk_tier\":\"medium\",\"use_case\":\"block_ip\",\"time_range\":\"1h\",\"auto_approve\":true,\"action_args\":{\"agent_id\":\"${DEMO_AGENT_ID}\",\"src_ip\":\"198.51.100.27\",\"duration\":1800}}"
    ;;
  high-isolate)
    run_case "HIGH ISOLATE HOST" "{\"incident_id\":\"INC-high-003\",\"risk_tier\":\"high\",\"use_case\":\"isolate_host\",\"time_range\":\"1h\",\"auto_approve\":true,\"action_args\":{\"agent_id\":\"${DEMO_AGENT_ID}\"}}"
    ;;
  critical-rollback)
    run_case "CRITICAL QUARANTINE WITH ROLLBACK" "{\"incident_id\":\"INC-crit-004\",\"risk_tier\":\"critical\",\"use_case\":\"quarantine_file\",\"time_range\":\"6h\",\"auto_approve\":true,\"force_verify_fail\":true,\"action_args\":{\"agent_id\":\"${DEMO_AGENT_ID}\",\"file_path\":\"/tmp/suspicious.bin\"}}"
    ;;
  critical-parallel)
    run_case "CRITICAL PARALLEL ACTIONS" "{\"incident_id\":\"INC-parallel-001\",\"risk_tier\":\"critical\",\"use_case\":\"isolate_host\",\"time_range\":\"1h\",\"auto_approve\":true,\"proposed_actions\":[{\"tool\":\"wazuh_isolate_host\",\"args\":{\"agent_id\":\"${DEMO_AGENT_ID}\"}},{\"tool\":\"wazuh_firewall_drop\",\"args\":{\"agent_id\":\"${DEMO_AGENT_ID}\",\"src_ip\":\"198.51.100.27\",\"duration\":1800}},{\"tool\":\"wazuh_disable_user\",\"args\":{\"agent_id\":\"${DEMO_AGENT_ID}\",\"user\":\"suspicious_user\"}}],\"action_args\":{\"agent_id\":\"${DEMO_AGENT_ID}\"}}"
    ;;
  all)
    run_case_collect "LOW READ-ONLY" '{"incident_id":"INC-low-001","risk_tier":"low","use_case":"block_ip","time_range":"1h","query":"scan","auto_approve":false,"approval_decision":"rejected"}'
    run_case_collect "MEDIUM BLOCK IP" "{\"incident_id\":\"INC-med-002\",\"risk_tier\":\"medium\",\"use_case\":\"block_ip\",\"time_range\":\"1h\",\"auto_approve\":true,\"action_args\":{\"agent_id\":\"${DEMO_AGENT_ID}\",\"src_ip\":\"198.51.100.27\",\"duration\":1800}}"
    run_case_collect "HIGH ISOLATE HOST" "{\"incident_id\":\"INC-high-003\",\"risk_tier\":\"high\",\"use_case\":\"isolate_host\",\"time_range\":\"1h\",\"auto_approve\":true,\"action_args\":{\"agent_id\":\"${DEMO_AGENT_ID}\"}}"
    run_case_collect "CRITICAL QUARANTINE WITH ROLLBACK" "{\"incident_id\":\"INC-crit-004\",\"risk_tier\":\"critical\",\"use_case\":\"quarantine_file\",\"time_range\":\"6h\",\"auto_approve\":true,\"force_verify_fail\":true,\"action_args\":{\"agent_id\":\"${DEMO_AGENT_ID}\",\"file_path\":\"/tmp/suspicious.bin\"}}"
    run_case_collect "CRITICAL PARALLEL ACTIONS" "{\"incident_id\":\"INC-parallel-001\",\"risk_tier\":\"critical\",\"use_case\":\"isolate_host\",\"time_range\":\"1h\",\"auto_approve\":true,\"proposed_actions\":[{\"tool\":\"wazuh_isolate_host\",\"args\":{\"agent_id\":\"${DEMO_AGENT_ID}\"}},{\"tool\":\"wazuh_firewall_drop\",\"args\":{\"agent_id\":\"${DEMO_AGENT_ID}\",\"src_ip\":\"198.51.100.27\",\"duration\":1800}},{\"tool\":\"wazuh_disable_user\",\"args\":{\"agent_id\":\"${DEMO_AGENT_ID}\",\"user\":\"suspicious_user\"}}],\"action_args\":{\"agent_id\":\"${DEMO_AGENT_ID}\"}}"
    echo "\n=== ALL SCENARIOS SUMMARY ==="
    echo "Total: ${TOTAL_SCENARIOS}"
    echo "Passed: ${PASSED_SCENARIOS}"
    echo "Failed: ${FAILED_SCENARIOS}"
    if [[ ${FAILED_SCENARIOS} -gt 0 ]]; then
      exit 1
    fi
    ;;
  *)
    echo "Unknown scenario: ${scenario}" >&2
    usage >&2
    exit 2
    ;;
esac
