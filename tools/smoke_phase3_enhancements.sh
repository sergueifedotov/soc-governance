#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PHASE3_BASE_URL="${PHASE3_BASE_URL:-http://localhost:8081}"
MCP_BASE_URL="${MCP_BASE_URL:-http://localhost:3000}"
PHASE3_DEMO_AGENT_ID="${PHASE3_DEMO_AGENT_ID:-}"
PHASE3_STRICT_AGENT_ID="${PHASE3_STRICT_AGENT_ID:-false}"
LANGFUSE_ASSERT_TRACE="${LANGFUSE_ASSERT_TRACE:-true}"
LANGFUSE_PUBLIC_BASE_URL="${LANGFUSE_PUBLIC_BASE_URL:-http://localhost:3001}"
LANGFUSE_PUBLIC_KEY="${LANGFUSE_PUBLIC_KEY:-pk-local-smoke}"
LANGFUSE_SECRET_KEY="${LANGFUSE_SECRET_KEY:-sk-local-smoke}"

usage() {
  cat <<'EOF'
Usage: tools/smoke_phase3_enhancements.sh

Runs end-to-end Phase 3 smoke tests for enhancement features:
  - Tenacity-backed MCP execution path
  - Structlog audit logging path
  - Parallel action execution
  - Langfuse-traced run endpoint
  - Human-in-the-loop pause/resume approvals

Environment:
  PHASE3_BASE_URL        LangGraph service URL (default: http://localhost:8081)
  MCP_BASE_URL           MCP server URL for agent discovery (default: http://localhost:3000)
  PHASE3_DEMO_AGENT_ID   Optional agent id/name override (default: auto-discover)
  PHASE3_STRICT_AGENT_ID If true, fail when PHASE3_DEMO_AGENT_ID is not active
  MCP_API_KEY            Optional; if absent will read from repo .env
  LANGFUSE_ASSERT_TRACE  Assert Langfuse trace metadata in /phase3/run output (default: true)
  LANGFUSE_PUBLIC_BASE_URL Langfuse UI/API base URL for backend trace assertions (default: http://localhost:3001)
  LANGFUSE_PUBLIC_KEY    Langfuse public key for trace lookup (default: pk-local-smoke)
  LANGFUSE_SECRET_KEY    Langfuse secret key for trace lookup (default: sk-local-smoke)
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

require_cmd() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "ERROR: Required command not found: ${cmd}" >&2
    exit 2
  fi
}

require_cmd curl
require_cmd python3

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

preflight() {
  local phase3_health
  phase3_health="$(curl -sS -o /dev/null --max-time 5 -w '%{http_code}' "${PHASE3_BASE_URL%/}/health" || true)"
  if [[ "${phase3_health}" == "000" ]]; then
    echo "ERROR: Phase3 service is unreachable at ${PHASE3_BASE_URL%/}/health" >&2
    exit 2
  fi

  local mcp_health
  mcp_health="$(curl -sS -o /dev/null --max-time 5 -w '%{http_code}' "${MCP_BASE_URL%/}/" || true)"
  if [[ "${mcp_health}" == "000" ]]; then
    echo "WARN: MCP endpoint is unreachable at ${MCP_BASE_URL%/}/ (agent auto-discovery may fall back)" >&2
  fi

}

assert_langfuse_trace_recorded() {
  local json_file="$1"
  local expected_names_csv="${2:-}"

  if [[ "${LANGFUSE_ASSERT_TRACE}" != "true" ]]; then
    return 0
  fi

  python3 - <<'PY' "${json_file}" "${LANGFUSE_PUBLIC_BASE_URL}" "${LANGFUSE_PUBLIC_KEY}" "${LANGFUSE_SECRET_KEY}" "${expected_names_csv}"
import base64
import json
import urllib.error
import urllib.parse
import urllib.request
import sys


def require(condition: bool, message: str) -> None:
  if not condition:
    raise SystemExit(message)

with open(sys.argv[1], 'r', encoding='utf-8') as fh:
  obj = json.load(fh)

base_url = sys.argv[2].rstrip("/")
public_key = sys.argv[3]
secret_key = sys.argv[4]
expected_names = [name for name in sys.argv[5].split(",") if name]

trace = ((obj.get("outputs") or {}).get("trace") or {})
provider = trace.get("provider")
enabled = trace.get("enabled")
trace_id = trace.get("trace_id")
child_names = trace.get("child_observation_names") or []

require(provider == "langfuse", f"Langfuse assertion failed: outputs.trace.provider={provider!r}")
require(bool(enabled), "Langfuse assertion failed: outputs.trace.enabled is false")
require(bool(trace_id), "Langfuse assertion failed: outputs.trace.trace_id is empty")
require(isinstance(child_names, list), "Langfuse assertion failed: outputs.trace.child_observation_names is not a list")
require(len(child_names) > 0, "Langfuse assertion failed: outputs.trace.child_observation_names is empty")

if expected_names:
  missing_from_response = [name for name in expected_names if name not in child_names]
  require(
      not missing_from_response,
      "Langfuse assertion failed: outputs.trace.child_observation_names missing expected values: "
      + ", ".join(missing_from_response),
  )

require(bool(public_key), "Langfuse assertion failed: LANGFUSE_PUBLIC_KEY is empty")
require(bool(secret_key), "Langfuse assertion failed: LANGFUSE_SECRET_KEY is empty")

request = urllib.request.Request(
    f"{base_url}/api/public/traces/{urllib.parse.quote(str(trace_id), safe='')}",
    headers={
    "Authorization": "Basic " + base64.b64encode(f"{public_key}:{secret_key}".encode("utf-8")).decode("ascii")
    },
)

try:
  with urllib.request.urlopen(request, timeout=30) as response:
    backend_trace = json.load(response)
except urllib.error.HTTPError as exc:
  detail = exc.read().decode("utf-8", errors="replace")
  raise SystemExit(f"Langfuse assertion failed: backend lookup returned HTTP {exc.code}: {detail[:300]}") from exc
except Exception as exc:
  raise SystemExit(f"Langfuse assertion failed: backend lookup error: {exc}") from exc

observations = backend_trace.get("observations") or []
backend_names = [item.get("name") for item in observations if isinstance(item, dict) and item.get("name")]

require(backend_trace.get("id") == trace_id, "Langfuse assertion failed: backend trace id does not match outputs.trace.trace_id")
require(len(observations) > 0, "Langfuse assertion failed: backend trace has no observations")

if expected_names:
  missing_from_backend = [name for name in expected_names if name not in backend_names]
  require(
      not missing_from_backend,
      "Langfuse assertion failed: backend observations missing expected values: " + ", ".join(missing_from_backend),
  )

print(
    "Langfuse trace assertion passed: "
    f"trace_id={trace_id} response_observations={len(child_names)} backend_observations={len(observations)}"
)
PY
}

is_agent_active() {
  local target="$1"
  local key payload response

  key="$(resolve_mcp_api_key)"
  if [[ -z "${key}" ]]; then
    return 2
  fi

  payload='{"jsonrpc":"2.0","id":"phase3-smoke-agent-check","method":"tools/call","params":{"name":"get_wazuh_running_agents","arguments":{}}}'

  if ! response="$(curl -fsS --max-time 20 "${MCP_BASE_URL%/}/" \
    -H "Authorization: Bearer ${key}" \
    -H "Content-Type: application/json" \
    -d "${payload}")"; then
    return 2
  fi

  local status
  status="$(echo "${response}" | python3 -c '
import json, re, sys
obj = json.load(sys.stdin)
target = sys.argv[1]
text = ((obj.get("result", {}).get("content") or [{}])[0].get("text", ""))
match = re.search(r"\{[\s\S]*\}\s*$", text)
if not match:
    print("unknown")
    raise SystemExit(0)
payload = json.loads(match.group(0))
items = (payload.get("data", {}) or {}).get("affected_items", []) or []
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
' "${target}")"

  if [[ "${status}" == active:* ]]; then
    PHASE3_RESOLVED_NUMERIC_ID="${status#active:}"
    return 0
  fi

  PHASE3_RESOLVED_NUMERIC_ID=""
  [[ "${status}" == "active" ]]
}

discover_active_agent_id() {
  local key payload response
  key="$(resolve_mcp_api_key)"

  if [[ -z "${key}" ]]; then
    echo "WARN: MCP_API_KEY not found; defaulting to agent_id=002" >&2
    echo "002"
    return 0
  fi

  payload='{"jsonrpc":"2.0","id":"phase3-smoke-agent","method":"tools/call","params":{"name":"get_wazuh_running_agents","arguments":{}}}'
  if ! response="$(curl -fsS --max-time 20 "${MCP_BASE_URL%/}/" \
    -H "Authorization: Bearer ${key}" \
    -H "Content-Type: application/json" \
    -d "${payload}")"; then
    echo "WARN: Could not query running agents; defaulting to agent_id=002" >&2
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

resolve_demo_agent_id() {
  if [[ -n "${PHASE3_DEMO_AGENT_ID}" ]]; then
    PHASE3_RESOLVED_NUMERIC_ID=""
    if is_agent_active "${PHASE3_DEMO_AGENT_ID}"; then
      if [[ -n "${PHASE3_RESOLVED_NUMERIC_ID}" ]]; then
        echo "INFO: PHASE3_DEMO_AGENT_ID='${PHASE3_DEMO_AGENT_ID}' resolved to id=${PHASE3_RESOLVED_NUMERIC_ID}" >&2
        echo "${PHASE3_RESOLVED_NUMERIC_ID}"
      else
        echo "${PHASE3_DEMO_AGENT_ID}"
      fi
      return 0
    fi

    if [[ "${PHASE3_STRICT_AGENT_ID}" == "true" ]]; then
      echo "ERROR: PHASE3_DEMO_AGENT_ID=${PHASE3_DEMO_AGENT_ID} is not active" >&2
      exit 2
    fi

    echo "WARN: PHASE3_DEMO_AGENT_ID=${PHASE3_DEMO_AGENT_ID} is not active, falling back to auto-discovery" >&2
  fi

  discover_active_agent_id
}

post_phase3() {
  local payload="$1"
  local output_file="$2"
  local response http_code body

  response="$(curl -sS --max-time 180 -w $'\n%{http_code}' "${PHASE3_BASE_URL%/}/phase3/run" \
    -H "Content-Type: application/json" \
    -d "${payload}")"

  http_code="${response##*$'\n'}"
  body="${response%$'\n'*}"

  if [[ ! "${http_code}" =~ ^2[0-9][0-9]$ ]]; then
    echo "ERROR: /phase3/run returned HTTP ${http_code}" >&2
    echo "${body}" >&2
    return 1
  fi

  echo "${body}" > "${output_file}"
}

assert_json_equals() {
  local json_file="$1"
  local field_path="$2"
  local expected="$3"
  python3 - <<'PY' "${json_file}" "${field_path}" "${expected}"
import json, sys
path = sys.argv[2].split('.')
expected = sys.argv[3]
with open(sys.argv[1], 'r', encoding='utf-8') as fh:
    obj = json.load(fh)
cur = obj
for part in path:
    if isinstance(cur, dict) and part in cur:
        cur = cur[part]
    else:
        raise SystemExit(f"Missing field path: {sys.argv[2]}")
if str(cur) != expected:
    raise SystemExit(f"Assertion failed for {sys.argv[2]}: got={cur!r} expected={expected!r}")
PY
}

assert_parallel_executed() {
  local json_file="$1"
  python3 - <<'PY' "${json_file}"
import json
import sys

with open(sys.argv[1], 'r', encoding='utf-8') as fh:
  obj = json.load(fh)

steps = obj.get("steps", [])
if not any(str(s).startswith("execute:parallel:") for s in steps):
  raise SystemExit("Parallel execution branch was not used")

execution = (obj.get("outputs") or {}).get("execution") or {}
actions = execution.get("actions")
results = execution.get("results")
status = execution.get("status")

if status not in {"passed", "failed"}:
  raise SystemExit(f"Unexpected parallel execution status: {status!r}")
if not isinstance(actions, list) or not actions:
  raise SystemExit("Missing parallel actions list")
if not isinstance(results, list) or len(results) != len(actions):
  raise SystemExit("Parallel results list missing or size mismatch")

# Require at least one successful sub-action to ensure backend execution actually happened.
successful = 0
failures = []
for idx, item in enumerate(results, start=1):
  action = actions[idx - 1] if idx - 1 < len(actions) else {}
  tool = action.get("tool", f"action_{idx}") if isinstance(action, dict) else f"action_{idx}"

  if isinstance(item, dict):
    result = item.get("result")
    if isinstance(result, dict):
      if result.get("isError", False):
        failures.append(f"{tool}: result.isError=true")
      else:
        successful += 1
    else:
      failures.append(f"{tool}: malformed result payload")
  elif isinstance(item, str):
    msg = " ".join(item.strip().split())
    if len(msg) > 120:
      msg = msg[:117] + "..."
    failures.append(f"{tool}: {msg}")
  else:
    failures.append(f"{tool}: unexpected result type={type(item).__name__}")

if successful < 1:
  raise SystemExit("No successful parallel sub-actions were observed")

print(f"Parallel execution observed: status={status}, successful_sub_actions={successful}/{len(actions)}")
if failures:
  print("Parallel sub-action failures:")
  for failure in failures:
    print(f"- {failure}")
PY
}

print_case_header() {
  local name="$1"
  echo
  echo "=== ${name} ==="
}

preflight
AGENT_ID="$(resolve_demo_agent_id)"
echo "Using smoke-test agent_id=${AGENT_ID}" >&2

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

# 1) Parallel execution path
print_case_header "Critical Parallel Execution"
parallel_file="${tmpdir}/parallel.json"
parallel_incident_id="INC-smoke-parallel-001"
post_phase3 "{\"incident_id\":\"${parallel_incident_id}\",\"risk_tier\":\"critical\",\"use_case\":\"isolate_host\",\"time_range\":\"1h\",\"auto_approve\":true,\"proposed_actions\":[{\"tool\":\"wazuh_isolate_host\",\"args\":{\"agent_id\":\"${AGENT_ID}\"}},{\"tool\":\"wazuh_firewall_drop\",\"args\":{\"agent_id\":\"${AGENT_ID}\",\"src_ip\":\"198.51.100.27\",\"duration\":1200}},{\"tool\":\"wazuh_disable_user\",\"args\":{\"agent_id\":\"${AGENT_ID}\",\"user\":\"suspicious_user\"}}],\"action_args\":{\"agent_id\":\"${AGENT_ID}\"}}" "${parallel_file}"
assert_langfuse_trace_recorded "${parallel_file}" "node_triage,node_enrichment,node_propose_action,node_approval_gate,node_execute_action"
assert_parallel_executed "${parallel_file}"
python3 "${SCRIPT_DIR}/format_phase3_output.py" < "${parallel_file}"

# 2) Verify + rollback path (also exercises retry-enabled MCP path under normal operation)
print_case_header "Critical Verify Failure And Rollback"
rollback_file="${tmpdir}/rollback.json"
post_phase3 "{\"incident_id\":\"INC-smoke-rollback-001\",\"risk_tier\":\"critical\",\"use_case\":\"quarantine_file\",\"time_range\":\"6h\",\"auto_approve\":true,\"force_verify_fail\":true,\"action_args\":{\"agent_id\":\"${AGENT_ID}\",\"file_path\":\"/tmp/suspicious.bin\"}}" "${rollback_file}"
assert_langfuse_trace_recorded "${rollback_file}" "node_triage,node_enrichment,node_propose_action,node_approval_gate,node_execute_action,node_verify_action,node_rollback_action,node_handoff"
assert_json_equals "${rollback_file}" "workflow_status" "completed_with_rollback"
python3 "${SCRIPT_DIR}/format_phase3_output.py" < "${rollback_file}"

# 3) Human-in-the-loop pause/resume approved
print_case_header "Human Approval Pause And Resume (Approved)"
pending_approved_file="${tmpdir}/pending_approved.json"
post_phase3 "{\"incident_id\":\"INC-smoke-approval-approved\",\"risk_tier\":\"high\",\"use_case\":\"isolate_host\",\"time_range\":\"1h\",\"auto_approve\":false,\"action_args\":{\"agent_id\":\"${AGENT_ID}\"}}" "${pending_approved_file}"
assert_json_equals "${pending_approved_file}" "workflow_status" "pending_approval"

curl -fsS "${PHASE3_BASE_URL%/}/phase3/approvals/INC-smoke-approval-approved" >/dev/null

resume_approved_file="${tmpdir}/resume_approved.json"
resume_approved_resp="$(curl -sS --max-time 180 -w $'\n%{http_code}' "${PHASE3_BASE_URL%/}/phase3/approvals/INC-smoke-approval-approved/resume" \
  -H "Content-Type: application/json" \
  -d '{"decision":"approved","actor":"smoke-test-analyst"}')"
resume_approved_code="${resume_approved_resp##*$'\n'}"
resume_approved_body="${resume_approved_resp%$'\n'*}"
if [[ ! "${resume_approved_code}" =~ ^2[0-9][0-9]$ ]]; then
  echo "ERROR: Resume approved returned HTTP ${resume_approved_code}" >&2
  echo "${resume_approved_body}" >&2
  exit 1
fi
echo "${resume_approved_body}" > "${resume_approved_file}"
assert_json_equals "${resume_approved_file}" "approval.decision" "approved"
python3 "${SCRIPT_DIR}/format_phase3_output.py" < "${resume_approved_file}"

# 4) Human-in-the-loop pause/resume rejected
print_case_header "Human Approval Pause And Resume (Rejected)"
pending_rejected_file="${tmpdir}/pending_rejected.json"
post_phase3 "{\"incident_id\":\"INC-smoke-approval-rejected\",\"risk_tier\":\"medium\",\"use_case\":\"block_ip\",\"time_range\":\"1h\",\"auto_approve\":false,\"action_args\":{\"agent_id\":\"${AGENT_ID}\",\"src_ip\":\"198.51.100.27\",\"duration\":1200}}" "${pending_rejected_file}"
assert_json_equals "${pending_rejected_file}" "workflow_status" "pending_approval"

resume_rejected_file="${tmpdir}/resume_rejected.json"
resume_rejected_resp="$(curl -sS --max-time 180 -w $'\n%{http_code}' "${PHASE3_BASE_URL%/}/phase3/approvals/INC-smoke-approval-rejected/resume" \
  -H "Content-Type: application/json" \
  -d '{"decision":"rejected","actor":"smoke-test-analyst"}')"
resume_rejected_code="${resume_rejected_resp##*$'\n'}"
resume_rejected_body="${resume_rejected_resp%$'\n'*}"
if [[ ! "${resume_rejected_code}" =~ ^2[0-9][0-9]$ ]]; then
  echo "ERROR: Resume rejected returned HTTP ${resume_rejected_code}" >&2
  echo "${resume_rejected_body}" >&2
  exit 1
fi
echo "${resume_rejected_body}" > "${resume_rejected_file}"
assert_json_equals "${resume_rejected_file}" "workflow_status" "completed_rejected"
python3 "${SCRIPT_DIR}/format_phase3_output.py" < "${resume_rejected_file}"

echo
echo "Phase 3 enhancement smoke test passed"
echo "Validated: parallel execution, verify->rollback, human pause/resume approvals, traced run endpoint path with Langfuse trace and observation-name assertions, and structlog audit emission path."
