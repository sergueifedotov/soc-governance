#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

MCP_BASE_URL="${MCP_BASE_URL:-http://localhost:3000}"
TIME_RANGE="${PHASE2_DEMO_TIME_RANGE:-24h}"
MIN_LEVEL="${PHASE2_DEMO_MIN_LEVEL:-7}"
TRIAGE_LIMIT="${PHASE2_DEMO_TRIAGE_LIMIT:-10}"
ENRICH_LIMIT="${PHASE2_DEMO_ENRICH_LIMIT:-10}"
ENRICH_QUERY="${PHASE2_DEMO_ENRICH_QUERY:-sqlmap OR nikto OR wp-login.php}"
REPORT_TYPE="${PHASE2_DEMO_REPORT_TYPE:-shift}"
INCLUDE_AGENT_HEALTH="${PHASE2_DEMO_INCLUDE_AGENT_HEALTH:-true}"
INCLUDE_RECOMMENDATIONS="${PHASE2_DEMO_INCLUDE_RECOMMENDATIONS:-true}"

usage() {
  cat <<'EOF'
Usage: tools/demo_phase2_orchestration.sh [options]

Runs a Phase 2 read-only orchestration demo across:
  1) triage_wazuh_alerts
  2) enrich_wazuh_context
  3) generate_soc_handoff_report

Options:
  --base-url URL                MCP server base URL (default: http://localhost:3000)
  --time-range RANGE            Time range for calls (default: 24h)
  --min-level N                 Triage minimum severity level (default: 7)
  --triage-limit N              Triage alert limit (default: 10)
  --enrich-limit N              Enrichment alert limit (default: 10)
  --enrich-query QUERY          Enrichment search query
  --report-type TYPE            shift|daily|incident (default: shift)
  --include-agent-health BOOL   true|false (default: true)
  --include-recommendations BOOL true|false (default: true)
  -h, --help                    Show this help message

Environment:
  MCP_API_KEY                         Bearer key for MCP calls (fallback: .env)
  MCP_BASE_URL                        Same as --base-url
  PHASE2_DEMO_TIME_RANGE              Same as --time-range
  PHASE2_DEMO_MIN_LEVEL               Same as --min-level
  PHASE2_DEMO_TRIAGE_LIMIT            Same as --triage-limit
  PHASE2_DEMO_ENRICH_LIMIT            Same as --enrich-limit
  PHASE2_DEMO_ENRICH_QUERY            Same as --enrich-query
  PHASE2_DEMO_REPORT_TYPE             Same as --report-type
  PHASE2_DEMO_INCLUDE_AGENT_HEALTH    Same as --include-agent-health
  PHASE2_DEMO_INCLUDE_RECOMMENDATIONS Same as --include-recommendations

Examples:
  tools/demo_phase2_orchestration.sh
  tools/demo_phase2_orchestration.sh --time-range 1h --min-level 3 --triage-limit 5
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base-url)
      MCP_BASE_URL="$2"
      shift 2
      ;;
    --time-range)
      TIME_RANGE="$2"
      shift 2
      ;;
    --min-level)
      MIN_LEVEL="$2"
      shift 2
      ;;
    --triage-limit)
      TRIAGE_LIMIT="$2"
      shift 2
      ;;
    --enrich-limit)
      ENRICH_LIMIT="$2"
      shift 2
      ;;
    --enrich-query)
      ENRICH_QUERY="$2"
      shift 2
      ;;
    --report-type)
      REPORT_TYPE="$2"
      shift 2
      ;;
    --include-agent-health)
      INCLUDE_AGENT_HEALTH="$2"
      shift 2
      ;;
    --include-recommendations)
      INCLUDE_RECOMMENDATIONS="$2"
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

if ! command -v curl >/dev/null 2>&1; then
  echo "Missing required command: curl" >&2
  exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "Missing required command: python3" >&2
  exit 2
fi

MCP_BASE_URL="${MCP_BASE_URL%/}"

if [[ -z "${MCP_API_KEY:-}" && -f "${REPO_ROOT}/.env" ]]; then
  MCP_API_KEY="$(grep '^MCP_API_KEY=' "${REPO_ROOT}/.env" | cut -d= -f2- || true)"
fi

if [[ -z "${MCP_API_KEY:-}" ]]; then
  echo "MCP_API_KEY is not set and was not found in .env" >&2
  exit 2
fi

echo "[0/4] Health check: ${MCP_BASE_URL}/health"
curl -fsS --max-time 10 "${MCP_BASE_URL}/health" >/dev/null

echo "[1/4] Phase 2 triage"
TRIAGE_PAYLOAD=$(cat <<JSON
{"jsonrpc":"2.0","id":"phase2-demo-triage","method":"tools/call","params":{"name":"triage_wazuh_alerts","arguments":{"time_range":"${TIME_RANGE}","min_level":${MIN_LEVEL},"limit":${TRIAGE_LIMIT},"include_agent_health":${INCLUDE_AGENT_HEALTH}}}}
JSON
)

TRIAGE_RESPONSE="$(curl -fsS --max-time 180 "${MCP_BASE_URL}/" \
  -H "Authorization: Bearer ${MCP_API_KEY}" \
  -H "Content-Type: application/json" \
  -d "${TRIAGE_PAYLOAD}")"

echo "${TRIAGE_RESPONSE}" | python3 -c '
import json, re, sys
raw = json.load(sys.stdin)
result = raw.get("result", {})
if result.get("isError"):
    text = ((result.get("content") or [{}])[0] or {}).get("text", "")
    print("triage_error=" + text[:400])
    raise SystemExit(3)
text = ((result.get("content") or [{}])[0] or {}).get("text", "")
m = re.search(r"\{[\s\S]*\}\s*$", text)
if not m:
    print("triage_error=missing payload")
    raise SystemExit(4)
payload = json.loads(m.group(0)).get("data", {})
orc = payload.get("orchestration", {})
print("triage_engine=" + str(orc.get("engine")))
print("triage_status=" + str(orc.get("status")))
print("triage_model=" + str(orc.get("model")))
print("triage_total_alerts=" + str(payload.get("total_alerts")))
print("triage_top_rules=" + str(len(payload.get("top_rules") or [])))
print("triage_analysis_preview=" + str(payload.get("analysis", ""))[:180])
'

echo "[2/4] Phase 2 enrichment"
ENRICH_PAYLOAD=$(cat <<JSON
{"jsonrpc":"2.0","id":"phase2-demo-enrich","method":"tools/call","params":{"name":"enrich_wazuh_context","arguments":{"time_range":"${TIME_RANGE}","limit":${ENRICH_LIMIT},"query":"${ENRICH_QUERY}"}}}
JSON
)

ENRICH_RESPONSE="$(curl -fsS --max-time 180 "${MCP_BASE_URL}/" \
  -H "Authorization: Bearer ${MCP_API_KEY}" \
  -H "Content-Type: application/json" \
  -d "${ENRICH_PAYLOAD}")"

echo "${ENRICH_RESPONSE}" | python3 -c '
import json, re, sys
raw = json.load(sys.stdin)
result = raw.get("result", {})
if result.get("isError"):
    text = ((result.get("content") or [{}])[0] or {}).get("text", "")
    print("enrich_error=" + text[:400])
    raise SystemExit(3)
text = ((result.get("content") or [{}])[0] or {}).get("text", "")
m = re.search(r"\{[\s\S]*\}\s*$", text)
if not m:
    print("enrich_error=missing payload")
    raise SystemExit(4)
payload = json.loads(m.group(0)).get("data", {})
orc = payload.get("orchestration", {})
print("enrich_engine=" + str(orc.get("engine")))
print("enrich_status=" + str(orc.get("status")))
print("enrich_match_count=" + str(payload.get("match_count")))
print("enrich_filters=" + str(payload.get("filters")))
print("enrich_analysis_preview=" + str(payload.get("analysis", ""))[:180])
'

echo "[3/4] Phase 2 SOC handoff report"
REPORT_PAYLOAD=$(cat <<JSON
{"jsonrpc":"2.0","id":"phase2-demo-report","method":"tools/call","params":{"name":"generate_soc_handoff_report","arguments":{"report_type":"${REPORT_TYPE}","time_range":"${TIME_RANGE}","include_recommendations":${INCLUDE_RECOMMENDATIONS}}}}
JSON
)

REPORT_RESPONSE="$(curl -fsS --max-time 180 "${MCP_BASE_URL}/" \
  -H "Authorization: Bearer ${MCP_API_KEY}" \
  -H "Content-Type: application/json" \
  -d "${REPORT_PAYLOAD}")"

echo "${REPORT_RESPONSE}" | python3 -c '
import json, re, sys
raw = json.load(sys.stdin)
result = raw.get("result", {})
if result.get("isError"):
    text = ((result.get("content") or [{}])[0] or {}).get("text", "")
    print("report_error=" + text[:400])
    raise SystemExit(3)
text = ((result.get("content") or [{}])[0] or {}).get("text", "")
m = re.search(r"\{[\s\S]*\}\s*$", text)
if not m:
    print("report_error=missing payload")
    raise SystemExit(4)
payload = json.loads(m.group(0)).get("data", {})
orc = payload.get("orchestration", {})
print("report_engine=" + str(orc.get("engine")))
print("report_status=" + str(orc.get("status")))
print("report_type=" + str(payload.get("report_type")))
print("report_sections=" + str(len(payload.get("sections") or {})))
print("report_analysis_preview=" + str(payload.get("analysis", ""))[:180])
'

echo "[4/4] Phase 2 orchestration demo completed"
