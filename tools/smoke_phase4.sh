#!/usr/bin/env bash

set -euo pipefail

PHASE4_BASE_URL="${PHASE4_BASE_URL:-http://localhost:8082}"
PHASE4_SOURCE_AGENT="${PHASE4_SOURCE_AGENT:-004}"
PHASE4_SOURCE_IP="${PHASE4_SOURCE_IP:-198.51.100.77}"
PHASE4_COMPROMISED_USER="${PHASE4_COMPROMISED_USER:-testuser}"
HEALTH_RETRIES="${PHASE4_HEALTH_RETRIES:-30}"
HEALTH_DELAY_SECONDS="${PHASE4_HEALTH_DELAY_SECONDS:-2}"
STRICT_PLAYBOOK_STATUS=true
EXPECT_ANALYTICS_200=true
OUTPUT_JSON=false
UI_PLAYWRIGHT_MODE="auto"
DISCOVERY_SMOKE_MODE="auto"

TOTAL=0
PASSED=0
FAILED=0

TMPDIR_SMOKE=""
LAST_RESPONSE_FILE=""

usage() {
  cat <<'EOF'
Usage: tools/smoke_phase4.sh [options]

Runs route-level Phase 4 smoke tests for:
- Core API health/root
- Incident routes (list + create)
- Playbook execution route
- Analytics routes
- ML routes
- Policy tuning UI browser regression (Playwright, auto mode)
- Discovery write-tool abuse alert regression (auto mode)

Options:
  --base-url URL                Phase 4 API base URL (default: http://localhost:8082)
  --agent-id ID                 Source agent ID for playbook execution (default: 004)
  --source-ip IP                Source IP for playbook context (default: 198.51.100.77)
  --compromised-user USER       Compromised username for playbook context (default: testuser)
  --allow-playbook-failed       Do not fail if playbook payload status is failed
  --allow-analytics-503         Accept analytics routes returning 503 (degraded mode)
  --with-ui-playwright          Require and run Playwright UI regression (fail on missing deps)
  --no-ui-playwright            Skip Playwright UI regression
  --with-discovery-smoke        Require and run discovery smoke script (write_tool_abuse)
  --no-discovery-smoke          Skip discovery smoke script
  --json                        Print JSON summary at the end
  -h, --help                    Show help

Environment:
  PHASE4_BASE_URL
  PHASE4_SOURCE_AGENT
  PHASE4_SOURCE_IP
  PHASE4_COMPROMISED_USER
  PHASE4_HEALTH_RETRIES
  PHASE4_HEALTH_DELAY_SECONDS
  PHASE4_UI_PLAYWRIGHT_MODE     auto|on|off (default: auto)
  PHASE4_DISCOVERY_SMOKE_MODE   auto|on|off (default: auto)
EOF
}

cleanup() {
  if [[ -n "${TMPDIR_SMOKE}" && -d "${TMPDIR_SMOKE}" ]]; then
    rm -rf "${TMPDIR_SMOKE}"
  fi
}

require_cmd() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "ERROR: Required command not found: ${cmd}" >&2
    exit 2
  fi
}

log_pass() {
  local name="$1"
  TOTAL=$((TOTAL + 1))
  PASSED=$((PASSED + 1))
  echo "PASS ${name}"
}

log_fail() {
  local name="$1"
  local message="$2"
  TOTAL=$((TOTAL + 1))
  FAILED=$((FAILED + 1))
  echo "FAIL ${name}: ${message}"
}

record_check() {
  local name="$1"
  local ok="$2"
  local details="$3"

  if [[ "${ok}" == "true" ]]; then
    log_pass "${name}"
  else
    log_fail "${name}" "${details}"
  fi
}

http_request() {
  local method="$1"
  local path="$2"
  local body="${3:-}"
  local out_file="$4"

  local url="${PHASE4_BASE_URL%/}${path}"
  local status

  if [[ "${method}" == "GET" ]]; then
    status="$(curl -sS -o "${out_file}" -w '%{http_code}' "${url}" || true)"
  else
    status="$(curl -sS -o "${out_file}" -w '%{http_code}' -X "${method}" -H 'Content-Type: application/json' -d "${body}" "${url}" || true)"
  fi

  echo "${status}"
}

json_field() {
  local file="$1"
  local path="$2"
  python3 - <<'PY' "${file}" "${path}"
import json
import sys

file_path = sys.argv[1]
path = sys.argv[2]

try:
    with open(file_path, 'r', encoding='utf-8') as fh:
        obj = json.load(fh)
except Exception:
    print("")
    raise SystemExit(0)

cur = obj
for part in path.split('.'):
    if isinstance(cur, dict) and part in cur:
        cur = cur[part]
    else:
        print("")
        raise SystemExit(0)

if cur is None:
    print("")
elif isinstance(cur, (dict, list)):
    print(json.dumps(cur))
else:
    print(str(cur))
PY
}

wait_for_health() {
  local health_file="${TMPDIR_SMOKE}/health_wait.json"
  local code="000"

  for ((i=1; i<=HEALTH_RETRIES; i++)); do
    code="$(http_request GET /health "" "${health_file}")"
    if [[ "${code}" == "200" ]]; then
      return 0
    fi
    echo "INFO waiting for health (${i}/${HEALTH_RETRIES}) status=${code}"
    sleep "${HEALTH_DELAY_SECONDS}"
  done

  return 1
}

run_preflight() {
  local base_host="${PHASE4_BASE_URL%/}"
  local preflight_failed=false

  if ! command -v docker >/dev/null 2>&1; then
    record_check "preflight.docker" "false" "docker CLI not found"
    echo "HINT start Docker Desktop (or install Docker CLI) before running smoke tests."
    return 1
  fi

  if ! docker info >/dev/null 2>&1; then
    record_check "preflight.docker" "false" "docker daemon/context not reachable"
    echo "HINT run: docker context ls ; then switch to a live context and start Docker Desktop."
    return 1
  fi

  record_check "preflight.docker" "true" "docker daemon reachable"

  # Only enforce container preflight for local runs against localhost.
  if [[ "${base_host}" == http://localhost* || "${base_host}" == http://127.0.0.1* ]]; then
    local running
    running="$(docker ps --format '{{.Names}}' | rg -n '^(phase4-api|mcp-security-proxy)$' -N || true)"
    if [[ -z "${running}" ]]; then
      record_check "preflight.containers" "false" "phase4-api and mcp-security-proxy are not running"
      echo "HINT start profile C first: bash tools/start-profile.sh C"

      # Diagnose common compose overlay misuse that causes undefined dependencies.
      if docker compose version >/dev/null 2>&1; then
        local compose_err=""
        compose_err="$(docker compose -f compose.phase4.yml config 2>&1 >/dev/null || true)"
        if [[ -z "${compose_err}" ]]; then
          compose_err="$(docker compose -f compose.yml -f compose.phase4.yml config 2>&1 >/dev/null || true)"
        fi

        if printf '%s\n' "${compose_err}" | grep -qiE 'depends on undefined service|invalid compose project'; then
          echo "HINT detected compose dependency error. Avoid running phase4 overlay alone."
          echo "HINT use the profile launcher instead: bash tools/start-profile.sh C"
          echo "HINT equivalent compose stack: -f compose.full.yml -f compose.phase3.langgraph.yml -f compose.phase4.yml -f compose.opencti.yml"
        fi
      fi

      preflight_failed=true
    else
      record_check "preflight.containers" "true" "required containers detected"
    fi
  else
    echo "INFO preflight.containers skipped (non-local base URL: ${PHASE4_BASE_URL%/})"
  fi

  if [[ "${preflight_failed}" == "true" ]]; then
    return 1
  fi

  return 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base-url)
      PHASE4_BASE_URL="$2"
      shift 2
      ;;
    --agent-id)
      PHASE4_SOURCE_AGENT="$2"
      shift 2
      ;;
    --source-ip)
      PHASE4_SOURCE_IP="$2"
      shift 2
      ;;
    --compromised-user)
      PHASE4_COMPROMISED_USER="$2"
      shift 2
      ;;
    --allow-playbook-failed)
      STRICT_PLAYBOOK_STATUS=false
      shift
      ;;
    --allow-analytics-503)
      EXPECT_ANALYTICS_200=false
      shift
      ;;
    --with-ui-playwright)
      UI_PLAYWRIGHT_MODE="on"
      shift
      ;;
    --no-ui-playwright)
      UI_PLAYWRIGHT_MODE="off"
      shift
      ;;
    --with-discovery-smoke)
      DISCOVERY_SMOKE_MODE="on"
      shift
      ;;
    --no-discovery-smoke)
      DISCOVERY_SMOKE_MODE="off"
      shift
      ;;
    --json)
      OUTPUT_JSON=true
      shift
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

if [[ -n "${PHASE4_UI_PLAYWRIGHT_MODE:-}" ]]; then
  UI_PLAYWRIGHT_MODE="${PHASE4_UI_PLAYWRIGHT_MODE}"
fi

if [[ -n "${PHASE4_DISCOVERY_SMOKE_MODE:-}" ]]; then
  DISCOVERY_SMOKE_MODE="${PHASE4_DISCOVERY_SMOKE_MODE}"
fi

require_cmd curl
require_cmd python3

TMPDIR_SMOKE="$(mktemp -d)"
trap cleanup EXIT

echo "INFO Phase 4 smoke starting"
echo "INFO base_url=${PHASE4_BASE_URL%/}"

echo "INFO running preflight checks"
if ! run_preflight; then
  echo
  echo "SUMMARY total=${TOTAL} passed=${PASSED} failed=${FAILED}"
  if [[ "${OUTPUT_JSON}" == "true" ]]; then
    python3 - <<'PY' "${TOTAL}" "${PASSED}" "${FAILED}"
import json
import sys
print(json.dumps({
    "total": int(sys.argv[1]),
    "passed": int(sys.argv[2]),
    "failed": int(sys.argv[3])
}, indent=2))
PY
  fi
  exit 1
fi

echo "INFO waiting for Phase 4 health"
if wait_for_health; then
  log_pass "health.wait"
else
  log_fail "health.wait" "service did not become healthy"
fi

# Core routes
LAST_RESPONSE_FILE="${TMPDIR_SMOKE}/health.json"
code="$(http_request GET /health "" "${LAST_RESPONSE_FILE}")"
record_check "core.health" "$( [[ "${code}" == "200" ]] && echo true || echo false )" "status=${code}"

LAST_RESPONSE_FILE="${TMPDIR_SMOKE}/root.json"
code="$(http_request GET / "" "${LAST_RESPONSE_FILE}")"
record_check "core.root" "$( [[ "${code}" == "200" ]] && echo true || echo false )" "status=${code}"

# Incidents routes
LAST_RESPONSE_FILE="${TMPDIR_SMOKE}/incidents_list.json"
code="$(http_request GET /incidents "" "${LAST_RESPONSE_FILE}")"
record_check "incidents.list" "$( [[ "${code}" == "200" ]] && echo true || echo false )" "status=${code}"

incident_title="Smoke Test Incident $(date -u +%Y%m%dT%H%M%SZ)"
incident_payload="{\"title\":\"${incident_title}\",\"description\":\"Phase 4 smoke\",\"risk_tier\":\"medium\",\"source_ip\":\"${PHASE4_SOURCE_IP}\"}"
LAST_RESPONSE_FILE="${TMPDIR_SMOKE}/incidents_create.json"
code="$(http_request POST /incidents "${incident_payload}" "${LAST_RESPONSE_FILE}")"
record_check "incidents.create" "$( [[ "${code}" == "200" ]] && echo true || echo false )" "status=${code}"

# Playbook route
playbook_payload="{\"source_agent\":\"${PHASE4_SOURCE_AGENT}\",\"source_ip\":\"${PHASE4_SOURCE_IP}\",\"compromised_user\":\"${PHASE4_COMPROMISED_USER}\"}"
LAST_RESPONSE_FILE="${TMPDIR_SMOKE}/playbook.json"
code="$(http_request POST /playbooks/ransomware/execute "${playbook_payload}" "${LAST_RESPONSE_FILE}")"
record_check "playbook.execute.http" "$( [[ "${code}" == "200" ]] && echo true || echo false )" "status=${code}"

if [[ "${code}" == "200" ]]; then
  pb_status="$(json_field "${LAST_RESPONSE_FILE}" status)"
  if [[ "${STRICT_PLAYBOOK_STATUS}" == "true" ]]; then
    record_check "playbook.execute.status" "$( [[ "${pb_status}" == "success" ]] && echo true || echo false )" "status_field=${pb_status}"
  else
    ok=false
    if [[ "${pb_status}" == "success" || "${pb_status}" == "failed" ]]; then
      ok=true
    fi
    record_check "playbook.execute.status" "${ok}" "status_field=${pb_status}"
  fi
fi

# Analytics routes
analytics_routes=(
  /analytics/sla-metrics
  /analytics/risk-distribution
  /analytics/workload
  /analytics/mttd
  /analytics/mttr
  '/analytics/trends?days=7'
  '/analytics/top-rules?limit=5'
  /analytics/false-positive-rate
)

for route in "${analytics_routes[@]}"; do
  safe_name="$(echo "${route}" | tr '/?=&' '____')"
  LAST_RESPONSE_FILE="${TMPDIR_SMOKE}/${safe_name}.json"
  code="$(http_request GET "${route}" "" "${LAST_RESPONSE_FILE}")"

  if [[ "${EXPECT_ANALYTICS_200}" == "true" ]]; then
    record_check "analytics.${route}" "$( [[ "${code}" == "200" ]] && echo true || echo false )" "status=${code}"
  else
    ok=false
    if [[ "${code}" == "200" || "${code}" == "503" ]]; then
      ok=true
    fi
    record_check "analytics.${route}" "${ok}" "status=${code}"
  fi
done

# ML routes
LAST_RESPONSE_FILE="${TMPDIR_SMOKE}/ml_status.json"
code="$(http_request GET /ml/status "" "${LAST_RESPONSE_FILE}")"
record_check "ml.status" "$( [[ "${code}" == "200" ]] && echo true || echo false )" "status=${code}"

LAST_RESPONSE_FILE="${TMPDIR_SMOKE}/ml_train.json"
code="$(http_request POST /ml/train '{}' "${LAST_RESPONSE_FILE}")"
record_check "ml.train" "$( [[ "${code}" == "200" ]] && echo true || echo false )" "status=${code}"

INFER_PAYLOAD="{\"alert_id\":\"smoke-infer-001\",\"agent_id\":\"${PHASE4_SOURCE_AGENT}\",\"rule_id\":5710,\"rule_severity\":8,\"rule_category\":20,\"src_ip\":\"${PHASE4_SOURCE_IP}\",\"dest_ip\":\"10.0.1.50\",\"contains_executable\":true,\"src_ip_reputation\":82.5,\"target_is_critical\":true,\"alert_frequency_per_hour\":12.0,\"zscore_volume\":2.1,\"entropy_rule_distribution\":1.6,\"geographic_anomaly\":true,\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
LAST_RESPONSE_FILE="${TMPDIR_SMOKE}/ml_infer.json"
code="$(http_request POST /ml/infer "${INFER_PAYLOAD}" "${LAST_RESPONSE_FILE}")"
if [[ "${code}" == "200" ]]; then
  infer_status="$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d.get('status',''))" "${LAST_RESPONSE_FILE}" 2>/dev/null || true)"
  record_check "ml.infer" "$( [[ "${infer_status}" == "success" ]] && echo true || echo false )" "status=${code} infer_status=${infer_status}"
elif [[ "${code}" == "409" ]]; then
  # Training may not have persisted in time; treat as non-fatal warning
  record_check "ml.infer" "false" "status=409 (models not fitted after train — check ml.train result)"
else
  record_check "ml.infer" "false" "status=${code}"
fi

# Policy tuning UI browser regression (Playwright)
if [[ "${UI_PLAYWRIGHT_MODE}" == "off" ]]; then
  echo "INFO ui.policy.playwright skipped (mode=off)"
else
  UI_TEST_PATH="tests/integration/test_phase4_policy_tuning_ui_playwright.py"
  UI_TEST_URL="${PHASE4_BASE_URL%/}/ui"
  if [[ ! -f "${UI_TEST_PATH}" ]]; then
    if [[ "${UI_PLAYWRIGHT_MODE}" == "on" ]]; then
      record_check "ui.policy.playwright" "false" "missing test file: ${UI_TEST_PATH}"
    else
      echo "INFO ui.policy.playwright skipped (test file missing: ${UI_TEST_PATH})"
    fi
  else
    PYTEST_RUNNER=""
    for candidate in ".venv/bin/python" "python3"; do
      if [[ "${candidate}" == "python3" ]]; then
        if ! command -v python3 >/dev/null 2>&1; then
          continue
        fi
      elif [[ ! -x "${candidate}" ]]; then
        continue
      fi

      set +e
      "${candidate}" -c "import playwright.sync_api" >/dev/null 2>&1
      HAS_PLAYWRIGHT=$?
      set -e
      if [[ "${HAS_PLAYWRIGHT}" -eq 0 ]]; then
        PYTEST_RUNNER="${candidate}"
        break
      fi
    done

    if [[ -z "${PYTEST_RUNNER}" ]]; then
      if [[ "${UI_PLAYWRIGHT_MODE}" == "on" ]]; then
        record_check "ui.policy.playwright" "false" "playwright not importable from .venv/bin/python or python3"
      else
        echo "INFO ui.policy.playwright skipped (playwright not importable in available interpreters)"
      fi
      UI_TEST_SUMMARY=""
      UI_TEST_RC=0
    else
      UI_TEST_OUTPUT="${TMPDIR_SMOKE}/ui_policy_playwright.out"
      set +e
      PHASE4_UI_URL="${UI_TEST_URL}" "${PYTEST_RUNNER}" -m pytest -q "${UI_TEST_PATH}" >"${UI_TEST_OUTPUT}" 2>&1
      UI_TEST_RC=$?
      set -e

      UI_TEST_SUMMARY="$(tail -n 3 "${UI_TEST_OUTPUT}" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g' | sed 's/^ //;s/ $//')"
      if [[ "${UI_TEST_RC}" -eq 0 ]]; then
        if grep -qi "skipped" "${UI_TEST_OUTPUT}"; then
          if [[ "${UI_PLAYWRIGHT_MODE}" == "on" ]]; then
            record_check "ui.policy.playwright" "false" "test skipped in required mode: ${UI_TEST_SUMMARY}"
          else
            record_check "ui.policy.playwright" "true" "auto mode: ${UI_TEST_SUMMARY}"
          fi
        else
          record_check "ui.policy.playwright" "true" "${UI_TEST_SUMMARY}"
        fi
      else
        record_check "ui.policy.playwright" "false" "${UI_TEST_SUMMARY}"
      fi
    fi

  fi
fi

# Discovery write-tool abuse smoke
if [[ "${DISCOVERY_SMOKE_MODE}" == "off" ]]; then
  echo "INFO discovery.write_tool_abuse skipped (mode=off)"
else
  DISCOVERY_TEST_PATH="tools/test_discovery_write_tool_abuse.sh"
  if [[ ! -f "${DISCOVERY_TEST_PATH}" ]]; then
    if [[ "${DISCOVERY_SMOKE_MODE}" == "on" ]]; then
      record_check "discovery.write_tool_abuse" "false" "missing test file: ${DISCOVERY_TEST_PATH}"
    else
      echo "INFO discovery.write_tool_abuse skipped (test file missing: ${DISCOVERY_TEST_PATH})"
    fi
  elif ! command -v jq >/dev/null 2>&1; then
    if [[ "${DISCOVERY_SMOKE_MODE}" == "on" ]]; then
      record_check "discovery.write_tool_abuse" "false" "jq not found"
    else
      echo "INFO discovery.write_tool_abuse skipped (jq not found)"
    fi
  else
    # Best-effort cleanup so stale alerts/cooldowns do not affect the assertion window.
    curl -sS -X POST "${PHASE4_BASE_URL%/}/soc/proxy-discovery-alerts/clear" \
      -H 'Content-Type: application/json' \
      -d '{"reset_cooldown":true}' >/dev/null 2>&1 || true

    DISCOVERY_TEST_OUTPUT="${TMPDIR_SMOKE}/discovery_write_tool_abuse.out"
    set +e
    bash "${DISCOVERY_TEST_PATH}" >"${DISCOVERY_TEST_OUTPUT}" 2>&1
    DISCOVERY_TEST_RC=$?
    set -e

    DISCOVERY_TEST_SUMMARY="$(tail -n 4 "${DISCOVERY_TEST_OUTPUT}" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g' | sed 's/^ //;s/ $//')"

    if [[ "${DISCOVERY_TEST_RC}" -eq 0 ]]; then
      record_check "discovery.write_tool_abuse" "true" "${DISCOVERY_TEST_SUMMARY}"
    else
      if [[ "${DISCOVERY_SMOKE_MODE}" == "on" ]]; then
        record_check "discovery.write_tool_abuse" "false" "${DISCOVERY_TEST_SUMMARY}"
      else
        # auto mode: skip hard-failure when proxy endpoint is not reachable
        if grep -qiE 'Failed to connect|Could not connect|Connection refused|proxy unreachable' "${DISCOVERY_TEST_OUTPUT}"; then
          echo "INFO discovery.write_tool_abuse skipped (proxy unreachable in auto mode)"
        else
          record_check "discovery.write_tool_abuse" "false" "${DISCOVERY_TEST_SUMMARY}"
        fi
      fi
    fi
  fi
fi

echo
echo "SUMMARY total=${TOTAL} passed=${PASSED} failed=${FAILED}"

if [[ "${OUTPUT_JSON}" == "true" ]]; then
  python3 - <<'PY' "${TOTAL}" "${PASSED}" "${FAILED}"
import json
import sys
print(json.dumps({
    "total": int(sys.argv[1]),
    "passed": int(sys.argv[2]),
    "failed": int(sys.argv[3])
}, indent=2))
PY
fi

if [[ "${FAILED}" -gt 0 ]]; then
  exit 1
fi

exit 0
