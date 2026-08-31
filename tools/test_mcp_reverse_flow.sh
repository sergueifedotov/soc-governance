#!/usr/bin/env bash
set -u

# Smoke-test script for MCP reverse-flow read tools.
# Validates tool registration and basic execution paths.

MCP_URL="${MCP_URL:-http://localhost:3000/mcp}"
MCP_KEY="${MCP_KEY:-${MCP_API_KEY:-wazuh_local_demo_change_me}}"

PASS=0
FAIL=0
SKIP=0

log() {
  printf "%s\n" "$*"
}

pass() {
  PASS=$((PASS + 1))
  log "PASS: $*"
}

fail() {
  FAIL=$((FAIL + 1))
  log "FAIL: $*"
}

skip() {
  SKIP=$((SKIP + 1))
  log "SKIP: $*"
}

require_bin() {
  local bin="$1"
  if ! command -v "$bin" >/dev/null 2>&1; then
    log "ERROR: required binary not found: $bin"
    exit 2
  fi
}

rpc_call() {
  local body="$1"
  curl -sS \
    -H "Authorization: Bearer ${MCP_KEY}" \
    -H "Content-Type: application/json" \
    "$MCP_URL" \
    -d "$body"
}

tool_call() {
  local id="$1"
  local name="$2"
  local args_json="$3"
  rpc_call "{\"jsonrpc\":\"2.0\",\"id\":\"${id}\",\"method\":\"tools/call\",\"params\":{\"name\":\"${name}\",\"arguments\":${args_json}}}"
}

check_tool_success() {
  local resp="$1"
  echo "$resp" | jq -e '.result.isError == false' >/dev/null 2>&1
}

check_tool_error() {
  local resp="$1"
  echo "$resp" | jq -e '.result.isError == true' >/dev/null 2>&1
}

extract_tool_text() {
  local resp="$1"
  echo "$resp" | jq -r '.result.content[0].text // ""'
}

require_bin curl
require_bin jq

log "=== MCP Reverse Flow Smoke Test ==="
log "MCP_URL=${MCP_URL}"

# 1) Health
health_resp="$(curl -sS http://localhost:3000/health || true)"
if echo "$health_resp" | jq -e '.status == "healthy"' >/dev/null 2>&1; then
  pass "MCP health endpoint"
else
  fail "MCP health endpoint"
  log "  Response: ${health_resp}"
fi

# 2) tools/list contains expected tools
list_resp="$(rpc_call '{"jsonrpc":"2.0","id":"list-1","method":"tools/list","params":{}}' || true)"
if [ -z "$list_resp" ]; then
  fail "tools/list returned empty response"
else
  expected_tools=(
    opencti_check_status
    opencti_sync_alerts
    opencti_query_indicators
    opencti_get_incident
    opencti_list_cases
    opencti_get_observable
    neo4j_attack_chain
    neo4j_lateral_movement
    neo4j_ip_context
    neo4j_query
  )

  for tool in "${expected_tools[@]}"; do
    if echo "$list_resp" | jq -e --arg t "$tool" '.result.tools[].name | select(. == $t)' >/dev/null 2>&1; then
      pass "tools/list includes ${tool}"
    else
      fail "tools/list missing ${tool}"
    fi
  done
fi

# 3) opencti_check_status
resp_opencti_status="$(tool_call "call-1" "opencti_check_status" '{}' || true)"
if check_tool_success "$resp_opencti_status"; then
  pass "opencti_check_status call"
else
  fail "opencti_check_status call"
  log "  Response: ${resp_opencti_status}"
fi

# 4) opencti_list_cases
resp_opencti_cases="$(tool_call "call-2" "opencti_list_cases" '{"hours":24,"limit":3}' || true)"
if check_tool_success "$resp_opencti_cases"; then
  pass "opencti_list_cases call"
else
  fail "opencti_list_cases call"
  log "  Response: ${resp_opencti_cases}"
fi

# 5) opencti_query_indicators
resp_opencti_query="$(tool_call "call-3" "opencti_query_indicators" '{"value":"198.51.100.42","limit":5}' || true)"
if check_tool_success "$resp_opencti_query"; then
  pass "opencti_query_indicators call"
else
  fail "opencti_query_indicators call"
  log "  Response: ${resp_opencti_query}"
fi

# 6) opencti_get_observable
resp_opencti_observable="$(tool_call "call-4" "opencti_get_observable" '{"value":"198.51.100.42"}' || true)"
if check_tool_success "$resp_opencti_observable"; then
  pass "opencti_get_observable call"
else
  fail "opencti_get_observable call"
  log "  Response: ${resp_opencti_observable}"
fi

# 7) opencti_get_incident (best effort: use first case id if available)
case_text="$(extract_tool_text "$resp_opencti_cases")"
case_id="$(echo "$case_text" | jq -r '.cases[0].id // empty' 2>/dev/null || true)"
if [ -n "$case_id" ]; then
  resp_opencti_incident="$(tool_call "call-5" "opencti_get_incident" "{\"stix_id\":\"${case_id}\"}" || true)"
  if check_tool_success "$resp_opencti_incident"; then
    pass "opencti_get_incident call"
  else
    fail "opencti_get_incident call"
    log "  Response: ${resp_opencti_incident}"
  fi
else
  skip "opencti_get_incident call (no case id available from opencti_list_cases)"
fi

# 8) neo4j_attack_chain
resp_neo_attack="$(tool_call "call-6" "neo4j_attack_chain" '{"ip":"198.51.100.42","max_hops":3}' || true)"
if check_tool_success "$resp_neo_attack"; then
  pass "neo4j_attack_chain call"
else
  fail "neo4j_attack_chain call"
  log "  Response: ${resp_neo_attack}"
fi

# 9) neo4j_lateral_movement
resp_neo_lateral="$(tool_call "call-7" "neo4j_lateral_movement" '{"hours":24,"min_machines":2}' || true)"
if check_tool_success "$resp_neo_lateral"; then
  pass "neo4j_lateral_movement call"
else
  fail "neo4j_lateral_movement call"
  log "  Response: ${resp_neo_lateral}"
fi

# 10) neo4j_ip_context
resp_neo_ip="$(tool_call "call-8" "neo4j_ip_context" '{"ip":"198.51.100.42"}' || true)"
if check_tool_success "$resp_neo_ip"; then
  pass "neo4j_ip_context call"
else
  fail "neo4j_ip_context call"
  log "  Response: ${resp_neo_ip}"
fi

# 11) neo4j_query read-only success
resp_neo_query_ok="$(tool_call "call-9" "neo4j_query" '{"cypher":"RETURN 1 AS ok"}' || true)"
if check_tool_success "$resp_neo_query_ok"; then
  pass "neo4j_query read-only call"
else
  fail "neo4j_query read-only call"
  log "  Response: ${resp_neo_query_ok}"
fi

# 12) neo4j_query write-blocking
resp_neo_query_block="$(tool_call "call-10" "neo4j_query" '{"cypher":"MERGE (n:TEST {id: 1}) RETURN n"}' || true)"
if check_tool_error "$resp_neo_query_block"; then
  pass "neo4j_query write-blocking"
else
  fail "neo4j_query write-blocking"
  log "  Response: ${resp_neo_query_block}"
fi

log ""
log "=== Summary ==="
log "PASS=${PASS} FAIL=${FAIL} SKIP=${SKIP}"

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

exit 0
