#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

ALLOW_DETERMINISTIC=false
MCP_BASE_URL="${MCP_BASE_URL:-http://localhost:3000}"
TIME_RANGE="${PHASE2_TEST_TIME_RANGE:-24h}"
MIN_LEVEL="${PHASE2_TEST_MIN_LEVEL:-10}"
LIMIT="${PHASE2_TEST_LIMIT:-20}"
INCLUDE_AGENT_HEALTH="${PHASE2_TEST_INCLUDE_AGENT_HEALTH:-true}"

usage() {
  cat <<'EOF'
Usage: tools/verify_phase2_langchain.sh [options]

Options:
  --allow-deterministic   Accept deterministic fallback as success
  --base-url URL          MCP server base URL (default: http://localhost:3000)
  -h, --help              Show this help message

Environment overrides:
  MCP_API_KEY                     Bearer key for MCP calls (fallback: .env)
  PHASE2_TEST_TIME_RANGE          Default: 24h
  PHASE2_TEST_MIN_LEVEL           Default: 10
  PHASE2_TEST_LIMIT               Default: 20
  PHASE2_TEST_INCLUDE_AGENT_HEALTH Default: true

Exit codes:
  0 success
  2 missing dependencies or config
  3 request/response failure
  4 unexpected payload format
  5 engine mismatch (expected langchain)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --allow-deterministic)
      ALLOW_DETERMINISTIC=true
      shift
      ;;
    --base-url)
      MCP_BASE_URL="$2"
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

echo "[1/3] Checking MCP health at ${MCP_BASE_URL}/health"
HEALTH_JSON="$(curl -fsS --max-time 10 "${MCP_BASE_URL}/health")" || {
  echo "Failed to reach MCP health endpoint" >&2
  exit 3
}

echo "${HEALTH_JSON}" | python3 -c 'import json,sys; data=json.load(sys.stdin); print("Health OK") if data.get("status") == "healthy" else (_ for _ in ()).throw(SystemExit(3))'

echo "[2/3] Calling triage_wazuh_alerts"
PAYLOAD=$(cat <<JSON
{"jsonrpc":"2.0","id":"phase2-verify","method":"tools/call","params":{"name":"triage_wazuh_alerts","arguments":{"time_range":"${TIME_RANGE}","min_level":${MIN_LEVEL},"limit":${LIMIT},"include_agent_health":${INCLUDE_AGENT_HEALTH}}}}
JSON
)

RESPONSE_JSON="$(curl -fsS --max-time 180 "${MCP_BASE_URL}/" \
  -H "Authorization: Bearer ${MCP_API_KEY}" \
  -H "Content-Type: application/json" \
  -d "${PAYLOAD}")" || {
  echo "Failed to call tools/call" >&2
  exit 3
}

echo "[3/3] Validating orchestration payload"
ENGINE_EXPECTATION="langchain"
if [[ "${ALLOW_DETERMINISTIC}" == "true" ]]; then
  ENGINE_EXPECTATION="langchain_or_deterministic"
fi

echo "${RESPONSE_JSON}" | ENGINE_EXPECTATION="${ENGINE_EXPECTATION}" python3 -c '
import json
import os
import sys

raw = json.load(sys.stdin)
result = raw.get("result", {})
if result.get("isError"):
  text = ""
  content = result.get("content", [])
  if content and isinstance(content[0], dict):
    text = content[0].get("text", "")
  print("Tool call returned error:", text[:600])
  raise SystemExit(3)

content = result.get("content", [])
if not content or not isinstance(content[0], dict):
  print("Missing result content")
  raise SystemExit(4)

text = content[0].get("text", "")
start = text.find("{")
if start < 0:
  print("Could not find JSON payload in result text")
  raise SystemExit(4)

payload = json.loads(text[start:])
data = payload.get("data", {})
orchestration = data.get("orchestration", {})
engine = orchestration.get("engine")
status = orchestration.get("status")
model = orchestration.get("model")
analysis = data.get("analysis", "")

print(f"engine={engine}")
print(f"status={status}")
print(f"model={model}")
print("analysis_preview=" + str(analysis)[:220])

if not analysis:
  print("analysis is empty")
  raise SystemExit(4)

expectation = os.getenv("ENGINE_EXPECTATION", "langchain")
if expectation == "langchain" and engine != "langchain":
  print("Expected engine=langchain")
  raise SystemExit(5)

if expectation == "langchain_or_deterministic" and engine not in {"langchain", "deterministic"}:
  print("Expected engine to be langchain or deterministic")
  raise SystemExit(5)

print("Phase 2 verifier passed")
'
