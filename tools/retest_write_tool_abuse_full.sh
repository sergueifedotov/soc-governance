#!/usr/bin/env bash

set -euo pipefail

PHASE4_BASE_URL="${PHASE4_BASE_URL:-http://localhost:8082}"
PROXY_BASE_URL="${PROXY_BASE_URL:-http://localhost:8090}"
RUN_UI_CHECK=false

usage() {
  cat <<'EOF'
Usage: bash tools/retest_write_tool_abuse_full.sh [options]

Runs full write_tool_abuse re-test in one command:
1) Accept auto-apply flow re-test (remove -> accept -> verify re-added)
2) Discovery trigger test (3 denied write-tool calls -> verify alert)

Options:
  --phase4-base-url URL   Phase 4 base URL (default: http://localhost:8082)
  --proxy-base-url URL    MCP proxy base URL (default: http://localhost:8090)
  --ui-check              Pass through UI check to accept-flow script
  -h, --help              Show help

Environment:
  PHASE4_BASE_URL
  PROXY_BASE_URL
  MCP_PROXY_API_KEY
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --phase4-base-url)
      PHASE4_BASE_URL="$2"
      shift 2
      ;;
    --proxy-base-url)
      PROXY_BASE_URL="$2"
      shift 2
      ;;
    --ui-check)
      RUN_UI_CHECK=true
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

echo "INFO: full write_tool_abuse re-test started"
echo "INFO: phase4_base_url=${PHASE4_BASE_URL%/}"
echo "INFO: proxy_base_url=${PROXY_BASE_URL%/}"

ACCEPT_ARGS=(
  --base-url "${PHASE4_BASE_URL%/}"
)
if [[ "${RUN_UI_CHECK}" == "true" ]]; then
  ACCEPT_ARGS+=(--ui-check)
fi

echo "INFO: step 1/2: running Accept auto-apply re-test"
bash tools/retest_write_tool_abuse_accept_flow.sh "${ACCEPT_ARGS[@]}"

echo "INFO: step 2/2: running discovery trigger verification"
PROXY_BASE_URL="${PROXY_BASE_URL%/}" bash tools/test_discovery_write_tool_abuse.sh

echo "PASS: full write_tool_abuse re-test succeeded"