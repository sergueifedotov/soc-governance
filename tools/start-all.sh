#!/usr/bin/env bash
# Start all SOC stack components: Phases 1-4 + Langfuse tracing
# Optionally also the OpenCTI threat intelligence overlay.
#
# Includes the MCP traffic observability stack (Prometheus scrape of
# wazuh-mcp-server:/metrics + provisioned Grafana dashboard "MCP Agent
# Traffic", uid mcp-agent-traffic). See docs/MCP_OBSERVABILITY.md.
#
# Usage:
#   bash tools/start-all.sh [--no-build] [--with-opencti] [--no-langfuse] [--test-reverse-flow]
#
# Flags:
#   --no-build       Skip `docker compose --build` (use existing images)
#   --no-langfuse    Omit compose.langfuse.oss.yml (saves ~1 GB RAM on dev machines)
#   --with-opencti   Also start compose.opencti.yml (OpenCTI platform + worker +
#                    STIX2 file-import connector).  See docs/OPENCTI_INTEGRATION.md.
#   --test-reverse-flow  Run tools/test_mcp_reverse_flow.sh after startup.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

start_mcp_proxy_stack() {
  local build_flag="$1"
  local mcp_compose=(
    -f mcp-security-proxy/docker-compose.yml
    -f mcp-security-proxy/docker-compose.phase4.yml
    -f mcp-security-proxy/docker-compose.isolated-executor.yml
  )
  docker compose "${mcp_compose[@]}" up -d ${build_flag}
}

BUILD_FLAG="--build"
WITH_OPENCTI=0
WITH_LANGFUSE=1
TEST_REVERSE_FLOW=0
for arg in "$@"; do
  case "$arg" in
    --no-build)     BUILD_FLAG="" ;;
    --no-langfuse)  WITH_LANGFUSE=0 ;;
    --with-opencti) WITH_OPENCTI=1 ;;
    --test-reverse-flow) TEST_REVERSE_FLOW=1 ;;
    -h|--help)
      sed -n '2,12p' "$0"
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      echo "Usage: $0 [--no-build] [--no-langfuse] [--with-opencti] [--test-reverse-flow]" >&2
      exit 2
      ;;
  esac
done

if [[ "${WITH_LANGFUSE}" -eq 1 ]]; then
  export LANGFUSE_ENABLED=true
  export LANGFUSE_PUBLIC_KEY="${LANGFUSE_PUBLIC_KEY:-pk-local-smoke}"
  export LANGFUSE_SECRET_KEY="${LANGFUSE_SECRET_KEY:-sk-local-smoke}"
fi

COMPOSE_FILES=(
  -f compose.full.yml
  -f compose.phase3.langgraph.yml
  -f compose.phase4.yml
)
if [[ "${WITH_LANGFUSE}" -eq 1 ]]; then
  COMPOSE_FILES+=( -f compose.langfuse.oss.yml )
fi
if [[ "${WITH_OPENCTI}" -eq 1 ]]; then
  COMPOSE_FILES+=( -f compose.opencti.yml )
fi

echo "Starting all components (Phases 1-4$( [[ $WITH_LANGFUSE -eq 1 ]] && echo ' + Langfuse' )$( [[ $WITH_OPENCTI -eq 1 ]] && echo ' + OpenCTI' ))..."
[[ "${WITH_LANGFUSE}" -eq 1 ]] && echo "  LANGFUSE_ENABLED=${LANGFUSE_ENABLED}" && echo "  LANGFUSE_PUBLIC_KEY=${LANGFUSE_PUBLIC_KEY}"
[[ "${WITH_OPENCTI}" -eq 1 ]] && echo "  OpenCTI overlay: ENABLED"
echo ""

docker compose "${COMPOSE_FILES[@]}" up -d ${BUILD_FLAG}
start_mcp_proxy_stack "${BUILD_FLAG}"

echo ""
echo "Stack is up. Key URLs:"
echo "  Wazuh Dashboard   https://localhost:8443"
echo "  Wazuh MCP Server  http://localhost:3000"
echo "  MCP Proxy         http://localhost:8090/ui"
echo "  Open WebUI        http://localhost:3100"
echo "  Phase 3 API       http://localhost:8081"
echo "  Phase 4 API       http://localhost:8082/docs"
[[ "${WITH_LANGFUSE}" -eq 1 ]] && echo "  Langfuse UI       http://localhost:3001  (local-admin@example.com / local-admin-password)"
echo "  Prefect UI        http://localhost:4200"
echo "  MLflow UI         http://localhost:5001"
echo "  Prometheus        http://localhost:9091"
echo "  Grafana           http://localhost:3002  (admin / \${GRAFANA_PASSWORD:-admin})"
echo ""
echo "MCP traffic observability (per-call metrics persisted in Prometheus,"
echo "visualised in Grafana; see docs/MCP_OBSERVABILITY.md):"
echo "  Grafana dashboard http://localhost:3002/d/mcp-agent-traffic/mcp-agent-traffic"
echo "  Live feed (5s)    http://localhost:3002/d/mcp-agent-traffic-live/mcp-agent-traffic-live"
echo "  Redirect          http://localhost:3000/observability/ui  (302 -> Grafana)"
echo "  Legacy in-page UI http://localhost:3000/observability/ui/legacy?token=\${MCP_API_KEY}"
echo "  Live SSE feed     http://localhost:3000/observability/stream"
echo "  JSON stats        http://localhost:3000/observability/stats"
echo "  Prometheus metrics http://localhost:3000/metrics  (wazuh_mcp_calls_total, ...)"
echo "  Bearer token      run 'source tools/mcp_api_key.sh --quiet' to export \$MCP_API_KEY"
if [[ "${WITH_OPENCTI}" -eq 1 ]]; then
  echo ""
  echo "  OpenCTI UI        http://localhost:8083  (\${OPENCTI_ADMIN_EMAIL} / \${OPENCTI_ADMIN_PASSWORD} in .env)"
fi

if [[ "${TEST_REVERSE_FLOW}" -eq 1 ]]; then
  echo ""
  echo "Running reverse-flow MCP smoke test..."
  if [[ -x "tools/test_mcp_reverse_flow.sh" ]]; then
    tools/test_mcp_reverse_flow.sh
  else
    bash tools/test_mcp_reverse_flow.sh
  fi
fi
