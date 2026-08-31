#!/usr/bin/env bash
# Stop all SOC stack components: Phases 1-4 + Langfuse tracing (+ optional OpenCTI)
#
# Usage: bash tools/stop-all.sh [--volumes] [--with-opencti]
#
# Notes on the MCP traffic observability stack (see docs/MCP_OBSERVABILITY.md):
#   * The MCP per-call ring buffer (/observability/recent, /stream, /stats) is
#     in-memory and is wiped when wazuh-mcp-server is stopped. This is expected.
#   * Persistent history lives in Prometheus (phase4-prometheus, retention
#     30 days / 5 GB) and survives `down` without --volumes.
#   * `--volumes` ALSO deletes the Prometheus TSDB and the Grafana DB, so all
#     long-term MCP traffic history and any UI-saved dashboards/users are lost.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

stop_mcp_proxy_stack() {
  local volumes_flag="$1"
  local mcp_compose=(
    -f mcp-security-proxy/docker-compose.yml
    -f mcp-security-proxy/docker-compose.phase4.yml
    -f mcp-security-proxy/docker-compose.isolated-executor.yml
  )
  docker compose "${mcp_compose[@]}" down --remove-orphans ${volumes_flag}
}

VOLUMES_FLAG=""
WITH_OPENCTI=0
for arg in "$@"; do
  case "$arg" in
    --volumes)      VOLUMES_FLAG="--volumes" ;;
    --with-opencti) WITH_OPENCTI=1 ;;
    *)
      echo "Unknown argument: $arg" >&2
      echo "Usage: $0 [--volumes] [--with-opencti]" >&2
      exit 2
      ;;
  esac
done

if [[ -n "${VOLUMES_FLAG}" ]]; then
  echo "WARNING: --volumes will delete all persistent data (Wazuh indices, Langfuse DB, Phase 4 data including Prometheus MCP-traffic TSDB and Grafana state$( [[ $WITH_OPENCTI -eq 1 ]] && echo ', OpenCTI ES + Redis' ))."
  read -r -p "Are you sure? [y/N] " confirm
  if [[ "${confirm}" != "y" && "${confirm}" != "Y" ]]; then
    echo "Aborted."
    exit 0
  fi
fi

COMPOSE_FILES=(
  -f compose.full.yml
  -f compose.phase3.langgraph.yml
  -f compose.phase4.yml
  -f compose.langfuse.oss.yml
)
if [[ "${WITH_OPENCTI}" -eq 1 ]]; then
  COMPOSE_FILES+=( -f compose.opencti.yml )
fi

echo "Stopping all components (Phases 1-4 + Langfuse$( [[ $WITH_OPENCTI -eq 1 ]] && echo ' + OpenCTI' ))..."

stop_mcp_proxy_stack "${VOLUMES_FLAG}"
docker compose "${COMPOSE_FILES[@]}" down --remove-orphans ${VOLUMES_FLAG}

echo ""
echo "All containers stopped."
