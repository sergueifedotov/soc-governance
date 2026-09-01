#!/usr/bin/env bash
# Recreate mcp-security-proxy so MCP_PROXY_UPSTREAM_API_KEY matches wazuh-mcp-server.
# Does not change MCP_PROXY_API_KEY (Phase 4 / UI client bearer), so Fetch Alerts
# keeps working with the existing proxy client key.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE=(
  -f "${ROOT_DIR}/mcp-security-proxy/docker-compose.yml"
  -f "${ROOT_DIR}/mcp-security-proxy/docker-compose.phase4.yml"
  -f "${ROOT_DIR}/mcp-security-proxy/docker-compose.isolated-executor.yml"
)
COMPOSE_ENV=()
if [[ -f "${ROOT_DIR}/.env" ]]; then
  COMPOSE_ENV+=(--env-file "${ROOT_DIR}/.env")
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker is required" >&2
  exit 2
fi
if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^wazuh-mcp-server$'; then
  echo "ERROR: wazuh-mcp-server container is not running" >&2
  exit 2
fi

MCP_API_KEY="$(docker exec wazuh-mcp-server printenv MCP_API_KEY)"
if [[ -z "${MCP_API_KEY}" ]]; then
  echo "ERROR: could not read MCP_API_KEY from wazuh-mcp-server" >&2
  exit 2
fi
if [[ "${MCP_API_KEY}" != wazuh_* ]]; then
  echo "WARN: wazuh-mcp-server MCP_API_KEY is not wazuh_<token> format; upstream calls may still 401." >&2
fi

# Preserve the live proxy client bearer so Phase 4 (MCP_PROXY_API_KEY default)
# does not start failing after this recreate.
LIVE_PROXY_KEY=""
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^mcp-security-proxy$'; then
  LIVE_PROXY_KEY="$(docker exec mcp-security-proxy printenv MCP_PROXY_API_KEY 2>/dev/null || true)"
fi

export MCP_API_KEY
if [[ -n "${LIVE_PROXY_KEY}" ]]; then
  export MCP_PROXY_API_KEY="${LIVE_PROXY_KEY}"
fi

echo "Aligning mcp-security-proxy upstream key with wazuh-mcp-server MCP_API_KEY..."
echo "  MCP_PROXY_UPSTREAM_API_KEY <- wazuh MCP_API_KEY"
if [[ -n "${LIVE_PROXY_KEY}" ]]; then
  echo "  MCP_PROXY_API_KEY <- existing proxy client bearer (unchanged)"
fi
docker compose "${COMPOSE_ENV[@]}" "${COMPOSE[@]}" up -d --force-recreate mcp-security-proxy

echo "Waiting for proxy health..."
for _ in $(seq 1 30); do
  if curl -sf "http://localhost:8090/health" | jq -e '.status == "healthy"' >/dev/null 2>&1; then
    echo "PASS: mcp-security-proxy is healthy"
    exit 0
  fi
  sleep 1
done

echo "WARN: proxy did not report healthy within 30s; check logs: docker logs mcp-security-proxy" >&2
exit 1
