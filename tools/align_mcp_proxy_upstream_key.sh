#!/usr/bin/env bash
# Recreate mcp-security-proxy so MCP_PROXY_UPSTREAM_API_KEY matches wazuh-mcp-server.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE=(
  -f "${ROOT_DIR}/mcp-security-proxy/docker-compose.yml"
  -f "${ROOT_DIR}/mcp-security-proxy/docker-compose.phase4.yml"
)

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

export MCP_API_KEY
export MCP_PROXY_API_KEY="${MCP_API_KEY}"

echo "Aligning mcp-security-proxy keys with wazuh-mcp-server MCP_API_KEY..."
echo "  MCP_PROXY_UPSTREAM_API_KEY <- wazuh MCP_API_KEY"
echo "  MCP_PROXY_API_KEY <- same (client bearer for /mcp and admin APIs)"
docker compose "${COMPOSE[@]}" up -d --force-recreate mcp-security-proxy

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
