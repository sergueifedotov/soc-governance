#!/usr/bin/env bash
# Build and start the isolated executor sidecar on Profile C networks.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

BUILD_FLAG="--build"
if [[ "${1:-}" == "--no-build" ]]; then
  BUILD_FLAG=""
  shift
fi

COMPOSE=(
  -f mcp-security-proxy/docker-compose.isolated-executor.yml
)

echo "Starting isolated-executor (networks: wazuh-soc_default, wazuh-soc_phase4)..."
docker compose "${COMPOSE[@]}" up -d ${BUILD_FLAG} isolated-executor

echo "Waiting for health..."
for _ in $(seq 1 30); do
  if curl -sf "http://localhost:${ISOLATED_EXECUTOR_HOST_PORT:-18088}/health" | jq -e '.status == "healthy"' >/dev/null 2>&1; then
    echo "PASS: isolated-executor healthy on host port ${ISOLATED_EXECUTOR_HOST_PORT:-18088}"
    exit 0
  fi
  sleep 1
done

echo "FAIL: isolated-executor did not become healthy" >&2
docker logs isolated-executor --tail 40 2>&1 || true
exit 1
