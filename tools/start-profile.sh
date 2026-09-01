#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

usage() {
  cat <<'EOF'
Usage: bash tools/start-profile.sh <A|B|C|D> [--no-build] [--autonomous-compose PATH]

Profiles:
  A  Everyday development baseline
  B  Autonomous hunting development
  C  Investigation mode with OpenCTI
  D  Heavy test / stress mode

Flags:
  --no-build                 Reuse existing images
  --autonomous-compose PATH  Optional compose overlay for autonomous hunt service
  -h, --help                 Show this help
EOF
}

detect_autonomous_compose() {
  if [[ -n "${AUTONOMOUS_COMPOSE}" ]]; then
    [[ -f "${AUTONOMOUS_COMPOSE}" ]] || {
      echo "Autonomous compose file not found: ${AUTONOMOUS_COMPOSE}" >&2
      exit 2
    }
    printf '%s\n' "${AUTONOMOUS_COMPOSE}"
    return
  fi

  local candidate
  for candidate in compose.autonomous-hunt.yml compose.autonomous.yml; do
    if [[ -f "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return
    fi
  done
}

start_mcp_proxy_stack() {
  local build_flag="$1"
  local mcp_compose=(
    -f mcp-security-proxy/docker-compose.yml
    -f mcp-security-proxy/docker-compose.phase4.yml
    -f mcp-security-proxy/docker-compose.isolated-executor.yml
  )
  local compose_env=()
  if [[ -f "${REPO_ROOT}/.env" ]]; then
    compose_env+=(--env-file "${REPO_ROOT}/.env")
  fi
  # Proxy compose files live under mcp-security-proxy/, so they would not
  # otherwise inherit repo-root MCP_API_KEY. Prefer the running Wazuh key
  # so MCP_PROXY_UPSTREAM_API_KEY matches wazuh-mcp-server.
  local wazuh_key=""
  wazuh_key="$(docker exec wazuh-mcp-server printenv MCP_API_KEY 2>/dev/null || true)"
  if [[ -n "${wazuh_key}" ]]; then
    export MCP_API_KEY="${wazuh_key}"
  fi
  if [[ -n "${MCP_API_KEY:-}" && "${MCP_API_KEY}" != wazuh_* ]]; then
    echo "WARN: MCP_API_KEY is not wazuh_<token> format. wazuh-mcp-server will ignore it and Fetch Alerts will 401." >&2
  fi
  docker compose "${compose_env[@]}" "${mcp_compose[@]}" up -d ${build_flag}
}

preflight_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker CLI is not installed or not on PATH." >&2
    exit 1
  fi

  if docker info >/dev/null 2>&1; then
    return
  fi

  echo "Docker daemon is not reachable. Refusing to start profile." >&2

  local context endpoint status_output
  context="$(docker context show 2>/dev/null || echo unknown)"
  endpoint="$(docker context inspect "${context}" --format '{{ .Endpoints.docker.Host }}' 2>/dev/null || echo unknown)"
  echo "  Docker context: ${context}" >&2
  echo "  Docker endpoint: ${endpoint}" >&2

  if docker desktop status >/dev/null 2>&1; then
    status_output="$(docker desktop status 2>/dev/null || true)"
    echo "  Docker Desktop status:" >&2
    printf '%s\n' "${status_output}" >&2

    if printf '%s\n' "${status_output}" | grep -qi 'Status[[:space:]]*starting'; then
      cat >&2 <<'EOF'

Docker Desktop appears to be stuck in "starting".
Recommended recovery:
  1) export PATH="/Applications/Docker.app/Contents/Resources/bin:$PATH"
  2) docker desktop restart --detach
  3) wait until "docker desktop status" shows running
  4) rerun: bash tools/start-profile.sh <A|B|C|D>
EOF
      exit 1
    fi
  fi

  cat >&2 <<'EOF'

General recovery:
  1) Ensure Docker Desktop or Docker Engine is running
  2) Verify with: docker version
  3) Retry this command
EOF
  exit 1
}

if [[ $# -ge 1 ]] && [[ "$1" == "-h" || "$1" == "--help" ]]; then
  usage
  exit 0
fi

[[ $# -ge 1 ]] || {
  usage
  exit 2
}

PROFILE="$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]')"
shift

BUILD_FLAG="--build"
AUTONOMOUS_COMPOSE="${AUTONOMOUS_COMPOSE:-}"

for arg in "$@"; do
  case "$arg" in
    --no-build)
      BUILD_FLAG=""
      ;;
    --autonomous-compose)
      echo "--autonomous-compose requires a path argument" >&2
      exit 2
      ;;
    --autonomous-compose=*)
      AUTONOMOUS_COMPOSE="${arg#*=}"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      usage >&2
      exit 2
      ;;
  esac
done

WITH_OPENCTI=0
WITH_AUTONOMOUS=0
PROFILE_DESC=""

case "${PROFILE}" in
  A)
    PROFILE_DESC="Everyday development baseline"
    ;;
  B)
    PROFILE_DESC="Autonomous hunting development"
    WITH_AUTONOMOUS=1
    ;;
  C)
    PROFILE_DESC="Investigation mode with OpenCTI"
    WITH_OPENCTI=1
    ;;
  D)
    PROFILE_DESC="Heavy test / stress mode"
    WITH_OPENCTI=1
    WITH_AUTONOMOUS=1
    ;;
  *)
    echo "Unknown profile: ${PROFILE}" >&2
    usage >&2
    exit 2
    ;;
esac

COMPOSE_FILES=(
  -f compose.full.yml
  -f compose.phase3.langgraph.yml
  -f compose.phase4.yml
)

if [[ "${WITH_OPENCTI}" -eq 1 ]]; then
  COMPOSE_FILES+=( -f compose.opencti.yml )
fi

AUTONOMOUS_FILE=""
if [[ "${WITH_AUTONOMOUS}" -eq 1 ]]; then
  AUTONOMOUS_FILE="$(detect_autonomous_compose || true)"
  if [[ -n "${AUTONOMOUS_FILE}" ]]; then
    COMPOSE_FILES+=( -f "${AUTONOMOUS_FILE}" )
  fi
fi

echo "Starting profile ${PROFILE}: ${PROFILE_DESC}"
echo "  Langfuse overlay: disabled"
echo "  OpenCTI overlay: $( [[ ${WITH_OPENCTI} -eq 1 ]] && echo enabled || echo disabled )"
if [[ "${WITH_AUTONOMOUS}" -eq 1 ]]; then
  if [[ -n "${AUTONOMOUS_FILE}" ]]; then
    echo "  Autonomous overlay: ${AUTONOMOUS_FILE}"
  else
    echo "  Autonomous overlay: not found (profile falls back to currently implemented stack only)"
  fi
fi

preflight_docker

docker compose "${COMPOSE_FILES[@]}" up -d ${BUILD_FLAG}
start_mcp_proxy_stack "${BUILD_FLAG}"

echo
echo "Profile ${PROFILE} is up. Key URLs:"
echo "  Wazuh Dashboard   https://localhost:8443"
echo "  Wazuh MCP Server  http://localhost:3000"
echo "  MCP Proxy         http://localhost:8090/ui"
echo "  Open WebUI        http://localhost:3100"
echo "  Phase 3 API       http://localhost:8081"
echo "  Phase 4 API       http://localhost:8082/docs"
echo "  Prometheus        http://localhost:9091"
echo "  Grafana           http://localhost:3002"
if [[ "${WITH_OPENCTI}" -eq 1 ]]; then
  echo "  OpenCTI UI        http://localhost:8083"
fi