#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

usage() {
  cat <<'EOF'
Usage: bash tools/stop-profile.sh <A|B|C|D> [--volumes] [--autonomous-compose PATH]

Profiles:
  A  Everyday development baseline
  B  Autonomous hunting development
  C  Investigation mode with OpenCTI
  D  Heavy test / stress mode

Flags:
  --volumes                  Delete persistent volumes after confirmation
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

stop_mcp_proxy_stack() {
  local volumes_flag="$1"
  local mcp_compose=(
    -f mcp-security-proxy/docker-compose.yml
    -f mcp-security-proxy/docker-compose.phase4.yml
    -f mcp-security-proxy/docker-compose.isolated-executor.yml
  )
  docker compose "${mcp_compose[@]}" down --remove-orphans ${volumes_flag}
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

VOLUMES_FLAG=""
AUTONOMOUS_COMPOSE="${AUTONOMOUS_COMPOSE:-}"

for arg in "$@"; do
  case "$arg" in
    --volumes)
      VOLUMES_FLAG="--volumes"
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

case "${PROFILE}" in
  A)
    ;;
  B)
    WITH_AUTONOMOUS=1
    ;;
  C)
    WITH_OPENCTI=1
    ;;
  D)
    WITH_OPENCTI=1
    WITH_AUTONOMOUS=1
    ;;
  *)
    echo "Unknown profile: ${PROFILE}" >&2
    usage >&2
    exit 2
    ;;
esac

if [[ -n "${VOLUMES_FLAG}" ]]; then
  echo "WARNING: --volumes will delete persistent state for the selected profile$( [[ ${WITH_OPENCTI} -eq 1 ]] && echo ' including OpenCTI data' )."
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
)

if [[ "${WITH_OPENCTI}" -eq 1 ]]; then
  COMPOSE_FILES+=( -f compose.opencti.yml )
fi

if [[ "${WITH_AUTONOMOUS}" -eq 1 ]]; then
  AUTONOMOUS_FILE="$(detect_autonomous_compose || true)"
  if [[ -n "${AUTONOMOUS_FILE:-}" ]]; then
    COMPOSE_FILES+=( -f "${AUTONOMOUS_FILE}" )
  fi
fi

echo "Stopping profile ${PROFILE}..."
stop_mcp_proxy_stack "${VOLUMES_FLAG}"
docker compose "${COMPOSE_FILES[@]}" down --remove-orphans ${VOLUMES_FLAG}
echo
echo "Profile ${PROFILE} stopped."