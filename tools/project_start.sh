#!/usr/bin/env bash

set -euo pipefail

MODE="standard"
BUILD=false
FORCE_RECREATE=false
NO_DEMO=false

usage() {
  cat <<'EOF'
Usage: tools/project_start.sh [--full|--standard] [--build] [--force-recreate] [--no-demo]

Start project services with Docker Compose.

Options:
  --full            Use compose.full.yml
  --standard        Use compose.yml (default)
  --build           Build before starting
  --force-recreate  Recreate containers even if unchanged
  --no-demo         In full mode, stop apache-log-generator after startup
  -h, --help        Show this help

Behavior:
  Automatically stops the other compose stack if it is running
  to avoid port conflicts when switching modes.
EOF
}

EXTRA_ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --full)
      MODE="full"
      shift
      ;;
    --standard)
      MODE="standard"
      shift
      ;;
    --build)
      BUILD=true
      shift
      ;;
    --force-recreate)
      FORCE_RECREATE=true
      shift
      ;;
    --no-demo)
      NO_DEMO=true
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

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is not installed or not in PATH" >&2
  exit 2
fi

COMPOSE_FILE="compose.yml"
if [[ "$MODE" == "full" ]]; then
  COMPOSE_FILE="compose.full.yml"
fi

CONFLICTING_COMPOSE_FILE="compose.full.yml"
if [[ "$MODE" == "full" ]]; then
  CONFLICTING_COMPOSE_FILE="compose.yml"
fi

if [[ "$BUILD" == "true" ]]; then
  EXTRA_ARGS+=("--build")
fi
if [[ "$FORCE_RECREATE" == "true" ]]; then
  EXTRA_ARGS+=("--force-recreate")
fi

conflicting_running_count=$(docker compose -f "$CONFLICTING_COMPOSE_FILE" ps --status running -q | wc -l | tr -d '[:space:]')
if [[ "$conflicting_running_count" != "0" ]]; then
  echo "Detected running services in $CONFLICTING_COMPOSE_FILE"
  echo "Stopping conflicting stack to avoid port collisions"
  docker compose -f "$CONFLICTING_COMPOSE_FILE" down
fi

echo "Starting project using $COMPOSE_FILE"
docker compose -f "$COMPOSE_FILE" up -d ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}

if [[ "$MODE" == "full" && "$NO_DEMO" == "true" ]]; then
  if docker compose -f "$COMPOSE_FILE" config --services | grep -Fxq "apache-log-generator"; then
    echo "Disabling synthetic alert traffic: stopping apache-log-generator"
    docker compose -f "$COMPOSE_FILE" stop apache-log-generator
  fi
fi

echo "Services started"
echo "Tip: check status with: docker compose -f $COMPOSE_FILE ps"
