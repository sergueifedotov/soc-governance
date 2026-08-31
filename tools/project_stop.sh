#!/usr/bin/env bash

set -euo pipefail

MODE="auto"
WITH_VOLUMES=false
REMOVE_ORPHANS=false
STOP_ALL=false

usage() {
  cat <<'EOF'
Usage: tools/project_stop.sh [--full|--standard|--auto|--all] [--volumes] [--remove-orphans]

Stop project services with Docker Compose.

Options:
  --full            Use compose.full.yml
  --standard        Use compose.yml
  --auto            Auto-detect active stack (default)
  --all             Stop both compose.yml and compose.full.yml
  --volumes         Remove named volumes
  --remove-orphans  Remove orphan containers
  -h, --help        Show this help
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
    --auto)
      MODE="auto"
      shift
      ;;
    --all)
      STOP_ALL=true
      shift
      ;;
    --volumes)
      WITH_VOLUMES=true
      shift
      ;;
    --remove-orphans)
      REMOVE_ORPHANS=true
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

if [[ "$WITH_VOLUMES" == "true" ]]; then
  EXTRA_ARGS+=("--volumes")
fi
if [[ "$REMOVE_ORPHANS" == "true" ]]; then
  EXTRA_ARGS+=("--remove-orphans")
fi

if [[ "$STOP_ALL" == "true" ]]; then
  echo "Stopping project using compose.yml"
  docker compose -f compose.yml down ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}
  echo "Stopping project using compose.full.yml"
  docker compose -f compose.full.yml down ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}
  echo "Services stopped for both compose stacks"
  exit 0
fi

if [[ "$MODE" == "auto" ]]; then
  full_running_count=$(docker compose -f compose.full.yml ps --status running -q | wc -l | tr -d '[:space:]')
  standard_running_count=$(docker compose -f compose.yml ps --status running -q | wc -l | tr -d '[:space:]')

  if [[ "$full_running_count" != "0" && "$standard_running_count" != "0" ]]; then
    echo "Both compose stacks appear active; stopping both"
    docker compose -f compose.yml down ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}
    docker compose -f compose.full.yml down ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}
    echo "Services stopped for both compose stacks"
    exit 0
  elif [[ "$full_running_count" != "0" && "$standard_running_count" == "0" ]]; then
    COMPOSE_FILE="compose.full.yml"
  elif [[ "$standard_running_count" != "0" ]]; then
    COMPOSE_FILE="compose.yml"
  else
    COMPOSE_FILE="compose.yml"
  fi
fi

echo "Stopping project using $COMPOSE_FILE"
docker compose -f "$COMPOSE_FILE" down ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}
echo "Services stopped"
