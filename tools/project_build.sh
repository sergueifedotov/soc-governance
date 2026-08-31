#!/usr/bin/env bash

set -euo pipefail

MODE="standard"

usage() {
  cat <<'EOF'
Usage: tools/project_build.sh [--full|--standard] [--no-cache] [--pull]

Build project images using Docker Compose.

Options:
  --full       Use compose.full.yml
  --standard   Use compose.yml (default)
  --no-cache   Build without cache
  --pull       Always attempt to pull newer base images
  -h, --help   Show this help
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
    --no-cache|--pull)
      EXTRA_ARGS+=("$1")
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

echo "Building project using $COMPOSE_FILE"
docker compose -f "$COMPOSE_FILE" build ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}
echo "Build complete"
