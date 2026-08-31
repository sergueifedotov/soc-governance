#!/usr/bin/env bash
# Build OpenCTI Docker images natively for the host architecture (primarily
# linux/arm64 on Apple Silicon) so the stack no longer relies on Rosetta
# emulation of the official linux/amd64 images.
#
# Images produced (loaded into the local Docker daemon):
#   - opencti/platform:${OPENCTI_VERSION}-local
#   - opencti/worker:${OPENCTI_VERSION}-local            (optional, --with-worker)
#   - opencti/connector-import-file-stix:${OPENCTI_VERSION}-local  (optional)
#
# These tags are referenced from compose.opencti.yml.  The script is idempotent:
# it skips anything that already exists in the local image store unless you
# pass --force. Source is checked out under ./build/opencti/<version>/ which
# is already covered by .gitignore (build/).
#
# Usage:
#   tools/build-opencti-arm64.sh                 # build platform only (default)
#   tools/build-opencti-arm64.sh --with-worker   # also build worker
#   tools/build-opencti-arm64.sh --with-connectors  # also build stix2 file-import connector
#   tools/build-opencti-arm64.sh --all           # platform + worker + connectors
#   tools/build-opencti-arm64.sh --force         # rebuild even if image exists
#   OPENCTI_VERSION=6.4.0 tools/build-opencti-arm64.sh
#
# Requires: git, docker buildx.

set -euo pipefail

OPENCTI_VERSION="${OPENCTI_VERSION:-6.4.0}"
REPO_URL="${OPENCTI_REPO_URL:-https://github.com/OpenCTI-Platform/opencti.git}"
CONNECTORS_REPO_URL="${OPENCTI_CONNECTORS_REPO_URL:-https://github.com/OpenCTI-Platform/connectors.git}"
PLATFORM="${OPENCTI_BUILD_PLATFORM:-linux/$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')}"
TAG_SUFFIX="${OPENCTI_TAG_SUFFIX:-local}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SRC_DIR="${REPO_ROOT}/build/opencti/${OPENCTI_VERSION}"
CONNECTORS_SRC_DIR="${REPO_ROOT}/build/opencti-connectors/${OPENCTI_VERSION}"

FORCE=0
BUILD_PLATFORM=1
BUILD_WORKER=0
BUILD_CONNECTORS=0

for arg in "$@"; do
  case "$arg" in
    --force)           FORCE=1 ;;
    --with-worker)     BUILD_WORKER=1 ;;
    --with-connectors) BUILD_CONNECTORS=1 ;;
    --all)             BUILD_WORKER=1; BUILD_CONNECTORS=1 ;;
    --platform-only)   ;;  # default
    -h|--help)
      grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

log()  { printf '\033[1;34m[build-opencti]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[build-opencti]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[build-opencti]\033[0m %s\n' "$*" >&2; exit 1; }

image_exists() {
  docker image inspect "$1" >/dev/null 2>&1
}

ensure_source() {
  if [[ ! -d "${SRC_DIR}/.git" ]]; then
    mkdir -p "$(dirname "${SRC_DIR}")"
    log "Cloning OpenCTI ${OPENCTI_VERSION} into ${SRC_DIR}"
    git clone --depth 1 --branch "${OPENCTI_VERSION}" "${REPO_URL}" "${SRC_DIR}"
  else
    log "Source already cloned at ${SRC_DIR}"
  fi
  apply_patches
}

ensure_connectors_source() {
  if [[ ! -d "${CONNECTORS_SRC_DIR}/.git" ]]; then
    mkdir -p "$(dirname "${CONNECTORS_SRC_DIR}")"
    log "Cloning OpenCTI connectors ${OPENCTI_VERSION} into ${CONNECTORS_SRC_DIR}"
    git clone --depth 1 --branch "${OPENCTI_VERSION}" "${CONNECTORS_REPO_URL}" "${CONNECTORS_SRC_DIR}"
  else
    log "Connectors source already cloned at ${CONNECTORS_SRC_DIR}"
  fi
  apply_connector_patches
}

apply_patches() {
  # OpenCTI 6.4.0's worker uses `FROM python:3-alpine` which now resolves to
  # Python 3.14, but pinned pydantic-core 2.20.1 only supports CPython <=3.13.
  # Pin the base image to python:3.12-alpine.
  local f="${SRC_DIR}/opencti-worker/Dockerfile"
  if [[ -f "$f" ]] && grep -q '^FROM python:3-alpine' "$f"; then
    log "Pinning Python base image to 3.12-alpine in opencti-worker/Dockerfile"
    sed -i.bak 's|^FROM python:3-alpine|FROM python:3.12-alpine|' "$f"
    rm -f "${f}.bak"
  fi
}

apply_connector_patches() {
  # Same Python pin for any connector that uses `FROM python:3-alpine`.
  while IFS= read -r -d '' f; do
    if grep -q '^FROM python:3-alpine' "$f"; then
      log "Pinning Python base image to 3.12-alpine in ${f#${CONNECTORS_SRC_DIR}/}"
      sed -i.bak 's|^FROM python:3-alpine|FROM python:3.12-alpine|' "$f"
      rm -f "${f}.bak"
    fi
  done < <(find "${CONNECTORS_SRC_DIR}" -name Dockerfile -print0 2>/dev/null)
}

build_image() {
  local name="$1"        # e.g. opencti/platform
  local context_dir="$2" # full path to the build context
  local tag="${name}:${OPENCTI_VERSION}-${TAG_SUFFIX}"

  if (( FORCE == 0 )) && image_exists "${tag}"; then
    log "Skipping ${tag} (already in local image store; pass --force to rebuild)"
    return
  fi

  [[ -d "${context_dir}" ]] \
    || die "Expected build context ${context_dir} not found"

  log "Building ${tag} for ${PLATFORM} from ${context_dir}"
  docker buildx build \
    --platform "${PLATFORM}" \
    --tag "${tag}" \
    --load \
    "${context_dir}"
  log "Built ${tag}"
}

command -v docker >/dev/null || die "docker not found in PATH"
docker buildx version >/dev/null 2>&1 || die "docker buildx plugin is required"
command -v git >/dev/null || die "git not found in PATH"

ensure_source

if (( BUILD_PLATFORM )); then
  build_image opencti/platform "${SRC_DIR}/opencti-platform"
fi

if (( BUILD_WORKER )); then
  build_image opencti/worker "${SRC_DIR}/opencti-worker"
fi

if (( BUILD_CONNECTORS )); then
  ensure_connectors_source
  # Built-in STIX2 file-import connector lives in the connectors repo under
  # internal-import-file/import-file-stix.
  build_image opencti/connector-import-file-stix \
    "${CONNECTORS_SRC_DIR}/internal-import-file/import-file-stix"
fi

log "Done."
log "Tagged images:"
docker image ls --filter "reference=opencti/*:${OPENCTI_VERSION}-${TAG_SUFFIX}" \
  --format 'table {{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.CreatedSince}}'
