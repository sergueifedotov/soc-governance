#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  backup_project_version.sh --version <version-tag> [options]

Required:
  --version <tag>           Version tag to create/use (example: v4.2.1)

Options:
  --output-dir <dir>        Output directory for backup artifacts (default: backups/git)
  --remote <name>           Git remote name for optional push (default: origin)
  --push-tag                Push the tag to remote after creation/validation
  --allow-dirty             Allow running with uncommitted changes
  -h, --help                Show this help

Artifacts created:
  1) <repo>_<version>_<utc>.bundle   (portable git backup for that tag)
  2) <repo>_<version>_<utc>.tar.gz   (source snapshot archive at tag)
  3) <repo>_<version>_<utc>.sha256   (checksums)
  4) <repo>_<version>_<utc>.meta     (metadata)
EOF
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: Required command not found: $cmd" >&2
    exit 1
  fi
}

VERSION=""
OUTPUT_DIR="backups/git"
REMOTE="origin"
PUSH_TAG=0
ALLOW_DIRTY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      VERSION="${2:-}"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="${2:-}"
      shift 2
      ;;
    --remote)
      REMOTE="${2:-}"
      shift 2
      ;;
    --push-tag)
      PUSH_TAG=1
      shift
      ;;
    --allow-dirty)
      ALLOW_DIRTY=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$VERSION" ]]; then
  echo "ERROR: --version is required" >&2
  usage
  exit 1
fi

require_cmd git
require_cmd tar
require_cmd shasum

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "$REPO_ROOT" ]]; then
  echo "ERROR: Not inside a git repository" >&2
  exit 1
fi
cd "$REPO_ROOT"

if [[ "$ALLOW_DIRTY" -eq 0 ]] && [[ -n "$(git status --porcelain)" ]]; then
  echo "ERROR: Working tree is dirty. Commit or stash changes, or use --allow-dirty." >&2
  exit 1
fi

if git rev-parse -q --verify "refs/tags/$VERSION" >/dev/null 2>&1; then
  echo "Using existing tag: $VERSION"
else
  echo "Creating annotated tag: $VERSION"
  git tag -a "$VERSION" -m "Backup tag $VERSION"
fi

TAG_COMMIT="$(git rev-list -n 1 "$VERSION")"
BRANCH_NAME="$(git rev-parse --abbrev-ref HEAD)"
REPO_NAME="$(basename "$REPO_ROOT")"
UTC_TS="$(date -u +%Y%m%dT%H%M%SZ)"
BASE_NAME="${REPO_NAME}_${VERSION}_${UTC_TS}"

mkdir -p "$OUTPUT_DIR"
BUNDLE_PATH="$OUTPUT_DIR/${BASE_NAME}.bundle"
ARCHIVE_PATH="$OUTPUT_DIR/${BASE_NAME}.tar.gz"
CHECKSUM_PATH="$OUTPUT_DIR/${BASE_NAME}.sha256"
META_PATH="$OUTPUT_DIR/${BASE_NAME}.meta"

echo "Creating bundle: $BUNDLE_PATH"
git bundle create "$BUNDLE_PATH" "$VERSION"

echo "Creating source archive: $ARCHIVE_PATH"
git archive --format=tar.gz --output "$ARCHIVE_PATH" "$VERSION"

echo "Generating checksums: $CHECKSUM_PATH"
{
  shasum -a 256 "$BUNDLE_PATH"
  shasum -a 256 "$ARCHIVE_PATH"
} > "$CHECKSUM_PATH"

cat > "$META_PATH" <<EOF
repo_name=$REPO_NAME
repo_root=$REPO_ROOT
version_tag=$VERSION
tag_commit=$TAG_COMMIT
source_branch=$BRANCH_NAME
created_utc=$UTC_TS
bundle_path=$BUNDLE_PATH
archive_path=$ARCHIVE_PATH
checksum_path=$CHECKSUM_PATH
EOF

if [[ "$PUSH_TAG" -eq 1 ]]; then
  echo "Pushing tag $VERSION to remote $REMOTE"
  git push "$REMOTE" "$VERSION"
fi

echo ""
echo "Backup complete"
echo "  Bundle   : $BUNDLE_PATH"
echo "  Archive  : $ARCHIVE_PATH"
echo "  Checksums: $CHECKSUM_PATH"
echo "  Metadata : $META_PATH"
echo ""
echo "Restore example:"
echo "  bash tools/restore_project_version.sh --bundle \"$BUNDLE_PATH\" --target-dir \"../${REPO_NAME}-restore-${VERSION}\" --ref \"$VERSION\""
