#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  restore_project_version.sh --bundle <path.bundle> --target-dir <dir> [options]

Required:
  --bundle <path>           Path to .bundle created by backup_project_version.sh
  --target-dir <dir>        Destination directory for restored repository

Options:
  --ref <git-ref>           Ref to checkout after clone (example: v4.2.1)
  --remote-url <url>        Optional remote URL to set as origin after restore
  --force                   Remove target directory if it already exists
  -h, --help                Show this help
EOF
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: Required command not found: $cmd" >&2
    exit 1
  fi
}

BUNDLE_PATH=""
TARGET_DIR=""
CHECKOUT_REF=""
REMOTE_URL=""
FORCE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bundle)
      BUNDLE_PATH="${2:-}"
      shift 2
      ;;
    --target-dir)
      TARGET_DIR="${2:-}"
      shift 2
      ;;
    --ref)
      CHECKOUT_REF="${2:-}"
      shift 2
      ;;
    --remote-url)
      REMOTE_URL="${2:-}"
      shift 2
      ;;
    --force)
      FORCE=1
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

if [[ -z "$BUNDLE_PATH" || -z "$TARGET_DIR" ]]; then
  echo "ERROR: --bundle and --target-dir are required" >&2
  usage
  exit 1
fi

require_cmd git

if [[ ! -f "$BUNDLE_PATH" ]]; then
  echo "ERROR: Bundle file not found: $BUNDLE_PATH" >&2
  exit 1
fi

if [[ -e "$TARGET_DIR" ]]; then
  if [[ "$FORCE" -eq 1 ]]; then
    rm -rf "$TARGET_DIR"
  else
    echo "ERROR: Target directory already exists: $TARGET_DIR (use --force to overwrite)" >&2
    exit 1
  fi
fi

echo "Verifying bundle..."
git bundle verify "$BUNDLE_PATH" >/dev/null

echo "Cloning from bundle into: $TARGET_DIR"
git clone "$BUNDLE_PATH" "$TARGET_DIR"

if [[ -n "$CHECKOUT_REF" ]]; then
  echo "Checking out ref: $CHECKOUT_REF"
  git -C "$TARGET_DIR" checkout "$CHECKOUT_REF"
fi

if [[ -n "$REMOTE_URL" ]]; then
  echo "Setting origin remote: $REMOTE_URL"
  git -C "$TARGET_DIR" remote set-url origin "$REMOTE_URL"
fi

echo ""
echo "Restore complete"
echo "  Restored repo: $TARGET_DIR"
if [[ -n "$CHECKOUT_REF" ]]; then
  echo "  Checked out : $CHECKOUT_REF"
fi
if [[ -n "$REMOTE_URL" ]]; then
  echo "  Origin URL  : $REMOTE_URL"
fi
