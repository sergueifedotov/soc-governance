#!/usr/bin/env bash

# Checks out repository state by git label (tag), optionally into a new branch.
set -euo pipefail

print_usage() {
  cat <<'USAGE'
Usage:
  bash tools/git_checkout_by_label.sh <label> [options]

Options:
  --fetch                 Fetch tags from remote before checkout.
  --remote <name>         Remote name for fetch (default: origin).
  -b, --branch <name>     Create and checkout a new branch from the label.
  -h, --help              Show this help.

Examples:
  bash tools/git_checkout_by_label.sh release-2026-05-22 --fetch
  bash tools/git_checkout_by_label.sh phase4-rc1 --fetch -b fix/phase4-rc1
USAGE
}

ensure_git_repo() {
  if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "ERROR: Not inside a git repository." >&2
    exit 1
  fi
}

validate_label() {
  local label="$1"
  if [[ -z "${label}" ]]; then
    echo "ERROR: Label is required." >&2
    exit 1
  fi
  if ! git check-ref-format --allow-onelevel "refs/tags/${label}" >/dev/null 2>&1; then
    echo "ERROR: Invalid git tag label '${label}'." >&2
    exit 1
  fi
}

main() {
  ensure_git_repo

  local label=""
  local do_fetch=0
  local remote_name="origin"
  local branch_name=""

  if [[ $# -eq 0 ]]; then
    print_usage
    exit 1
  fi

  label="$1"
  shift

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --fetch)
        do_fetch=1
        shift
        ;;
      --remote)
        [[ $# -ge 2 ]] || { echo "ERROR: --remote requires a value." >&2; exit 1; }
        remote_name="$2"
        shift 2
        ;;
      -b|--branch)
        [[ $# -ge 2 ]] || { echo "ERROR: --branch requires a value." >&2; exit 1; }
        branch_name="$2"
        shift 2
        ;;
      -h|--help)
        print_usage
        exit 0
        ;;
      *)
        echo "ERROR: Unknown option '$1'." >&2
        print_usage
        exit 1
        ;;
    esac
  done

  validate_label "${label}"

  if [[ ${do_fetch} -eq 1 ]]; then
    git fetch "${remote_name}" --tags
  fi

  if ! git rev-parse -q --verify "refs/tags/${label}" >/dev/null 2>&1; then
    echo "ERROR: Tag '${label}' not found locally." >&2
    echo "Hint: rerun with --fetch if the tag exists on remote." >&2
    exit 1
  fi

  if [[ -n "${branch_name}" ]]; then
    git checkout -b "${branch_name}" "refs/tags/${label}"
    echo "Checked out label '${label}' into new branch '${branch_name}'."
  else
    git checkout "refs/tags/${label}"
    echo "Checked out label '${label}' in detached HEAD mode."
    echo "Tip: use -b <branch> to create a working branch from this label."
  fi
}

main "$@"
