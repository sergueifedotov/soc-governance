#!/usr/bin/env bash

# Creates a git check-in by committing current changes and attaching a label tag.
set -euo pipefail

print_usage() {
  cat <<'USAGE'
Usage:
  bash tools/git_checkin_with_label.sh <label> [options]

Options:
  -m, --message <msg>      Commit message.
  --tag-message <msg>      Annotated tag message (default: "label: <label>").
  --no-add                 Do not run "git add -A" automatically.
  --push                   Push current branch and tag to remote.
  --remote <name>          Remote name for push (default: origin).
  --force-tag              Replace tag if it already exists locally.
  -h, --help               Show this help.

Examples:
  bash tools/git_checkin_with_label.sh release-2026-05-22 -m "Phase4 policy tuning"
  bash tools/git_checkin_with_label.sh phase4-rc1 --push
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
  local commit_message=""
  local tag_message=""
  local auto_add=1
  local push_after=0
  local remote_name="origin"
  local force_tag=0

  if [[ $# -eq 0 ]]; then
    print_usage
    exit 1
  fi

  label="$1"
  shift

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -m|--message)
        [[ $# -ge 2 ]] || { echo "ERROR: --message requires a value." >&2; exit 1; }
        commit_message="$2"
        shift 2
        ;;
      --tag-message)
        [[ $# -ge 2 ]] || { echo "ERROR: --tag-message requires a value." >&2; exit 1; }
        tag_message="$2"
        shift 2
        ;;
      --no-add)
        auto_add=0
        shift
        ;;
      --push)
        push_after=1
        shift
        ;;
      --remote)
        [[ $# -ge 2 ]] || { echo "ERROR: --remote requires a value." >&2; exit 1; }
        remote_name="$2"
        shift 2
        ;;
      --force-tag)
        force_tag=1
        shift
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

  if [[ -z "${commit_message}" ]]; then
    commit_message="checkin: ${label}"
  fi

  if [[ -z "${tag_message}" ]]; then
    tag_message="label: ${label}"
  fi

  if [[ ${auto_add} -eq 1 ]]; then
    git add -A
  fi

  if git diff --cached --quiet; then
    echo "ERROR: No staged changes to commit." >&2
    echo "Hint: add files first, or rerun without --no-add to auto-stage." >&2
    exit 1
  fi

  git commit -m "${commit_message}"

  if git rev-parse -q --verify "refs/tags/${label}" >/dev/null 2>&1; then
    if [[ ${force_tag} -eq 1 ]]; then
      git tag -d "${label}" >/dev/null
    else
      echo "ERROR: Tag '${label}' already exists. Use --force-tag to replace it." >&2
      exit 1
    fi
  fi

  git tag -a "${label}" -m "${tag_message}"

  echo "Created commit and tag '${label}'."

  if [[ ${push_after} -eq 1 ]]; then
    local branch_name
    branch_name="$(git rev-parse --abbrev-ref HEAD)"
    git push "${remote_name}" "${branch_name}"
    git push "${remote_name}" "refs/tags/${label}"
    echo "Pushed branch '${branch_name}' and tag '${label}' to '${remote_name}'."
  fi

  echo "Checkout later with: bash tools/git_checkout_by_label.sh ${label}"
}

main "$@"
