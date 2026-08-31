#!/usr/bin/env bash
# Phase C / Sprint 4: enterprise governance verification.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

SKIP_RBAC=0
SKIP_LIFECYCLE=0
SKIP_AUDIT=0

usage() {
  cat <<'EOF'
Usage: bash tools/test_mcp_proxy_phase_c.sh [options]

Verifies Sprint 4 / Phase C governance:
  1) RBAC role enforcement
  2) Policy lifecycle (versions, rollback, signed bundles)
  3) Audit integrity hash chain

Prerequisites: Profile C, mcp-security-proxy running with sprint-4-governance policy.

Options:
  --skip-rbac       Skip RBAC test
  --skip-lifecycle  Skip policy lifecycle test
  --skip-audit      Skip audit integrity test
  -h, --help        Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-rbac) SKIP_RBAC=1; shift ;;
    --skip-lifecycle) SKIP_LIFECYCLE=1; shift ;;
    --skip-audit) SKIP_AUDIT=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "ERROR: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

echo "== MCP PROXY PHASE C (Sprint 4 governance verification) =="

if [[ "${SKIP_RBAC}" -eq 0 ]]; then
  bash tools/test_mcp_proxy_phase_c_rbac.sh
fi

if [[ "${SKIP_LIFECYCLE}" -eq 0 ]]; then
  bash tools/test_mcp_proxy_phase_c_policy_lifecycle.sh
fi

if [[ "${SKIP_AUDIT}" -eq 0 ]]; then
  bash tools/test_mcp_proxy_phase_c_audit_integrity.sh
fi

echo "PHASE C SPRINT 4 GOVERNANCE PASSED"
