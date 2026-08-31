#!/usr/bin/env bash
# Phase C / Sprint 4: policy versioning, proposals, rollback, signed bundles.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=mcp_proxy_test_common.sh
source "${ROOT_DIR}/tools/mcp_proxy_test_common.sh"

PROXY_BASE_URL="${PROXY_BASE_URL:-http://localhost:8090}"

echo "== PHASE C POLICY LIFECYCLE TEST =="
mcp_test_require_proxy_healthy "${PROXY_BASE_URL}"

echo "Test 1: manual policy version snapshot"
snap="$(mcp_test_proxy_post_json \
  "${PROXY_BASE_URL%/}/admin/policy-versions" \
  "$(jq -n '{reason: "phase c lifecycle test"}')")"
version_id="$(echo "${snap}" | jq -r '.version.version_id // empty')"
if [[ -z "${version_id}" ]]; then
  echo "FAIL: snapshot missing version_id" >&2
  echo "${snap}" | jq . >&2 || true
  exit 1
fi
echo "PASS: snapshot ${version_id}"

echo "Test 2: list policy versions"
versions="$(mcp_test_proxy_get "${PROXY_BASE_URL%/}/admin/policy-versions")"
count="$(echo "${versions}" | jq -r '.versions | length')"
if [[ "${count}" -lt 1 ]]; then
  echo "FAIL: expected at least one version" >&2
  exit 1
fi
echo "PASS: versions listed (${count})"

echo "Test 3: admin force-write then rollback"
policy="$(mcp_test_proxy_get "${PROXY_BASE_URL%/}/admin/policy-config" | jq -c '.raw_policy')"
mutated="$(echo "${policy}" | jq -c '.denied_tools += ["phase_c_rollback_marker"]')"
mcp_test_proxy_post_json \
  "${PROXY_BASE_URL%/}/admin/policy-config" \
  "$(jq -n --argjson p "${mutated}" '{raw_policy: $p, force: true, reason: "phase c mutate"}')" >/dev/null
rollback="$(mcp_test_proxy_post_json \
  "${PROXY_BASE_URL%/}/admin/policy-rollback" \
  "$(jq -n --arg v "${version_id}" '{version_id: $v}')")"
if [[ "$(echo "${rollback}" | jq -r '.status // empty')" != "ok" ]]; then
  echo "FAIL: rollback did not return ok" >&2
  echo "${rollback}" | jq . >&2 || true
  exit 1
fi
current="$(mcp_test_proxy_get "${PROXY_BASE_URL%/}/admin/policy-config" | jq -r '.raw_policy.denied_tools[]?')"
if echo "${current}" | grep -q 'phase_c_rollback_marker'; then
  echo "FAIL: rollback marker still present" >&2
  exit 1
fi
echo "PASS: rollback restored prior policy"

echo "Test 4: sign and dry-run apply bundle"
bundle="$(jq -n '{
  discovery_updates: [{
    signal: "write_tool_abuse",
    action_on_trigger: "monitor",
    tool_scope: ["phase_c_bundle_tool"]
  }]
}')"
signed="$(mcp_test_proxy_post_json \
  "${PROXY_BASE_URL%/}/admin/sign-policy-bundle" \
  "$(jq -n --argjson b "${bundle}" '{policy_bundle: $b}')")"
envelope="$(echo "${signed}" | jq -c '.signed_bundle')"
apply="$(mcp_test_proxy_post_json \
  "${PROXY_BASE_URL%/}/admin/apply-policy-bundle" \
  "$(jq -n --argjson s "${envelope}" '{signed_bundle: $s, dry_run: true}')")"
verified="$(echo "${apply}" | jq -r '.signature.verified // false')"
if [[ "${verified}" != "true" ]]; then
  echo "FAIL: signed bundle not verified on apply" >&2
  exit 1
fi
echo "PASS: signed bundle dry-run verified"

echo "PHASE C POLICY LIFECYCLE TEST PASSED"
