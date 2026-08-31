#!/usr/bin/env bash
# Shared helpers for MCP proxy integration / sprint test scripts.
# Source from repo root: source tools/mcp_proxy_test_common.sh

_MCP_TEST_COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
MCP_TEST_REPO_ROOT="$(cd "${_MCP_TEST_COMMON_DIR}/.." && pwd)"

mcp_test_resolve_proxy_api_key() {
  if [[ -n "${MCP_PROXY_API_KEY:-}" ]]; then
    printf '%s' "${MCP_PROXY_API_KEY}"
    return 0
  fi
  if [[ -n "${PROXY_API_KEY:-}" ]]; then
    printf '%s' "${PROXY_API_KEY}"
    return 0
  fi
  "${MCP_TEST_REPO_ROOT}/tools/mcp_api_key.sh" --proxy
}

mcp_test_proxy_auth_header() {
  printf 'Authorization: Bearer %s' "$(mcp_test_resolve_proxy_api_key)"
}

mcp_test_proxy_get() {
  local url="$1"
  curl -sS -H "$(mcp_test_proxy_auth_header)" "${url}"
}

mcp_test_proxy_post_json() {
  local url="$1"
  local body="$2"
  curl -sS \
    -H "$(mcp_test_proxy_auth_header)" \
    -H "Content-Type: application/json" \
    -X POST \
    -d "${body}" \
    "${url}"
}

mcp_test_health_upstream_url() {
  local base="${PROXY_BASE_URL:-http://localhost:8090}"
  mcp_test_proxy_get "${base%/}/health" | jq -r '.upstream // empty'
}

# Merge the live upstream URL (from /health) into trusted_servers so tools/list can forward.
mcp_test_ensure_trusted_upstream_policy() {
  local base="${PROXY_BASE_URL:-http://localhost:8090}"
  local upstream_url
  upstream_url="$(mcp_test_health_upstream_url)"
  if [[ -z "${upstream_url}" ]]; then
    return 0
  fi

  local policy_resp current_policy merged
  policy_resp="$(mcp_test_proxy_get "${base%/}/admin/policy-config" || true)"
  current_policy="$(echo "${policy_resp}" | jq -c '.raw_policy // empty' 2>/dev/null || true)"
  if [[ -z "${current_policy}" || "${current_policy}" == "null" ]]; then
    return 0
  fi

  merged="$(echo "${current_policy}" | jq -c --arg u "${upstream_url}" '
    .trusted_servers = (
      ((.trusted_servers // []) | map(tostring))
      + [$u, ($u | sub("/mcp$"; ""))]
      | map(select(length > 0))
      | unique
    )
  ')"
  local body
  body="$(jq -n --argjson p "${merged}" '{raw_policy: $p}')"
  mcp_test_proxy_post_json "${base%/}/admin/policy-config" "${body}" >/dev/null
}

mcp_test_require_proxy_healthy() {
  local base="${1:-${PROXY_BASE_URL:-http://localhost:8090}}"
  local health
  health="$(mcp_test_proxy_get "${base%/}/health" || true)"
  if [[ -z "${health}" ]] || ! echo "${health}" | jq -e '.status == "healthy"' >/dev/null 2>&1; then
    echo "FAIL: proxy not healthy at ${base%/}/health" >&2
    exit 2
  fi
}

mcp_test_apply_policy_sample_file() {
  local policy_file="$1"
  local base="${PROXY_BASE_URL:-http://localhost:8090}"
  if [[ ! -f "${policy_file}" ]]; then
    echo "FAIL: policy sample not found: ${policy_file}" >&2
    return 1
  fi
  local body
  body="$(jq -n --slurpfile p "${policy_file}" '{raw_policy: $p[0]}')"
  mcp_test_proxy_post_json "${base%/}/admin/policy-config" "${body}" >/dev/null
}

# Fail fast when proxy cannot reach upstream MCP (common before tools/list discovery).
mcp_test_preflight_upstream_mcp() {
  local base="${PROXY_BASE_URL:-http://localhost:8090}"
  local mcp_url="${base%/}/mcp"
  local label="${1:-preflight}"

  local health
  health="$(mcp_test_proxy_get "${base%/}/health" || true)"
  if [[ -z "${health}" ]] || ! echo "${health}" | jq -e '.status == "healthy"' >/dev/null 2>&1; then
    echo "FAIL: proxy health check failed at ${base%/}/health" >&2
    echo "${health}" | jq '.' 2>/dev/null || echo "${health}" >&2
    exit 2
  fi

  local upstream_url
  upstream_url="$(echo "${health}" | jq -r '.upstream // "unknown"')"
  echo "PASS: proxy healthy (upstream=${upstream_url})"

  mcp_test_ensure_trusted_upstream_policy

  local ping_payload='{"jsonrpc":"2.0","id":"'"${label}"'-ping","method":"ping"}'
  local ping_resp
  ping_resp="$(mcp_test_proxy_post_json "${mcp_url}" "${ping_payload}" || true)"
  if [[ -z "${ping_resp}" ]]; then
    echo "FAIL: upstream preflight ping produced no response" >&2
    exit 2
  fi

  if mcp_test_response_is_upstream_auth_failure "${ping_resp}"; then
    echo "FAIL: upstream MCP rejected proxy upstream API key during preflight ping" >&2
    echo "${ping_resp}" | jq '.' >&2 || echo "${ping_resp}" >&2
    mcp_test_extract_tools_list_error_hint "${ping_resp}"
    mcp_test_require_upstream_api_key_alignment || true
    exit 2
  fi

  if echo "${ping_resp}" | jq -e '.error' >/dev/null 2>&1; then
    local err_code err_msg err_reason
    err_code="$(echo "${ping_resp}" | jq -r '.error.code // empty')"
    err_msg="$(echo "${ping_resp}" | jq -r '.error.message // ""')"
    err_reason="$(echo "${ping_resp}" | jq -r '.error.data.reason // empty')"
    echo "FAIL: upstream preflight ping failed (code=${err_code} reason=${err_reason} msg=${err_msg})" >&2
    echo "${ping_resp}" | jq '.' >&2 || true
    if [[ "${err_reason}" == "untrusted_server" ]]; then
      cat >&2 <<EOF
hint: trusted_servers does not include the configured upstream (${upstream_url}).
hint: bash tools/switch_mcp_policy_sample.sh sprint-1
EOF
    fi
    exit 2
  fi
  echo "PASS: upstream preflight ping reached MCP path"
}

mcp_test_print_key_report() {
  local env_file="${MCP_TEST_REPO_ROOT}/.env"
  local env_key="" dotenv_present=0
  if [[ -f "${env_file}" ]]; then
    dotenv_present=1
    env_key="$(grep -E '^[[:space:]]*MCP_API_KEY=' "${env_file}" 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d '"' | tr -d "'" || true)"
  fi

  local wazuh_key="" proxy_upstream="" proxy_bearer=""
  if command -v docker >/dev/null 2>&1; then
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^wazuh-mcp-server$'; then
      wazuh_key="$(docker exec wazuh-mcp-server printenv MCP_API_KEY 2>/dev/null || true)"
    fi
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^mcp-security-proxy$'; then
      proxy_upstream="$(docker exec mcp-security-proxy printenv MCP_PROXY_UPSTREAM_API_KEY 2>/dev/null || true)"
      proxy_bearer="$(docker exec mcp-security-proxy printenv MCP_PROXY_API_KEY 2>/dev/null || true)"
    fi
  fi

  jq -n \
    --argjson dotenv "${dotenv_present}" \
    --arg env_key "${env_key:-}" \
    --arg wazuh_key "${wazuh_key:-}" \
    --arg proxy_upstream "${proxy_upstream:-}" \
    --arg proxy_bearer "${proxy_bearer:-}" \
    '{
      dotenv_file_present: $dotenv,
      dotenv_mcp_api_key_set: ($env_key | length > 0),
      wazuh_mcp_api_key_set: ($wazuh_key | length > 0),
      proxy_upstream_key_set: ($proxy_upstream | length > 0),
      proxy_bearer_key_set: ($proxy_bearer | length > 0),
      upstream_matches_wazuh: (if ($proxy_upstream != "" and $wazuh_key != "") then $proxy_upstream == $wazuh_key else null end),
      bearer_matches_wazuh: (if ($proxy_bearer != "" and $wazuh_key != "") then $proxy_bearer == $wazuh_key else null end),
      dotenv_matches_wazuh: (if ($env_key != "" and $wazuh_key != "") then $env_key == $wazuh_key else null end)
    }'
}

mcp_test_require_upstream_api_key_alignment() {
  if ! command -v docker >/dev/null 2>&1; then
    return 0
  fi
  if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^mcp-security-proxy$'; then
    return 0
  fi
  if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^wazuh-mcp-server$'; then
    return 0
  fi

  local upstream_key wazuh_key
  upstream_key="$(docker exec mcp-security-proxy printenv MCP_PROXY_UPSTREAM_API_KEY 2>/dev/null || true)"
  wazuh_key="$(docker exec wazuh-mcp-server printenv MCP_API_KEY 2>/dev/null || true)"
  if [[ -z "${upstream_key}" || -z "${wazuh_key}" ]]; then
    return 0
  fi
  local proxy_bearer
  proxy_bearer="$(docker exec mcp-security-proxy printenv MCP_PROXY_API_KEY 2>/dev/null || true)"

  if [[ "${upstream_key}" == "${wazuh_key}" ]]; then
    echo "PASS: proxy upstream API key matches wazuh-mcp-server MCP_API_KEY"
    if [[ -n "${proxy_bearer}" && "${proxy_bearer}" != "${wazuh_key}" ]]; then
      echo "WARN: MCP_PROXY_API_KEY (client bearer) differs from wazuh MCP_API_KEY — run bash tools/align_mcp_proxy_upstream_key.sh" >&2
      return 1
    fi
    if [[ -n "${proxy_bearer}" ]]; then
      echo "PASS: MCP_PROXY_API_KEY (client bearer) matches wazuh MCP_API_KEY"
    fi
    return 0
  fi

  echo "FAIL: MCP_PROXY_UPSTREAM_API_KEY on mcp-security-proxy does not match wazuh-mcp-server MCP_API_KEY" >&2
  cat >&2 <<EOF
hint: recreate the proxy with the wazuh key, for example:
  export MCP_API_KEY="\$(docker exec wazuh-mcp-server printenv MCP_API_KEY)"
  docker compose -f mcp-security-proxy/docker-compose.yml -f mcp-security-proxy/docker-compose.phase4.yml up -d --force-recreate mcp-security-proxy
hint: or run: bash tools/align_mcp_proxy_upstream_key.sh
EOF
  return 1
}

mcp_test_response_is_upstream_auth_failure() {
  local resp="$1"
  echo "${resp}" | jq -e '(.detail // "") | test("invalid|expired|token|unauthorized"; "i")' >/dev/null 2>&1
}

mcp_test_extract_tools_list_error_hint() {
  local resp="$1"
  if echo "${resp}" | jq -e '.detail' >/dev/null 2>&1; then
    cat >&2 <<EOF
hint: upstream MCP rejected the proxy upstream API key (HTTP-style "detail" in response).
hint: align keys in the mcp-security-proxy container, for example:
  MCP_PROXY_UPSTREAM_API_KEY must match the wazuh-mcp-server MCP_API_KEY
hint: check:
  docker exec mcp-security-proxy printenv MCP_PROXY_UPSTREAM_API_KEY
  docker exec wazuh-mcp-server printenv MCP_API_KEY
EOF
    return 0
  fi
  if echo "${resp}" | jq -e '.error.data.reason == "untrusted_server"' >/dev/null 2>&1; then
    cat >&2 <<EOF
hint: trusted_servers blocked the upstream URL. Apply a sprint-1 policy sample first:
  bash tools/switch_mcp_policy_sample.sh sprint-1
EOF
  fi
}

# tools/list via proxy; prints tool names to stdout (one per line) on success.
mcp_test_tools_list_names() {
  local base="${PROXY_BASE_URL:-http://localhost:8090}"
  local mcp_url="${base%/}/mcp"
  local list_payload='{"jsonrpc":"2.0","id":"tools-list","method":"tools/list","params":{}}'
  local list_resp
  list_resp="$(mcp_test_proxy_post_json "${mcp_url}" "${list_payload}")"

  if echo "${list_resp}" | jq -e '.result.tools | length > 0' >/dev/null 2>&1; then
    echo "${list_resp}" | jq -r '.result.tools[].name'
    return 0
  fi

  echo "FAIL: tools/list did not return result.tools" >&2
  echo "${list_resp}" | jq '.' >&2 || echo "${list_resp}" >&2
  mcp_test_extract_tools_list_error_hint "${list_resp}"
  return 1
}
