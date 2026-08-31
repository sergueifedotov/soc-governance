#!/usr/bin/env bash
# Resolve the MCP API key (used as the bearer token for /mcp and
# /observability/*) and export it as MCP_API_KEY for the current shell.
#
# Resolution order (first hit wins):
#   1. MCP_API_KEY already set in the environment
#   2. MCP_OBSERVABILITY_TOKEN already set in the environment
#   3. MCP_API_KEY=... in <repo>/.env
#   4. MCP_OBSERVABILITY_TOKEN=... in <repo>/.env
#   5. The MCP_PROXY_API_KEY env var inside the running mcp-security-proxy container
#   6. The MCP_API_KEY env var inside the running wazuh-mcp-server container
#
# Usage:
#   source tools/mcp_api_key.sh           # exports MCP_API_KEY and MCP_PROXY_API_KEY
#   tools/mcp_api_key.sh                  # prints the key to stdout
#   tools/mcp_api_key.sh --print          # same as above, explicit
#   tools/mcp_api_key.sh --proxy          # resolve the proxy bearer token only
#   tools/mcp_api_key.sh --quiet          # exit 0 if found, no output
#
# Examples:
#   source tools/mcp_api_key.sh
#   curl -H "Authorization: Bearer $MCP_API_KEY" \
#        http://localhost:3000/observability/stats

set -euo pipefail

# zsh sets BASH_SOURCE only when emulating bash; fall back to $0 when sourced.
_self="${BASH_SOURCE[0]:-${(%):-%N}}"
_self="${_self:-$0}"
SCRIPT_DIR="$(cd "$(dirname "${_self}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${REPO_ROOT}/.env"

MODE="print"
RESOLVE_PROXY_ONLY=0
for arg in "${@:-}"; do
  case "${arg}" in
    --print) MODE="print" ;;
    --proxy) RESOLVE_PROXY_ONLY=1 ;;
    --quiet) MODE="quiet" ;;
    -h|--help)
      sed -n '2,22p' "${_self}"
      return 0 2>/dev/null || exit 0
      ;;
    "") ;;
    *)
      echo "Unknown argument: ${arg}" >&2
      return 2 2>/dev/null || exit 2
      ;;
  esac
done

read_env_var() {
  # $1 = var name, $2 = file
  local name="$1" file="$2"
  [[ -f "${file}" ]] || return 1
  local line
  line="$(grep -E "^[[:space:]]*${name}=" "${file}" | tail -n1 || true)"
  [[ -n "${line}" ]] || return 1
  local val="${line#*=}"
  # strip optional surrounding quotes
  val="${val%\"}"; val="${val#\"}"
  val="${val%\'}"; val="${val#\'}"
  printf '%s' "${val}"
}

KEY=""

if [[ ${RESOLVE_PROXY_ONLY} -eq 1 ]]; then
  container_key=""
  if command -v docker >/dev/null 2>&1 && \
     docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^mcp-security-proxy$'; then
    container_key="$(docker exec mcp-security-proxy printenv MCP_PROXY_API_KEY 2>/dev/null || true)"
  fi
  if [[ -n "${container_key}" ]]; then
    KEY="${container_key}"
  elif [[ -n "${MCP_PROXY_API_KEY:-}" ]]; then
    KEY="${MCP_PROXY_API_KEY}"
  elif KEY="$(read_env_var MCP_PROXY_API_KEY "${ENV_FILE}")" && [[ -n "${KEY}" ]]; then
    :
  elif KEY="$(read_env_var MCP_API_KEY "${ENV_FILE}")" && [[ -n "${KEY}" ]]; then
    :
  else
    KEY="mcp_proxy_local_demo_change_me"
  fi
  if [[ "${MODE}" != "quiet" && -n "${container_key}" ]]; then
    env_key=""
    if KEY="$(read_env_var MCP_API_KEY "${ENV_FILE}")" && [[ -n "${KEY}" ]]; then
      env_key="${KEY}"
    fi
    if [[ -n "${env_key}" && "${env_key}" != "${container_key}" ]]; then
      echo "WARN: running proxy MCP_PROXY_API_KEY differs from ${ENV_FILE} MCP_API_KEY." >&2
      echo "WARN: UI/admin auth must use the running proxy key above (or run: bash tools/align_mcp_proxy_upstream_key.sh)." >&2
    fi
  fi
elif [[ -n "${MCP_PROXY_API_KEY:-}" ]]; then
  KEY="${MCP_PROXY_API_KEY}"
elif command -v docker >/dev/null 2>&1 && \
     docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^mcp-security-proxy$'; then
  KEY="$(docker exec mcp-security-proxy printenv MCP_PROXY_API_KEY 2>/dev/null || true)"
elif [[ -n "${MCP_API_KEY:-}" ]]; then
  KEY="${MCP_API_KEY}"
elif [[ -n "${MCP_OBSERVABILITY_TOKEN:-}" ]]; then
  KEY="${MCP_OBSERVABILITY_TOKEN}"
elif KEY="$(read_env_var MCP_API_KEY "${ENV_FILE}")" && [[ -n "${KEY}" ]]; then
  :
elif KEY="$(read_env_var MCP_OBSERVABILITY_TOKEN "${ENV_FILE}")" && [[ -n "${KEY}" ]]; then
  :
elif command -v docker >/dev/null 2>&1 && \
     docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^wazuh-mcp-server$'; then
  KEY="$(docker exec wazuh-mcp-server printenv MCP_API_KEY 2>/dev/null || true)"
fi

if [[ -z "${KEY}" ]]; then
  if [[ "${MODE}" != "quiet" ]]; then
    echo "ERROR: could not resolve MCP_API_KEY (checked env, ${ENV_FILE}, container)" >&2
  fi
  return 1 2>/dev/null || exit 1
fi

export MCP_API_KEY="${KEY}"
export MCP_PROXY_API_KEY="${KEY}"

if [[ "${MODE}" == "print" ]]; then
  printf '%s\n' "${KEY}"
fi
