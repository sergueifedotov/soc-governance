# MCP Isolated Executor

Hardened sidecar service for [mcp-security-proxy](../mcp-security-proxy) Sprint 3
`isolated_executor_profile`. The proxy POSTs wrapped MCP `tools/call` requests to
`/execute` and records `runtime_info` for rootless verification.

## Runtime model

- **Default:** `hardened-container` — non-root user (`uid=1000`), read-only root
  filesystem, `no-new-privileges`, dropped capabilities, no network egress.
- **Not** gVisor/Firecracker in this reference image; swap the image/runtime in
  production while keeping the same HTTP contract.

## API

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Liveness; includes `runtime_info` |
| `POST /execute` | Body: `{ "original_request": <json-rpc>, "security_context": { ... } }` |

Successful response (proxy consumes `runtime_info` and optional `result`):

```json
{
  "status": "ok",
  "execution_id": "uuid",
  "runtime_info": { "uid": 1000, "gid": 1000, "no_new_privs": true, "seccomp_enabled": true, "runtime": "hardened-container" },
  "result": { "jsonrpc": "2.0", "id": "...", "result": { "content": [...] } }
}
```

Demo execution only allows safe commands: `whoami`, `id`, `pwd`, `uname`, `echo`, `date`.

**Interpreting live test JSON** (`whoami` → `"output": "executor"`, `WARN` on
`/recent-denied`, etc.): [docs/MCP_PROXY_PHASE_A1_DEPLOY.md](../docs/MCP_PROXY_PHASE_A1_DEPLOY.md)
— *Interpreting isolated executor test results*.

## Deploy with Profile C

**Runbook:** [docs/MCP_PROXY_PHASE_A1_DEPLOY.md](../docs/MCP_PROXY_PHASE_A1_DEPLOY.md)

```bash
bash tools/start-profile.sh C
bash tools/align_mcp_proxy_upstream_key.sh
bash tools/start_isolated_executor.sh
bash tools/deploy_isolated_executor_a1.sh
bash tools/test_isolated_executor_live.sh
```

Start Profile C **first** so Docker networks `wazuh-soc_default` and `wazuh-soc_phase4`
exist. Do not paste `# comment` text on the same line as commands in zsh.

Compose file: [../mcp-security-proxy/docker-compose.isolated-executor.yml](../mcp-security-proxy/docker-compose.isolated-executor.yml)

Host debug port: `http://localhost:18088/health` (override with `ISOLATED_EXECUTOR_HOST_PORT`; default `18088` avoids AgentGuard on `8088`).

## Environment

| Variable | Default | Description |
|----------|---------|-------------|
| `ISOLATED_EXECUTOR_RUNTIME` | `hardened-container` | Reported in `runtime_info.runtime` |
| `ISOLATED_EXECUTOR_ALLOW_NETWORK` | `false` | Exposed in health payload |
| `ISOLATED_EXECUTOR_TIMEOUT_SECONDS` | `25` | Subprocess timeout |
| `ISOLATED_EXECUTOR_MAX_OUTPUT_BYTES` | `65536` | Truncate combined stdout/stderr |

## Policy

Use sample `config/phase4/mcp_proxy/policy.sample.sprint-3-executor-operational.json`:

```bash
bash tools/switch_mcp_policy_sample.sh sprint-3-executor
```

Key settings: `isolated_executor_profile.executor_url`, `fallback_to_upstream: false`,
`execution_tool_profile.enabled: false` (executor handles execution-like tools).
