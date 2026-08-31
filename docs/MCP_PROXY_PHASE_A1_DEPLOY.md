# Phase A1 — Isolated executor deployment (summary and runbook)

This document is the operator runbook for **roadmap Phase A1**: deploy the reference
[isolated executor](../mcp-isolated-executor/) sidecar, wire it to
`mcp-security-proxy`, and verify `tools/call` routing for execution-like tools.

Related docs:

- [MCP_PROXY_PHASE_A_COMPLETE.md](MCP_PROXY_PHASE_A_COMPLETE.md) — Phase A master guide (A1–A5)
- [MCP_PROXY_PHASE_A2.md](MCP_PROXY_PHASE_A2.md) — Phase A2 after A1 (limits, filesystem, provenance)
- [MCP_PROXY_NEXT_STEPS.md](MCP_PROXY_NEXT_STEPS.md) — **operator checklist after A1 / Sprint 3**
- [MCP_PROXY_ROADMAP.md](MCP_PROXY_ROADMAP.md) — overall roadmap (phases A–E)
- [MCP_PROXY_ISOLATED_EXECUTION.md](MCP_PROXY_ISOLATED_EXECUTION.md) — policy fields and deny reasons
- [MCP_PROXY_SPRINT_TESTING.md](MCP_PROXY_SPRINT_TESTING.md) — Sprint 1–3 E2E tests

---

## What was implemented (summary)

| Component | Location | Purpose |
|-----------|----------|---------|
| Executor service | `mcp-isolated-executor/` | `GET /health`, `POST /execute` (proxy contract) |
| Docker image | `mcp-isolated-executor:local` | Non-root (`uid=1000`), read-only root, no network |
| Compose overlay | `mcp-security-proxy/docker-compose.isolated-executor.yml` | Joins `wazuh-soc_default` + `wazuh-soc_phase4` |
| Operational policy | `config/phase4/mcp_proxy/policy.sample.sprint-3-executor-operational.json` | Live routing to `http://isolated-executor:8080/execute` |
| Start script | `tools/start_isolated_executor.sh` | Build/start sidecar only |
| Deploy script | `tools/deploy_isolated_executor_a1.sh` | Health checks, apply policy, smoke `shell_exec` |
| Live test | `tools/test_isolated_executor_live.sh` | End-to-end via proxy `/mcp` |
| Profile C integration | `tools/start-profile.sh C` | Starts proxy + executor compose stack |

**Runtime choice:** reference image uses a **hardened container** (not gVisor/Firecracker).
Replace the image in production; keep the same HTTP API.

**Policy highlights** (`sprint-3-executor`):

| Field | Value | Why |
|-------|-------|-----|
| `isolated_executor_profile.enabled` | `true` | Route matching tools to executor |
| `executor_url` | `http://isolated-executor:8080/execute` | Docker DNS on Profile C networks |
| `fallback_to_upstream` | `false` | Fail closed if executor unavailable |
| `forward_on_success` | `false` | Return executor response directly (smoke-friendly) |
| `execution_tool_profile.enabled` | `false` | Avoid `execution_tool_blocked` before executor runs |
| `upstream_provenance_profile.allowed_destinations` | includes executor host | Provenance allows forward to executor |

---

## Prerequisites

1. **Docker** running (Docker Desktop or engine).
2. **Profile C started at least once** so external networks exist:
   - `wazuh-soc_default`
   - `wazuh-soc_phase4`
3. **CLI:** `bash`, `curl`, `jq`.
4. **Repo root** as working directory.

Check networks:

```bash
docker network ls | grep wazuh-soc
```

You should see `wazuh-soc_default` and `wazuh-soc_phase4`. If not, start Profile C first.

Check core containers:

```bash
docker ps --format 'table {{.Names}}\t{{.Status}}' | grep -E 'mcp-security-proxy|wazuh-mcp-server|isolated-executor'
```

---

## Deployment procedure (copy-paste safe)

Run **one command per line**. Do not paste shell comments (`# ...`) on the same line as
a command — zsh will treat `#` as arguments or try to run `#` as a command.

### Step 1 — Start Profile C (creates networks + proxy + Wazuh stack)

```bash
cd /path/to/Wazuh-MCP-Neo4j-OCTI-Mon-C-6
bash tools/start-profile.sh C
```

Wait until the stack is up. Verify:

```bash
curl -s http://localhost:8090/health | jq .
```

Expected: `"status": "healthy"`.

Optional — align proxy upstream API key with Wazuh (fixes `Invalid or expired token` on `tools/list`):

```bash
bash tools/align_mcp_proxy_upstream_key.sh
```

Profile C also brings up `isolated-executor` if compose includes
`docker-compose.isolated-executor.yml`. If the executor is missing, use Step 2.

### Step 2 — Start isolated executor (if not already running)

```bash
bash tools/start_isolated_executor.sh
```

Host health (default port **18088**, not 8088 — AgentGuard may use 8088):

```bash
curl -s http://localhost:18088/health | jq .
```

### Step 3 — Deploy A1 (verify + policy + smoke)

```bash
bash tools/deploy_isolated_executor_a1.sh
```

Expected trailer:

```text
PASS: mcp-security-proxy -> isolated-executor:8080/health
PASS: operational policy active
PASS: isolated executor smoke call succeeded
Phase A1 deployment complete.
```

### Step 4 — Live integration test

```bash
bash tools/test_isolated_executor_live.sh
```

Expected final line: `PASS: live isolated executor integration`.

For a **field-by-field explanation** of the JSON and warnings, see
[Interpreting isolated executor test results](#interpreting-isolated-executor-test-results)
below.

### Step 5 — Apply policy to disk (optional)

```bash
bash tools/switch_mcp_policy_sample.sh sprint-3-executor
```

---

## Interpreting isolated executor test results

This section explains output from:

- `bash tools/deploy_isolated_executor_a1.sh` (deploy + smoke)
- `bash tools/test_isolated_executor_live.sh` (live integration)

A **successful** live run proves: the proxy accepted your MCP call, routed
`shell_exec` to the sidecar, the sidecar ran a safe command as a non-root user, and the
proxy returned the executor JSON (not an upstream Wazuh error).

### Script lines before the JSON

| Line | Meaning |
|------|---------|
| `== ISOLATED EXECUTOR LIVE TEST ==` | Start of `test_isolated_executor_live.sh`. |
| `PASS: proxy upstream API key matches wazuh-mcp-server MCP_API_KEY` | `MCP_PROXY_UPSTREAM_API_KEY` on `mcp-security-proxy` equals `MCP_API_KEY` on `wazuh-mcp-server`. Required for `tools/list` and any path that forwards to Wazuh; live executor test still works if only executor routing is used. |
| *(no `FAIL:` lines)* | Preconditions passed: `isolated-executor` container running, operational policy applied via admin API. |

If you see `FAIL: isolated-executor container not running` or
`FAIL: mcp-security-proxy is not running`, fix deployment first (see
[Troubleshooting](#troubleshooting)) — do not interpret the JSON below.

### Successful HTTP body (what the proxy returns)

With operational policy (`forward_on_success: false`), a successful `tools/call` to
`shell_exec` with `{"cmd":"whoami"}` returns the **executor response body** directly
(not a normal Wazuh tool result). Example:

```json
{
  "status": "ok",
  "execution_id": "e9e64b2b-0c1e-4c67-a022-ff963cbae7b5",
  "runtime_info": {
    "uid": 1000,
    "gid": 1000,
    "no_new_privs": true,
    "seccomp_enabled": true,
    "runtime": "hardened-container",
    "allow_network": false
  },
  "elapsed_ms": 2,
  "exit_code": 0,
  "result": {
    "jsonrpc": "2.0",
    "id": "live-1",
    "result": {
      "content": [
        {
          "type": "text",
          "text": "{ ... executor, argv, output ... }"
        }
      ],
      "_isolated_executor": {
        "execution_id": "e9e64b2b-0c1e-4c67-a022-ff963cbae7b5",
        "elapsed_ms": 2
      }
    }
  }
}
```

#### Top-level fields

| Field | Good value | What it means |
|-------|------------|----------------|
| `status` | `"ok"` | Executor finished without HTTP 4xx/5xx. |
| `execution_id` | UUID string | Correlates this run in executor logs and proxy `executor_evidence` on decision events. |
| `runtime_info` | object (see below) | Evidence the proxy uses for **rootless verification** when `require_rootless: true`. |
| `elapsed_ms` | small integer | Time spent inside the executor for this call. |
| `exit_code` | `0` | Subprocess exit code for the allowed command (`whoami` → typically `0`). |
| `result` | MCP-shaped object | Synthetic tool result the client can display; includes nested JSON in `content[0].text`. |

**Failure shapes** (live test exits `FAIL`):

| Shape | Typical cause |
|-------|----------------|
| `"error": { "code": -32003, "data": { "reason": "..." } }` | Proxy policy deny (`execution_tool_blocked`, `sandbox_attestation_missing`, `isolated_executor_unavailable`, etc.). |
| `"error": { "code": -32004, ... }` | Executor unreachable or transport error after retries. |
| `Internal Server Error` (plain text) | Proxy bug or unhandled exception; check `docker logs mcp-security-proxy`. |
| Missing `runtime_info` / `execution_id` | Response was not from the executor path (wrong policy or call did not match `require_for_tools`). |

#### `runtime_info` (rootless and runtime attestation)

| Field | Good value | What it means |
|-------|------------|----------------|
| `uid` | non-zero (e.g. `1000`) | Process not running as root inside the executor container. `uid: 0` → proxy denies with `rootless_execution_required` when `require_rootless: true`. |
| `gid` | non-zero (e.g. `1000`) | Primary group of the executor process. |
| `no_new_privs` | `true` | Matches container `security_opt: no-new-privileges:true`. |
| `seccomp_enabled` | `true` | Reported as enabled for the reference image (informational for policy). |
| `runtime` | `"hardened-container"` | Label for this reference implementation (not gVisor/Firecracker unless you change the image). |
| `allow_network` | `false` | Executor has no egress in the reference compose setup. |

#### `result.content[0].text` (parsed inner JSON)

The text block is a JSON string. After parsing it:

| Field | Example | What it means |
|-------|---------|----------------|
| `executor` | `"hardened-container"` | Same runtime label as `runtime_info.runtime`. |
| `execution_id` | same UUID as top level | Duplicate for convenience inside MCP content. |
| `argv` | `["whoami"]` | Command actually executed (must be in the executor allowlist). |
| `output` | `"executor"` | stdout of `whoami` — the Linux username in the container (user `executor`), **not** your Mac username. |
| `exit_code` | `0` | Success. |

Allowed demo commands only: `whoami`, `id`, `pwd`, `uname`, `echo`, `date`. Anything else returns executor HTTP 403 and proxy `isolated_executor_error`.

#### `result._isolated_executor`

Metadata attached to the synthetic MCP tool result so clients can see the call was
served by the sidecar.

### What the test script checks

`test_isolated_executor_live.sh` fails if:

1. HTTP body contains JSON-RPC `.error`, or
2. Top-level `runtime_info` or `execution_id` is missing.

It does **not** require a specific `output` string for `whoami`.

### `WARN: recent denied contains isolated_executor* for shell_exec`

```text
WARN: recent denied contains isolated_executor* for shell_exec (unexpected on success)
PASS: live isolated executor integration
```

| Aspect | Explanation |
|--------|----------------|
| Is it a failure? | **No.** The script still prints `PASS` and exits 0. |
| Why it appears | `/recent-denied` is a **rolling history**. Older attempts (empty `executor_url`, executor down, policy without `execution_tool_profile` disabled, etc.) left `shell_exec` rows with reasons like `isolated_executor_unavailable` or `isolated_executor_error`. |
| This successful call | Did **not** add a new deny for `shell_exec`; the live call returned `status: ok`. |
| How to confirm | Inspect only the HTTP JSON: no `.error`, `status: "ok"`, `uid: 1000`. Optionally open `http://localhost:8090/ui` → Evidence and Decisions → look for a recent **allow** decision with `executor_evidence` on the `isolated_executor` stage. |

To reduce noise in `/recent-denied`, run new tests after a fresh proxy start, or focus on the latest event timestamps in the UI.

### `deploy_isolated_executor_a1.sh` smoke output (shorter JSON)

The deploy script prints a one-line summary after the same `tools/call`:

```json
{
  "error": null,
  "execution_id": "56a10df4-3c37-404a-935b-b1cb413c26c3",
  "runtime_uid": 1000,
  "has_result": true
}
```

| Field | Good value | Meaning |
|-------|------------|---------|
| `error` | `null` | No proxy JSON-RPC error. |
| `execution_id` | UUID | Executor run id. |
| `runtime_uid` | `1000` (not `0`) | Rootless check would pass. |
| `has_result` | `true` | MCP-shaped `result` present. |

### Where to see this in the UI

1. Open `http://localhost:8090/ui` (not Phase 4 SOC on `:8082`).
2. **Tuning Studio** → **Evidence and Decisions**.
3. **Recent Decision Events** — look for `stage: isolated_executor`, `decision: allow`, and `executor_evidence` (execution id, elapsed ms).
4. **Recent Denied Calls** — may still show **older** `isolated_executor_*` rows; that does not contradict a successful live test.

### Policy settings that produce this success shape

From `policy.sample.sprint-3-executor-operational.json`:

| Setting | Value | Effect on this test |
|---------|-------|---------------------|
| `isolated_executor_profile.enabled` | `true` | Routes matching tools to executor. |
| `executor_url` | `http://isolated-executor:8080/execute` | Target sidecar. |
| `require_for_tools` | `shell`, `exec`, … | `shell_exec` matches. |
| `fallback_to_upstream` | `false` | No silent fallback to Wazuh on executor errors. |
| `forward_on_success` | `false` | Client sees executor JSON (table above). |
| `execution_tool_profile.enabled` | `false` | Avoids `execution_tool_blocked` before routing. |
| `require_rootless` | `true` | Requires `runtime_info.uid != 0` (satisfied). |

### After a successful live test

Phase A1 is **complete** when `deploy_isolated_executor_a1.sh` and
`test_isolated_executor_live.sh` both pass (executor JSON with `uid: 1000`,
`runtime: hardened-container`).

**Full operator checklist (persist policy, A2–A5, stale telemetry, production,
roadmap):** [MCP_PROXY_NEXT_STEPS.md](MCP_PROXY_NEXT_STEPS.md).

Immediate actions:

```bash
bash tools/switch_mcp_policy_sample.sh sprint-3-executor
bash tools/test_sprint3_no_restart.sh
```

Then run Phase A2 — full runbook: [MCP_PROXY_PHASE_A2.md](MCP_PROXY_PHASE_A2.md):

```bash
bash tools/apply_mcp_proxy_phase_a2.sh
```
Then **A3** `monitor` → `deny`, **A4** [keys](MCP_PROXY_PHASE_A4.md), **A5** regression and UI review. Longer term:
Sprint 4–5 per [MCP_PROXY_ROADMAP.md](MCP_PROXY_ROADMAP.md).

---

## All-in-one command block

```bash
cd /path/to/Wazuh-MCP-Neo4j-OCTI-Mon-C-6
bash tools/start-profile.sh C
bash tools/align_mcp_proxy_upstream_key.sh
bash tools/start_isolated_executor.sh
bash tools/deploy_isolated_executor_a1.sh
bash tools/test_isolated_executor_live.sh
```

---

## Troubleshooting

### `Unknown argument: #` or `zsh: command not found: #`

**Cause:** Pasting documentation that includes inline comments, e.g.

```bash
bash tools/start-profile.sh C          # now includes isolated-executor
```

zsh runs `#` as part of the command line.

**Fix:** Run only the command, on its own line:

```bash
bash tools/start-profile.sh C
```

### `network wazuh-soc_default declared as external, but could not be found`

**Cause:** `start_isolated_executor.sh` (or executor compose) runs **before** Profile C
creates the Docker networks.

**Fix:**

```bash
bash tools/start-profile.sh C
docker network ls | grep wazuh-soc
bash tools/start_isolated_executor.sh
```

### `FAIL: mcp-security-proxy is not running`

**Cause:** Profile C is not up, or proxy container exited.

**Fix:**

```bash
bash tools/start-profile.sh C
docker ps | grep mcp-security-proxy
curl -s http://localhost:8090/health | jq .
```

### `FAIL: isolated-executor container not running`

**Cause:** Executor start failed (often due to missing network or port conflict).

**Fix:**

```bash
docker logs isolated-executor --tail 50
bash tools/start_isolated_executor.sh
```

If host port **18088** is in use:

```bash
export ISOLATED_EXECUTOR_HOST_PORT=18089
bash tools/start_isolated_executor.sh
```

### `Bind for 0.0.0.0:8088 failed: port is already allocated`

**Cause:** Port 8088 is used by AgentGuard in this repo’s Phase 2 stack.

**Fix:** Default executor host port is **18088**. Use `http://localhost:18088/health`.

### `Internal Server Error` (HTTP 500) on `tools/call` through proxy

**Cause (fixed in tree):** proxy called `_record_decision_event(..., executor_evidence=...)`
before `executor_evidence` was a supported parameter.

**Fix:** Restart proxy so mounted `mcp_security_proxy/app.py` is loaded:

```bash
docker restart mcp-security-proxy
```

Or rebuild:

```bash
cd mcp-security-proxy
docker compose -f docker-compose.yml -f docker-compose.phase4.yml up -d --build mcp-security-proxy
```

### `execution_tool_blocked` instead of executor success

**Cause:** `execution_tool_profile` denies `shell_exec` before isolated executor routing.

**Fix:** Use operational policy:

```bash
bash tools/switch_mcp_policy_sample.sh sprint-3-executor
```

or re-run `bash tools/deploy_isolated_executor_a1.sh` (applies operational policy via admin API).

### `{"detail":"Invalid or expired token"}` on `tools/list`

**Cause:** `MCP_PROXY_UPSTREAM_API_KEY` ≠ `wazuh-mcp-server` `MCP_API_KEY`.

**Fix:**

```bash
bash tools/align_mcp_proxy_upstream_key.sh
```

---

## Verification checklist

| Check | Command | Expected |
|-------|---------|----------|
| Networks exist | `docker network ls \| grep wazuh-soc` | `_default` and `_phase4` |
| Proxy healthy | `curl -s http://localhost:8090/health \| jq .status` | `"healthy"` |
| Executor healthy (host) | `curl -s http://localhost:18088/health \| jq .status` | `"healthy"` |
| Executor from proxy net | `docker exec mcp-security-proxy python -c "import urllib.request; print(urllib.request.urlopen('http://isolated-executor:8080/health').read().decode())"` | `"healthy"` |
| Policy applied | `curl -s -H "Authorization: Bearer $(tools/mcp_api_key.sh --proxy)" http://localhost:8090/admin/policy-config \| jq '.raw_policy.isolated_executor_profile.executor_url'` | `http://isolated-executor:8080/execute` |
| Smoke call | `bash tools/deploy_isolated_executor_a1.sh` | `PASS: isolated executor smoke call succeeded` |

---

## Architecture (request flow)

```text
Client  --Bearer MCP_PROXY_API_KEY-->  mcp-security-proxy:8090/mcp
                                           |
                                           | POST /execute
                                           v
                                    isolated-executor:8080
                                    (hardened-container, uid 1000)
                                           |
                                           | JSON: runtime_info + result
                                           v
                                    proxy records executor_evidence
                                    returns JSON to client
```

When `forward_on_success: true`, the proxy may also forward the original MCP body to
`wazuh-mcp-server` after a successful executor run.

---

## Files reference

| Path | Description |
|------|-------------|
| `mcp-isolated-executor/isolated_executor/app.py` | Executor HTTP service |
| `mcp-isolated-executor/Dockerfile` | Non-root executor image |
| `mcp-security-proxy/docker-compose.isolated-executor.yml` | Compose service + networks |
| `config/phase4/mcp_proxy/policy.sample.sprint-3-executor-operational.json` | Operational policy |
| `tools/start_isolated_executor.sh` | Start sidecar |
| `tools/deploy_isolated_executor_a1.sh` | A1 deploy + smoke |
| `tools/test_isolated_executor_live.sh` | Live test |
