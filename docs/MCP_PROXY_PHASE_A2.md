# Phase A2 — Runtime limits, filesystem, and upstream provenance (runbook)

This document is the operator runbook for **roadmap Phase A2**: apply a tuned
operational policy on top of Phase A1 (live isolated executor), enable restrictive
**runtime limits**, **filesystem restrictions**, and **upstream provenance**, then
verify Sprint 3 sub-gates and live `shell_exec` routing.

Related docs:

- [MCP_PROXY_PHASE_A1_DEPLOY.md](MCP_PROXY_PHASE_A1_DEPLOY.md) — prerequisite: executor sidecar + A1 smoke
- [MCP_PROXY_NEXT_STEPS.md](MCP_PROXY_NEXT_STEPS.md) — checklist after A2 (Phase A3–A5)
- [MCP_PROXY_ROADMAP.md](MCP_PROXY_ROADMAP.md) — Phase A overview
- [MCP_PROXY_ISOLATED_EXECUTION.md](MCP_PROXY_ISOLATED_EXECUTION.md) — policy fields and deny reasons

---

## What was implemented (summary)

| Component | Location | Purpose |
|-----------|----------|---------|
| A2 policy sample | `config/phase4/mcp_proxy/policy.sample.sprint-3-a2-operational.json` | A1 executor routing + tightened limits / FS / provenance |
| Policy alias | `sprint-3-a2` / `sprint-3-a2-operational` | `bash tools/switch_mcp_policy_sample.sh sprint-3-a2` |
| Apply + verify script | `tools/apply_mcp_proxy_phase_a2.sh` | Apply policy, run gates, live executor test |
| Runtime gate test | `tools/test_runtime_limits.sh` | CPU/memory argument checks |
| Filesystem gate test | `tools/test_filesystem_restrictions.sh` | Deny read/write path checks |
| Provenance gate test | `tools/test_upstream_provenance.sh` | Allow/block destination policy |
| Live regression | `tools/test_isolated_executor_live.sh` | `POLICY_FILE` can point at A2 sample |

**Scope:** A2 configures **proxy-side** checks before/for executor routing. It does not
replace the reference executor image (still `mcp-isolated-executor:local` hardened container).

---

## Prerequisites

1. **Phase A1 complete** — see [MCP_PROXY_PHASE_A1_DEPLOY.md](MCP_PROXY_PHASE_A1_DEPLOY.md):
   - `mcp-security-proxy` and `isolated-executor` running
   - `bash tools/deploy_isolated_executor_a1.sh` passed, or equivalent Profile C + executor setup
2. **Profile C** (or same stack) still up:

```bash
curl -s http://localhost:8090/health | jq .status
curl -s http://localhost:18088/health | jq .status
```

3. **CLI:** `bash`, `curl`, `jq`, `docker`.

---

## Policy: `sprint-3-a2` vs `sprint-3-executor`

Both profiles keep the executor path from A1 (`execution_tool_profile.enabled: false`,
`fallback_to_upstream: false`, `forward_on_success: false`). A2 adds operational tuning.

| Area | `sprint-3-executor` (A1) | `sprint-3-a2` (A2) |
|------|--------------------------|---------------------|
| `timeout_seconds` | 60 | 45 |
| `runtime_limits.max_cpu_seconds` | 30 | 15 |
| `runtime_limits.max_memory_mb` | 512 | 256 |
| `runtime_limits.max_wall_time_seconds` | 60 | 45 |
| `runtime_limits.max_processes` | 10 | 8 |
| `runtime_limits.max_file_descriptors` | 100 | 64 |
| `filesystem_restrictions.deny_read_paths` | 4 paths | 7 paths (+ `/etc/sudoers`, `/proc/self/environ`, `/root/.docker`) |
| `filesystem_restrictions.deny_write_paths` | 6 prefixes | 8 (+ `/boot`, `/sys`) |
| `max_file_size_mb` / `max_total_size_mb` | 100 / 500 | 50 / 200 |
| `upstream_provenance_profile.max_egress_bytes` | 1048576 | 524288 |
| `blocked_destinations` | 5 patterns | 6 (+ `*.requestbin.com`) |
| `discovery_rules` | no `runtime_limits_violations` | includes `runtime_limits_violations` → monitor |

Shared (unchanged intent):

| Field | Value |
|-------|-------|
| `isolated_executor_profile.enabled` | `true` |
| `executor_url` | `http://isolated-executor:8080/execute` |
| `require_rootless` | `true` |
| `upstream_provenance_profile.enabled` | `true` |
| `allowed_destinations` | executor + `wazuh-mcp-server:3000` |
| `dependency_fail_safe_profile.enabled` | `false` (lab-friendly; enable in A3/production) |

---

## Deployment procedure (copy-paste safe)

Run **one command per line**. Do not paste inline `#` comments on the same line as commands.

### Step 1 — Confirm Phase A1 stack

```bash
cd /path/to/Wazuh-MCP-Neo4j-OCTI-Mon-C-6
docker ps --format 'table {{.Names}}\t{{.Status}}' | grep -E 'mcp-security-proxy|isolated-executor'
```

If the executor is missing:

```bash
bash tools/start_isolated_executor.sh
```

### Step 2 — Apply A2 and run all gates (recommended)

```bash
bash tools/apply_mcp_proxy_phase_a2.sh
```

Expected trailer:

```text
Phase A2 complete.
  Active policy: config/phase4/mcp_proxy/policy.json (sprint-3-a2-operational)
```

Sub-steps inside the script:

| Step | Action |
|------|--------|
| Preflight | Proxy healthy; start executor if needed |
| Policy | `switch_mcp_policy_sample.sh sprint-3-a2` → disk + reload |
| Keys | `align_mcp_proxy_upstream_key.sh` |
| [1/4] | `test_runtime_limits.sh` |
| [2/4] | `test_filesystem_restrictions.sh` |
| [3/4] | `test_upstream_provenance.sh` |
| [4/4] | `test_isolated_executor_live.sh` with A2 `POLICY_FILE` |

Skip live test only if executor is intentionally down:

```bash
bash tools/apply_mcp_proxy_phase_a2.sh --skip-live-test
```

### Step 3 — Manual apply (alternative)

```bash
bash tools/switch_mcp_policy_sample.sh sprint-3-a2
bash tools/align_mcp_proxy_upstream_key.sh
bash tools/test_runtime_limits.sh
bash tools/test_filesystem_restrictions.sh
bash tools/test_upstream_provenance.sh
POLICY_FILE=config/phase4/mcp_proxy/policy.sample.sprint-3-a2-operational.json \
  bash tools/test_isolated_executor_live.sh
```

### Step 4 — Verify active policy

```bash
curl -s -H "Authorization: Bearer $(bash tools/mcp_api_key.sh --proxy)" \
  http://localhost:8090/admin/policy-config | jq '{
    executor_url: .raw_policy.isolated_executor_profile.executor_url,
    runtime_limits: .raw_policy.isolated_executor_profile.runtime_limits,
    upstream_provenance_enabled: .raw_policy.upstream_provenance_profile.enabled
  }'
```

---

## How enforcement works (proxy)

Checks run in `mcp-security-proxy` before forwarding to the isolated executor. See
[MCP_PROXY_ISOLATED_EXECUTION.md](MCP_PROXY_ISOLATED_EXECUTION.md) for full deny reason list.

### Runtime limits

Proxy reads `shell_exec` (and matching tool) **arguments** and compares to
`isolated_executor_profile.runtime_limits`:

| Argument field | Limit field |
|----------------|-------------|
| `timeout_seconds` | `max_cpu_seconds`, `max_wall_time_seconds` |
| `memory_mb` | `max_memory_mb` |

Typical deny reason: `runtime_limits_exceeded`. Discovery signal:
`runtime_limits_violations` (monitor in A2 sample).

### Filesystem restrictions

Proxy scans argument keys such as `path`, `file`, `output`, `destination` against
`deny_read_paths` and `deny_write_paths`.

Typical deny reason: `filesystem_restriction_violation`. Discovery signal:
`filesystem_violations`.

### Upstream provenance

Before calling `executor_url`, proxy checks the destination against
`allowed_destinations` and `blocked_destinations` (glob-style patterns).

Typical deny reasons: `upstream_dest_blocked`, `upstream_provenance_denied`.
Discovery signal: `upstream_provenance_violations`.

---

## Completion criteria

Phase A2 is **complete** when:

1. `bash tools/apply_mcp_proxy_phase_a2.sh` exits 0 with `Phase A2 complete.`
2. Live test prints `PASS: live isolated executor integration` with `runtime_info.uid: 1000`
3. Active `policy.json` matches the A2 sample (or equivalent admin policy)

| Check | Command | Expected |
|-------|---------|----------|
| Policy on disk | `grep -l sprint-3-a2 config/phase4/mcp_proxy/policy.json` or compare to sample | Same structure as `policy.sample.sprint-3-a2-operational.json` |
| Runtime limits | `bash tools/test_runtime_limits.sh` | `RUNTIME LIMITS TEST PASSED` |
| Filesystem | `bash tools/test_filesystem_restrictions.sh` | `FILESYSTEM RESTRICTIONS TEST PASSED` |
| Provenance | `bash tools/test_upstream_provenance.sh` | `UPSTREAM PROVENANCE TEST PASSED` |
| Live routing | `POLICY_FILE=.../policy.sample.sprint-3-a2-operational.json bash tools/test_isolated_executor_live.sh` | `PASS: live isolated executor integration` |

---

## Troubleshooting

### `FAIL: mcp-security-proxy is not running`

Start Profile C:

```bash
bash tools/start-profile.sh C
```

### Sub-gate tests pass but live test fails

- Confirm executor: `docker ps | grep isolated-executor`
- Re-apply A2 policy: `bash tools/switch_mcp_policy_sample.sh sprint-3-a2`
- Align keys: `bash tools/align_mcp_proxy_upstream_key.sh`
- Check provenance allows executor URL in `allowed_destinations`

### `upstream_provenance_denied` on otherwise valid calls

Add the destination to `allowed_destinations` in policy or UI. A2 sample already includes:

- `http://isolated-executor:8080`
- `http://isolated-executor:8080/execute`
- `http://wazuh-mcp-server:3000` (+ `/mcp`)

### Legitimate work blocked by tight limits

Widen in UI or edit `runtime_limits` / `filesystem_restrictions` in
`policy.sample.sprint-3-a2-operational.json`, then:

```bash
bash tools/switch_mcp_policy_sample.sh sprint-3-a2
```

Document changes in Tuning Studio evidence before moving controls to `deny` (Phase A3).

### Sprint test scripts restore policy

`test_runtime_limits.sh` (and siblings) snapshot policy at start and restore on exit.
`apply_mcp_proxy_phase_a2.sh` re-applies A2 at the beginning; run it again if you
only ran individual tests and lost the A2 active policy.

---

## After Phase A2

1. **Phase A3** — Staged rollout: [MCP_PROXY_PHASE_A3.md](MCP_PROXY_PHASE_A3.md)

```bash
bash tools/apply_mcp_proxy_phase_a3.sh
```
2. **Phase A5** — Regression: `bash tools/test_sprint3_no_restart.sh` or `bash tools/smoke_mcp_proxy.sh`
3. **UI** — `http://localhost:8090/ui` → Tuning Studio → Evidence and Decisions

---

## Files reference

| Path | Description |
|------|-------------|
| `config/phase4/mcp_proxy/policy.sample.sprint-3-a2-operational.json` | A2 policy sample |
| `config/phase4/mcp_proxy/policy.json` | Active policy (after `switch_mcp_policy_sample.sh sprint-3-a2`) |
| `tools/apply_mcp_proxy_phase_a2.sh` | A2 apply + verify |
| `tools/switch_mcp_policy_sample.sh` | Profile switcher (`sprint-3-a2` alias) |
| `tools/test_runtime_limits.sh` | Runtime limits gate |
| `tools/test_filesystem_restrictions.sh` | Filesystem gate |
| `tools/test_upstream_provenance.sh` | Provenance gate |
| `tools/test_isolated_executor_live.sh` | Live executor (`POLICY_FILE` override) |
| `mcp-security-proxy/mcp_security_proxy/app.py` | `_check_runtime_limits`, `_check_filesystem_restrictions`, `_check_upstream_provenance` |
