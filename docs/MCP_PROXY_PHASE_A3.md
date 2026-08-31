# Phase A3 — Staged enforcement rollout (runbook)

Operator runbook for **roadmap Phase A3**: roll Sprint 3 controls through
**monitor → challenge → deny** without restarting Profile C.

Builds on [Phase A1](MCP_PROXY_PHASE_A1_DEPLOY.md) (live executor) and
[Phase A2](MCP_PROXY_PHASE_A2.md) (runtime / filesystem / provenance tuning).

Related:

- [MCP_PROXY_NEXT_STEPS.md](MCP_PROXY_NEXT_STEPS.md) — A4 keys, A5 regression
- [MCP_PROXY_ISOLATED_EXECUTION.md](MCP_PROXY_ISOLATED_EXECUTION.md) — deny reasons
- [MCP_PROXY_ROADMAP.md](MCP_PROXY_ROADMAP.md) — Phase A overview

---

## What was implemented

| Component | Location | Purpose |
|-----------|----------|---------|
| Monitor policy | `policy.sample.sprint-3-a3-monitor.json` | `action: monitor` on key profiles |
| Challenge policy | `policy.sample.sprint-3-a3-challenge.json` | `action: challenge` on violations |
| Deny policy | `policy.sample.sprint-3-a3-deny.json` | Production fail-closed (A2 limits + deny) |
| Apply script | `tools/apply_mcp_proxy_phase_a3.sh` | Run staged verification |
| Test script | `tools/test_mcp_proxy_phase_a3.sh` | Per-stage or `all` |
| Proxy fix | `mcp_security_proxy/app.py` | Upstream provenance respects `monitor` / `challenge` on executor forward |

Policy alias: `bash tools/switch_mcp_policy_sample.sh sprint-3-a3-{monitor,challenge,deny}`

---

## Staged rollout model

For each security profile the proxy supports three enforcement levels:

| Level | Profile `action` | Behavior on violation |
|-------|------------------|------------------------|
| **1. Monitor** | `monitor` | Record decision events / discovery; **do not** return MCP error for that layer |
| **2. Challenge** | `challenge` | Return HTTP 403 with `*challenge*` reason (operator/agent acknowledgment flow) |
| **3. Deny** | `deny` | Fail closed with deny reason (`runtime_limits_exceeded`, `filesystem_restriction_violation`, etc.) |

Profiles adjusted in A3 samples:

| Profile | Monitor | Challenge | Deny (production) |
|---------|---------|-----------|-------------------|
| `isolated_executor_profile` | observe limit/FS violations | `isolated_executor_challenge` | `runtime_limits_exceeded`, etc. |
| `sandbox_attestation_profile` | enabled, monitor | enabled, challenge | disabled in lab deny sample; enable when attestor is wired |
| `upstream_provenance_profile` | monitor (executor forward) | `upstream_provenance_challenge` | provenance deny |
| `untrusted_server_action` | monitor | challenge | deny |
| `descriptor_drift_action` | monitor | challenge | deny |
| `execution_tool_profile` | monitor (if enabled) | challenge | deny |

**Lab note:** `execution_tool_profile` stays **`enabled: false`** in all A3 samples so
`shell_exec` routes to the isolated executor (same as A1/A2). Enable it only when
intentionally blocking execution-like tools before the executor path.

**LLM layers:** `llm_risk.enforce` and `tool_intent.enforce` remain `false` in samples
so staged rollout focuses on Sprint 3 executor/containment profiles. Enable enforce in
production separately.

---

## Prerequisites

1. Phase **A1** and **A2** complete (or equivalent stack + `sprint-3-a2` policy).
2. `mcp-security-proxy` and `isolated-executor` running.
3. Rebuild proxy after pulling A3 code (provenance monitor/challenge on executor forward):

```bash
cd mcp-security-proxy
docker compose -f docker-compose.yml -f docker-compose.phase4.yml up -d --build mcp-security-proxy
```

---

## Quick start

```bash
bash tools/apply_mcp_proxy_phase_a3.sh
```

Runs **monitor → challenge → deny** in sequence and verifies each stage.

Single stage:

```bash
bash tools/apply_mcp_proxy_phase_a3.sh monitor
bash tools/apply_mcp_proxy_phase_a3.sh challenge
bash tools/apply_mcp_proxy_phase_a3.sh deny
```

Persist production deny policy:

```bash
bash tools/switch_mcp_policy_sample.sh sprint-3-a3-deny
```

---

## What each test proves

The test script sends `tools/call` → `shell_exec` with `memory_mb: 9999` (exceeds A2
`max_memory_mb: 256`).

| Stage | Expected on limits probe | Live `whoami` |
|-------|--------------------------|---------------|
| **monitor** | No hard deny for `runtime_limits` / `filesystem` on pre-check | Not required |
| **challenge** | JSON-RPC error; `error.data.reason` contains `challenge` | Not required |
| **deny** | JSON-RPC error; reason `runtime_limits_*`, `filesystem_*`, or `isolated_executor_*` | **PASS** via live test |

---

## Manual rollout (UI or API)

1. Start from A2: `bash tools/switch_mcp_policy_sample.sh sprint-3-a2`
2. Open **http://localhost:8090/ui** → Tuning Studio
3. For each control, set profile `action` to `monitor` → observe Evidence and Decisions
4. Promote to `challenge` → validate challenge UX
5. Promote to `deny` → run `bash tools/test_isolated_executor_live.sh`

Or apply samples directly:

```bash
bash tools/switch_mcp_policy_sample.sh sprint-3-a3-monitor
# ... observe ...
bash tools/switch_mcp_policy_sample.sh sprint-3-a3-challenge
# ... validate ...
bash tools/switch_mcp_policy_sample.sh sprint-3-a3-deny
```

---

## Completion criteria

Phase A3 is **complete** when:

```bash
bash tools/apply_mcp_proxy_phase_a3.sh all
```

exits 0 with:

- `PHASE A3 STAGED ENFORCEMENT TEST PASSED (all)`
- `PASS: live isolated executor integration` on deny stage

---

## Troubleshooting

### Monitor stage still denies limits probe

- Confirm active policy: `isolated_executor_profile.action` must be `monitor`
- Rebuild/restart proxy if an old image ignores monitor semantics

### Challenge stage returns `runtime_limits_exceeded` instead of `*challenge*`

- Policy not applied: `bash tools/switch_mcp_policy_sample.sh sprint-3-a3-challenge`
- Check admin API: `GET /admin/policy-config`

### Deny stage live test fails

- Executor down: `bash tools/start_isolated_executor.sh`
- Provenance: deny sample includes `isolated-executor` in `allowed_destinations`
- Keys: `bash tools/align_mcp_proxy_upstream_key.sh`

### Sandbox attestation blocks all `shell_exec` in deny stage

Deny sample enables `sandbox_attestation_profile` with `action: deny`. Calls without
attestation metadata receive `sandbox_attestation_missing`. For lab executor smoke,
live test re-applies deny policy via admin API (same as A2 operational path). In
production, require attestation or keep sandbox disabled until attestor is wired.

---

## After Phase A3

- **A4** — [MCP_PROXY_PHASE_A4.md](MCP_PROXY_PHASE_A4.md) — `bash tools/apply_mcp_proxy_phase_a4.sh`
- **A5** — [MCP_PROXY_PHASE_A5.md](MCP_PROXY_PHASE_A5.md) — `bash tools/apply_mcp_proxy_phase_a5.sh`
- Enable `llm_risk.enforce` / `dependency_fail_safe_profile` when ready for production

---

## Files reference

| Path | Description |
|------|-------------|
| `config/phase4/mcp_proxy/policy.sample.sprint-3-a3-*.json` | Staged policy samples |
| `tools/apply_mcp_proxy_phase_a3.sh` | Apply + verify |
| `tools/test_mcp_proxy_phase_a3.sh` | Stage tests |
| `tools/switch_mcp_policy_sample.sh` | Profile switcher |
