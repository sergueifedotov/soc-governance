# MCP Security Proxy — Next steps (operator guide)

Use this guide after Sprint 1–3 verification and/or Phase A (A1–A5) rollout.

**Master guide (everything in Phase A + why A5 is slow + what’s next):**
[MCP_PROXY_PHASE_A_COMPLETE.md](MCP_PROXY_PHASE_A_COMPLETE.md)

**Go / REST gateway options (Phase E):**
[MCP_PROXY_GO_REST_ARCHITECTURE.md](MCP_PROXY_GO_REST_ARCHITECTURE.md)

**Phase B commercialization (MVP):**
[MCP_PROXY_PHASE_B.md](MCP_PROXY_PHASE_B.md)

**Verification status (what is done + re-run commands):**
[MCP_PROXY_VERIFICATION_STATUS.md](MCP_PROXY_VERIFICATION_STATUS.md)

Related docs:

- [MCP_PROXY_PHASE_A_COMPLETE.md](MCP_PROXY_PHASE_A_COMPLETE.md) — **Phase A master guide (A1–A5)**
- [MCP_PROXY_PHASE_A1_DEPLOY.md](MCP_PROXY_PHASE_A1_DEPLOY.md) — Phase A1 deploy runbook
- [MCP_PROXY_PHASE_A2.md](MCP_PROXY_PHASE_A2.md) — Phase A2 runtime / filesystem / provenance runbook
- [MCP_PROXY_PHASE_A3.md](MCP_PROXY_PHASE_A3.md) — Phase A3 staged enforcement (monitor → deny)
- [MCP_PROXY_PHASE_A4.md](MCP_PROXY_PHASE_A4.md) — Phase A4 keys and deployment hygiene
- [MCP_PROXY_PHASE_A5.md](MCP_PROXY_PHASE_A5.md) — Phase A5 regression validation
- [MCP_PROXY_ROADMAP.md](MCP_PROXY_ROADMAP.md) — phases A–E and Sprint 4–5 scope
- [MCP_PROXY_SPRINT_TESTING.md](MCP_PROXY_SPRINT_TESTING.md) — Sprint 1–3 E2E tests
- [MCP_PROXY_ISOLATED_EXECUTION.md](MCP_PROXY_ISOLATED_EXECUTION.md) — Sprint 3 policy fields

---

## Where you are (completion signals)

| Milestone | How you know it is done |
|-----------|-------------------------|
| **Profile C up** | `curl -s http://localhost:8090/health \| jq .status` → `"healthy"`; `docker network ls \| grep wazuh-soc` shows `_default` and `_phase4` |
| **Sprint 1–3 gates** | `bash tools/test_sprint1_no_restart.sh` (and 2, 3) end with `SPRINT N VERIFICATION PASSED` |
| **Phase A1 deploy** | `bash tools/deploy_isolated_executor_a1.sh` → `Phase A1 deployment complete.` |
| **Live executor routing** | `bash tools/test_isolated_executor_live.sh` → `PASS: live isolated executor integration`; JSON includes `runtime_info.uid: 1000`, `runtime: hardened-container` |
| **Phase A2 operational** | `bash tools/apply_mcp_proxy_phase_a2.sh` → `Phase A2 complete.`; active policy `sprint-3-a2` |
| **Phase A3 staged enforcement** | `bash tools/apply_mcp_proxy_phase_a3.sh` → `Phase A3 complete.`; production `sprint-3-a3-deny` |
| **Phase A4 keys / hygiene** | `bash tools/apply_mcp_proxy_phase_a4.sh` → `PHASE A4 KEYS AND HYGIENE TEST PASSED` |
| **Phase A5 regression** | `bash tools/apply_mcp_proxy_phase_a5.sh` → `PHASE A5 REGRESSION VALIDATION PASSED` |
| **Phase B MVP** | `bash tools/apply_mcp_proxy_phase_b.sh` → `Phase B deploy complete.` |
| **Phase B verify** | `bash tools/test_mcp_proxy_phase_b.sh` → `PHASE B COMMERCIALIZATION PASSED` |

Sprint test scripts **temporarily** apply sprint policy samples and **restore** your
previous policy on exit. A passing Sprint 3 run does **not** by itself leave
`isolated_executor_profile.enabled: true` on disk — see [Persist operational policy](#1-persist-operational-policy) below.

---

## Quick checklist

### First time (full Phase A)

See [MCP_PROXY_PHASE_A_COMPLETE.md — greenfield sequence](MCP_PROXY_PHASE_A_COMPLETE.md#greenfield-full-phase-a-sequence).

```bash
bash tools/start-profile.sh C
bash tools/deploy_isolated_executor_a1.sh
bash tools/apply_mcp_proxy_phase_a2.sh
bash tools/apply_mcp_proxy_phase_a3.sh
bash tools/apply_mcp_proxy_phase_a4.sh
bash tools/apply_mcp_proxy_phase_a5.sh
```

### After Phase B is complete (daily — Core MVP)

Run **one command per line**. Default preset: **`core-balanced`**.

```bash
bash tools/switch_mcp_policy_sample.sh core-balanced

curl -s -H "Authorization: Bearer $(bash tools/mcp_api_key.sh --proxy)" \
  http://localhost:8090/admin/entitlements | jq '{tier, features}'

bash tools/test_mcp_proxy_phase_b.sh --skip-audit

open http://localhost:8090/ui
```

Re-auth UI and confirm policy loads: [MCP_PROXY_OPERATE_UI_AND_PRESETS.md](MCP_PROXY_OPERATE_UI_AND_PRESETS.md).

For **executor / staged enforcement** ops (Phase A policy), use `sprint-3-a3-deny` or
`sprint-3-executor` instead — see [MCP_PROXY_PHASE_A_COMPLETE.md](MCP_PROXY_PHASE_A_COMPLETE.md).

### After Phase C (governance demos)

```bash
bash tools/switch_mcp_policy_sample.sh sprint-4-governance
bash tools/test_mcp_proxy_phase_c.sh
```

Use **admin** bearer (`bash tools/mcp_api_key.sh --proxy`) in the UI — not operator/auditor demo tokens unless testing RBAC. Preset comparison: [MCP_PROXY_OPERATE_UI_AND_PRESETS.md](MCP_PROXY_OPERATE_UI_AND_PRESETS.md).

### After policy or proxy code changes

```bash
bash tools/align_mcp_proxy_upstream_key.sh
bash tools/test_mcp_proxy_phase_a4.sh
bash tools/test_sprint3_no_restart.sh --skip-unit-tests
```

Full regression (slow, ~5–15 min): `bash tools/apply_mcp_proxy_phase_a5.sh` — see
[why A5 is slow](MCP_PROXY_PHASE_A_COMPLETE.md#why-phase-a5-takes-a-long-time).

---

## Phase A — Operationalize Sprint 3

Roadmap detail: [MCP_PROXY_ROADMAP.md — Phase A](MCP_PROXY_ROADMAP.md#phase-a--operationalize-sprint-3-near-term).

### 1. Persist operational policy

After `test_isolated_executor_live.sh` or `deploy_isolated_executor_a1.sh`, the
running proxy may have operational policy in memory while `policy.json` on disk still
reflects an older baseline.

Apply the operational sample and reload:

```bash
bash tools/switch_mcp_policy_sample.sh sprint-3-executor
```

Key fields (`policy.sample.sprint-3-executor-operational.json`):

| Field | Recommended value | Why |
|-------|-------------------|-----|
| `isolated_executor_profile.enabled` | `true` | Route execution-like tools to the sidecar |
| `executor_url` | `http://isolated-executor:8080/execute` | Docker DNS on Profile C networks |
| `fallback_to_upstream` | `false` | Fail closed if executor is down |
| `execution_tool_profile.enabled` | `false` | Avoid blocking `shell_exec` before executor routing |
| `upstream_provenance_profile` | tuned + `enabled: true` when ready | Egress allow/deny for forwards |

Adjust further via **http://localhost:8090/ui** (Tuning Studio) or
`POST /admin/policy-config`.

### 2. Configure runtime, filesystem, and egress (A2)

**Full runbook:** [MCP_PROXY_PHASE_A2.md](MCP_PROXY_PHASE_A2.md)

**One-shot apply + verify** (requires Phase A1):

```bash
bash tools/apply_mcp_proxy_phase_a2.sh
```

This applies `policy.sample.sprint-3-a2-operational.json` (alias `sprint-3-a2`), runs
runtime/filesystem/provenance gates, and re-runs the live executor test.

**A2 is complete** when the script ends with `Phase A2 complete.` and live test passes.
See [MCP_PROXY_PHASE_A2.md — completion criteria](MCP_PROXY_PHASE_A2.md#completion-criteria).

Policy profile highlights vs `sprint-3-executor`:

| Area | A2 tuning |
|------|-----------|
| `runtime_limits` | `max_cpu_seconds: 15`, `max_memory_mb: 256`, `max_wall_time_seconds: 45` |
| `filesystem_restrictions` | Extra deny read/write paths; lower `max_file_size_mb` / `max_total_size_mb` |
| `upstream_provenance_profile` | `enabled: true`, executor + Wazuh allow-list, extra blocked patterns, `log_all_egress: true` |
| `discovery_rules` | Includes `runtime_limits_violations` (monitor) |

Manual steps (if not using the script):

1. **Runtime limits** — `runtime_limits.max_cpu_seconds`, `max_memory_mb`, timeouts.
2. **Rootless** — `require_rootless: true` when the runtime reports non-root (`uid != 0`).
3. **Filesystem** — minimal `allow_write_paths`; explicit `deny_read_paths` / `deny_write_paths`.
4. **Upstream provenance** — `allowed_destinations`, `blocked_destinations`, optional `log_all_egress`.

```bash
bash tools/switch_mcp_policy_sample.sh sprint-3-a2
bash tools/test_runtime_limits.sh
bash tools/test_filesystem_restrictions.sh
bash tools/test_upstream_provenance.sh
POLICY_FILE=config/phase4/mcp_proxy/policy.sample.sprint-3-a2-operational.json \
  bash tools/test_isolated_executor_live.sh
```

### 3. Staged enforcement rollout (A3)

**Full runbook:** [MCP_PROXY_PHASE_A3.md](MCP_PROXY_PHASE_A3.md)

```bash
bash tools/apply_mcp_proxy_phase_a3.sh
```

Applies `sprint-3-a3-{monitor,challenge,deny}` samples and verifies each stage.
**A3 complete** when `PHASE A3 STAGED ENFORCEMENT TEST PASSED (all)` and live test passes on deny.

Persist production deny:

```bash
bash tools/switch_mcp_policy_sample.sh sprint-3-a3-deny
```

Manual rollout: set profile `action` to `monitor` → `challenge` → `deny` in UI or JSON.

### 4. Keys and deployment hygiene (A4)

**Full runbook:** [MCP_PROXY_PHASE_A4.md](MCP_PROXY_PHASE_A4.md)

```bash
bash tools/apply_mcp_proxy_phase_a4.sh
```

Aligns upstream + client bearer keys with Wazuh, verifies health, ping, and `tools/list`.
**A4 complete** when `PHASE A4 KEYS AND HYGIENE TEST PASSED`.

| Step | Command |
|------|---------|
| One-shot apply + verify | `bash tools/apply_mcp_proxy_phase_a4.sh` |
| Align only | `bash tools/align_mcp_proxy_upstream_key.sh` |
| Verify only | `bash tools/test_mcp_proxy_phase_a4.sh` |
| Rebuild + align | `bash tools/apply_mcp_proxy_phase_a4.sh --rebuild-proxy` |
| Before first Profile C | Set `MCP_API_KEY` and `MCP_PROXY_API_KEY` in `.env` (see `.env.example`) |

### 5. Validate after changes (A5)

**Full runbook:** [MCP_PROXY_PHASE_A5.md](MCP_PROXY_PHASE_A5.md)

```bash
bash tools/apply_mcp_proxy_phase_a5.sh
```

Runs A4 preflight, Sprint 1–3 E2E (`--skip-unit-tests`), live executor check, restores
`sprint-3-a3-deny`. **A5 complete** when `PHASE A5 REGRESSION VALIDATION PASSED`.

```bash
# Heavier regression:
bash tools/apply_mcp_proxy_phase_a5.sh --full --with-unit-tests --with-smoke
```

Monitor **http://localhost:8090/ui** → Tuning Studio → **Evidence and Decisions**.

Faster A5 options: [MCP_PROXY_PHASE_A5.md](MCP_PROXY_PHASE_A5.md) and
[MCP_PROXY_PHASE_A_COMPLETE.md — faster A5](MCP_PROXY_PHASE_A_COMPLETE.md#faster-a5-trade-offs).

---

## What to do next (after Phase A)

Phase A is **operational Sprint 3 on Profile C**. Product roadmap continues with
**Phase B** (MVP), **Sprint 4** (audit, RBAC, policy lifecycle), and **Sprint 5**
(SIEM/HA). Full detail: [MCP_PROXY_PHASE_A_COMPLETE.md — what to do next](MCP_PROXY_PHASE_A_COMPLETE.md#what-to-do-next-after-phase-a).

| Priority | Focus |
|----------|--------|
| 1 | Operate: `sprint-3-a3-deny`, UI tuning, light regression (`test_sprint3_no_restart.sh`) |
| 2 | Production: real executor sandbox, LLM/attestation as needed |
| 3 | Phase B: deploy UX, presets, metering, audit baseline |
| 4 | Sprint 4–5: enterprise control plane and SOC integration |

---

## Stale telemetry vs a successful live test

`test_isolated_executor_live.sh` may print:

```text
WARN: recent denied contains isolated_executor* for shell_exec (unexpected on success)
```

**Meaning:** `/recent-denied` still lists **older** failures (for example from a run
before Profile C or before the executor was healthy). That does **not** invalidate a
current success if the response JSON shows `status: "ok"` and `exit_code: 0`.

To reduce noise:

- Rely on **Recent Decision Events** for the latest `isolated_executor` allow/deny.
- Restart the proxy or clear discovery/denied state via admin APIs after policy is stable (optional).

---

## Production hardening (beyond the reference sidecar)

The repo ships a **reference** executor (`mcp-isolated-executor:local`) — hardened
container, non-root `uid=1000`, read-only root, no network. It is suitable for lab and
integration tests, not a substitute for your production isolation standard.

| Topic | Guidance |
|-------|----------|
| **Runtime** | Replace with gVisor, Firecracker, or your approved sandbox; keep `GET /health` and `POST /execute` contract |
| **Startup order** | Profile C first (creates `wazuh-soc_default` / `wazuh-soc_phase4`), then executor only if missing |
| **Host debug port** | Default `18088` (not `8088` — may be used by AgentGuard) |
| **Policy** | `fallback_to_upstream: false`; provenance must allow `isolated-executor` host |

Deploy runbook: [MCP_PROXY_PHASE_A1_DEPLOY.md](MCP_PROXY_PHASE_A1_DEPLOY.md).

---

## Goals: which path to follow

| Goal | Focus |
|------|--------|
| **Daily dev on Profile C** | `sprint-3-executor` on disk; executor in compose; `align_mcp_proxy_upstream_key.sh` after key changes |
| **Demo / trial** | Sprint samples + UI tuning; `bash tools/smoke_mcp_proxy.sh`; document URLs in [OPERATIONS.md](OPERATIONS.md) |
| **Production rollout** | A2–A3 staged `monitor` → `deny`; replace executor image; durable audit (Sprint 4); SIEM hooks (Sprint 5) |

---

## Longer-term roadmap (after Phase A)

Priority order from [MCP_PROXY_ROADMAP.md](MCP_PROXY_ROADMAP.md):

```text
1. Operationalize Sprint 3     → executor + provenance + limits in prod policy
2. Audit durability and export → Phase 1 + Sprint 4 foundation
3. Sprint 4                    → SSO/RBAC, policy versioning, signing, approvals
4. Sprint 5                    → SIEM/SOAR, HA, metering at scale
5. Phase 1 polish              → presets, 30-min deploy story, metering UX
```

| Phase | Summary |
|-------|---------|
| **B** | Phase 1 MVP — [MCP_PROXY_PHASE_B.md](MCP_PROXY_PHASE_B.md) — `bash tools/apply_mcp_proxy_phase_b.sh` |
| **C (Sprint 4)** | SSO/RBAC, policy lifecycle, signed bundles, durable audit export |
| **D (Sprint 5)** | SIEM/SOAR/ITSM connectors, HA topology, entitlements |
| **E** | Optional Go/Rust hot paths (profiling-driven) — [MCP_PROXY_GO_REST_ARCHITECTURE.md](MCP_PROXY_GO_REST_ARCHITECTURE.md) |

Product context: [ai-security-product-strategy.md](ai-security-product-strategy.md).

---

## Command reference

| Task | Command |
|------|---------|
| Start Profile C | `bash tools/start-profile.sh C` |
| Start executor only | `bash tools/start_isolated_executor.sh` |
| Deploy A1 (health + policy + smoke) | `bash tools/deploy_isolated_executor_a1.sh` |
| Apply Phase A2 | [MCP_PROXY_PHASE_A2.md](MCP_PROXY_PHASE_A2.md) — `bash tools/apply_mcp_proxy_phase_a2.sh` |
| Apply Phase A3 | [MCP_PROXY_PHASE_A3.md](MCP_PROXY_PHASE_A3.md) — `bash tools/apply_mcp_proxy_phase_a3.sh` |
| Apply Phase A4 | [MCP_PROXY_PHASE_A4.md](MCP_PROXY_PHASE_A4.md) — `bash tools/apply_mcp_proxy_phase_a4.sh` |
| Apply Phase A5 | [MCP_PROXY_PHASE_A5.md](MCP_PROXY_PHASE_A5.md) — `bash tools/apply_mcp_proxy_phase_a5.sh` |
| Phase A master guide | [MCP_PROXY_PHASE_A_COMPLETE.md](MCP_PROXY_PHASE_A_COMPLETE.md) |
| Live integration test | `bash tools/test_isolated_executor_live.sh` |
| Switch policy sample | `bash tools/switch_mcp_policy_sample.sh sprint-3-executor` or `sprint-3-a2` |
| List policy samples | `bash tools/switch_mcp_policy_sample.sh --list` |
| Align upstream API key | `bash tools/align_mcp_proxy_upstream_key.sh` |
| Sprint 3 all-in-one test | `bash tools/test_sprint3_no_restart.sh` |
| Feature smoke (Sprints 1–3; not Phase B) | `bash tools/smoke_mcp_proxy.sh --with-isolated-executor` |
| Phase B commercial verify | `bash tools/test_mcp_proxy_phase_b.sh` |
| Smoke + Phase B (recommended) | `bash tools/smoke_mcp_proxy.sh --with-isolated-executor && bash tools/test_mcp_proxy_phase_b.sh` |
| Full Phase A sign-off | `bash tools/apply_mcp_proxy_phase_a5.sh` |

---

## Troubleshooting pointers

If deploy or live tests fail, see [MCP_PROXY_PHASE_A1_DEPLOY.md — Troubleshooting](MCP_PROXY_PHASE_A1_DEPLOY.md#troubleshooting):

- `Unknown argument: #` / `command not found: #` — pasted comments; run one command per line
- `network wazuh-soc_default ... could not be found` — start Profile C before the executor
- `mcp-security-proxy is not running` — `bash tools/start-profile.sh C`
- `execution_tool_blocked` — use `sprint-3-executor` operational policy
