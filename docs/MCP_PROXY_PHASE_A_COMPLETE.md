# Phase A complete — Operationalize Sprint 3 (master guide)

This is the **single entry point** for roadmap **Phase A**: deploy the isolated
executor, tune policy, roll out enforcement, fix keys, and run regression — using
the scripts and runbooks added in this repo.

**Start here after Sprints 1–3 pass:** run phases **A1 → A5 in order** (or use the
one-shot sequences below). When all completion signals are green, Phase A is done;
continue with [What to do next](#what-to-do-next-after-phase-a).

Related:

| Doc | Use for |
|-----|---------|
| [MCP_PROXY_NEXT_STEPS.md](MCP_PROXY_NEXT_STEPS.md) | Short checklist and command table |
| [MCP_PROXY_ROADMAP.md](MCP_PROXY_ROADMAP.md) | Phases B–E, Sprint 4–5 |
| [MCP_PROXY_SPRINT_TESTING.md](MCP_PROXY_SPRINT_TESTING.md) | Sprint 1–3 test details |
| [MCP_PROXY_SMOKE_TEST.md](MCP_PROXY_SMOKE_TEST.md) | Consolidated smoke catalog |

---

## Phase A at a glance

| Step | Name | One command | Runbook |
|------|------|-------------|---------|
| **A1** | Isolated executor deploy | `bash tools/deploy_isolated_executor_a1.sh` | [MCP_PROXY_PHASE_A1_DEPLOY.md](MCP_PROXY_PHASE_A1_DEPLOY.md) |
| **A2** | Runtime / FS / provenance | `bash tools/apply_mcp_proxy_phase_a2.sh` | [MCP_PROXY_PHASE_A2.md](MCP_PROXY_PHASE_A2.md) |
| **A3** | Staged enforcement | `bash tools/apply_mcp_proxy_phase_a3.sh` | [MCP_PROXY_PHASE_A3.md](MCP_PROXY_PHASE_A3.md) |
| **A4** | Keys and hygiene | `bash tools/apply_mcp_proxy_phase_a4.sh` | [MCP_PROXY_PHASE_A4.md](MCP_PROXY_PHASE_A4.md) |
| **A5** | Regression validation | `bash tools/apply_mcp_proxy_phase_a5.sh` | [MCP_PROXY_PHASE_A5.md](MCP_PROXY_PHASE_A5.md) |

**Phase A is complete** when A1–A5 completion signals (below) are all satisfied.

**After Phase A:** continue with [Phase B (MVP commercialization)](MCP_PROXY_PHASE_B.md)
or see [verification status](MCP_PROXY_VERIFICATION_STATUS.md) for the full done/next picture.

---

## Greenfield: full Phase A sequence

Run **one command per line**. Do not paste `#` comments on the same line as a command.

```bash
cd /path/to/Wazuh-MCP-Neo4j-OCTI-Mon-C-6

# 0) Set MCP_API_KEY (+ MCP_PROXY_API_KEY) in .env before first Profile C start
#    See .env.example

bash tools/start-profile.sh C
bash tools/align_mcp_proxy_upstream_key.sh

bash tools/deploy_isolated_executor_a1.sh
bash tools/apply_mcp_proxy_phase_a2.sh
bash tools/apply_mcp_proxy_phase_a3.sh
bash tools/apply_mcp_proxy_phase_a4.sh
bash tools/apply_mcp_proxy_phase_a5.sh
```

**Day-to-day policy on disk after A5:** `sprint-3-a3-deny` (production deny + A2 limits).

```bash
bash tools/switch_mcp_policy_sample.sh sprint-3-a3-deny
```

---

## Completion signals (checklist)

| Phase | Done when |
|-------|-----------|
| **A1** | `Phase A1 deployment complete.` + `PASS: live isolated executor integration` |
| **A2** | `Phase A2 complete.` + live test under A2 policy |
| **A3** | `PHASE A3 STAGED ENFORCEMENT TEST PASSED (all)` |
| **A4** | `PHASE A4 KEYS AND HYGIENE TEST PASSED`; `bearer_matches_wazuh: true` in key report |
| **A5** | `PHASE A5 REGRESSION VALIDATION PASSED` |
| **B (MVP)** | `PHASE B COMMERCIALIZATION PASSED` — [MCP_PROXY_PHASE_B.md](MCP_PROXY_PHASE_B.md) |

Quick health:

```bash
docker ps | grep -E 'mcp-security-proxy|wazuh-mcp-server|isolated-executor'
curl -s http://localhost:8090/health | jq .status
curl -s http://localhost:18088/health | jq .status
```

---

## What each phase implemented

### A1 — Isolated executor sidecar

| Item | Location |
|------|----------|
| Executor service | `mcp-isolated-executor/` |
| Compose overlay | `mcp-security-proxy/docker-compose.isolated-executor.yml` |
| Operational policy | `policy.sample.sprint-3-executor-operational.json` |
| Deploy + live test | `deploy_isolated_executor_a1.sh`, `test_isolated_executor_live.sh` |

Executor routes `shell_exec` (and matching tools) to `http://isolated-executor:8080/execute`.
Reference runtime: **hardened container**, non-root `uid=1000`.

### A2 — Limits, filesystem, provenance

| Item | Location |
|------|----------|
| Policy | `policy.sample.sprint-3-a2-operational.json` (alias `sprint-3-a2`) |
| Apply script | `tools/apply_mcp_proxy_phase_a2.sh` |
| Sub-gates | `test_runtime_limits.sh`, `test_filesystem_restrictions.sh`, `test_upstream_provenance.sh` |

Tighter `runtime_limits`, expanded `filesystem_restrictions`, full
`upstream_provenance_profile` with executor + Wazuh allow-list.

### A3 — Monitor → challenge → deny

| Item | Location |
|------|----------|
| Policies | `policy.sample.sprint-3-a3-{monitor,challenge,deny}.json` |
| Apply script | `tools/apply_mcp_proxy_phase_a3.sh` |
| Test script | `tools/test_mcp_proxy_phase_a3.sh` |
| Proxy fix | Provenance `monitor`/`challenge` on executor forward path |

Production sample: **`sprint-3-a3-deny`** (lab: sandbox attestation off so live `whoami` works).

### A4 — API keys and deployment hygiene

| Item | Location |
|------|----------|
| Align script | `tools/align_mcp_proxy_upstream_key.sh` (upstream key; preserves client bearer) |
| Apply / test | `apply_mcp_proxy_phase_a4.sh`, `test_mcp_proxy_phase_a4.sh` |
| Key report | `mcp_test_print_key_report` in `mcp_proxy_test_common.sh` |

Aligns `MCP_PROXY_UPSTREAM_API_KEY` with `wazuh-mcp-server` `MCP_API_KEY`. Leaves
`MCP_PROXY_API_KEY` unchanged so Phase 4 / the operate UI keep the same client bearer.

### A5 — Regression validation

| Item | Location |
|------|----------|
| Apply / test | `apply_mcp_proxy_phase_a5.sh`, `test_mcp_proxy_phase_a5.sh` |
| Scope | A4 preflight + Sprint 1–3 E2E + live executor + restore `sprint-3-a3-deny` |

---

## Policy samples (Profile C)

| Alias | File | When to use |
|-------|------|-------------|
| `sprint-3-executor` | `policy.sample.sprint-3-executor-operational.json` | A1 live routing |
| `sprint-3-a2` | `policy.sample.sprint-3-a2-operational.json` | A2 tuned limits/provenance |
| `sprint-3-a3-monitor` | `policy.sample.sprint-3-a3-monitor.json` | Observe violations |
| `sprint-3-a3-challenge` | `policy.sample.sprint-3-a3-challenge.json` | Challenge stage |
| `sprint-3-a3-deny` | `policy.sample.sprint-3-a3-deny.json` | **Production lab default** after A3/A5 |
| `sprint-1` / `sprint-2` / `sprint-3` | Sprint baselines | E2E tests only |

```bash
bash tools/switch_mcp_policy_sample.sh --list
```

Active file: `config/phase4/mcp_proxy/policy.json` (mounted into proxy).

---

## Why Phase A5 takes a long time

Default `bash tools/apply_mcp_proxy_phase_a5.sh` is a **full stacked regression**, not
one quick check. Typical runtime: **~5–15 minutes** (sometimes more).

### What runs (default)

```text
test_mcp_proxy_phase_a4.sh           # keys, ping, tools/list, admin API
test_sprint1_no_restart.sh           # 3 gates + descriptor drift (2× tools/list)
test_sprint2_no_restart.sh           # sandbox + dependency fail-safe
test_sprint3_no_restart.sh           # 4 gates + docker symbol check
test_isolated_executor_live.sh       # whoami via proxy + executor
switch_mcp_policy_sample.sh sprint-3-a3-deny
```

### Time drivers

1. **Three full sprint suites** — each reapplies policy, checks keys/health, runs multiple sub-scripts.
2. **Policy snapshot/restore per sub-test** — many `GET`/`POST /admin/policy-config` cycles.
3. **Repeated upstream paths** — A4 + Sprint 1 + drift tests call `tools/list` / ping through proxy → Wazuh.
4. **LLM on `tools/call`** — policies keep `llm_risk` and `tool_intent` **enabled**. Each `tools/call` can invoke **two** model calls (up to **5s timeout each**) *before* executor routing. Slow or missing Docker Model Runner adds seconds per call (notably **live executor `whoami`**).
5. **Sprint 2 dependency test** — enables `llm_risk` enforce with health check (short timeout in test policy, still network-bound).

See [MCP_PROXY_PHASE_A5.md — troubleshooting](MCP_PROXY_PHASE_A5.md#troubleshooting) for faster options.

### Faster A5 (trade-offs)

```bash
# Skip A4 if keys already aligned
bash tools/test_mcp_proxy_phase_a5.sh --skip-a4-preflight

# Skip live executor (avoids LLM + executor on whoami)
bash tools/test_mcp_proxy_phase_a5.sh --skip-a4-preflight --skip-live-executor

# Single sprint while debugging
bash tools/test_sprint3_no_restart.sh --skip-unit-tests

# Full CI-style (slowest)
bash tools/apply_mcp_proxy_phase_a5.sh --full --with-unit-tests --with-smoke
```

For small changes after Phase A is green: **`bash tools/test_sprint3_no_restart.sh --skip-unit-tests`** is often enough.

### Smoke vs Phase A5

`tools/smoke_mcp_proxy.sh` overlaps **partially** with A5 (same sprint wrappers and optional
live executor) but is **not** a substitute for A5:

| | `smoke_mcp_proxy.sh` | `apply_mcp_proxy_phase_a5.sh` |
|--|----------------------|-------------------------------|
| Sprint 1–3 suites | Yes | Yes |
| A4 keys / admin hygiene | No | Yes (`test_mcp_proxy_phase_a4.sh`) |
| A3 staged enforcement flows | No | Yes (policy switch to `sprint-3-a3-deny`) |
| Phase B presets / metering / audit | No | No |
| Typical use | Quick feature regression after code changes | Full Phase A sign-off |

A5 can optionally append smoke: `bash tools/apply_mcp_proxy_phase_a5.sh --full --with-smoke`.

After Phase B is deployed, also run `bash tools/test_mcp_proxy_phase_b.sh` — smoke does not
cover commercial presets or audit export. See
[MCP_PROXY_SMOKE_TEST.md — overlap](MCP_PROXY_SMOKE_TEST.md#overlap-with-phase-a-and-phase-b).

---

## Tools and scripts reference

| Script | Purpose |
|--------|---------|
| `tools/start-profile.sh C` | Wazuh stack + proxy + executor compose |
| `tools/start_isolated_executor.sh` | Sidecar only |
| `tools/align_mcp_proxy_upstream_key.sh` | Recreate proxy with Wazuh keys |
| `tools/mcp_api_key.sh --proxy` | Resolve client bearer token |
| `tools/deploy_isolated_executor_a1.sh` | A1 |
| `tools/apply_mcp_proxy_phase_a2.sh` | A2 |
| `tools/apply_mcp_proxy_phase_a3.sh` | A3 |
| `tools/apply_mcp_proxy_phase_a4.sh` | A4 |
| `tools/apply_mcp_proxy_phase_a5.sh` | A5 |
| `tools/smoke_mcp_proxy.sh` | Feature smoke (partial A5 overlap; not Phase B) |
| `tools/switch_mcp_policy_sample.sh` | Apply policy to disk + reload |

Sub-gate tests (used by sprints): `test_trusted_servers.sh`, `test_descriptor_drift.sh`,
`test_execution_tool_profile.sh`, `test_sandbox_attestation.sh`,
`test_dependency_fail_safe.sh`, `test_isolated_executor.sh`, `test_runtime_limits.sh`,
`test_filesystem_restrictions.sh`, `test_upstream_provenance.sh`.

---

## Common issues (quick fixes)

| Symptom | Fix |
|---------|-----|
| `network wazuh-soc_default ... could not be found` | `bash tools/start-profile.sh C` before executor |
| `Unknown argument: #` / `command not found: #` | One command per line; no inline comments |
| `Invalid or expired token` on `tools/list` | `bash tools/align_mcp_proxy_upstream_key.sh` |
| `bearer_matches_wazuh: false` | Re-run align script (sets both upstream + client bearer) |
| `A4_ARGS[@]: unbound variable` | Fixed in tree — pull latest `apply_mcp_proxy_phase_a4.sh` |
| `execution_tool_blocked` | `sprint-3-executor` or `sprint-3-a3-deny` (executor on, execution_tool off) |
| WARN stale `isolated_executor*` in `/recent-denied` | Old events; success JSON still valid |
| A5 very slow | See [Why Phase A5 takes a long time](#why-phase-a5-takes-a-long-time); use skip flags |

Full A1 troubleshooting: [MCP_PROXY_PHASE_A1_DEPLOY.md](MCP_PROXY_PHASE_A1_DEPLOY.md#troubleshooting).

---

## URLs (Profile C)

| Service | URL |
|---------|-----|
| MCP Proxy UI | http://localhost:8090/ui |
| MCP Proxy health | http://localhost:8090/health |
| MCP via proxy | http://localhost:8090/mcp |
| Executor (host) | http://localhost:18088/health |
| Wazuh MCP (direct) | http://localhost:3000/mcp |
| Phase 4 API | http://localhost:8082/docs |

---

## What to do next (after Phase A)

Phase A makes Sprint 3 **operational on Profile C**. It does not finish the product
roadmap. Recommended order:

### 1. Operate and tune (ongoing)

- Keep policy: `bash tools/switch_mcp_policy_sample.sh sprint-3-a3-deny`
- Monitor: http://localhost:8090/ui → Tuning Studio → Evidence and Decisions
- After policy edits: `bash tools/test_sprint3_no_restart.sh --skip-unit-tests` or targeted sub-gate tests
- Re-align keys after `.env` or container recreate: `bash tools/align_mcp_proxy_upstream_key.sh`

### 2. Production hardening (before real prod traffic)

| Topic | Action |
|-------|--------|
| **Executor runtime** | Replace reference image with gVisor/Firecracker; keep HTTP contract |
| **LLM latency** | Ensure Docker Model Runner reachable; or disable `llm_risk`/`tool_intent` for test paths; tune `timeout_seconds` |
| **Sandbox attestation** | Enable `sandbox_attestation_profile` when attestor is wired |
| **Dependency fail-safe** | Enable `dependency_fail_safe_profile` when LLM paths are production-ready |
| **Secrets** | `MCP_API_KEY` in `.env` before Profile C; never commit real keys |

### 3. Phase B — Phase 1 commercialization (MVP)

**Runbook:** [MCP_PROXY_PHASE_B.md](MCP_PROXY_PHASE_B.md)  
**Apply + verify:** `bash tools/apply_mcp_proxy_phase_b.sh`

- Deploy UX (30-minute story, presets, compose)
- Execution-risk presets (`core-balanced`, `core-strict`, `core-observe`)
- Metering / tier gating (`/admin/usage`, `commercial` policy block)
- Audit baseline (`/admin/audit-export`, restart survival)

Presets: [MCP_PROXY_PRESETS.md](MCP_PROXY_PRESETS.md).

### 4. Sprint 4 — Enterprise control plane

| Capability | Outcome |
|------------|---------|
| Durable audit export | Compliance conversations |
| Policy versioning + rollback | Change control |
| SSO / RBAC | Delegated admin |
| Signed policy bundles | Integrity attestation |

Suggested build order in roadmap: audit store → policy lifecycle → RBAC → SSO → signing.

### 5. Sprint 5 — Scale and SOC integration

| Capability | Outcome |
|------------|---------|
| SIEM / SOAR / ITSM connectors | External workflows |
| HA / production topology | SLOs, failover |
| Metering at scale | Contract governance |

### 6. Optional engineering

- **Phase E:** profiling-driven Go/Rust hot paths — see
  [MCP_PROXY_GO_REST_ARCHITECTURE.md](MCP_PROXY_GO_REST_ARCHITECTURE.md) and
  [MCP_PROXY_ROADMAP.md](MCP_PROXY_ROADMAP.md)
- Reconcile [OPERATIONS.md](OPERATIONS.md) tracker with shipped Sprints 1–3

---

## Priority summary

```text
Done           → Sprints 1–3, Phase A (A1–A5), Phase B Core MVP
Next (ops)     → core-balanced preset; test_mcp_proxy_phase_b.sh after changes
Next (prod)    → Customer executor runtime, LLM/attestation tuning
Next (product) → Sprint 4 audit/RBAC → Sprint 5 SIEM/HA
```

---

## Document index (Phase A)

| Document |
|----------|
| [MCP_PROXY_PHASE_A_COMPLETE.md](MCP_PROXY_PHASE_A_COMPLETE.md) (this file) |
| [MCP_PROXY_PHASE_A1_DEPLOY.md](MCP_PROXY_PHASE_A1_DEPLOY.md) |
| [MCP_PROXY_PHASE_A2.md](MCP_PROXY_PHASE_A2.md) |
| [MCP_PROXY_PHASE_A3.md](MCP_PROXY_PHASE_A3.md) |
| [MCP_PROXY_PHASE_A4.md](MCP_PROXY_PHASE_A4.md) |
| [MCP_PROXY_PHASE_A5.md](MCP_PROXY_PHASE_A5.md) |
| [MCP_PROXY_PHASE_B.md](MCP_PROXY_PHASE_B.md) |
| [MCP_PROXY_PRESETS.md](MCP_PROXY_PRESETS.md) |
| [MCP_PROXY_VERIFICATION_STATUS.md](MCP_PROXY_VERIFICATION_STATUS.md) |
| [MCP_PROXY_NEXT_STEPS.md](MCP_PROXY_NEXT_STEPS.md) |
| [MCP_PROXY_ROADMAP.md](MCP_PROXY_ROADMAP.md) |
| [MCP_PROXY_GO_REST_ARCHITECTURE.md](MCP_PROXY_GO_REST_ARCHITECTURE.md) |
| [MCP_PROXY_GO_REST_ARCHITECTURE.md](MCP_PROXY_GO_REST_ARCHITECTURE.md) |
