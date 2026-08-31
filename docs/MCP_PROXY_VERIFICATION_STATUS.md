# MCP Security Proxy — Verification status

Single checklist of **what is implemented, verified, and what is next**. Re-run the
commands below after policy or proxy changes.

Related:

- [MCP_PROXY_ROADMAP.md](MCP_PROXY_ROADMAP.md) — full roadmap
- [MCP_PROXY_PHASE_A_COMPLETE.md](MCP_PROXY_PHASE_A_COMPLETE.md) — Phase A (A1–A5)
- [MCP_PROXY_PHASE_B.md](MCP_PROXY_PHASE_B.md) — Phase B (MVP commercialization)
- [MCP_PROXY_NEXT_STEPS.md](MCP_PROXY_NEXT_STEPS.md) — operator checklist

---

## Summary (current stack)

| Layer | Status | Notes |
|-------|--------|-------|
| **Sprints 1–3** | Shipped + E2E scripts | Trust, containment, isolated execution policy |
| **Phase A (A1–A5)** | Shipped + runbooks | Operationalize Sprint 3 on Profile C |
| **Phase B** | Shipped + **verified** | Core presets, metering, audit export |
| **Phase C (Sprint 4)** | Shipped + **verified** | RBAC, policy lifecycle, signed bundles, audit chain |
| **Phase C (Sprint 4)** | Shipped | RBAC, policy lifecycle, signed bundles, audit chain |
| **Phase D (Sprint 5)** | Not started | SIEM/SOAR, HA, enterprise metering |
| **Phase E** | Optional | Go/Rust hot paths (profiling-driven) |

**Recommended production lab policy after Phase B:** `core-balanced` or `core-strict`
([MCP_PROXY_PRESETS.md](MCP_PROXY_PRESETS.md)).  
**Staged enforcement / executor ops policy:** `sprint-3-a3-deny` or `sprint-3-executor`.

---

## Last verification (Profile C)

Environment: `mcp-security-proxy`, `wazuh-mcp-server`, `isolated-executor` running;
proxy healthy at `http://localhost:8090`; executor at `http://localhost:18088`.

| Check | Result |
|-------|--------|
| `curl -s http://localhost:8090/health` | `status: healthy` |
| `GET /admin/entitlements` | `tier: core`, `policy_bundles: false` |
| `bash tools/test_mcp_proxy_phase_b.sh` | `PHASE B COMMERCIALIZATION PASSED` |
| Core-strict preset test | `CORE STRICT PRESET TEST PASSED` |
| Metering test | `PHASE B METERING TEST PASSED` |
| Audit + restart survival | `PHASE B AUDIT BASELINE TEST PASSED` |
| Phase C governance | `PHASE C SPRINT 4 GOVERNANCE PASSED` |
| Isolated executor health | `runtime: hardened-container`, `uid: 1000` |

Re-verify anytime:

```bash
bash tools/test_mcp_proxy_phase_b.sh
bash tools/test_sprint3_no_restart.sh --skip-unit-tests   # after sprint policy changes
bash tools/apply_mcp_proxy_phase_a5.sh --skip-a4-preflight --skip-live-executor  # light A regression
```

---

## Testing coverage matrix (smoke vs Phase A vs Phase B)

Three orchestrators cover different layers. None alone is a full release gate.

| Layer | Entrypoint | Typical runtime | Covers |
|-------|------------|-----------------|--------|
| **Feature smoke** | `bash tools/smoke_mcp_proxy.sh` | ~5–15 min | Preflight, core gateway, discovery, tool-intent, LLM risk, Sprints 1–3; optional live executor, reverse-flow, pytest |
| **Phase B commercial** | `bash tools/test_mcp_proxy_phase_b.sh` | ~2–5 min | `core-*` presets, metering/tiers, audit export, restart survival |
| **Phase A operational** | `bash tools/apply_mcp_proxy_phase_a5.sh` | ~5–15 min | A4 hygiene + all sprint suites + live executor + policy restore to `sprint-3-a3-deny` |

### What smoke includes (partial Phase A only)

- Sprint 1–3 E2E wrappers (`test_sprintN_no_restart.sh`)
- Tool-intent, LLM risk, discovery alert scripts
- Optional Phase A1 live executor (`--with-isolated-executor` or auto when sidecar is up)
- Preflight upstream key alignment check

### What smoke does **not** include

| Gap | Use instead |
|-----|-------------|
| Phase A2 apply / policy rollout | `bash tools/apply_mcp_proxy_phase_a2.sh` |
| Phase A3 staged enforcement | `bash tools/test_mcp_proxy_phase_a3.sh` |
| Phase A4 keys and admin hygiene | `bash tools/test_mcp_proxy_phase_a4.sh` |
| Full A5 stacked regression | `bash tools/apply_mcp_proxy_phase_a5.sh` |
| Phase B presets, metering, audit | `bash tools/test_mcp_proxy_phase_b.sh` |
| Greenfield Phase B deploy | `bash tools/apply_mcp_proxy_phase_b.sh` |

`apply_mcp_proxy_phase_a5.sh --with-smoke` can invoke smoke at the end of A5; smoke itself
never calls Phase B or A2–A4 apply scripts.

### Recommended commands by change type

| You changed… | Run |
|--------------|-----|
| Proxy Python code (`mcp_security_proxy/`) | `bash tools/smoke_mcp_proxy.sh --with-unit-tests --with-isolated-executor` then `bash tools/test_mcp_proxy_phase_b.sh` if commercial paths touched |
| Sprint policy samples only | `bash tools/test_sprint3_no_restart.sh --skip-unit-tests` (or the affected sprint wrapper) |
| Core presets or `commercial` policy block | `bash tools/test_mcp_proxy_phase_b.sh` |
| Before tagging / major release | `bash tools/smoke_mcp_proxy.sh --with-isolated-executor && bash tools/test_mcp_proxy_phase_b.sh && bash tools/apply_mcp_proxy_phase_a5.sh` |

Full smoke reference: [MCP_PROXY_SMOKE_TEST.md — overlap section](MCP_PROXY_SMOKE_TEST.md#overlap-with-phase-a-and-phase-b).

---

## Phase A — completion signals

| Phase | Done when | Runbook |
|-------|-----------|---------|
| **A1** | `Phase A1 deployment complete.` + live executor PASS | [MCP_PROXY_PHASE_A1_DEPLOY.md](MCP_PROXY_PHASE_A1_DEPLOY.md) |
| **A2** | `Phase A2 complete.` | [MCP_PROXY_PHASE_A2.md](MCP_PROXY_PHASE_A2.md) |
| **A3** | `PHASE A3 STAGED ENFORCEMENT TEST PASSED (all)` | [MCP_PROXY_PHASE_A3.md](MCP_PROXY_PHASE_A3.md) |
| **A4** | `PHASE A4 KEYS AND HYGIENE TEST PASSED` | [MCP_PROXY_PHASE_A4.md](MCP_PROXY_PHASE_A4.md) |
| **A5** | `PHASE A5 REGRESSION VALIDATION PASSED` | [MCP_PROXY_PHASE_A5.md](MCP_PROXY_PHASE_A5.md) |

One-shot: [MCP_PROXY_PHASE_A_COMPLETE.md](MCP_PROXY_PHASE_A_COMPLETE.md).

---

## Phase B — completion signals

| Workstream | Done when | Command |
|------------|-----------|---------|
| **B1 Deploy** | `Phase B deploy complete.` | `bash tools/apply_mcp_proxy_phase_b.sh` |
| **B2 Presets** | `CORE STRICT PRESET TEST PASSED` | `bash tools/test_mcp_proxy_preset_core_strict.sh` |
| **B3 Metering** | `PHASE B METERING TEST PASSED` | `bash tools/test_mcp_proxy_phase_b_metering.sh` |
| **B4 Audit** | `PHASE B AUDIT BASELINE TEST PASSED` | `bash tools/test_mcp_proxy_phase_b_audit.sh` |
| **B5 All** | `PHASE B COMMERCIALIZATION PASSED` | `bash tools/test_mcp_proxy_phase_b.sh` |

Runbook: [MCP_PROXY_PHASE_B.md](MCP_PROXY_PHASE_B.md).  
Presets: [MCP_PROXY_PRESETS.md](MCP_PROXY_PRESETS.md).

### Phase B deliverables (code + config)

| Item | Location |
|------|----------|
| Core presets | `config/phase4/mcp_proxy/policy.sample.core-{observe,balanced,strict}.json` |
| Commercial / metering | `mcp-security-proxy/mcp_security_proxy/app.py` — `commercial` block, `/admin/usage`, `/admin/entitlements` |
| Audit export | `GET /admin/audit-export?format=json\|ndjson` |
| Deploy script | `tools/apply_mcp_proxy_phase_b.sh` |
| Policy reload retries | `tools/switch_mcp_policy_sample.sh` — `reload_proxy_policy()` |

---

## What is ready vs not ready

### Ready now

- MCP gateway with allow/deny/challenge, LLM risk, tool-intent, discovery
- Sprints 1–3 E2E test suites
- Reference isolated executor (Profile C + sidecar)
- Phase A operational scripts (A1–A5)
- Phase B Core MVP: presets, metering, audit export, 30-min deploy story
- Standalone UI, Prometheus metrics, API-key admin

### Not ready (Sprint 5 + production hardening)

- Full OIDC/SAML UI login and external IdP JWKS automation
- Compliance export packs (SOC2/HIPAA artifact bundles)
- Multi-tenant policy scopes
- Customer production executor (gVisor/Firecracker) — reference only today
- SIEM/SOAR/ITSM connector pack, HA topology, contract metering at scale

---

## What to do next

```text
Operate  → core-balanced (daily) or sprint-4-governance (Phase C demos)
           UI http://localhost:8090/ui — re-auth: MCP_PROXY_OPERATE_UI_AND_PRESETS.md
Validate → smoke + phase_b (+ phase_c when on governance preset)
Product  → Sprint 5 (SIEM/SOAR, HA); harden OIDC/SAML for production IdP
Scale    → Sprint 5 (SIEM, HA)
Optional → Phase E native hot paths after profiling
```

**UI + preset runbook:** [MCP_PROXY_OPERATE_UI_AND_PRESETS.md](MCP_PROXY_OPERATE_UI_AND_PRESETS.md)

---

## Quick command reference

| Goal | Command |
|------|---------|
| Feature regression (smoke) | `bash tools/smoke_mcp_proxy.sh --with-isolated-executor` |
| Smoke + Phase B (day-to-day) | `bash tools/smoke_mcp_proxy.sh --with-isolated-executor && bash tools/test_mcp_proxy_phase_b.sh` |
| Verify Phase C / Sprint 4 | `bash tools/test_mcp_proxy_phase_c.sh` |
| Deploy Phase C | `bash tools/apply_mcp_proxy_phase_c.sh` |
| Deploy Phase B (greenfield) | `bash tools/apply_mcp_proxy_phase_b.sh` |
| Verify Phase B | `bash tools/test_mcp_proxy_phase_b.sh` |
| UI re-auth + preset choice | [MCP_PROXY_OPERATE_UI_AND_PRESETS.md](MCP_PROXY_OPERATE_UI_AND_PRESETS.md) |
| Switch Core preset | `bash tools/switch_mcp_policy_sample.sh core-balanced` |
| Switch governance preset | `bash tools/switch_mcp_policy_sample.sh sprint-4-governance` |
| Full Phase A regression | `bash tools/apply_mcp_proxy_phase_a5.sh` |
| Usage / entitlements | `curl -s -H "Authorization: Bearer $(bash tools/mcp_api_key.sh --proxy)" http://localhost:8090/admin/usage \| jq` |
| Audit export | `curl -s -H "Authorization: Bearer $(bash tools/mcp_api_key.sh --proxy)" 'http://localhost:8090/admin/audit-export?format=json' \| jq '.audit.counts'` |
