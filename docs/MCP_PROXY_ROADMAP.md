# MCP Security Proxy — Implementation status and next steps

This document summarizes what is shipped (Sprints 1–3), what to do next
operationally, and the planned enterprise roadmap (Sprints 4–5).

**Verification checklist (what is done + re-run commands):**
[MCP_PROXY_VERIFICATION_STATUS.md](MCP_PROXY_VERIFICATION_STATUS.md).

It complements:

- [MCP_PROXY_SPRINT_TESTING.md](MCP_PROXY_SPRINT_TESTING.md) — how to verify Sprints 1–3
- [ai-security-product-strategy.md](ai-security-product-strategy.md) — product phases and commercialization
- [mcp-security-proxy/README.md](../mcp-security-proxy/README.md) — implementation snapshot

---

## Current state (shipped)

| Sprint | Theme | Design doc | Policy sample |
|--------|--------|------------|---------------|
| 1 | Trust hardening | [MCP_PROXY_TRUST_HARDENING.md](MCP_PROXY_TRUST_HARDENING.md) | `config/phase4/mcp_proxy/policy.sample.sprint-1-trust-hardening.json` |
| 2 | Containment / fail-safe | [MCP_PROXY_CONTAINMENT_FAILSAFE.md](MCP_PROXY_CONTAINMENT_FAILSAFE.md) | `policy.sample.sprint-2-containment-failsafe.json` |
| 3 | Isolated execution / provenance | [MCP_PROXY_ISOLATED_EXECUTION.md](MCP_PROXY_ISOLATED_EXECUTION.md) | `policy.sample.sprint-3-isolated-execution.json` |

**Core proxy (pre-sprint):** MCP allow/deny/challenge, LLM risk, tool-intent, discovery
alerts, `/ui` tuning studio, admin APIs, API-key auth, Prometheus metrics.

**Verification:**

```bash
bash tools/smoke_mcp_proxy.sh                    # all features (recommended)
bash tools/test_sprint1_no_restart.sh            # or per-sprint
bash tools/test_sprint2_no_restart.sh
bash tools/test_sprint3_no_restart.sh
```

See [MCP_PROXY_SMOKE_TEST.md](MCP_PROXY_SMOKE_TEST.md) for the consolidated suite;
[MCP_PROXY_SPRINT_TESTING.md](MCP_PROXY_SPRINT_TESTING.md) for per-sprint preparation.

---

## Phase A — Operationalize Sprint 3

**Status:** Shipped (A1–A5 runbooks + scripts). Reference executor deployed on Profile C;
customer production runtime (gVisor/Firecracker) remains operator-owned.

Master guide: [MCP_PROXY_PHASE_A_COMPLETE.md](MCP_PROXY_PHASE_A_COMPLETE.md).

### A1. Deploy isolated executor service

**Status:** Reference implementation shipped in repo. When deploy + live tests pass,
Phase A1 is complete — follow [MCP_PROXY_NEXT_STEPS.md](MCP_PROXY_NEXT_STEPS.md) for
the post-A1 operator checklist (persist policy, A2–A5, production hardening).

**Full runbook (summary, prerequisites, copy-paste commands, troubleshooting):**
[MCP_PROXY_PHASE_A1_DEPLOY.md](MCP_PROXY_PHASE_A1_DEPLOY.md)

Quick sequence (run **one command per line** — do not paste inline `#` comments):

```bash
bash tools/start-profile.sh C
bash tools/align_mcp_proxy_upstream_key.sh
bash tools/start_isolated_executor.sh
bash tools/deploy_isolated_executor_a1.sh
bash tools/test_isolated_executor_live.sh
```

**Common failure:** `network wazuh-soc_default ... could not be found` → start Profile C
**before** `start_isolated_executor.sh`.

**Reference implementation:** [mcp-isolated-executor/](../mcp-isolated-executor/) —
hardened-container sidecar (`uid=1000`). Service DNS:
`http://isolated-executor:8080/execute`. Host debug: `http://localhost:18088/health`.

Policy profile: `bash tools/switch_mcp_policy_sample.sh sprint-3-executor`

See also: [MCP_PROXY_ISOLATED_EXECUTION.md](MCP_PROXY_ISOLATED_EXECUTION.md)

### A2. Configure runtime, filesystem, and egress

**Runbook:** [MCP_PROXY_PHASE_A2.md](MCP_PROXY_PHASE_A2.md)  
**Apply + verify:** `bash tools/apply_mcp_proxy_phase_a2.sh`  
**Policy sample:** `bash tools/switch_mcp_policy_sample.sh sprint-3-a2` →
`policy.sample.sprint-3-a2-operational.json`

1. **Runtime limits** — `runtime_limits.max_cpu_seconds`, `max_memory_mb`, timeouts;
   start restrictive.
2. **Rootless** — `require_rootless: true` when the runtime supports it.
3. **Filesystem** — minimal `allow_write_paths`; explicit `deny_read_paths` /
   `deny_write_paths`.
4. **Upstream provenance** — explicit `allowed_destinations`; `blocked_destinations`
   for known-bad patterns; optional `log_all_egress`.

Sub-gate tests: `test_runtime_limits.sh`, `test_filesystem_restrictions.sh`,
`test_upstream_provenance.sh`.

### A3. Staged enforcement rollout

**Runbook:** [MCP_PROXY_PHASE_A3.md](MCP_PROXY_PHASE_A3.md)  
**Apply + verify:** `bash tools/apply_mcp_proxy_phase_a3.sh`  
**Policy samples:** `sprint-3-a3-monitor`, `sprint-3-a3-challenge`, `sprint-3-a3-deny`

For each control (`isolated_executor`, `sandbox_attestation`,
`execution_tool_profile`, etc.):

1. `monitor` — observe decision events, no deny
2. `challenge` — require operator/agent acknowledgment where supported
3. `deny` — fail-closed in production

Production policy: `bash tools/switch_mcp_policy_sample.sh sprint-3-a3-deny`

### A4. Keys and deployment hygiene

**Runbook:** [MCP_PROXY_PHASE_A4.md](MCP_PROXY_PHASE_A4.md)  
**Apply + verify:** `bash tools/apply_mcp_proxy_phase_a4.sh`

| Step | Command / check |
|------|------------------|
| Align upstream + client bearer | `bash tools/align_mcp_proxy_upstream_key.sh` |
| Verify hygiene | `bash tools/test_mcp_proxy_phase_a4.sh` |
| Rebuild after code changes | `bash tools/apply_mcp_proxy_phase_a4.sh --rebuild-proxy` |
| Health | `curl -s http://localhost:8090/health \| jq` |

Set `MCP_API_KEY` and `MCP_PROXY_API_KEY` in repo `.env` **before**
`bash tools/start-profile.sh C` so proxy and Wazuh share the same key at container create time.

### A5. Validate after operational changes

**Runbook:** [MCP_PROXY_PHASE_A5.md](MCP_PROXY_PHASE_A5.md)  
**Apply + verify:** `bash tools/apply_mcp_proxy_phase_a5.sh`

Runs A4 preflight, Sprint 1–3 E2E (fast: `--skip-unit-tests`), optional live executor
and smoke, restores `sprint-3-a3-deny`.

```bash
# Manual equivalent:
bash tools/test_sprint1_no_restart.sh --skip-unit-tests
bash tools/test_sprint2_no_restart.sh --skip-unit-tests
bash tools/test_sprint3_no_restart.sh --skip-unit-tests
```

Monitor: `http://localhost:8090/ui` → Tuning Studio → Evidence and Decisions.

**Operator guide (checklist, goals matrix, command table):**
[MCP_PROXY_NEXT_STEPS.md](MCP_PROXY_NEXT_STEPS.md).

**Phase A master guide (A1–A5, scripts, policies, A5 duration, next steps):**
[MCP_PROXY_PHASE_A_COMPLETE.md](MCP_PROXY_PHASE_A_COMPLETE.md).

---

## Phase B — Phase 1 commercialization (MVP revenue)

**Status:** Implemented — runbook [MCP_PROXY_PHASE_B.md](MCP_PROXY_PHASE_B.md),
presets [MCP_PROXY_PRESETS.md](MCP_PROXY_PRESETS.md).

```bash
bash tools/apply_mcp_proxy_phase_b.sh
bash tools/test_mcp_proxy_phase_b.sh
```

From [ai-security-product-strategy.md](ai-security-product-strategy.md) Phase 1 exit
criteria:

| Work item | Target outcome | Status |
|-----------|----------------|--------|
| Deploy UX | Paid team deploys proxy in under 30 minutes | `apply_mcp_proxy_phase_b.sh` |
| Execution-risk presets | Strict preset blocks exfiltration chains OOTB | `core-strict` + test |
| Trust controls | Descriptor/hash mismatch in denies/discovery | Sprint 1 + Core presets |
| Metering / tier gating | Usage metering and feature gates | `/admin/usage`, `commercial` block |
| Audit baseline | Durable events; export survives restart | `/admin/audit-export` + volume |

**Verified on Profile C:** `bash tools/test_mcp_proxy_phase_b.sh` →
`PHASE B COMMERCIALIZATION PASSED`. See
[MCP_PROXY_VERIFICATION_STATUS.md](MCP_PROXY_VERIFICATION_STATUS.md).

Acceptable for MVP; Sprint 4 adds enterprise governance depth.

---

## Phase C — Sprint 4 (enterprise control plane)

**Status:** Implemented — runbook [MCP_PROXY_PHASE_C.md](MCP_PROXY_PHASE_C.md).

```bash
bash tools/apply_mcp_proxy_phase_c.sh
bash tools/test_mcp_proxy_phase_c.sh
```

| Capability | Description | Status |
|------------|-------------|--------|
| **RBAC** | Roles (`admin`, `operator`, `auditor`); scoped API tokens on admin routes | Shipped |
| **Policy lifecycle** | Versioning, proposals, approval workflow, rollback | Shipped |
| **Signed policy bundles** | HMAC-SHA256 sign/verify on bundle apply | Shipped |
| **Audit integrity** | Tamper-evident hash chain on denied/decision events | Shipped |
| **OIDC stub** | HS256 JWT bearer + `/admin/auth/oidc/config` (lab); full IdP UI flow = production hardening | Baseline shipped |

Policy sample: `bash tools/switch_mcp_policy_sample.sh sprint-4-governance`

**Still planned for production hardening (post-Sprint 4 MVP):**

- Full OIDC authorization-code / SAML UI login
- External JWKS rotation and multi-tenant policy scopes
- Compliance export packs (SOC2/HIPAA artifact bundles)

---

## Phase D — Sprint 5 (scale and SOC integration)

| Capability | Description |
|------------|-------------|
| **SIEM / SOAR / ITSM** | Webhooks/connectors for denies, discovery alerts, decision events |
| **Metering and entitlements** | Feature tiers, workspace limits, contract governance |
| **HA and production topology** | Multi-instance proxy, documented SLOs, load and failover validation |

Phase 2–3 exit criteria in the strategy doc depend on Sprint 5 items (for example,
at least one SIEM integration validated end-to-end).

---

## Phase E — Optional engineering (architecture)

**Selective native code** (Rust or Go) for hot paths (enforcement, parsing) per the
strategy doc — profiling-driven, not a full rewrite. Keep Python for policy UI,
admin APIs, and integrations.

**Full architecture guide (Go vs REST, sidecar pattern, what not to rewrite):**
[MCP_PROXY_GO_REST_ARCHITECTURE.md](MCP_PROXY_GO_REST_ARCHITECTURE.md).

---

## Priority summary (recommended order)

```text
Done  → Sprints 1–3, Phase A (A1–A5), Phase B (Core MVP), Phase C (Sprint 4 governance)
Next  → Operate (core-balanced / sprint-4-governance); test_mcp_proxy_phase_b.sh + phase_c.sh after changes
Next  → Sprint 5 — SIEM/SOAR, HA, enterprise metering
Later → Phase E — Go/Rust hot paths (profiling-driven)
```

---

## What is ready vs not ready today

**Ready now** (from product strategy):

- Standalone MCP gateway, small-team / internal platform
- Policy tuning, discovery-assisted monitoring, demo/trial
- Sprints 1–3 controls and E2E test suites
- Phase A operational rollout (reference executor on Profile C)
- Phase B Core MVP (presets, metering, audit export, deploy UX)

**Not ready yet** (Sprint 5 + production hardening):

- Full OIDC/SAML UI login and external IdP JWKS automation
- Compliance export packs and multi-tenant policy scopes
- Customer production executor (gVisor/Firecracker) — reference sidecar only
- Turnkey external SOC workflows (SIEM/SOAR/ITSM connectors)

---

## Documentation maintenance

Reconcile [OPERATIONS.md](OPERATIONS.md) “Implementation priority tracker” with
shipped Sprints 1–3 so ops runbooks match the codebase.

---

## Quick links

| Task | Doc / command |
|------|----------------|
| **Verification status (done / next)** | [MCP_PROXY_VERIFICATION_STATUS.md](MCP_PROXY_VERIFICATION_STATUS.md) |
| **Phase A complete (A1–A5)** | [MCP_PROXY_PHASE_A_COMPLETE.md](MCP_PROXY_PHASE_A_COMPLETE.md) |
| **After A1 / Sprint 3 pass** | [MCP_PROXY_NEXT_STEPS.md](MCP_PROXY_NEXT_STEPS.md) |
| Phase A2 runbook | [MCP_PROXY_PHASE_A2.md](MCP_PROXY_PHASE_A2.md) — `bash tools/apply_mcp_proxy_phase_a2.sh` |
| Phase A3 runbook | [MCP_PROXY_PHASE_A3.md](MCP_PROXY_PHASE_A3.md) — `bash tools/apply_mcp_proxy_phase_a3.sh` |
| Phase A4 runbook | [MCP_PROXY_PHASE_A4.md](MCP_PROXY_PHASE_A4.md) — `bash tools/apply_mcp_proxy_phase_a4.sh` |
| Phase A5 runbook | [MCP_PROXY_PHASE_A5.md](MCP_PROXY_PHASE_A5.md) — `bash tools/apply_mcp_proxy_phase_a5.sh` |
| Phase A1 deploy runbook | [MCP_PROXY_PHASE_A1_DEPLOY.md](MCP_PROXY_PHASE_A1_DEPLOY.md) |
| Consolidated proxy smoke | [MCP_PROXY_SMOKE_TEST.md](MCP_PROXY_SMOKE_TEST.md) — `bash tools/smoke_mcp_proxy.sh` |
| Run sprint tests | [MCP_PROXY_SPRINT_TESTING.md](MCP_PROXY_SPRINT_TESTING.md) |
| Switch policy sample | `bash tools/switch_mcp_policy_sample.sh sprint-{1,2,3,3-executor}` |
| Align API keys | `bash tools/align_mcp_proxy_upstream_key.sh` |
| Go / REST architecture options | [MCP_PROXY_GO_REST_ARCHITECTURE.md](MCP_PROXY_GO_REST_ARCHITECTURE.md) |
| Phase B deploy (MVP) | [MCP_PROXY_PHASE_B.md](MCP_PROXY_PHASE_B.md) — `bash tools/apply_mcp_proxy_phase_b.sh` |
| Phase C / Sprint 4 | [MCP_PROXY_PHASE_C.md](MCP_PROXY_PHASE_C.md) — `bash tools/apply_mcp_proxy_phase_c.sh` |
| UI re-auth + preset choice | [MCP_PROXY_OPERATE_UI_AND_PRESETS.md](MCP_PROXY_OPERATE_UI_AND_PRESETS.md) |
| Core presets | [MCP_PROXY_PRESETS.md](MCP_PROXY_PRESETS.md) |
| Sprint 3 policy fields | [MCP_PROXY_ISOLATED_EXECUTION.md](MCP_PROXY_ISOLATED_EXECUTION.md) |
| Commercial phases | [ai-security-product-strategy.md](ai-security-product-strategy.md) |
