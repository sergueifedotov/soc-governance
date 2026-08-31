# MCP Security Proxy — Go / REST architecture options

This document answers: **can critical parts of the MCP security proxy be converted to
Go or REST?** It describes the current split between MCP (data plane) and REST
(control plane), what is worth porting, recommended migration shapes, and when that
work should wait.

Related:

- [MCP_PROXY_ROADMAP.md](MCP_PROXY_ROADMAP.md) — Phase E (optional hot-path engineering)
- [ai-security-product-strategy.md](ai-security-product-strategy.md) — selective Rust/Go adoption strategy
- [mcp-security-proxy/README.md](../mcp-security-proxy/README.md) — implementation snapshot
- [MCP_PROXY_PHASE_A_COMPLETE.md](MCP_PROXY_PHASE_A_COMPLETE.md) — current operational baseline

**Short answer:** Yes, **deterministic enforcement and forwarding** can move to Go (or
Rust) as a sidecar. **Admin and ops APIs are already REST.** Do **not** replace
`POST /mcp` with generic REST — MCP clients require JSON-RPC. Expand REST **alongside**
`/mcp` for integrations (Sprint 5), not as a replacement.

---

## Current architecture

The proxy is a **single FastAPI application** (~3,800 lines in
`mcp-security-proxy/mcp_security_proxy/app.py`), deployed via Docker Compose on port
**8090**.

```text
                    ┌─────────────────────────────────────────┐
  MCP clients       │  mcp-security-proxy (Python / FastAPI)  │
  (Cursor, agents)  │                                         │
       │            │  POST /mcp  ──► policy pipeline ──►     │
       └───────────►│               upstream Wazuh MCP or       │
                    │               isolated executor           │
                    │                                         │
  Operators / UI    │  GET/POST /admin/*, /soc/*  (REST)      │
       └───────────►│  GET /ui, /metrics, /health             │
                    └─────────────────────────────────────────┘
                                          │
                    ┌─────────────────────┴─────────────────────┐
                    ▼                                           ▼
           Wazuh MCP upstream                          mcp-isolated-executor
           (JSON-RPC /mcp)                             POST /execute (REST)
```

| Surface | Protocol | Path examples | Role |
|---------|----------|---------------|------|
| **Data plane** | MCP JSON-RPC over HTTP | `POST /mcp` | Gate and forward tool traffic |
| **Control plane** | REST (FastAPI) | `/admin/policy-config`, `/soc/*` | Policy, tuning, observability |
| **Metrics** | Prometheus text | `GET /metrics` | Counters, histograms |
| **UI** | Static HTML + REST | `GET /ui` | Tuning Studio |

The isolated executor (`mcp-isolated-executor/`) is already a small **REST** service:
`POST /execute` with `{ original_request, security_context }`.

There is **no Go code** in this repository today. All gateway logic is Python.

---

## What “critical” means in this codebase

On each `POST /mcp` request, the proxy runs a **ordered pipeline** before forwarding.
These stages are security-sensitive and are the primary candidates for a native
language port:

| Stage | Python entry points (indicative) | Portability |
|-------|----------------------------------|-------------|
| Body size / auth | `mcp_proxy`, `_validate_proxy_auth` | High — pure logic + HTTP |
| Deterministic policy | `_policy_decision`, `_contains_blocked_pattern` | High — JSON + regex |
| Trusted upstream | `_is_trusted_upstream` | High |
| Sandbox attestation | `_sandbox_attestation_check` | High |
| Dependency fail-safe | `_dependency_fail_safe_check` | Medium — async health probes |
| Isolated executor routing | `_isolated_executor_check`, `_forward_to_isolated_executor` | Medium — HTTP forward |
| Upstream provenance | `_check_upstream_provenance` | High |
| LLM risk | `_llm_risk_score` (LangChain) | Low — keep in Python or separate scorer |
| Tool intent | `_tool_intent_score` (LangChain) | Low |
| Discovery rules | `_evaluate_discovery_rules` | Medium — coupled to in-memory state |
| Telemetry | Prometheus counters, `_record_denied_event` | High in Go/Rust |

The deterministic core (`_policy_decision`) is compact and well-tested:

```2248:2272:mcp-security-proxy/mcp_security_proxy/app.py
def _policy_decision(payload: Dict[str, Any]) -> Tuple[bool, str]:
    method, tool = _extract_method_and_tool(payload)
    if policy.allowed_methods and method not in policy.allowed_methods:
        return False, "method_not_allowed"
    if method == "tools/call":
        ...
        if _is_execution_like_tool(tool):
            exec_action = str(policy.execution_tool_profile.get("action", "deny")).lower()
            ...
        blocked_reason = _contains_blocked_pattern(params.get("arguments", {}))
        ...
    return True, "allow"
```

The full `/mcp` handler chains trust, containment, LLM, forwarding, and JSON-RPC error
shaping — see `mcp_proxy` starting around line 3327 in the same file.

---

## Go vs REST — different questions

### “Convert to REST”

| Interpretation | Feasible? | Recommendation |
|----------------|-----------|----------------|
| Admin APIs → REST | **Already done** | `/admin/*`, `/soc/*` are FastAPI REST today |
| Replace `/mcp` with REST | Technically possible | **Do not** — breaks MCP clients (Cursor, IDE agents) |
| Add REST for SIEM / automation | Yes (Sprint 5) | Webhooks, export APIs **alongside** `/mcp` |
| Executor → REST | **Already done** | `POST /execute` on port 18088 |

MCP is the product’s wire protocol for agents. REST is the right surface for operators,
policy lifecycle, and enterprise integrations — not a substitute for `/mcp`.

### “Convert to Go”

Go (or Rust) fits the **data-plane hot path**: parse JSON-RPC, evaluate policy,
forward HTTP, emit metrics. The repo’s written preference in
[ai-security-product-strategy.md](ai-security-product-strategy.md) is **selective Rust**
for measured bottlenecks; the **same sidecar pattern** applies to Go if your team
prefers it for ops, hiring, or static binaries.

**Do not** plan a full monolith rewrite while Phase B / Sprint 4–5 gaps (audit, RBAC,
SIEM) remain the commercial blockers.

---

## Recommended migration shapes

### Option A — Go (or Rust) policy sidecar (recommended first slice)

Extract deterministic evaluation behind a stable internal API. Python `/mcp` (or a thin
Go gateway) calls the sidecar before forward/deny.

```text
POST /mcp ──► gateway ──► POST /v1/evaluate (Go sidecar)
                              │
                              ├─ allow + route: upstream | executor
                              └─ deny/challenge + reason + stages
```

Example evaluate contract (illustrative, not implemented yet):

```json
// Request
{
  "method": "tools/call",
  "tool": "shell_exec",
  "arguments": { "command": "whoami" },
  "upstream_url": "http://wazuh-mcp:3000/mcp",
  "client_ip": "10.0.0.5"
}

// Response
{
  "decision": "allow",
  "reason": "allow",
  "route": "executor",
  "executor_url": "http://mcp-isolated-executor:18088",
  "stages": [
    { "stage": "policy", "decision": "allow" },
    { "stage": "isolated_executor", "decision": "route" }
  ]
}
```

**Port first:** `_policy_decision`, blocked patterns, execution-tool profile, trusted
upstream, upstream provenance, isolated-executor routing checks.

**Keep in Python initially:** LLM risk, tool intent, discovery, UI, policy CRUD.

**Acceptance bar:** existing E2E suites must pass unchanged:

```bash
bash tools/test_sprint1_no_restart.sh --skip-unit-tests
bash tools/test_sprint2_no_restart.sh --skip-unit-tests
bash tools/test_sprint3_no_restart.sh --skip-unit-tests
bash tools/test_mcp_proxy_phase_a5.sh --skip-a4-preflight
```

Unit tests in `mcp-security-proxy/tests/test_app.py` should gain parity cases for any
extracted evaluator.

### Option B — Go MCP gateway (no LLM in v1)

A Go service owns `POST /mcp`, `/health`, `/metrics`. It implements deterministic
gates + upstream/executor forwarding. Python remains a **control-plane** service for
`/admin/*`, `/ui`, and optional LLM scoring invoked via HTTP from Go.

Higher effort than Option A; use when profiling shows Python HTTP overhead dominates and
you are ready to operate two gateway images.

### Option C — REST integration layer only (Sprint 5)

No change to `/mcp`. Add durable export, webhooks, and connector-friendly REST for
denies, discovery alerts, and decision events. Aligns with Phase D in
[MCP_PROXY_ROADMAP.md](MCP_PROXY_ROADMAP.md).

### Option D — Full monolith port (not recommended now)

Rewriting `app.py`, LangChain layers, UI, and discovery in Go/Rust is **months of
work** with high regression risk and little near-term revenue impact. Explicitly
de-prioritized in the product strategy during PMF and early commercialization.

---

## When to migrate vs when to wait

### Justify Go/Rust work when

- Production profiling shows CPU or latency bottlenecks in **parsing, regex, or policy
  eval** — not in LLM calls.
- Infrastructure cost pressure from Python hot paths at sustained QPS.
- SLO targets require tighter p99 on `/mcp` than horizontal Python scaling affords.
- Security review demands memory-safe handling of untrusted JSON at the gateway edge.

### Wait when

- Primary pain is **LLM latency** on `tools/call` (see
  [MCP_PROXY_PHASE_A5.md](MCP_PROXY_PHASE_A5.md) — A5 slowness). A Go gateway does not
  remove model round-trips.
- Team bandwidth is better on **Phase B** (deploy UX, metering), **Sprint 4** (audit,
  RBAC, policy versioning), or **Sprint 5** (SIEM, HA).
- No realistic workload has been measured under load.

**Commercial rule of thumb** (from product strategy): close enterprise-readiness gaps
first; move only **proven** hot paths to native code to improve margin and reliability.

---

## Effort and risk (ballpark)

| Scope | Effort | Risk | Notes |
|-------|--------|------|-------|
| Policy evaluator sidecar (deterministic only) | Weeks | Low | Parity with Sprint 1–3 tests |
| Go `/mcp` gateway without LLM | Medium–large | Medium | Forwarding, provenance, executor |
| REST integration / export APIs | Small–medium | Low | Additive; Sprint 5 |
| Full monolith port incl. LLM + UI | Months | High | Not recommended pre–Sprint 5 |

---

## Suggested implementation order

If Phase E work is approved **after** profiling:

1. **Document policy JSON schema** as the evaluator input (reuse `config/phase4/mcp_proxy/policy.json` shapes).
2. **Implement Go `/v1/evaluate`** with table-driven tests mirroring `test_app.py` policy cases.
3. **Wire Python `/mcp`** to call the sidecar for deterministic stages only (feature flag).
4. **Re-run Phase A5** and sprint no-restart suites; compare p50/p99 and CPU.
5. **Optionally** move forwarding + metrics into Go; keep LLM scoring as HTTP to Python or direct to model runner.
6. **Add REST export/webhooks** for SOC workflows (Sprint 5) — independent of gateway language.

---

## What stays in Python (control plane)

Per [ai-security-product-strategy.md](ai-security-product-strategy.md) and
[MCP_PROXY_ROADMAP.md](MCP_PROXY_ROADMAP.md) Phase E:

- Policy editing, rollout, simulation, and approval workflows (Sprint 4).
- Tuning Studio UI (`/ui`).
- LangChain-based LLM risk and tool-intent (unless extracted to a dedicated scorer service).
- Compliance reporting orchestration and connector configuration.
- Rapid product iteration on admin APIs.

---

## REST endpoints already shipped (reference)

Control-plane routes in `app.py` (non-exhaustive):

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health` | Liveness |
| GET | `/metrics` | Prometheus |
| GET/POST | `/admin/policy-config` | Policy read/write |
| POST | `/admin/reload-policy` | Reload from disk |
| GET/POST | `/admin/llm-risk-config`, `/admin/tool-intent-config` | Tuning |
| GET | `/recent-denied`, `/recent-decisions`, `/recent-discovery-alerts` | Runtime history |
| GET | `/ui` | Tuning Studio |

MCP data plane:

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/mcp` | JSON-RPC gateway (must remain for MCP clients) |

---

## Decision summary

| Question | Answer |
|----------|--------|
| Can critical enforcement move to Go? | **Yes** — sidecar or gateway for deterministic pipeline |
| Should `/mcp` become REST? | **No** — keep MCP JSON-RPC; add REST for ops/integrations |
| Is admin already REST? | **Yes** — FastAPI `/admin/*` and `/soc/*` |
| Full rewrite now? | **No** — prioritize Phase B, Sprint 4–5; profile first |
| Go or Rust? | Team choice; repo strategy names **Rust** for hot paths; **Go** is equally viable for the sidecar pattern |
| First slice? | Deterministic policy + trust/provenance evaluator behind `/v1/evaluate` |

---

## Quick links

| Task | Doc / command |
|------|----------------|
| Roadmap Phase E | [MCP_PROXY_ROADMAP.md](MCP_PROXY_ROADMAP.md) |
| Product strategy (native code triggers) | [ai-security-product-strategy.md](ai-security-product-strategy.md) |
| Regression after any gateway change | `bash tools/apply_mcp_proxy_phase_a5.sh` |
| Sprint E2E | [MCP_PROXY_SPRINT_TESTING.md](MCP_PROXY_SPRINT_TESTING.md) |
| Proxy source | `mcp-security-proxy/mcp_security_proxy/app.py` |
| Executor REST API | `mcp-isolated-executor/isolated_executor/app.py` |
