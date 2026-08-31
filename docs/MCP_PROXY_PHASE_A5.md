# Phase A5 — Regression validation (runbook)

Operator runbook for **roadmap Phase A5**: run end-to-end regression after Phases
**A1–A4** without restarting Profile C.

Related:

- [MCP_PROXY_PHASE_A_COMPLETE.md](MCP_PROXY_PHASE_A_COMPLETE.md) — **master guide (A1–A5, performance, next steps)**
- [MCP_PROXY_PHASE_A4.md](MCP_PROXY_PHASE_A4.md) — keys (run before A5 if drift suspected)
- [MCP_PROXY_SPRINT_TESTING.md](MCP_PROXY_SPRINT_TESTING.md) — sprint test details
- [MCP_PROXY_SMOKE_TEST.md](MCP_PROXY_SMOKE_TEST.md) — consolidated smoke catalog
- [MCP_PROXY_NEXT_STEPS.md](MCP_PROXY_NEXT_STEPS.md) — after Phase A

---

## What was implemented

| Component | Location | Purpose |
|-----------|----------|---------|
| Test script | `tools/test_mcp_proxy_phase_a5.sh` | Sprint 1–3 + optional pytest, live, smoke |
| Apply script | `tools/apply_mcp_proxy_phase_a5.sh` | Wrapper with optional key align |
| Sprint wrappers | `tools/test_sprint{1,2,3}_no_restart.sh` | Per-sprint gates (called by A5) |
| Consolidated smoke | `tools/smoke_mcp_proxy.sh` | Optional full feature smoke |
| Live check | `tools/test_isolated_executor_live.sh` | Executor routing under deny policy |

---

## Prerequisites

1. **Profile C** running (`mcp-security-proxy`, `wazuh-mcp-server`).
2. **Phases A1–A4** complete (executor, A2 policy, A3 deny stage, aligned keys).
3. **Recommended:** `isolated-executor` running for live test.
4. **CLI:** `bash`, `curl`, `jq`, `docker`; `.venv` for optional pytest.

Quick preflight:

```bash
bash tools/test_mcp_proxy_phase_a4.sh
```

---

## Quick start

**Fast regression** (default — sprint E2E, skip per-sprint pytest, live executor, restore policy):

```bash
bash tools/apply_mcp_proxy_phase_a5.sh
```

Equivalent:

```bash
bash tools/test_mcp_proxy_phase_a5.sh
```

**Full regression** (sprint unit tests + pytest + smoke):

```bash
bash tools/apply_mcp_proxy_phase_a5.sh --full --with-unit-tests --with-smoke
```

**Smoke only:**

```bash
bash tools/test_mcp_proxy_phase_a5.sh --smoke-only --with-smoke
```

---

## What the default run does

| Step | Action |
|------|--------|
| 1 | `test_mcp_proxy_phase_a4.sh` — key alignment preflight |
| 2 | `test_sprint1_no_restart.sh --skip-unit-tests` |
| 3 | `test_sprint2_no_restart.sh --skip-unit-tests` |
| 4 | `test_sprint3_no_restart.sh --skip-unit-tests` |
| 5 | `test_isolated_executor_live.sh` (if `isolated-executor` up) with `sprint-3-a3-deny` policy |
| 6 | `switch_mcp_policy_sample.sh sprint-3-a3-deny` — restore operational policy |
| 7 | Telemetry snapshot from `/recent-denied` |

Sprint scripts **temporarily** apply sprint baselines and restore prior policy on exit.
A5 **re-applies** `sprint-3-a3-deny` at the end for day-to-day operation.

---

## Options reference

### `test_mcp_proxy_phase_a5.sh`

| Flag | Effect |
|------|--------|
| `--skip-a4-preflight` | Skip embedded A4 checks |
| `--full` | Run pytest inside each sprint script |
| `--with-unit-tests` | Run `pytest mcp-security-proxy/tests/test_app.py` once after sprints |
| `--with-smoke` | Also run `smoke_mcp_proxy.sh --with-isolated-executor` |
| `--smoke-only` | Skip sprint 1–3; smoke only |
| `--skip-live-executor` | Skip live executor test |
| `--no-restore-policy` | Do not switch policy at end |
| `--restore-policy NAME` | Policy alias to restore (default: `sprint-3-a3-deny`) |

### `apply_mcp_proxy_phase_a5.sh`

| Flag | Effect |
|------|--------|
| `--align-keys-first` | Run `align_mcp_proxy_upstream_key.sh` before tests |
| (pass-through) | All `test_mcp_proxy_phase_a5.sh` flags above |

---

## Completion criteria

Phase A5 is **complete** when:

```bash
bash tools/apply_mcp_proxy_phase_a5.sh
```

exits 0 with:

- `SPRINT 1 VERIFICATION PASSED`
- `SPRINT 2 VERIFICATION PASSED`
- `SPRINT 3 VERIFICATION PASSED`
- `PASS: live isolated executor integration` (if executor running)
- `PHASE A5 REGRESSION VALIDATION PASSED`

Then review **http://localhost:8090/ui** → Tuning Studio → Evidence and Decisions.

---

## Manual regression (equivalent)

```bash
bash tools/test_mcp_proxy_phase_a4.sh

bash tools/test_sprint1_no_restart.sh --skip-unit-tests
bash tools/test_sprint2_no_restart.sh --skip-unit-tests
bash tools/test_sprint3_no_restart.sh --skip-unit-tests

POLICY_FILE=config/phase4/mcp_proxy/policy.sample.sprint-3-a3-deny.json \
  bash tools/test_isolated_executor_live.sh

bash tools/switch_mcp_policy_sample.sh sprint-3-a3-deny
```

---

## Why A5 takes a long time (default run)

Default `apply_mcp_proxy_phase_a5.sh` runs **A4 + Sprint 1 + Sprint 2 + Sprint 3 + live
executor** — typically **~5–15 minutes**.

Main reasons:

1. **Three sprint suites**, each with policy apply, key checks, and multiple sub-gates.
2. **Many policy snapshot/restore cycles** (`GET`/`POST /admin/policy-config`).
3. **Repeated `tools/list` / ping** through proxy → Wazuh (A4 + Sprint 1 drift tests).
4. **LLM latency** — `llm_risk` and `tool_intent` stay enabled; each `tools/call` can
   hit two model calls (up to 5s each) before routing, including live `whoami`.

Full explanation and faster options:
[MCP_PROXY_PHASE_A_COMPLETE.md — why A5 is slow](MCP_PROXY_PHASE_A_COMPLETE.md#why-phase-a5-takes-a-long-time).

```bash
bash tools/test_mcp_proxy_phase_a5.sh --skip-a4-preflight --skip-live-executor
bash tools/test_sprint3_no_restart.sh --skip-unit-tests
```

---

## Troubleshooting

### A4 preflight fails

```bash
bash tools/align_mcp_proxy_upstream_key.sh
bash tools/test_mcp_proxy_phase_a4.sh
```

Or skip embedded check: `bash tools/test_mcp_proxy_phase_a5.sh --skip-a4-preflight`

### Sprint test fails on policy

Re-apply sprint baseline for that sprint (see [MCP_PROXY_SPRINT_TESTING.md](MCP_PROXY_SPRINT_TESTING.md)),
then re-run A5.

### Live executor skipped

```bash
bash tools/start_isolated_executor.sh
bash tools/test_mcp_proxy_phase_a5.sh --skip-a4-preflight
```

### Long runtime

Use fast default (no `--full`, no `--with-smoke`). Smoke duplicates sprint coverage.

---

## After Phase A5

Phase **A (operationalize Sprint 3)** is complete when A1–A5 all pass.

**Next steps (operate, prod hardening, Phase B, Sprint 4–5):**
[MCP_PROXY_PHASE_A_COMPLETE.md — what to do next](MCP_PROXY_PHASE_A_COMPLETE.md#what-to-do-next-after-phase-a).

Next roadmap items:

- **Phase B** — MVP commercialization ([MCP_PROXY_ROADMAP.md](MCP_PROXY_ROADMAP.md))
- **Sprint 4–5** — SSO/RBAC, audit export, SIEM/HA

Continue monitoring denies and tuning in the proxy UI.

---

## Files reference

| Path | Description |
|------|-------------|
| `tools/apply_mcp_proxy_phase_a5.sh` | A5 apply wrapper |
| `tools/test_mcp_proxy_phase_a5.sh` | A5 regression suite |
| `tools/smoke_mcp_proxy.sh` | Optional consolidated smoke |
| `docs/MCP_PROXY_SMOKE_TEST.md` | Smoke catalog |
