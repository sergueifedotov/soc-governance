# MCP Security Proxy — Sprint 1–3 testing (preparation and execution)

End-to-end verification for trust hardening (Sprint 1), containment / fail-safe
(Sprint 2), and isolated execution (Sprint 3). Tests run **without restarting**
Profile C once the stack is up.

For implementation status and roadmap phases, see [MCP_PROXY_ROADMAP.md](MCP_PROXY_ROADMAP.md).
For the **post-verification operator checklist** (persist executor policy, A2–A5,
stale telemetry, production), see [MCP_PROXY_NEXT_STEPS.md](MCP_PROXY_NEXT_STEPS.md).
Phase A2 runbook: [MCP_PROXY_PHASE_A2.md](MCP_PROXY_PHASE_A2.md).  
Phase A master guide (A1–A5): [MCP_PROXY_PHASE_A_COMPLETE.md](MCP_PROXY_PHASE_A_COMPLETE.md).
For one-command regression across all proxy features, see [MCP_PROXY_SMOKE_TEST.md](MCP_PROXY_SMOKE_TEST.md).

| Sprint | Design reference |
|--------|------------------|
| 1 | [MCP_PROXY_TRUST_HARDENING.md](MCP_PROXY_TRUST_HARDENING.md) |
| 2 | [MCP_PROXY_CONTAINMENT_FAILSAFE.md](MCP_PROXY_CONTAINMENT_FAILSAFE.md) |
| 3 | [MCP_PROXY_ISOLATED_EXECUTION.md](MCP_PROXY_ISOLATED_EXECUTION.md) |

---

## Policy templates (samples)

Sprint baselines live under **`config/phase4/mcp_proxy/`**:

| Profile | Alias | File |
|---------|-------|------|
| `sprint-1-trust-hardening` | `sprint-1` | `policy.sample.sprint-1-trust-hardening.json` |
| `sprint-2-containment-failsafe` | `sprint-2` | `policy.sample.sprint-2-containment-failsafe.json` |
| `sprint-3-isolated-execution` | `sprint-3` | `policy.sample.sprint-3-isolated-execution.json` |
| `sprint-3-executor-operational` | `sprint-3-executor` | `policy.sample.sprint-3-executor-operational.json` |
| `sprint-3-a2-operational` | `sprint-3-a2` | `policy.sample.sprint-3-a2-operational.json` |
| `sprint-3-a3-monitor` | `sprint-3-a3-monitor` | `policy.sample.sprint-3-a3-monitor.json` |
| `sprint-3-a3-challenge` | `sprint-3-a3-challenge` | `policy.sample.sprint-3-a3-challenge.json` |
| `sprint-3-a3-deny` | `sprint-3-a3-deny` | `policy.sample.sprint-3-a3-deny.json` |

Operational profiles: [MCP_PROXY_PHASE_A1_DEPLOY.md](MCP_PROXY_PHASE_A1_DEPLOY.md),
[MCP_PROXY_PHASE_A2.md](MCP_PROXY_PHASE_A2.md), [MCP_PROXY_PHASE_A3.md](MCP_PROXY_PHASE_A3.md).

The **active** policy file (mounted into the proxy container) is:

`config/phase4/mcp_proxy/policy.json` → `/app/phase4-config/policy.json`

Apply a sample to disk and reload the running proxy:

```bash
bash tools/switch_mcp_policy_sample.sh sprint-1   # or sprint-2, sprint-3
bash tools/switch_mcp_policy_sample.sh --list
```

Each `test_sprintN_no_restart.sh` wrapper also POSTs the matching sample via
`/admin/policy-config` at the start of the run (so tests do not depend on a stale
on-disk file).

---

## One-time environment preparation

Do this once per machine (or after wiping Docker volumes).

### 1. Repository and Python venv

```bash
cd /path/to/Wazuh-MCP-Neo4j-OCTI-Mon-C-6
python3 -m venv .venv
source .venv/bin/activate
pip install -r mcp-security-proxy/requirements.txt
pip install pytest   # if not already installed for unit-test steps
```

### 2. CLI tools

Ensure these are on `PATH`:

- `bash`, `curl`, `jq`
- `docker` (for key alignment, Sprint 2/3 symbol checks, `mcp_api_key.sh --proxy`)

### 3. Start Profile C (stack)

```bash
bash tools/start-profile.sh C
```

Wait until core containers are up:

```bash
docker ps --format 'table {{.Names}}\t{{.Status}}' | grep -E 'mcp-security-proxy|wazuh-mcp-server'
curl -s http://localhost:8090/health | jq .
```

Expected: `"status": "healthy"` and `upstream` pointing at Wazuh MCP (e.g.
`http://wazuh-mcp-server:3000/mcp`).

### 4. Align proxy upstream API key with Wazuh

The proxy uses **two** credentials:

| Credential | Used for |
|------------|----------|
| `MCP_PROXY_API_KEY` | Client → proxy (`/mcp`, `/admin/*`) |
| `MCP_PROXY_UPSTREAM_API_KEY` | Proxy → `wazuh-mcp-server` |

If they diverge, admin calls work but `tools/list` returns
`{"detail":"Invalid or expired token"}`.

**Check:**

```bash
docker exec mcp-security-proxy printenv MCP_PROXY_UPSTREAM_API_KEY
docker exec wazuh-mcp-server printenv MCP_API_KEY
```

**Fix (recreates proxy with Wazuh’s key):**

```bash
bash tools/align_mcp_proxy_upstream_key.sh
```

**Durable fix:** set `MCP_API_KEY` in repo `.env` to the same value Wazuh uses
*before* starting compose, so both services get the same key at create time.

### 5. Rebuild proxy after code changes (when needed)

If Sprint 2/3 scripts report missing symbols in the container:

```bash
cd mcp-security-proxy
docker compose -f docker-compose.yml -f docker-compose.phase4.yml build mcp-security-proxy
docker compose -f docker-compose.yml -f docker-compose.phase4.yml up -d mcp-security-proxy
```

### 6. Export proxy bearer token (optional)

Wrappers resolve this automatically; for manual `curl`:

```bash
export MCP_PROXY_API_KEY="$(tools/mcp_api_key.sh --proxy)"
```

Use **`--proxy`** only for proxy endpoints. Do not use the Wazuh `MCP_API_KEY`
for `/admin/policy-config` unless it happens to match the proxy token.

---

## Shared test mechanics

| Helper | Role |
|--------|------|
| [tools/mcp_proxy_test_common.sh](../tools/mcp_proxy_test_common.sh) | Auth, upstream preflight, policy sample apply, key alignment check |
| [tools/mcp_api_key.sh](../tools/mcp_api_key.sh) | `--proxy` resolves live proxy bearer |
| [tools/align_mcp_proxy_upstream_key.sh](../tools/align_mcp_proxy_upstream_key.sh) | Recreate proxy with matching upstream key |

Each gate script:

1. `GET /admin/policy-config` → snapshot
2. `POST /admin/policy-config` → test policy
3. `POST /mcp` → exercise control
4. Assert `/recent-denied` and `/recent-discovery-alerts`
5. Restore snapshot on exit (`trap`)

Clear discovery cooldown before each case (scripts call
`POST /admin/clear-discovery-alerts` with `{"reset_cooldown":true}`).

**UI (optional):** `http://localhost:8090/ui` → **Tuning Studio** → **Evidence and
Decisions** (not the Phase 4 SOC UI on `:8082`).

---

## Consolidated smoke (all implemented proxy features)

**Full documentation:** [MCP_PROXY_SMOKE_TEST.md](MCP_PROXY_SMOKE_TEST.md) — prerequisites,
execution order, every check name, CLI flags, SOC bridge (HTTP 410), policy side effects,
troubleshooting, and CI examples.

Quick start:

```bash
bash tools/start-profile.sh C
bash tools/align_mcp_proxy_upstream_key.sh
bash tools/smoke_mcp_proxy.sh
```

With live executor: `bash tools/start_isolated_executor.sh` then
`bash tools/smoke_mcp_proxy.sh --with-isolated-executor`.

---

## Sprint 1 — Trust hardening

### What is verified

| Control | Deny reason (example) | Discovery signal |
|---------|----------------------|------------------|
| `trusted_servers` | `untrusted_server` | `untrusted_server_calls` |
| `tool_descriptor_hashes` | `descriptor_drift` | `descriptor_drift_events` |
| `execution_tool_profile` | `execution_tool_blocked` | `execution_tool_attempts` |

### Preparation (before run)

```bash
# Stack + keys (see one-time prep above)
bash tools/start-profile.sh C
bash tools/align_mcp_proxy_upstream_key.sh

# Optional: apply sprint-1 sample to disk (wrapper applies it anyway)
bash tools/switch_mcp_policy_sample.sh sprint-1
```

### Execution

**All-in-one (recommended):**

```bash
source .venv/bin/activate
bash tools/test_sprint1_no_restart.sh
```

Fast iteration (skip pytest):

```bash
bash tools/test_sprint1_no_restart.sh --skip-unit-tests
```

**Wrapper steps:**

| Step | Action |
|------|--------|
| Preflight | Apply `policy.sample.sprint-1-trust-hardening.json` |
| Preflight | Verify upstream API keys match |
| Preflight | Ping upstream via proxy |
| 1/5 | `test_trusted_servers.sh` |
| 2/5 | `test_descriptor_drift.sh` |
| 3/5 | `test_execution_tool_profile.sh` |
| 4/5 | `pytest mcp-security-proxy/tests/test_app.py` (optional) |
| 5/5 | Telemetry summary |

**Individual gates:**

```bash
bash tools/test_trusted_servers.sh
bash tools/test_descriptor_drift.sh
# optional: DRIFT_TARGET_TOOL=get_wazuh_alerts bash tools/test_descriptor_drift.sh
bash tools/test_execution_tool_profile.sh
```

### Expected success output

Terminal ends with:

```text
SPRINT 1 VERIFICATION PASSED
```

Each sub-script ends with `ALL … CHECKS PASSED`.

### Sprint 1 troubleshooting

| Symptom | Fix |
|---------|-----|
| `Invalid or expired token` on `tools/list` | `bash tools/align_mcp_proxy_upstream_key.sh` |
| Descriptor drift fails with `untrusted_server` | Re-run wrapper (applies sprint-1 baseline) or `switch_mcp_policy_sample.sh sprint-1` |
| Trusted-server test leaves bad `trusted_servers` | Re-run sprint-1 wrapper; each script restores policy on exit |

---

## Sprint 2 — Containment and fail-safe

### What is verified

| Control | Deny reason (example) | Discovery signal |
|---------|----------------------|------------------|
| `sandbox_attestation_profile` | `sandbox_attestation_missing` | `sandbox_attestation_failures` |
| `dependency_fail_safe_profile` | `dependency_health_failed` | `dependency_health_failures` |

### Preparation (before run)

```bash
bash tools/start-profile.sh C
bash tools/align_mcp_proxy_upstream_key.sh

# Sprint 2 code must be in the running image (rebuild if preflight fails)
cd mcp-security-proxy
docker compose -f docker-compose.yml -f docker-compose.phase4.yml build mcp-security-proxy
docker compose -f docker-compose.yml -f docker-compose.phase4.yml up -d mcp-security-proxy
cd ..

bash tools/switch_mcp_policy_sample.sh sprint-2   # optional; wrapper applies sample
```

### Execution

```bash
source .venv/bin/activate
bash tools/test_sprint2_no_restart.sh
# or
bash tools/test_sprint2_no_restart.sh --skip-unit-tests
```

**Wrapper steps:**

| Step | Action |
|------|--------|
| Preflight | Apply `policy.sample.sprint-2-containment-failsafe.json` |
| Preflight | Upstream API key alignment |
| Preflight | `/health` |
| 1/4 | `test_sandbox_attestation.sh` |
| 2/4 | `test_dependency_fail_safe.sh` |
| 3/4 | pytest (optional) |
| 4/4 | Telemetry summary |

**Sandbox test isolation:** the script enables sandbox attestation deny on
`shell_exec`, disables `tool_intent.enforce`, and sets
`execution_tool_profile.enabled=false` so Sprint 1 does not return
`execution_tool_blocked` before attestation is evaluated.

**Dependency test:** uses non-execution tool `wazuh_lookup_alert`, unreachable
`llm_risk.base_url`, and `dependency_fail_safe_profile` deny.

**Individual gates:**

```bash
bash tools/test_sandbox_attestation.sh
bash tools/test_dependency_fail_safe.sh
```

### Expected success output

```text
ALL SANDBOX ATTESTATION CHECKS PASSED.
ALL DEPENDENCY FAIL-SAFE CHECKS PASSED.
SPRINT 2 VERIFICATION PASSED
```

### Sprint 2 troubleshooting

| Symptom | Fix |
|---------|-----|
| Expected `sandbox_attestation_missing`, got `execution_tool_blocked` | Fixed in `test_sandbox_attestation.sh` (disables `execution_tool_profile` for the case); pull latest script |
| `llm_intent_challenge` instead of sandbox/dependency reason | Rebuild proxy; ensure sub-script policy patch ran |
| Script exits: Sprint 2 symbol missing | Rebuild `mcp-security-proxy` image (see preparation) |

---

## Sprint 3 — Isolated execution and provenance

### What is verified

| Script | Focus | Typical deny / signal |
|--------|--------|------------------------|
| `test_isolated_executor.sh` | Executor unreachable | `isolated_executor_*` |
| `test_runtime_limits.sh` | CPU/memory caps | Runtime limit denies |
| `test_filesystem_restrictions.sh` | Path allowlist | Filesystem violation denies |
| `test_upstream_provenance.sh` | Egress allow/block lists | `upstream_dest_blocked` / provenance |

### Preparation (before run)

```bash
bash tools/start-profile.sh C
bash tools/align_mcp_proxy_upstream_key.sh

cd mcp-security-proxy
docker compose -f docker-compose.yml -f docker-compose.phase4.yml build mcp-security-proxy
docker compose -f docker-compose.yml -f docker-compose.phase4.yml up -d mcp-security-proxy
cd ..

bash tools/switch_mcp_policy_sample.sh sprint-3   # optional; wrapper applies sample
```

Sprint 3 E2E tests often use **mock/unreachable executor URLs** in policy for deny-path
cases. For a **live executor** (Phase A1), see [MCP_PROXY_PHASE_A1_DEPLOY.md](MCP_PROXY_PHASE_A1_DEPLOY.md):

```bash
bash tools/start-profile.sh C
bash tools/align_mcp_proxy_upstream_key.sh
bash tools/start_isolated_executor.sh
bash tools/deploy_isolated_executor_a1.sh
bash tools/test_isolated_executor_live.sh
```

Policy profile: `bash tools/switch_mcp_policy_sample.sh sprint-3-executor`

**Understanding test output:** [MCP_PROXY_PHASE_A1_DEPLOY.md](MCP_PROXY_PHASE_A1_DEPLOY.md)
— section *Interpreting isolated executor test results* (explains `runtime_info`,
`output: "executor"`, and the `WARN` about stale `/recent-denied` entries).

### Execution

```bash
source .venv/bin/activate
bash tools/test_sprint3_no_restart.sh
# or
bash tools/test_sprint3_no_restart.sh --skip-unit-tests
```

**Wrapper steps:**

| Step | Action |
|------|--------|
| Preflight | Apply `policy.sample.sprint-3-isolated-execution.json` |
| Preflight | Upstream API key alignment |
| Preflight | `/health` |
| Preflight | Python symbol check in `mcp-security-proxy` container |
| 1/6 | `test_isolated_executor.sh` |
| 2/6 | `test_runtime_limits.sh` |
| 3/6 | `test_filesystem_restrictions.sh` |
| 4/6 | `test_upstream_provenance.sh` |
| 5/6 | pytest subset (optional) |
| 6/6 | Telemetry summary |

Pass `--proxy-base-url` to sub-scripts via the wrapper’s `PROXY_BASE_URL` export.

### Expected success output

```text
SPRINT 3 VERIFICATION PASSED
```

(Sub-scripts print their own `PASS` lines.)

### Sprint 3 troubleshooting

| Symptom | Fix |
|---------|-----|
| Sprint 3 symbols not found | Rebuild and recreate proxy container |
| Unrelated deny reasons | Ensure sprint-3 baseline applied; check script policy patch |

### After Sprint 3 verification passes

Sprint wrappers restore your previous policy on exit. For day-to-day executor routing
and Phase A follow-up (persist policy, live deploy, A2–A5, production), see
[MCP_PROXY_NEXT_STEPS.md](MCP_PROXY_NEXT_STEPS.md).

After Phase A1 (live executor), apply Phase A2:

```bash
bash tools/apply_mcp_proxy_phase_a2.sh
```

Details: [MCP_PROXY_PHASE_A2.md](MCP_PROXY_PHASE_A2.md). Then Phase A3:

```bash
bash tools/apply_mcp_proxy_phase_a3.sh
```

Details: [MCP_PROXY_PHASE_A3.md](MCP_PROXY_PHASE_A3.md).

---

## Full regression sequence (Sprints 1 → 3)

Run in order after one-time prep:

```bash
cd /path/to/Wazuh-MCP-Neo4j-OCTI-Mon-C-6
source .venv/bin/activate

bash tools/align_mcp_proxy_upstream_key.sh

bash tools/test_sprint1_no_restart.sh --skip-unit-tests
bash tools/test_sprint2_no_restart.sh --skip-unit-tests
bash tools/test_sprint3_no_restart.sh --skip-unit-tests

# Optional: full unit suite once
.venv/bin/python -m pytest mcp-security-proxy/tests/test_app.py -q
```

Approximate time: a few minutes per sprint (LLM-backed policy may add latency if
not disabled in test patches).

---

## Manual verification (curl)

After any sprint run:

```bash
export MCP_PROXY_API_KEY="$(tools/mcp_api_key.sh --proxy)"

curl -sS -H "Authorization: Bearer $MCP_PROXY_API_KEY" \
  "http://localhost:8090/recent-denied?limit=50" | jq .

curl -sS -H "Authorization: Bearer $MCP_PROXY_API_KEY" \
  "http://localhost:8090/recent-discovery-alerts?limit=50" | jq .
```

---

## Evidence capture (audits / demos)

Archive per sprint:

1. Full terminal log from `test_sprintN_no_restart.sh`
2. JSON snapshots of `/recent-denied` and `/recent-discovery-alerts` (above)
3. Screenshot of `http://localhost:8090/ui` → Evidence and Decisions
4. Note active policy: `GET /admin/policy-config` (requires bearer token)

---

## Unit tests (all sprints)

```bash
.venv/bin/python -m pytest mcp-security-proxy/tests/test_app.py -q
```

Sprint-focused cases are listed in each sprint design doc.

---

## Quick reference — commands only

```bash
# Prep
bash tools/start-profile.sh C
bash tools/align_mcp_proxy_upstream_key.sh

# Policy samples (optional)
bash tools/switch_mcp_policy_sample.sh sprint-{1,2,3}

# Execute
bash tools/test_sprint1_no_restart.sh [--skip-unit-tests]
bash tools/test_sprint2_no_restart.sh [--skip-unit-tests]
bash tools/test_sprint3_no_restart.sh [--skip-unit-tests]
```
