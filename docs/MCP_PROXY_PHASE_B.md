# Phase B — Phase 1 commercialization (MVP)

Phase B operationalizes **Core SKU** revenue readiness: 30-minute deploy story, named
execution-risk presets, usage metering / tier gating, and durable audit export.

**Prerequisites:** Phase A complete (or Profile C + proxy healthy).

Related:

- [MCP_PROXY_PRESETS.md](MCP_PROXY_PRESETS.md) — `core-*` preset matrix
- [MCP_PROXY_PHASE_A_COMPLETE.md](MCP_PROXY_PHASE_A_COMPLETE.md) — Phase A master guide
- [MCP_PROXY_ROADMAP.md](MCP_PROXY_ROADMAP.md) — Phase C (Sprint 4) next
- [MCP_PROXY_COMMERCIAL_PACKAGING.md](MCP_PROXY_COMMERCIAL_PACKAGING.md) — product tiers

---

## Phase B at a glance

| Workstream | Deliverable | Verify |
|------------|-------------|--------|
| **B1 Deploy UX** | `apply_mcp_proxy_phase_b.sh` | `Phase B deploy complete.` |
| **B2 Presets** | `core-observe`, `core-balanced`, `core-strict` | `CORE STRICT PRESET TEST PASSED` |
| **B3 Metering** | `/admin/usage`, `/admin/entitlements`, tier limits | `PHASE B METERING TEST PASSED` |
| **B4 Audit** | `/admin/audit-export`, persisted `data/runtime_history.json` | `PHASE B AUDIT BASELINE TEST PASSED` |
| **B5 Verify** | `test_mcp_proxy_phase_b.sh` | `PHASE B COMMERCIALIZATION PASSED` |

**Phase B is complete** when `bash tools/apply_mcp_proxy_phase_b.sh` finishes green (or
all B5 tests pass manually).

**Verification status:** [MCP_PROXY_VERIFICATION_STATUS.md](MCP_PROXY_VERIFICATION_STATUS.md)
— last Profile C run: `PHASE B COMMERCIALIZATION PASSED` (preset, metering, audit +
restart survival).

### Smoke test does not cover Phase B

`tools/smoke_mcp_proxy.sh` exercises Sprints 1–3, tool-intent, LLM risk, discovery, and
optional live executor — it does **not** run preset switches, metering/tier gates, or audit
export. After proxy or commercial-policy changes, run Phase B explicitly:

```bash
bash tools/test_mcp_proxy_phase_b.sh
```

For combined day-to-day validation (features + commercial):

```bash
bash tools/smoke_mcp_proxy.sh --with-isolated-executor && bash tools/test_mcp_proxy_phase_b.sh
```

Details: [MCP_PROXY_SMOKE_TEST.md — overlap with Phase A and B](MCP_PROXY_SMOKE_TEST.md#overlap-with-phase-a-and-phase-b).

---

## Greenfield: one-shot deploy (~30 minutes)

Run **one command per line**.

```bash
# 1) Set keys in repo .env before first Profile C start (see .env.example)
bash tools/apply_mcp_proxy_phase_b.sh

# Optional: strict preset + isolated executor
bash tools/apply_mcp_proxy_phase_b.sh --preset core-strict --with-executor
```

Manual equivalent:

```bash
bash tools/start-profile.sh C
bash tools/align_mcp_proxy_upstream_key.sh
bash tools/switch_mcp_policy_sample.sh core-balanced
bash tools/test_mcp_proxy_phase_b.sh
```

---

## Presets (B2)

Default after Phase B deploy: **`core-balanced`**.

```bash
bash tools/switch_mcp_policy_sample.sh core-balanced   # default MVP
bash tools/switch_mcp_policy_sample.sh core-strict     # strict execution-risk
bash tools/switch_mcp_policy_sample.sh core-observe   # trial / observe-only
```

Details: [MCP_PROXY_PRESETS.md](MCP_PROXY_PRESETS.md).

---

## Metering and entitlements (B3)

Policy `commercial` block (see preset JSON files). Environment overrides:

| Variable | Purpose |
|----------|---------|
| `MCP_PROXY_TIER` | Override tier (`trial`, `core`, `enterprise`) |
| `MCP_PROXY_LICENSE_KEY` | License key string (reported in entitlements) |
| `MCP_PROXY_USAGE_COUNTERS_FILE` | Daily counter file (default: `data/usage_counters.json`) |

Endpoints:

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/admin/usage` | Daily counters + limits |
| GET | `/admin/entitlements` | Tier, features, webhook config |

Prometheus: `mcp_security_proxy_usage_total{tier,kind}`,
`mcp_security_proxy_tier_limit_total{tier,kind,enforcement}`.

**Feature gates (Core tier):**

- `policy_bundles` → `403` on `/admin/apply-policy-bundle` (Enterprise in Sprint 4)

---

## Audit baseline (B4)

Runtime history persists to **`mcp-security-proxy/data/runtime_history.json`**
(mounted via `./data:/app/data` in compose).

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/admin/audit-export?format=json` | Full audit payload |
| GET | `/admin/audit-export?format=ndjson` | NDJSON event stream |

Optional deny webhook: set in policy:

```json
"commercial": {
  "webhook": {
    "enabled": true,
    "url": "https://your-siem.example/hooks/mcp-deny",
    "on_deny": true,
    "timeout_seconds": 5
  }
}
```

Restart survival test restarts `mcp-security-proxy` container and verifies export
still contains denied events.

---

## Verification (B5)

```bash
bash tools/test_mcp_proxy_phase_b.sh
bash tools/test_mcp_proxy_preset_core_strict.sh
bash tools/test_mcp_proxy_phase_b_metering.sh
bash tools/test_mcp_proxy_phase_b_audit.sh
```

Skip audit restart (no docker restart):

```bash
bash tools/test_mcp_proxy_phase_b.sh --skip-audit
```

Unit tests:

```bash
cd mcp-security-proxy && python -m pytest tests/test_app.py -q -k "usage or audit or policy_bundle or tier_limit"
```

---

## Environment (.env)

See `mcp-security-proxy/.env.example` for Core MVP variables. Before Profile C:

```bash
export MCP_API_KEY='<shared-secret>'
export MCP_PROXY_API_KEY="${MCP_API_KEY}"
```

---

## After Phase B

| Priority | Focus |
|----------|--------|
| Operate | `core-balanced` or `core-strict`, UI at `http://localhost:8090/ui` |
| Sprint 4 | SSO/RBAC, policy versioning, signed bundles, compliance audit |
| Sprint 5 | SIEM/SOAR connectors, HA, metering at scale |

---

## Troubleshooting

### Empty policy editor in UI

Policy is usually still on disk and via API; the UI failed auth before loading the editor.

```bash
bash tools/mcp_api_key.sh --proxy   # paste into Admin bearer token at http://localhost:8090/ui → Refresh
```

See [MCP_PROXY_OPERATE_UI_AND_PRESETS.md](MCP_PROXY_OPERATE_UI_AND_PRESETS.md).

### `jq: parse error` on policy reload

The proxy may return a non-JSON body briefly after container recreate. Retry:

```bash
bash tools/switch_mcp_policy_sample.sh core-balanced
```

`switch_mcp_policy_sample.sh` retries reload up to 5 times. If it persists, check proxy logs:

```bash
docker logs mcp-security-proxy --tail 50
```

### `tier_limit_exceeded` during tests

Restore limits or switch preset:

```bash
bash tools/switch_mcp_policy_sample.sh core-balanced
```

### Audit restart test fails

Ensure `mcp-security-proxy` container name and `./data` volume mount:

```bash
docker inspect mcp-security-proxy --format '{{json .Mounts}}' | jq
```

### Policy bundle 403

Expected on **Core** tier. Enable `commercial.features.policy_bundles: true` only for
enterprise trials (Sprint 4 adds formal RBAC).

---

## Quick links

| Task | Command |
|------|---------|
| Deploy Phase B | `bash tools/apply_mcp_proxy_phase_b.sh` |
| Verify Phase B | `bash tools/test_mcp_proxy_phase_b.sh` |
| Presets doc | [MCP_PROXY_PRESETS.md](MCP_PROXY_PRESETS.md) |
| Phase A regression | `bash tools/apply_mcp_proxy_phase_a5.sh` |
