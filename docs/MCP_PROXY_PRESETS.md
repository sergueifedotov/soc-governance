# MCP Security Proxy — Core MVP presets (Phase B)

Named policy presets for **Phase 1 commercialization** (Core SKU). Apply with:

```bash
bash tools/switch_mcp_policy_sample.sh <preset>
```

Phase B default deploy preset: **`core-balanced`**.

---

## Preset matrix

| Preset | Tier | Enforcement | Trust (Sprint 1) | Best for |
|--------|------|-------------|-------------------|----------|
| **core-observe** | `trial` | Monitor-only LLM/tool-intent (`enforce: false`) | Light | Evaluation, tuning lab |
| **core-balanced** | `core` | Balanced challenge patterns + trust deny | Full Sprint 1 trust | **Default paid team MVP** |
| **core-strict** | `core` | Pattern-first **deny** + execution-tool deny | Full Sprint 1 trust | High-risk / strict execution posture |

Policy files:

| Alias | File |
|-------|------|
| `core-observe` | `config/phase4/mcp_proxy/policy.sample.core-observe.json` |
| `core-balanced`, `core-mvp` | `config/phase4/mcp_proxy/policy.sample.core-balanced.json` |
| `core-strict` | `config/phase4/mcp_proxy/policy.sample.core-strict.json` |

---

## Commercial block (all Core presets)

Each preset includes a `commercial` section:

- **Tier** — `trial` | `core` | `enterprise` (override with `MCP_PROXY_TIER`)
- **Limits** — daily MCP / LLM / tool-intent caps (`0` = unlimited)
- **Features** — `policy_bundles`, `webhook_export`, `discovery_advanced`, etc.
- **Webhook** — optional deny notifications (`commercial.webhook`)

Admin APIs:

```bash
curl -s -H "Authorization: Bearer $(bash tools/mcp_api_key.sh --proxy)" \
  http://localhost:8090/admin/usage | jq

curl -s -H "Authorization: Bearer $(bash tools/mcp_api_key.sh --proxy)" \
  http://localhost:8090/admin/entitlements | jq
```

**Limit behavior:**

- `trial` — over limit → **monitor** (logged, request continues)
- `core` / `enterprise` — over limit → **deny** (`tier_limit_exceeded`)

---

## Verification

```bash
bash tools/test_mcp_proxy_preset_core_strict.sh
bash tools/test_mcp_proxy_phase_b.sh
```

Status log: [MCP_PROXY_VERIFICATION_STATUS.md](MCP_PROXY_VERIFICATION_STATUS.md).

---

## `core-balanced` vs `sprint-4-governance` (operate)

| | **core-balanced** | **sprint-4-governance** |
|--|-------------------|-------------------------|
| Phase | B (Core MVP) | C (Sprint 4) |
| Tier | `core` | `enterprise` |
| RBAC | Off | On |
| Policy UI writes | Direct | Approval workflow for operators |
| Default use | **Daily SOC lab / tuning** | Governance demos / Phase C tests |

```bash
bash tools/switch_mcp_policy_sample.sh core-balanced
bash tools/switch_mcp_policy_sample.sh sprint-4-governance
```

Full UI re-auth and verification steps:
[MCP_PROXY_OPERATE_UI_AND_PRESETS.md](MCP_PROXY_OPERATE_UI_AND_PRESETS.md).

---

## Related

- [MCP_PROXY_OPERATE_UI_AND_PRESETS.md](MCP_PROXY_OPERATE_UI_AND_PRESETS.md) — UI auth + preset choice
- [MCP_PROXY_PHASE_B.md](MCP_PROXY_PHASE_B.md) — full Phase B runbook
- [MCP_PROXY_PHASE_C.md](MCP_PROXY_PHASE_C.md) — Sprint 4 governance
- [MCP_PROXY_COMMERCIAL_PACKAGING.md](MCP_PROXY_COMMERCIAL_PACKAGING.md) — tier matrix
- [MCP_PROXY_ROADMAP.md](MCP_PROXY_ROADMAP.md) — Phase B status
