# MCP Security Proxy — UI re-auth, policy load, and preset choice

Operator runbook for day-to-day use after Phase B and Phase C: authenticate the
standalone UI, confirm policy is loading, and choose between **`core-balanced`**
and **`sprint-4-governance`**.

Related:

- [MCP_PROXY_PRESETS.md](MCP_PROXY_PRESETS.md) — Core MVP preset matrix
- [MCP_PROXY_PHASE_C.md](MCP_PROXY_PHASE_C.md) — Sprint 4 governance APIs
- [MCP_PROXY_VERIFICATION_STATUS.md](MCP_PROXY_VERIFICATION_STATUS.md) — test matrix
- UI: `http://localhost:8090/ui`

---

## Quick start (three steps)

Run **one command per line**.

```bash
# 1) Resolve the live admin bearer token
bash tools/mcp_api_key.sh --proxy

# 2) (Optional) Confirm API returns policy before opening the UI
curl -s -H "Authorization: Bearer $(bash tools/mcp_api_key.sh --proxy)" \
  http://localhost:8090/admin/policy-config | jq '.status, .summary'

# 3) Open UI, paste token, refresh
open http://localhost:8090/ui
```

In the UI toolbar:

1. Paste the full value into **Admin bearer token**
2. Click **Refresh**
3. Open **Policy Management** — the editor should show full JSON (not `{}` or auth hints)

---

## 1. Re-auth the UI

### Get the admin key

```bash
bash tools/mcp_api_key.sh --proxy
```

This resolves `MCP_PROXY_API_KEY` from repo `.env` / compose (local default is often
`mcp_proxy_local_demo_change_me` unless overridden).

### Browser steps

1. Open http://localhost:8090/ui
2. Hard refresh once (`Cmd+Shift+R` / `Ctrl+Shift+R`) to load the latest UI scripts
3. Paste the token into **Admin bearer token**
4. Click **Refresh**

### If auth still fails

| Symptom | Fix |
|---------|-----|
| Empty policy editor after Refresh | Stale token in browser storage — DevTools → Application → Local Storage → delete `mcpProxyUiApiKey`, re-paste token |
| `Unauthorized` in result panel | Token does not match running proxy — re-run `bash tools/mcp_api_key.sh --proxy` |
| `tools/list` invalid token (MCP path) | Upstream key drift — `bash tools/align_mcp_proxy_upstream_key.sh` (separate from UI admin key) |
| Proxy recreated / key aligned | UI keeps old bearer in `localStorage` — always re-paste after `align_mcp_proxy_upstream_key.sh` |

### Why governance preset needs re-auth

With **`sprint-4-governance`**, `governance.enabled: true` enforces auth on admin
routes. Empty or wrong bearer → `401` on `/admin/policy-config`. The policy file on
disk is unchanged; only the UI session is invalid.

Use the **admin** key (`MCP_PROXY_API_KEY`) in the UI — not operator/auditor demo tokens
unless you are testing RBAC flows intentionally.

---

## 2. Confirm policy loads

### In the UI

After re-auth and **Refresh**:

- **Policy Management** → editor shows formatted JSON
- Method / denied-tool counts update in the policy panel
- Bottom **result** panel shows `"status": "ok"` from policy-config

### From the terminal

```bash
curl -s -H "Authorization: Bearer $(bash tools/mcp_api_key.sh --proxy)" \
  http://localhost:8090/admin/policy-config \
  | jq '.status, .summary, (.raw_policy | keys | length)'
```

Expect: `ok`, a summary with counts, and a non-zero key count (typically 15–20 on
Core/governance presets).

### Governance principal check (when on `sprint-4-governance`)

```bash
curl -s -H "Authorization: Bearer $(bash tools/mcp_api_key.sh --proxy)" \
  http://localhost:8090/admin/auth/me | jq '.principal'
```

Expect: `role: "admin"`, `auth_method: "api_key"`.

### Active preset check

```bash
curl -s -H "Authorization: Bearer $(bash tools/mcp_api_key.sh --proxy)" \
  http://localhost:8090/admin/policy-config \
  | jq '{
    tier: .raw_policy.commercial.tier,
    governance: .raw_policy.governance.enabled,
    denied_tools: (.raw_policy.denied_tools | length)
  }'
```

| Preset | Typical `tier` | `governance` |
|--------|----------------|--------------|
| `core-balanced` | `core` | `false` or absent |
| `sprint-4-governance` | `enterprise` | `true` |

---

## 3. Pick `core-balanced` vs `sprint-4-governance`

### Comparison

| | **core-balanced** | **sprint-4-governance** |
|--|-------------------|-------------------------|
| **Tier** | `core` | `enterprise` |
| **Enforcement** | Balanced challenge + Sprint 1 trust | Same base + governance layer |
| **RBAC** | Off — single API key = full admin | On — admin / operator / auditor tokens |
| **Policy writes (UI)** | Direct save | Operators → approval queue; admins approve |
| **Policy bundles** | Off on Core tier | On + optional signing |
| **Audit** | Phase B export (`/admin/audit-export`) | + hash chain (`/admin/audit-integrity`) |
| **UI friction** | Lower | Higher — admin key required; approvals for operators |
| **Best for** | Daily SOC lab, tuning, demos | Governance demos, RBAC/approval testing, compliance conversations |

### Recommendation

```text
Operate daily        → core-balanced     (less friction in policy editor)
Governance demos     → sprint-4-governance   (switch when testing Phase C)
Executor / staging   → sprint-3-a3-deny or sprint-3-executor   (Phase A ops)
```

### Switch presets

```bash
# Simpler day-to-day ops (Phase B default)
bash tools/switch_mcp_policy_sample.sh core-balanced

# Enterprise governance (Phase C)
bash tools/switch_mcp_policy_sample.sh sprint-4-governance
```

After switching: re-paste `bash tools/mcp_api_key.sh --proxy` in the UI and click
**Refresh**.

### Verify after switch

```bash
# After core-balanced
bash tools/test_mcp_proxy_phase_b.sh

# After sprint-4-governance
bash tools/test_mcp_proxy_phase_c.sh
```

---

## Weekly validation (after proxy or policy changes)

```bash
bash tools/smoke_mcp_proxy.sh --with-isolated-executor
bash tools/test_mcp_proxy_phase_b.sh
bash tools/test_mcp_proxy_phase_c.sh   # only when governance preset is active
```

Full release sign-off: `bash tools/apply_mcp_proxy_phase_a5.sh`

See [MCP_PROXY_SMOKE_TEST.md](MCP_PROXY_SMOKE_TEST.md) for smoke vs Phase A/B overlap.

---

## Sprint 4 demo secrets (rotate in production)

When using `sprint-4-governance`, replace lab values in policy or env:

| Item | Policy path / env |
|------|-------------------|
| Operator token | `governance.rbac.api_tokens` (demo: `mcp_proxy_operator_demo_change_me`) |
| Auditor token | `governance.rbac.api_tokens` (demo: `mcp_proxy_auditor_demo_change_me`) |
| Bundle signing | `governance.signing.signing_key` or `MCP_PROXY_POLICY_SIGNING_KEY` |
| OIDC JWT (lab) | `governance.oidc.jwt_secret` or `MCP_PROXY_OIDC_JWT_SECRET` |

---

## UI implementation note

The standalone UI (`mcp-security-proxy/mcp_security_proxy/ui/static/index.html`)
loads policy via `refreshPolicy()` even when other dashboard panels fail auth.
Invalid stored tokens are cleared with an in-editor hint. If the editor shows
auth instructions instead of policy, follow **Re-auth the UI** above.
