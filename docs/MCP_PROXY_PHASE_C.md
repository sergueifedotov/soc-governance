# Phase C — Sprint 4 (enterprise control plane)

Sprint 4 adds **enterprise governance**: RBAC on admin routes, policy versioning and
approval workflow, signed policy bundles, and a tamper-evident audit hash chain.

**Prerequisites:** Phase B complete (or Profile C + proxy healthy).

Related:

- [MCP_PROXY_PHASE_B.md](MCP_PROXY_PHASE_B.md) — Core MVP commercialization
- [MCP_PROXY_ROADMAP.md](MCP_PROXY_ROADMAP.md) — Phase D (Sprint 5) next
- [MCP_PROXY_VERIFICATION_STATUS.md](MCP_PROXY_VERIFICATION_STATUS.md) — verification matrix

---

## Phase C at a glance

| Workstream | Deliverable | Verify |
|------------|-------------|--------|
| **C1 RBAC** | Role-scoped API tokens (`admin`, `operator`, `auditor`) | `PHASE C RBAC TEST PASSED` |
| **C2 Policy lifecycle** | Versions, proposals, approval, rollback | `PHASE C POLICY LIFECYCLE TEST PASSED` |
| **C3 Signed bundles** | HMAC-SHA256 sign + verify on apply | Lifecycle test (signed dry-run) |
| **C4 Audit integrity** | Hash chain on denied/decision events | `PHASE C AUDIT INTEGRITY TEST PASSED` |
| **C5 OIDC stub** | HS256 JWT validation + config endpoint | Unit tests + `/admin/auth/oidc/config` |
| **C6 Verify** | `test_mcp_proxy_phase_c.sh` | `PHASE C SPRINT 4 GOVERNANCE PASSED` |

---

## Greenfield apply

Run **one command per line**:

```bash
bash tools/start-profile.sh C
bash tools/align_mcp_proxy_upstream_key.sh
bash tools/apply_mcp_proxy_phase_c.sh
```

Manual equivalent:

```bash
bash tools/switch_mcp_policy_sample.sh sprint-4-governance
bash tools/test_mcp_proxy_phase_c.sh
```

Policy sample: `config/phase4/mcp_proxy/policy.sample.sprint-4-governance.json`

---

## Governance policy block

```json
"governance": {
  "enabled": true,
  "rbac": {
    "enabled": true,
    "api_tokens": [
      {"token": "...", "role": "operator", "subject": "ops-team"},
      {"token": "...", "role": "auditor", "subject": "audit-team"}
    ]
  },
  "policy_lifecycle": {
    "enabled": true,
    "require_approval_for_writes": true,
    "max_versions": 50,
    "auto_version_on_write": true
  },
  "signing": {
    "enabled": true,
    "require_signature_on_apply": false,
    "signing_key": "rotate-in-production"
  },
  "audit_chain": {"enabled": true},
  "oidc": {
    "enabled": true,
    "issuer": "https://idp.example.com/",
    "audience": "mcp-security-proxy",
    "jwt_secret": "local-hs256-demo-only"
  }
}
```

Environment overrides:

| Variable | Purpose |
|----------|---------|
| `MCP_PROXY_POLICY_SIGNING_KEY` | Bundle signing secret |
| `MCP_PROXY_OIDC_JWT_SECRET` | HS256 JWT validation (lab) |
| `MCP_PROXY_GOVERNANCE_DATA_DIR` | Policy versions + proposals store |

The main `MCP_PROXY_API_KEY` retains **admin** role when governance is enabled.

---

## Admin API (Sprint 4)

| Method | Path | Permission | Purpose |
|--------|------|------------|---------|
| GET | `/admin/auth/me` | any valid token | Current principal + permissions |
| GET | `/admin/governance/status` | `governance:read` | Governance feature flags |
| GET | `/admin/auth/oidc/config` | `governance:read` | OIDC integration metadata |
| GET | `/admin/policy-versions` | `policy:read` | List version index |
| GET | `/admin/policy-versions/{id}` | `policy:read` | Fetch stored version |
| POST | `/admin/policy-versions` | `policy:write` | Manual snapshot |
| POST | `/admin/policy-rollback` | `policy:rollback` | Restore version |
| GET | `/admin/policy-proposals` | `policy:read` | List proposals |
| POST | `/admin/policy-proposals` | `policy:write` | Submit proposal |
| POST | `/admin/policy-proposals/{id}/approve` | `policy:approve` | Promote proposal |
| POST | `/admin/policy-proposals/{id}/reject` | `policy:approve` | Reject proposal |
| POST | `/admin/sign-policy-bundle` | `bundle:sign` | Sign bundle envelope |
| GET | `/admin/audit-integrity` | `audit:read` | Verify hash chain |

`POST /admin/policy-config` with `require_approval_for_writes: true`:

- **Operator** → returns `pending_approval` + `proposal_id` (no direct write)
- **Admin** (`MCP_PROXY_API_KEY`) → direct write; use `force: true` to bypass queue when needed

`POST /admin/apply-policy-bundle` accepts `signed_bundle` envelope; verifies HMAC when signing is enabled.

---

## Roles

| Role | Typical use | Cannot |
|------|-------------|--------|
| `admin` | Break-glass, approvals, rollback | — |
| `operator` | Policy edits, bundle apply | Approve proposals, purge audit |
| `auditor` | Read policy, export audit | Write policy, apply bundles |

---

## Verification

```bash
bash tools/test_mcp_proxy_phase_c.sh
bash tools/test_mcp_proxy_phase_c_rbac.sh
bash tools/test_mcp_proxy_phase_c_policy_lifecycle.sh
bash tools/test_mcp_proxy_phase_c_audit_integrity.sh
```

Unit tests:

```bash
cd mcp-security-proxy && python -m pytest tests/test_app.py -q -k "rbac or governance or rollback or sign_and or audit_chain"
```

---

## After Phase C

| Priority | Focus |
|----------|--------|
| Operate | `sprint-4-governance` or enterprise tier; rotate demo tokens and signing keys |
| Sprint 5 | SIEM/SOAR connectors, HA topology, enterprise metering at scale |

**Not in Sprint 4 MVP:** full OIDC authorization-code flow UI, external IdP JWKS rotation automation, multi-tenant policy scopes — wire those in production hardening.

### Operate: UI re-auth, policy load, preset choice

Step-by-step for authenticating http://localhost:8090/ui, confirming policy loads, and
choosing **`core-balanced`** vs **`sprint-4-governance`**:

[MCP_PROXY_OPERATE_UI_AND_PRESETS.md](MCP_PROXY_OPERATE_UI_AND_PRESETS.md)

Quick fix for empty policy editor after key align or proxy restart:

```bash
bash tools/mcp_api_key.sh --proxy   # paste into Admin bearer token → Refresh
```
