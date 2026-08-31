# MCP Security Proxy Commercial Packaging

One-page packaging and positioning matrix for commercializing the standalone MCP Security Proxy.

## Product Boundary

Keep in-scope features limited to MCP request-time security decisions and governance:

- Allow/deny/challenge enforcement
- LLM risk and tool-intent verification
- Policy lifecycle, audit, and observability

Keep out-of-scope features in separate modules/integrations:

- SOC case management and analyst workflow UI
- General orchestration engines and incident playbooks
- Broad Phase 4 analytics platform capabilities

## Tier Matrix

| Tier | Buyer Persona | Core Value | Included | Excluded | Pricing Posture |
|---|---|---|---|---|---|
| Core Proxy | Security engineer, platform engineer, DevSecOps | Fast MCP guardrails with low deployment friction | MCP gateway, policy engine, deny/challenge controls, basic LLM risk + tool intent, admin API/UI, metrics, denied-call views | Multi-tenant policy hierarchy, enterprise approval workflows, SOC case lifecycle | Entry SKU, volume-friendly |
| Enterprise Proxy | Security architect, GRC, regulated orgs | Governance, compliance, and controlled operations at scale | Everything in Core plus SSO/OIDC/SAML, RBAC, policy versioning and approvals, signed policy bundles, rollback controls, tenant/environment policy scopes, HA guidance, audit export | Full SOC orchestration and case management platform | Premium annual contract |
| SOC Integration Pack | SOC lead, SecOps manager, SIEM/SOAR owner | Connect proxy decisions into SOC workflows without bloating core | Connectors/webhooks for SIEM/SOAR/ITSM, enrichment handoff, Phase 3/4 style adapters, optional managed tuning services | Repackaging full SOC platform into proxy runtime | Add-on expansion revenue |

## Feature-to-Tier Mapping

| Capability | Core | Enterprise | Integration Pack |
|---|---:|---:|---:|
| MCP request enforcement (allow/deny/challenge) | Yes | Yes | Via Enterprise/Core |
| LLM risk + tool-intent scoring | Yes | Yes | Via Enterprise/Core |
| Standalone policy tuning UI and SOC denied-call report | Yes | Yes | Via Enterprise/Core |
| API key auth | Yes | Yes | N/A |
| SSO + RBAC | No | Yes | N/A |
| Policy approvals and signed bundles | No | Yes | N/A |
| Multi-tenant policy scopes | No | Yes | N/A |
| Immutable audit export / compliance reports | Limited | Yes | Optional connectors |
| SIEM/SOAR/ITSM integration | Basic webhook | Advanced | Primary |
| Incident/case workflow engine | No | No | External integration only |

## Upgrade Triggers

Move from Core to Enterprise when:

- Multiple teams need delegated policy ownership
- Security review requires approval workflows and signed config lineage
- Auditors require identity-backed access and immutable audit evidence
- Production needs repeatable rollback and staged promotion controls

Add SOC Integration Pack when:

- Analysts need proxy decisions in existing SIEM/SOAR/ITSM workflows
- Incident response requires automated handoff from denied-call signals
- Customers request Phase 3/4 style orchestration without embedding that logic in proxy runtime

## Positioning Statements

Core Proxy:
"Deploy MCP security controls in hours, not weeks, with direct enforcement and clear telemetry."

Enterprise Proxy:
"Operationalize MCP governance with enterprise identity, policy approvals, and compliance-ready auditability."

SOC Integration Pack:
"Extend proxy decisions into your SOC ecosystem while keeping the proxy lightweight and reliable."

## Commercial Packaging Guardrails

- Do not merge SOC incident management UI into proxy core SKU.
- Do not require orchestration stack components for core proxy value.
- Keep runtime dependencies minimal for Core and Enterprise SKUs.
- Treat integration breadth as add-on value, not base product complexity.

## Implementation Status Snapshot (2026-06-02)

This snapshot reflects what is currently implemented in `mcp-security-proxy` today.

### Implemented Now (Core)

- MCP request enforcement: allow, deny, and challenge behavior
- LLM risk and tool-intent scoring/tuning flows
- Standalone policy tuning UI and denied-call SOC-style report views
- API key authentication for proxy/admin endpoints
- Metrics and operational observability endpoints
- Admin policy/config APIs for runtime policy management
- **Phase B:** Core MVP presets (`core-balanced`, `core-strict`, `core-observe`) — [MCP_PROXY_PRESETS.md](MCP_PROXY_PRESETS.md)
- **Phase B:** Usage metering and tier gating (`/admin/usage`, `commercial` policy block)
- **Phase B:** Audit export baseline (`/admin/audit-export`, persisted runtime history)

### Not Implemented Yet (Enterprise and Integration Pack)

- SSO/OIDC/SAML
- RBAC
- Policy approvals workflow
- Signed policy bundles
- Multi-tenant policy scopes
- Immutable/compliance-grade audit export
- Dedicated SIEM/SOAR/ITSM connector layer
- Incident/case workflow engine inside the proxy

### Evidence Pointers

- `mcp-security-proxy/README.md` documents current standalone capabilities and scope
- `mcp-security-proxy/mcp_security_proxy/app.py` contains implemented API/auth/enforcement logic
- `mcp-security-proxy/mcp_security_proxy/ui/static/index.html` contains implemented standalone UX and tuning/report flows
