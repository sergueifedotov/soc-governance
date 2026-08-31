# AI Security — Solo-Developer Product Strategy

Focused take on AI-security niches where a single developer can realistically reach $10K–$100K MRR within 12–24 months. Ranked by solo-dev viability (technical leverage × buyer willingness-to-pay × low support burden × short sales cycle).

## Tier 1 — Best fit for a single developer

### 1. AI-generated code security scanner

**Premise**: Cursor, Lovable, Bolt, v0, Replit Agent ship millions of LOC per week with predictable vulnerabilities (hardcoded keys, missing auth, IDOR, SQLi from string-templated queries, public S3 buckets in Terraform). Existing SAST (Snyk, Semgrep) wasn't trained on these patterns.

**Why solo-friendly**: Pure static analysis = no runtime, no infra to operate. GitHub App + VS Code extension. PLG funnel.

**Monetization**: $19/dev/mo Pro, $99/dev/mo Team. Free tier = 1 repo. Selling motion is content (blog one CVE-class per week mined from public Lovable apps).

**Moat**: Curated rules pack specific to AI-coder outputs + a continuously updated "AI codegen vuln corpus". Hard to replicate without obsessing on it.

**Realistic ARR ceiling solo**: $500K–$2M.

---

### 2. MCP server security & supply-chain auditor

**Premise**: MCP is exploding (Anthropic, Cursor, Claude Desktop, n8n, etc.). Every "awesome-mcp-servers" entry is unvetted code with broad tool access. There's no equivalent of `npm audit` for MCP. Enterprises rolling out internal MCP catalogs need scanning.

**Product**:

- CLI: `mcpaudit <repo|npm-pkg>` → reports tool-permission scope, dangerous handlers, prompt-injection in tool descriptions, transitive deps
- SaaS: signed-manifest registry, "verified MCP" badge
- Enterprise: private MCP catalog with policy enforcement

**Why solo-friendly**: First mover. ~2 competitors today. Pure scanner = no PII, no compliance baggage.

**Monetization**: $0 OSS CLI for funnel; $499–$2.5K/mo SaaS per org; $25K/yr enterprise self-hosted.

**Realistic ARR ceiling solo**: $300K–$1M.

---

### 3. PII / secret egress proxy for LLM teams (productized AgentGuard)

**Premise**: Every fintech, healthtech, and legaltech using OpenAI/Anthropic worries about sensitive data leaking in prompts. They want a drop-in proxy that scrubs PII/PHI/PCI/secrets before egress and audits everything.

**Why solo-friendly**: 80% of code already exists in `agentic-ai-firewall/`. Move it from open-source to dual-license + hosted SaaS edition. Single binary on customer infra OR managed regional endpoint.

**Monetization**: $99/mo Starter (1K req/min, BYO model), $499/mo Team, $2.5K+/mo Enterprise with HIPAA BAA + on-prem deployment. The BAA tier alone justifies the price.

**Moat**: Detector quality compounds. Regulated industry references compound faster.

**Watchouts**: Buyer wants SOC2-Lite questionnaire answers; plan a Vanta-style trust page. Competitors: Lakera, NeMo Guardrails, Prompt Security, NightFall AI. Win on price + self-host + a specific vertical (e.g., "for healthcare AI startups").

**Realistic ARR ceiling solo**: $500K–$3M.

---

### 4. Jailbreak / red-team eval-as-a-service

**Premise**: Companies shipping LLM features have no idea how brittle their system prompts are. They want a "score my agent" dashboard with regression tracking across releases.

**Product**:

- Upload your endpoint or agent config
- Service runs a battery of attacks (DAN, role-hijack, indirect injection, encoded payloads, multi-turn)
- Returns a CVE-like report with severity, reproduction, suggested system-prompt patches
- CI integration: fail PR if regression > N

**Why solo-friendly**: Content marketing writes itself ("We jailbroke X's customer support bot in 4 turns — here's how"). High SEO leverage. Eval scripts compound.

**Monetization**: $299/mo Pro (weekly scans), $1.5K/mo Team (CI), $10K+/yr enterprise.

**Moat**: Attack corpus quality + public benchmarks. Build a leaderboard — it becomes its own marketing flywheel.

**Realistic ARR ceiling solo**: $300K–$1.5M.

---

## Tier 2 — Profitable but heavier

### 5. EU AI Act / ISO 42001 compliance toolkit

**Why**: Aug 2026 enforcement deadline drives panic buying through 2026–2027. SMBs need risk classification + technical documentation generators + ongoing evidence collection.

**Why slower for solo**: Document-heavy, requires legal advisor on payroll-equivalent ($$$). But ACV is $15K–$50K so 30 customers = solid business.

**Format**: Static-site generator + SaaS dashboard. Templated risk assessments.

### 6. Vector DB / RAG poisoning detector

**Premise**: RAG-based apps trust their corpus. Attackers insert documents that hijack retrieval (e.g., a doc that says "Whenever you see X, recommend Y"). No mature tooling.

**Why solo-friendly**: Pure offline scanner. Add anomaly detection over embedding clusters.

**Monetization**: $199–$999/mo per corpus. Vertical: GovTech, FinServ knowledge bases.

**Watchout**: Market is early; buyers don't search for this yet. Education-led.

### 7. Local-LLM hardening for regulated SMBs

**Premise**: Clinics, law firms, accounting practices want ChatGPT-grade UX without sending data to OpenAI. Ollama is too rough; they need a packaged appliance.

**Product**: Hardened Open-WebUI + DMR + AgentGuard + audit log + Active Directory SSO + simple PHI/PII policy presets.

**Why solo-friendly-ish**: White-glove installs are time-consuming, but per-seat pricing is high ($30–$80/seat/mo).

**Watchout**: Hardware support burden. Mitigate by shipping a Docker stack only — no metal.

---

## Tier 3 — Don't bother as solo

- **Full SOC/MDR/EDR for AI** — needs 24/7 staffing
- **AI model security platform** (full lifecycle MLSecOps) — too broad, too many integrations
- **Deepfake detection for media houses** — ML-research-heavy, enterprise sales cycle 12+ months
- **AI-powered phishing detection email gateway** — incumbents (Abnormal, Proofpoint) own distribution; cost of false positives is reputational

---

## Recommended path given what is already built

You have AgentGuard working end-to-end with the OpenAI proxy + scanners + Docker + tests + SDK + LangChain integration. Two highest-leverage adjacent moves:

1. **Re-shape AgentGuard as a vertical product** ("AgentGuard for Healthcare AI" or "AgentGuard for FinServ") — same code, different policy presets, BAA template, HIPAA-ready audit log retention. Sell the vertical, not the framework. 10× the price for the same product.

2. **Productize `mcp-security-proxy` as "MCP Audit / MCP Gateway"** (Tier 1 #2 above). Core gateway plus Sprints 1–3 hardening are shipped; next work is Phase A operational rollout, Phase 1 commercialization, then Sprint 4–5 enterprise features ([MCP_PROXY_ROADMAP.md](MCP_PROXY_ROADMAP.md)). Different buyer (DevSecOps / Platform) than AgentGuard's buyer (AI App Eng), so it doesn't cannibalize.

These two together cover both the runtime (AgentGuard) and the supply-chain (MCP Audit) sides of agentic AI security — natural cross-sell.

---

## Distribution playbook for solo dev (any of the above)

- **Open-source core + paid SaaS**: free CLI/SDK generates inbound; paid dashboard captures revenue
- **One vertical landing page per ICP**: "for X" beats generic 10:1 in conversion
- **Content: vuln-disclosure as marketing**: publicly disclose 1 finding/week in a public AI app; each one is a PR moment
- **Skip self-serve PLG below $99/mo**: support cost eats margin. Either free or ≥$99
- **Never sell into Fortune 500 alone**: avoid 9-month security reviews. Target Series A–C startups (1–500 employees) where one champion can sign a $5–15K ACV without committee
- **One-page SOC2-Lite "trust" page from day one** (Vanta is $3K/yr, worth it once you hit $5K MRR)

---

## Net recommendation

Focus now on **vertical AgentGuard (Pattern 1) + MCP Audit CLI as funnel (Pattern 2)**. The code is mostly already written; what remains is positioning, pricing, and distribution.

---

## AgentGuard packaging: container vs browser plugin

Recommendation: **container/gateway is the primary commercial product; a browser plugin should only be a companion/funnel, not the main SKU.**

### Why container should remain the main SKU

- AgentGuard's value lives on server paths: backend agents, MCP tool execution, batch jobs, workers, multi-tenant traffic. A browser plugin cannot see those.
- Enterprise buyers ($2.5K+/mo) require centralized policy, immutable audit, and enforcement they control. Plugins are user-controlled and bypassable.
- Compliance posture (HIPAA, SOC2, EU AI Act) is far easier with a server-side control plane and tamper-evident audit log.
- Existing code is already a proxy + scanners + audit + policy reload pipeline. Container packaging matches that architecture; plugin packaging would require rewriting most of the value layer.
- ACV asymmetry: container/SaaS plans can charge $500–$25K/mo; plugin plans realistically cap at $5–$30/seat/mo with higher support burden.

### Where a browser plugin genuinely helps

- Acquisition: 30-second installs convert prospects who would never run Docker first.
- Demos: a visible inline indicator on ChatGPT/Claude/Gemini/Cursor is a strong show-and-tell.
- Individual developer trial that can upgrade to a team/org gateway.
- Lightweight DLP for users pasting sensitive text into web LLMs.
- Telemetry that warms the funnel into enterprise gateway sales.

### Where a plugin seriously limits scope (if it is the main product)

- No coverage of server-to-server agent traffic.
- No coverage of MCP tool calls or non-browser orchestration.
- Easy to bypass (incognito, disable, alternate browser, API client).
- Browser store policies can affect distribution and enforcement features.
- Cannot enforce centralized policy or produce audit you trust for regulators.

### Recommended product shape

1. **Primary: AgentGuard Gateway** (Docker self-host + managed regional endpoint).
2. **Companion: AgentGuard Browser Companion** (free or low-cost) that:
   - Visualizes scan decisions inline on popular web LLMs.
   - Calls the gateway when configured (org mode) for authoritative scanning.
   - Provides best-effort local scrubbing when not connected to a gateway (personal mode).
3. **Cross-sell motion**: plugin captures individuals, gateway captures their org.

### Pricing implication

- **Plugin**: free Personal; $9–$19/mo Pro (org-aware); drives funnel.
- **Gateway**: $99 Starter; $499 Team; $2.5K+ Enterprise (BAA/HIPAA).
- Same scanners, two distribution surfaces, one revenue spine.

### Decision rule

- If buyer = AI engineering, security, compliance, or platform team -> sell **gateway**.
- If buyer = individual user or small team experimenting -> start with **plugin**, upsell to gateway.

### Bottom line

Do both, but only if the container/gateway stays the primary revenue product. A plugin-only commercial AgentGuard would significantly limit scope, ACV, and defensibility.

---

## Protecting AgentGuard from copying (practical playbook)

You cannot fully prevent copying of a self-hosted Docker product, but you can make cloning commercially unattractive.

### Strategic principle

Keep core enforcement local, keep the highest-value capabilities remote.

### Product architecture to reduce copy risk

- Ship the gateway container for local scanning and proxy enforcement.
- Keep premium value in a managed control plane:
   - Policy intelligence updates
   - Threat intelligence feeds
   - Team analytics and long-term audit
   - Managed detector/signature packs
   - Enterprise admin controls (SSO, RBAC, compliance exports)
- Outcome: copied gateway runs, but lacks the paid value layer.

### Licensing and legal controls

- Use dual licensing:
   - Community license for limited use
   - Commercial license for production and enterprise deployment
- Include explicit terms that restrict unauthorized redistribution, white-label resale, and commercial re-hosting.
- Register and enforce trademark for AgentGuard name and logo.

### License enforcement model (customer-friendly)

- Per-tenant signed license token with expiry, feature flags, and throughput/seat entitlements.
- Periodic online verification with grace window for outages.
- Enforce entitlements at startup and on refresh interval.
- Degrade premium features on license failure instead of hard-stopping core security scanning.

### Supply-chain trust as a moat

- Sign images and release artifacts (for example with Sigstore Cosign).
- Publish checksums and build provenance/attestations.
- Position official signed builds as the enterprise-trusted distribution.

### Anti-tamper reality check

- Assume binaries and containers can be reverse engineered.
- Avoid over-investing in obfuscation.
- Keep sensitive logic server-side: proprietary tuning, detection heuristics, enrichment logic, and intelligence correlation.

### Defensibility that matters more than code secrecy

- Faster policy and detector update cadence
- Better precision/recall from private evaluation corpus
- Compliance package quality (BAA workflows, trust artifacts, audit exports)
- Incident response support and SLAs

These capabilities are materially harder to copy than source code alone.

### Suggested 30/60/90 rollout

- **30 days**: dual-license text, signed releases, basic license token checks.
- **60 days**: hosted policy/threat feed service and feature-gated premium controls.
- **90 days**: enterprise trust bundle (attestations, compliance exports, SLA-backed support) and enforcement hardening.

---

## Q&A Addendum: Most profitable niche and AgentGuard readiness

### Most profitable niche for a solo AI security developer

The most profitable niche in this strategy is a **PII/secret egress proxy for regulated AI teams** (healthtech, fintech, legaltech), delivered as a self-hosted and/or managed gateway.

Why this is the strongest solo-developer revenue path:

1. **High willingness to pay**
   Security and compliance budgets support premium pricing for data-leak prevention and auditability.
2. **Clear, urgent pain**
   Prompt/completion leakage risk is immediate and often executive-visible.
3. **Enterprise-compatible product shape**
   Gateway controls map directly to policy enforcement, logging, and compliance evidence requirements.
4. **Pricing power and ACV headroom**
   Realistic tiering remains strong from SMB through enterprise (including BAA-driven plans).
5. **Compounding moat**
   Detector quality, vertical policy packs, and trust/compliance artifacts improve over time and raise switching costs.

### Is the AgentGuard here already that product?

Short answer: **it is a real egress-proxy MVP/foundation, but not yet a full enterprise product package**.

What is already present in this repo:

- Inbound/outbound scanning paths for prompt injection and sensitive content.
- OpenAI-compatible proxy routing and policy enforcement.
- Audit + metrics + UI visibility for operational verification.

What is still missing for production-grade commercialization:

1. **Identity and access controls**
   SSO, RBAC, scoped API auth, and robust tenant isolation.
2. **Durable compliance-grade audit**
   Tamper-evident storage, long retention, integrity verification, and export workflows.
3. **Secrets and key management hardening**
   KMS/Vault integration, key rotation, secret scoping, and operational controls.
4. **Detection quality lifecycle**
   Continuous eval harnesses, FP/FN tracking, and vertical tuning pipelines.
5. **Reliability and scale posture**
   HA deployment model, SLOs, backpressure handling, and explicit fail-open/fail-closed controls.
6. **Policy governance lifecycle**
   Versioning, staged rollouts, approval workflows, and automated rollback.
7. **Enterprise integrations and response hooks**
   SIEM/SOAR connectors, alert routing, and incident-response automation.
8. **Commercial platform features**
   Licensing, entitlements, usage metering, billing, SLA packaging, and trust-center artifacts.

### Practical interpretation

- **Technical status**: meaningful egress-proxy capability exists now.
- **Business status**: additional enterprise controls are required to win and retain paid security buyers at scale.

---

## Q&A Addendum: MCP security proxy commercialization

### Can the MCP security proxy in this project be commercialized?

Yes. It is commercially viable, especially as a distinct product focused on MCP tool and server governance.

Recommended positioning:

- Productize it as an **MCP security control plane**, not only a request proxy.
- Keep a community edition for adoption and developer trust.
- Sell managed and enterprise controls for policy, compliance, and fleet governance.

### Product shape and packaging

1. **Developer SKU (adoption layer)**
   Local proxy + policy packs + CLI audit + lightweight dashboard.
2. **Team/Platform SKU (core revenue layer)**
   Central policy management, org-wide enforcement, signed allowlists, trust levels, SSO/RBAC, SIEM exports, extended retention.
3. **Enterprise SKU (high ACV layer)**
   Private control plane or on-prem deployment, compliance evidence exports, tamper-evident logging, SLA-backed support.

### Commercialization conditions

1. **Technical conditions**
   High-volume reliability, low-latency enforcement, explicit fail-open/fail-closed controls, policy versioning, staged rollout, rollback.
2. **Security and compliance conditions**
   Strong authn/authz, tenant isolation, durable auditable logs, supply-chain trust (signed artifacts and provenance).
3. **Product-market conditions**
   Clear ICP (platform and security teams adopting MCP), clear ROI (risk reduction, approval speed, audit readiness), clear enforcement outcomes.
4. **Business model conditions**
   Open-core or dual-license model, paid control-plane features, value-based pricing metric (protected calls, controlled tools, active workspaces), and support SLAs.

### Strategic fit with AgentGuard

- **AgentGuard** addresses prompt/completion and data-egress risk.
- **MCP security proxy** addresses tool-call and MCP supply-chain/runtime governance risk.

Together they create a strong cross-sell motion while preserving separate buyer entry points.

---

## Q&A Addendum: AgentGuard vs MCP proxy (commercial comparison)

### Executive summary

- **AgentGuard** is typically the stronger long-term revenue anchor (higher compliance-driven ACV ceiling).
- **MCP security proxy** is often the faster technical wedge (quicker platform/security adoption).
- Best outcome is a two-product motion: land with one, expand with the other.

### Commercial comparison matrix

<table>
   <colgroup>
      <col style="width: 20%;" />
      <col style="width: 40%;" />
      <col style="width: 40%;" />
   </colgroup>
   <thead>
      <tr>
         <th>Dimension</th>
         <th>AgentGuard (LLM ingress/egress firewall)</th>
         <th>MCP security proxy (tool/MCP governance)</th>
      </tr>
   </thead>
   <tbody>
      <tr>
         <td>Core buyer pain</td>
         <td>Prompt/completion data leakage, injection exposure, compliance risk</td>
         <td>Risky tool execution, unvetted MCP servers, runtime governance gaps</td>
      </tr>
      <tr>
         <td>Primary buyer</td>
         <td>AI app engineering, security/compliance, risk teams</td>
         <td>Platform engineering, DevSecOps, security architecture</td>
      </tr>
      <tr>
         <td>Typical buying trigger</td>
         <td>Regulated data handling, customer security reviews, audit pressure</td>
         <td>Organization-wide MCP rollout, internal tool catalog control, policy standardization</td>
      </tr>
      <tr>
         <td>Product-led motion</td>
         <td>Moderate (works best with compliance narrative)</td>
         <td>Strong (developer and platform teams can trial quickly)</td>
      </tr>
      <tr>
         <td>Monetization pattern</td>
         <td>Premium tiers with enterprise compliance add-ons</td>
         <td>Team/platform tiers, then enterprise control-plane upsell</td>
      </tr>
      <tr>
         <td>ACV upside</td>
         <td>High, especially with BAA/compliance requirements</td>
         <td>High when sold org-wide as governance control plane</td>
      </tr>
      <tr>
         <td>Sales cycle profile</td>
         <td>Can be longer in enterprise; faster in regulated startups with urgent risk</td>
         <td>Often faster technical evaluation; enterprise length grows with governance scope</td>
      </tr>
      <tr>
         <td>Support burden driver</td>
         <td>False-positive tuning + compliance artifacts</td>
         <td>Policy lifecycle management + platform integrations</td>
      </tr>
      <tr>
         <td>Defensibility</td>
         <td>Detector quality, vertical policy packs, trust/compliance assets</td>
         <td>Governance workflows, signed allowlists, enforcement telemetry, org policy graphs</td>
      </tr>
   </tbody>
</table>

### Stage fit and sequencing

1. **Early stage (first paying teams)**
   MCP proxy can close quickly with platform/security teams adopting MCP now.
2. **Growth stage (repeatable motion)**
   AgentGuard often expands contract size where compliance and data-risk controls become procurement requirements.
3. **Enterprise stage**
   Both products can scale if identity, audit durability, policy governance, SIEM integrations, and SLA/support posture are mature.

### Income model by stage (practical)

1. **Fastest initial revenue**
   MCP proxy developer/team plans with optional onboarding services.
2. **Largest long-term contracts**
   AgentGuard enterprise plans tied to compliance and data-egress controls.
3. **Best combined revenue model**
   Land one control plane, expand with the second: tool governance + data-egress governance.

### Recommended go-to-market rule

- If pipeline is technical/platform-led, lead with **MCP proxy**.
- If pipeline is compliance/risk-led, lead with **AgentGuard**.
- Always preserve cross-sell packaging so accounts can adopt both over time.

---

## Execution Addendum: Final Gap-Closure Items (MCP Security Gateway + Agent Sandbox)

This section captures the final implementation items needed to move from a strong MCP policy gateway to full protection against indirect prompt-injection, tool poisoning, and unsafe local execution.

### Current state summary

- Gateway controls are implemented in `mcp-security-proxy` (policy allow/deny/challenge, LLM risk and tool-intent controls, discovery alerts, and observability).
- **Sprints 1–3 are shipped** in this repository (policy fields, proxy enforcement, E2E test suites, and design docs). See [MCP_PROXY_ROADMAP.md](MCP_PROXY_ROADMAP.md) for the consolidated status table.
- **Phase A1 (reference isolated executor)** is shipped: `mcp-isolated-executor/` sidecar, Docker compose overlay, operational policy sample (`sprint-3-executor`), deploy and live-test scripts. Runbook: [MCP_PROXY_PHASE_A1_DEPLOY.md](MCP_PROXY_PHASE_A1_DEPLOY.md).
- The biggest **remaining** gaps are operational and enterprise-facing:
  - production-grade isolation (gVisor/Firecracker/Kata swap for the reference hardened-container executor),
  - staged enforcement rollout (monitor → challenge → deny) with sandbox attestation and execution profile precedence documented for operators,
  - durable audit export and integrity evidence,
  - SSO/RBAC, policy approvals, signed bundles (Sprint 4),
  - SIEM/SOAR/ITSM connectors, HA topology, metering at scale (Sprint 5).

### Shipped hardening checklist (Sprints 1–3)

| # | Capability | Status | Primary references |
|---|------------|--------|-------------------|
| 1 | Upstream tool metadata trust | Shipped (Sprint 1) | `trusted_servers`, `tool_descriptor_hashes`, `descriptor_drift_*`; [MCP_PROXY_TRUST_HARDENING.md](MCP_PROXY_TRUST_HARDENING.md) |
| 2 | Execution-risk strict profile | Shipped (Sprint 1) | `execution_tool_profile`; deny/challenge execution-like tools |
| 3 | Sandbox attestation gate | Shipped (Sprint 2) | `sandbox_attestation_profile`; [MCP_PROXY_CONTAINMENT_FAILSAFE.md](MCP_PROXY_CONTAINMENT_FAILSAFE.md) |
| 4 | Fail-closed dependency behavior | Shipped (Sprint 2) | `dependency_fail_safe_profile`, `prevent_silent_bypass` |
| 5 | Isolated executor routing | Shipped (Sprint 3 + A1 ref) | `isolated_executor_profile`; [MCP_PROXY_ISOLATED_EXECUTION.md](MCP_PROXY_ISOLATED_EXECUTION.md), [mcp-isolated-executor/](../mcp-isolated-executor/) |
| 6 | Upstream provenance controls | Shipped (Sprint 3) | `upstream_provenance_profile`, runtime/filesystem/egress policy fields |
| 7 | SOC discovery for trust/containment | Shipped | Discovery signals + Tuning Studio recommendations for trust and containment |

### Near-term priority checklist (post–Sprint 3)

1. **Operationalize Sprint 3 in production (Phase A)** — deploy executor sidecar, align upstream API keys, tune runtime/filesystem/egress, roll controls from monitor to deny. See [MCP_PROXY_ROADMAP.md](MCP_PROXY_ROADMAP.md) Phase A and [MCP_PROXY_PHASE_A1_DEPLOY.md](MCP_PROXY_PHASE_A1_DEPLOY.md).
2. **Phase 1 commercialization** — 30-minute deploy story, strict presets, metering/tier gating, durable audit baseline (survives restart).
3. **Sprint 4** — SSO/RBAC, policy versioning and approvals, signed bundles, compliance-grade export.
4. **Sprint 5** — SIEM/SOAR/ITSM connectors, HA/SLO guidance, entitlements and metering at scale.
5. **Optional** — descriptor signature verification packs; selective Rust on measured hot paths only.

### Delivery sequence

1. ~~Sprint 1: metadata trust verification plus strict deny defaults.~~ **Done**
2. ~~Sprint 2: sandbox attestation gate plus fail-closed dependency checks.~~ **Done**
3. ~~Sprint 3: isolated executor integration plus upstream provenance controls.~~ **Done**
4. **Phase A:** operationalize executor + provenance in live deployments (A1 reference executor shipped; A2–A5 tuning and validation).
5. **Sprint 4 / 5:** enterprise control plane and SOC integration (see roadmap).

### Product and commercialization impact

- Sprints 1–3 moved the MCP proxy from policy guardrail toward **defensible runtime governance** (trust, containment, isolated execution).
- Phase A and Phase 1 commercialization turn shipped controls into **customer-deployable** posture; Sprints 4–5 close enterprise procurement gaps.
- Cross-sell with AgentGuard remains clear:
  - AgentGuard for prompt/completion and LLM data egress,
  - MCP proxy for tool/runtime governance, supply-chain trust, and isolated execution.

## Detailed status: MCP Security Proxy implementation, hardening, and next steps

This section consolidates where the MCP Security Proxy stands now, what is already implemented, what remains partial, and what should be built next.

### Where the MCP Security Proxy is today

Current maturity: the proxy is a **Core-plus** product — beyond prototype, with **Sprints 1–3 hardening shipped** and a **reference isolated executor** (Phase A1) for live integration smoke. It is not yet an Enterprise governance control plane or turnkey external SOC integration.

Practical interpretation:

- It works as a standalone MCP security gateway with trust, containment, and isolated-execution policy paths.
- It exposes a usable operator UI, Tuning Studio recommendations, and admin APIs.
- It performs real policy enforcement, discovery-assisted monitoring, and E2E-validated hardening controls.
- Production operators still need Phase A rollout (executor deploy, key alignment, staged enforce modes) before claiming strong execution isolation in prod.
- Sprint 4–5 items (SSO/RBAC, signed policy, durable audit export, SIEM/SOAR) remain the procurement blockers for regulated enterprise buyers.

### Where the implementation lives

Primary implementation surfaces in this repository:

1. `mcp-security-proxy/mcp_security_proxy/app.py`
   - FastAPI service.
   - Request-time MCP policy enforcement.
   - Decision recording, denied-call tracking, discovery signal generation, and admin endpoints.

2. `mcp-security-proxy/mcp_security_proxy/ui/static/index.html`
   - Standalone operator console.
   - Policy tuning flows.
   - Denied-call and discovery-alert views.
   - Time-windowed dashboard behavior.

3. `mcp-security-proxy/config/policy.json`
   - Active policy source for allowed methods, denied tools, blocked patterns, rollout controls, LLM risk, tool-intent, and discovery rules.

4. `mcp-security-proxy/README.md`
   - Product boundary, current capabilities, and explicit not-yet-implemented enterprise features.

5. `docs/OPERATIONS.md`
   - Runtime procedures, rollout steps, smoke tests, and operator guidance.

6. `docs/MCP_PROXY_COMMERCIAL_PACKAGING.md`
   - Product-tier framing: Core, Enterprise, and SOC Integration Pack.

7. `mcp-isolated-executor/`
   - Reference isolated executor sidecar (`POST /execute`, hardened-container, allowlisted commands).
   - Wired from proxy via `isolated_executor_profile`; compose overlay in `mcp-security-proxy/docker-compose.isolated-executor.yml`.

8. Hardening and roadmap docs
   - [MCP_PROXY_TRUST_HARDENING.md](MCP_PROXY_TRUST_HARDENING.md), [MCP_PROXY_CONTAINMENT_FAILSAFE.md](MCP_PROXY_CONTAINMENT_FAILSAFE.md), [MCP_PROXY_ISOLATED_EXECUTION.md](MCP_PROXY_ISOLATED_EXECUTION.md)
   - [MCP_PROXY_ROADMAP.md](MCP_PROXY_ROADMAP.md), [MCP_PROXY_SPRINT_TESTING.md](MCP_PROXY_SPRINT_TESTING.md), [MCP_PROXY_PHASE_A1_DEPLOY.md](MCP_PROXY_PHASE_A1_DEPLOY.md)

9. Policy samples and E2E tooling
   - Samples: `config/phase4/mcp_proxy/policy.sample.sprint-{1,2,3}-*.json`, `policy.sample.sprint-3-executor-operational.json`
   - Consolidated smoke: `tools/smoke_mcp_proxy.sh` — [MCP_PROXY_SMOKE_TEST.md](MCP_PROXY_SMOKE_TEST.md)
   - Wrappers: `tools/test_sprint{1,2,3}_no_restart.sh`, `tools/mcp_proxy_test_common.sh`, `tools/align_mcp_proxy_upstream_key.sh`, `tools/deploy_isolated_executor_a1.sh`, `tools/test_isolated_executor_live.sh`

### Implemented now

The following capabilities are implemented and already form a real Core product surface:

1. MCP gateway enforcement
   - Intercepts MCP JSON-RPC traffic.
   - Supports allow, deny, and challenge outcomes.
   - Applies policy against methods, tools, and argument patterns.

2. LLM risk controls
   - Scores requests for risky or malicious characteristics.
   - Supports staged rollout from score-only to enforcement.
   - Produces telemetry and challenge/deny reasons.

3. Tool-intent verification
   - Evaluates whether declared intent matches selected tools and arguments.
   - Supports threshold tuning and enforcement.
   - Emits reasoned decision events for operator review.

4. Discovery alerts and campaign-style detection
   - Correlates events over time windows.
   - Detects repeated suspicious patterns such as `attack_pattern_denials`.
   - Surfaces recent alert summaries for SOC review.

5. Standalone UI and admin workflows
   - Native standalone `/ui` console.
   - Policy tuning, denied-call review, and rollout workflows.
   - Time-window aware dashboard views validated in recent QA.

6. Observability and metrics
   - Prometheus metrics at `/metrics`.
   - Recent decision, denied-call, and discovery-alert endpoints.
   - Operational visibility adequate for single-team usage.

7. Runtime policy management
   - Admin endpoints for runtime config changes.
   - Policy-file-driven behavior with reload/update flows.
   - Score-only to enforce workflows available in the UI.

8. Basic administrative protection
   - API-key-based protection for admin and proxy-facing endpoints.

9. Sprint 1 — trust hardening (shipped)
   - Trusted upstream servers, descriptor hash pinning, descriptor drift deny/challenge/monitor.
   - `execution_tool_profile` strict defaults for execution-like tool names.
   - Discovery signals: `untrusted_server_calls`, `descriptor_drift_events`, `execution_tool_attempts`.

10. Sprint 2 — containment and fail-safe (shipped)
   - `sandbox_attestation_profile` for risky tools (issuer, mode, freshness, pass status).
   - `dependency_fail_safe_profile` with health probes and `prevent_silent_bypass`.
   - Discovery signals: `sandbox_attestation_failures`, `dependency_health_failures`, `security_layer_bypass_attempts`.

11. Sprint 3 — isolated execution and provenance (shipped in policy/proxy; executor via Phase A1)
   - `isolated_executor_profile` routes matching tools to executor `POST /execute`.
   - `upstream_provenance_profile`, `runtime_limits`, filesystem and egress restrictions in policy.
   - Executor evidence recorded in decision telemetry (`executor_evidence` on decision events).

### Partially implemented or only minimally covered

These areas exist in limited form but are not yet hardened enough for enterprise deployment:

1. Authentication and authorization
   - Current state: API key only.
   - Gap: no SSO, no RBAC, no delegated administration, no strong tenant separation.

2. Audit durability
   - Current state: runtime telemetry, recent-event views, metrics.
   - Gap: no immutable audit chain, no compliance-grade retention/export workflow, no strong lineage of policy changes.

3. Policy lifecycle governance
   - Current state: policy can be changed and tuned operationally.
   - Gap: no approval workflow, no signed policy bundles, no staged promotion with formal rollback history.

4. Enterprise integration
   - Current state: proxy has local observability and can conceptually hand off events.
   - Gap: no finished SIEM/SOAR/ITSM connector layer and no automatic incident creation in the broader SOC workflow.

5. Runtime hardening depth
   - Current state: Sprints 1–3 policy and proxy paths are implemented; reference executor (`mcp-isolated-executor`) runs in Docker with operational sample policy.
   - Gap: production swap to stronger runtimes (gVisor/Firecracker/Kata), operator precedence docs when `execution_tool_profile` and `sandbox_attestation_profile` both apply, and signature verification for descriptor catalogs (not only hashes).

6. Reliability posture
   - Current state: working standalone deployment and validated operator flows.
   - Gap: no fully documented HA topology, clustering model, or enterprise durability guidance.

### Not implemented yet but required for enterprise commercialization

Sprint 1–3 hardening is in the codebase; the items below are what still block regulated enterprise procurement and Phase 2–3 exit criteria:

1. Descriptor signature verification (extension beyond Sprint 1 hash pinning)
   - Signed manifest or attested catalog sync for tool metadata.
   - Continuous trust drift workflows tied to external registry.

2. Enterprise identity and governance
   - SSO/OIDC/SAML.
   - RBAC.
   - Approval workflows.
   - Signed bundles and rollback controls.

3. Compliance-grade audit and export
   - Durable audit storage.
   - Tamper-evident records.
   - Export formats suitable for customer review and regulated environments.

4. SOC integration pack
   - Webhooks and connectors for SIEM/SOAR/ITSM.
   - Automatic routing of high-value proxy decisions into incident workflows.

5. Production isolation at scale
   - Replace or augment reference hardened-container executor with customer-chosen sandbox runtime.
   - HA executor pool and documented blast-radius / egress allowlist operations.

### Recommended implementation priority

Sprint 1–3 security hardening is **done in repo**; prioritize operationalization and commercialization blockers next (aligned with [MCP_PROXY_ROADMAP.md](MCP_PROXY_ROADMAP.md)):

1. **Priority 1: Phase A — operationalize Sprint 3**
   - Deploy isolated executor (`deploy_isolated_executor_a1.sh`, `test_isolated_executor_live.sh`).
   - Align `MCP_PROXY_UPSTREAM_API_KEY` with Wazuh `MCP_API_KEY` (`align_mcp_proxy_upstream_key.sh`).
   - Tune runtime/filesystem/egress; roll `isolated_executor`, `sandbox_attestation`, and `execution_tool_profile` from monitor → deny.

2. **Priority 2: Phase 1 commercialization**
   - 30-minute deploy docs and presets; metering/tier gating; durable audit baseline (export survives restart).

3. **Priority 3: Sprint 4 — enterprise governance**
   - Durable audit store + export API first, then policy versioning/rollback, RBAC, SSO, signed bundles and approvals.

4. **Priority 4: Sprint 5 — scale and SOC**
   - SIEM/SOAR/ITSM connectors; HA/SLO reference architecture; entitlements and contract governance.

5. **Priority 5 (optional): engineering efficiency**
   - Descriptor signature packs; selective Rust only on profiled hot paths.

## Functional requirements: MCP Security Proxy

The MCP Security Proxy should be treated as a policy enforcement and observability control plane, not just a request filter. The minimum functional requirements are:

1. Request interception and policy evaluation
   - Intercept MCP JSON-RPC traffic before it reaches upstream tools.
   - Evaluate methods, tools, argument patterns, and declared intent.
   - Support allow, deny, challenge, and monitor outcomes.

2. Trust and provenance checks
   - Pin trusted upstream servers and tool descriptors (**Sprint 1 shipped**).
   - Detect descriptor drift and unexpected capability expansion.
   - Require provenance signals for risky tools and execution-capable actions (**Sprint 3 upstream provenance shipped**).

3. Runtime containment
   - Apply stricter controls for write-capable, file-access, and code-execution tools (**Sprint 1 execution profile shipped**).
   - Support sandbox attestation or isolated execution paths where needed (**Sprints 2–3 shipped**; Phase A for production rollout).
   - Fail closed when security-critical dependencies are unavailable (**Sprint 2 shipped**).

4. Auditability and operator visibility
   - Record decision events, denied calls, discovery alerts, and policy changes.
   - Provide time-windowed dashboards and exportable evidence.
   - Preserve enough context for review, tuning, and incident response.

5. Policy lifecycle management
   - Support versioning, staged rollout, rollback, and approval workflows.
   - Separate score-only, observe, challenge, and enforce modes.
   - Keep policy changes auditable and attributable.

6. Administrative safety
   - Protect admin endpoints with strong authentication and scoped authorization.
   - Support operator and reviewer roles rather than a single shared key.
   - Expose health, status, and runtime-history endpoints for safe operations.

## AI security feature map

The MCP Security Proxy is one layer in a broader AI security stack. A useful implementation map is:

| Layer | Example capabilities | Best implemented |
|---|---|---|
| Inside the proxy | allow/deny/challenge policy, argument pattern blocking, tool-intent verification, LLM risk scoring, trust/descriptor drift, execution profile, provenance checks, decision logging | Directly in `mcp-security-proxy` |
| Adjacent to the proxy | sandbox attestation (Sprint 2), isolated executor (Sprint 3 + `mcp-isolated-executor`), upstream descriptor signing, policy bundle signing, approval workflows, SIEM/SOAR export | Shared services or sidecars |
| Outside the proxy | agent identity governance, SSO/RBAC, secrets management, incident workflows, compliance exports, data-loss prevention, model registry controls | Platform, SOC, IdP, and governance systems |
| Agentic security | tool-use guardrails, planner constraints, memory controls, step-level approvals, action provenance, bounded autonomy, human-in-the-loop gates | Agent runtime and orchestration layer |

### Desirable AI security capabilities beyond the proxy

1. Agentic security controls
   - Bound what an agent can plan, call, remember, and execute.
   - Require approvals for high-risk multi-step actions.
   - Log step-level reasoning, tool selection, and action provenance.

2. Policy-aware orchestration
   - Let workflows consult proxy decisions before continuing.
   - Gate autonomous playbooks on risk, confidence, or blast radius.
   - Support pause, cancel, and revert operations when a run becomes unsafe.

3. Data protection controls
   - Redact or tokenize sensitive inputs before they reach models.
   - Apply DLP-like checks to prompts, tool arguments, and outputs.
   - Restrict retrieval against sensitive corpora or regulated datasets.

4. Model and supply-chain trust
   - Validate model endpoints, prompts, policy packs, and tool descriptors.
   - Track model/version drift and release changes.
   - Keep provenance for agent code, prompts, and connectors.

5. Detection and response
   - Detect prompt injection, tool poisoning, exfiltration attempts, and abuse campaigns.
   - Correlate proxy events with agent traces, tickets, and SIEM alerts.
   - Trigger playbooks for containment, rollback, and investigation.

6. Governance and assurance
   - Define approval matrices, ownership, and blast-radius tiers.
   - Produce audit evidence for internal review and external compliance.
   - Support safe experimentation with simulation and canary policies.

### Practical product split

If the goal is a shippable roadmap, a good split is:

- Proxy-owned: request gatekeeping, discovery, policy tuning, provenance checks, and enforcement telemetry.
- Platform-owned: identity, secrets, compliance exports, and incident workflow integration.
- Agent-owned: planner constraints, step approvals, memory governance, and autonomous-action limits.

That split keeps the proxy focused on runtime governance while still supporting a larger AI security and agentic-security product story.

### Suggested execution sequence

#### Sprint 1: close the most dangerous trust gaps

Status: **Shipped** (see [MCP_PROXY_TRUST_HARDENING.md](MCP_PROXY_TRUST_HARDENING.md)).

- Add trusted-server and descriptor-hash policy fields.
  - Policy fields: `trusted_servers`, `untrusted_server_action`, `tool_descriptor_hashes`, `descriptor_drift_action`.
- Block or challenge descriptor drift.
  - `tools/list` responses are post-filtered against `tool_descriptor_hashes`; drift surfaces as `_descriptor_drift[]` findings and `descriptor_drift{,_challenge,_monitor}` deny reasons.
- Introduce strict profile defaults for execution-like tools.
  - Policy field: `execution_tool_profile` (defaults cover `exec`, `shell`, `eval`, `subprocess`, `python_repl`, `bash`, `powershell`, `ssh`, etc.). Reasons: `execution_tool_blocked`, `execution_tool_challenge`.
- Expand discovery signals for trust failures.
  - New signals: `untrusted_server_calls`, `descriptor_drift_events`, `execution_tool_attempts`.

Validation:

- Unit tests in `mcp-security-proxy/tests/test_app.py` (`test_execution_tool_*`, `test_untrusted_upstream_*`, `test_descriptor_drift_*`).
- End-to-end: [tools/test_sprint1_no_restart.sh](../tools/test_sprint1_no_restart.sh) (applies `sprint-1` policy baseline, upstream key check, then trusted-server / descriptor-drift / execution-profile gates). Individual scripts: [test_trusted_servers.sh](../tools/test_trusted_servers.sh), [test_descriptor_drift.sh](../tools/test_descriptor_drift.sh), [test_execution_tool_profile.sh](../tools/test_execution_tool_profile.sh). Shared helpers: [mcp_proxy_test_common.sh](../tools/mcp_proxy_test_common.sh), [align_mcp_proxy_upstream_key.sh](../tools/align_mcp_proxy_upstream_key.sh). See [MCP_PROXY_SPRINT_TESTING.md](MCP_PROXY_SPRINT_TESTING.md).
- Policy sample: `bash tools/switch_mcp_policy_sample.sh sprint-1`.
- SOC UI: three new `TRUST` recommendations in the Tuning Studio (`trust-untrusted-server`, `trust-descriptor-drift`, `trust-execution-profile`).

#### Sprint 2: enforce containment and fail-safe behavior

Status: **Shipped** (see [MCP_PROXY_CONTAINMENT_FAILSAFE.md](MCP_PROXY_CONTAINMENT_FAILSAFE.md)).

- Add sandbox attestation checks in policy evaluation.
  - Policy field: `sandbox_attestation_profile` with `enabled`, `action` (`deny`/`challenge`/`monitor`), `require_for_tools` (default covers `shell`, `exec`, `python_repl`, `bash`, `powershell`), `trusted_issuers`, `allowed_modes` (default `isolated`, `sandboxed`, `gvisor`, `firecracker`, `kata`, `wasm`), `max_age_seconds` (default 900), `allow_missing_expiry`, `require_pass`.
  - Callers attach attestation in `params.sandbox_attestation` (or `params._sandbox_attestation`); the proxy validates issuer, mode, freshness, expiry, and pass status before forwarding.
  - Deny reasons: `sandbox_attestation_missing`, `sandbox_attestation_invalid`, `sandbox_attestation_untrusted_issuer`, `sandbox_attestation_mode_not_allowed`, `sandbox_attestation_expired`, `sandbox_attestation_stale`, `sandbox_attestation_failed`. Each is also emitted as a `challenge`/`monitor` variant when the profile is not in `deny` mode.
- Add required dependency health checks for enforcing mode.
  - Policy field: `dependency_fail_safe_profile` with `enabled`, `action`, `required_controls` (default `llm_risk`, `tool_intent`), `require_network_reachability`, `health_cache_ttl_seconds` (default 15), `prevent_silent_bypass`.
  - When a required control is in enforce mode, the proxy probes its `base_url` (with a per-URL TTL cache and short timeout) before allowing a call. Unreachable dependencies trigger a fail-closed decision with reason `dependency_health_failed` (with the failing controls in event metadata).
- Prevent silent bypass of required security layers.
  - When `prevent_silent_bypass=true` and an enforcing layer cannot produce a real decision (e.g. `llm_risk` or `tool_intent` engine returns `engine=none` / `*_unavailable`), the proxy denies with reason `security_layer_bypass_prevented` and records `required_layer` in the deny event instead of falling through to allow.
- Expand discovery signals for containment failures.
  - New signals: `sandbox_attestation_failures`, `dependency_health_failures`, `security_layer_bypass_attempts` (default discovery thresholds: 1 event in 1 hour, action `monitor`).

Validation:

- Unit tests in `mcp-security-proxy/tests/test_app.py` (`test_sandbox_attestation_missing_denies_execution_tool`, `test_dependency_fail_safe_blocks_when_enforcing_dependency_unreachable`, `test_prevent_silent_bypass_denies_when_required_llm_layer_unavailable`).
- End-to-end: [tools/test_sprint2_no_restart.sh](../tools/test_sprint2_no_restart.sh); [test_sandbox_attestation.sh](../tools/test_sandbox_attestation.sh), [test_dependency_fail_safe.sh](../tools/test_dependency_fail_safe.sh). See [MCP_PROXY_SPRINT_TESTING.md](MCP_PROXY_SPRINT_TESTING.md).
- Policy sample: `bash tools/switch_mcp_policy_sample.sh sprint-2`.
- SOC UI: three new `CONTAINMENT` recommendations in the Tuning Studio (`containment-sandbox-attestation`, `failsafe-dependency-health`, `failsafe-prevent-silent-bypass`); Accept now persists the full `sandbox_attestation_profile` and `dependency_fail_safe_profile` objects plus the matching discovery rules.

#### Sprint 3: separate execution into a hardened path

Status: **Shipped** (see [MCP_PROXY_ISOLATED_EXECUTION.md](MCP_PROXY_ISOLATED_EXECUTION.md)).

- Proxy `isolated_executor_profile` routes matching tools to a dedicated executor instead of upstream MCP.
- Policy fields for `runtime_limits`, filesystem restrictions, and egress/upstream provenance.
- Sandbox attestation and executor evidence recorded in decision telemetry (`executor_evidence` on `_record_decision_event`).

Validation:

- End-to-end: [tools/test_sprint3_no_restart.sh](../tools/test_sprint3_no_restart.sh); [test_isolated_executor.sh](../tools/test_isolated_executor.sh), [test_runtime_limits.sh](../tools/test_runtime_limits.sh), [test_filesystem_restrictions.sh](../tools/test_filesystem_restrictions.sh), [test_upstream_provenance.sh](../tools/test_upstream_provenance.sh). See [MCP_PROXY_SPRINT_TESTING.md](MCP_PROXY_SPRINT_TESTING.md).
- Policy samples: `bash tools/switch_mcp_policy_sample.sh sprint-3` (policy-only gates); `sprint-3-executor` for live executor integration (`policy.sample.sprint-3-executor-operational.json`).
- SOC UI: isolated-execution and provenance tuning recommendations in Tuning Studio (see isolated-execution design doc).

**Operator note:** `execution_tool_profile` is evaluated before isolated-executor routing. Operational executor tests typically set `execution_tool_profile.enabled: false` so Sprint 3 path is reachable; production rollouts should document precedence when re-enabling both profiles.

#### Phase A: operationalize Sprint 3 in production

Status: **A1 reference executor shipped**; A2–A5 are operator rollout (see [MCP_PROXY_ROADMAP.md](MCP_PROXY_ROADMAP.md)).

| Step | What | Commands / docs |
|------|------|-----------------|
| A1 | Deploy reference executor sidecar | `bash tools/start-profile.sh C` → `align_mcp_proxy_upstream_key.sh` → `start_isolated_executor.sh` → `deploy_isolated_executor_a1.sh` → `test_isolated_executor_live.sh` |
| A2 | Tune runtime, FS, egress | Policy `runtime_limits`, `filesystem_restrictions`, `egress_controls`, `upstream_provenance_profile` |
| A3 | Staged enforcement | Per-control monitor → challenge → deny via `/ui` or `POST /admin/policy-config` |
| A4 | Key and compose hygiene | [MCP_PROXY_PHASE_A1_DEPLOY.md](MCP_PROXY_PHASE_A1_DEPLOY.md) troubleshooting (networks, ports, zsh comments) |
| A5 | Regression after changes | `test_sprint{1,2,3}_no_restart.sh --skip-unit-tests` |

Executor service: [mcp-isolated-executor/](../mcp-isolated-executor/) — DNS `http://isolated-executor:8080/execute`, host health `http://localhost:18088/health`.

#### Sprint 4: finish enterprise control-plane requirements

Status: **Planned** — not started in codebase.

- Add SSO and RBAC.
- Add policy versioning, approvals, rollback, and signed bundles.
- Add durable audit export and integrity evidence.

Detailed next steps and priority order: [MCP_PROXY_ROADMAP.md](MCP_PROXY_ROADMAP.md) (Phase C).

#### Sprint 5: package for larger deployments

Status: **Planned** — not started in codebase.

- Add SIEM/SOAR/ITSM connectors.
- Add metering, license/entitlement controls, and supportable deployment guidance.
- Publish HA and production topology guidance.

Detailed next steps: [MCP_PROXY_ROADMAP.md](MCP_PROXY_ROADMAP.md) (Phase D).

### What the proxy is ready for right now

Ready now:

- Standalone MCP gateway usage with Sprints 1–3 controls (trust, containment, isolated-execution policy).
- Small-team or internal platform deployment; demo/trial with sprint policy samples and E2E scripts.
- Policy tuning, Tuning Studio recommendations, and discovery-assisted monitoring.
- Reference isolated executor path for integration validation (Phase A1).
- Core commercialization planning; Phase 1 MVP revenue work can start in parallel with Phase A rollout.

Not ready yet for:

- Regulated enterprise procurement requiring SSO/RBAC, signed policy bundles, and formal approvals (Sprint 4).
- Multi-team delegated administration and compliance-grade immutable audit export.
- Customer-mandated sandbox runtimes (gVisor/Firecracker) without swapping the reference executor.
- Turnkey external SOC workflows (SIEM/SOAR/ITSM) without Sprint 5 connectors.

### Decision summary

The MCP Security Proxy has completed its **foundational hardening program** (Sprints 1–3) and a **reference executor** for isolated tool execution. The core gateway, operator UI, and E2E test suites are validated.

Next engineering should **not** be a rewrite. It should be:

1. **Phase A** — run the executor and provenance controls in real deployments with staged enforce modes.
2. **Phase 1 commercialization** — deploy UX, metering, durable audit baseline.
3. **Sprints 4–5** — enterprise governance and SOC integration to close procurement blockers.

### Commercialization feature matrix (Phase checkpoints)

| Capability | Current state | Phase 1 (MVP revenue) | Phase 2 (Team/Enterprise readiness) | Phase 3 (Enterprise scale) |
|---|---|---|---|---|
| MCP policy enforcement (allow/deny/challenge) | Implemented | Hardened defaults, profile presets | Governance-safe defaults by tenant/workspace | Policy simulation and canary rollout controls |
| Tool metadata trust and provenance | Implemented (Sprint 1); signatures planned | Trusted server allowlist + descriptor hash pinning in production presets | Signature verification + provenance policy packs | Continuous trust drift + attested catalog sync |
| Execution-risk containment | Implemented (Sprints 1–3); prod rollout via Phase A | Strict execution profile + sandbox attestation + reference executor path | Tuned egress/FS/runtime limits per environment | gVisor/Firecracker-class executor + HA pool |
| LLM risk and tool-intent controls | Implemented | Deterministic rollout profiles and guardrails | Scoped policy packs by environment/team | Cross-workspace policy inheritance and override audit |
| Discovery and campaign detection | Implemented | Signals for tool poisoning and trust failures | Correlated multi-signal campaigns | Adaptive baseline and anomaly scoring over long windows |
| Auth and admin access | Basic API key | Role-separated admin/operator tokens | SSO + RBAC + scoped API tokens | Fine-grained delegated administration and break-glass controls |
| Audit and compliance evidence | Basic runtime events | Durable event storage and export baseline | Tamper-evident chain and retention policies | Compliance-grade export packs (SOC2, HIPAA, EU AI Act) |
| Policy lifecycle and approvals | Basic write/reload | Policy versioning and rollback | Approval workflow and staged rollout | Signed policy bundles and change-control attestations |
| Reliability and fail-safe behavior | Implemented (Sprint 2 dependency fail-safe); HA planned | Explicit fail-open/fail-closed modes + dependency health gates in enforcing profiles | Staged rollout playbooks per control | HA control-plane posture and SLO-backed operations |
| Enterprise integrations | Minimal | Alert webhooks and standard JSON exports | SIEM/SOAR/ITSM connectors | Bi-directional incident workflow integrations |
| Commercial controls | Minimal | License keys + usage metering baseline | Entitlements by feature tier and workspace | SLA-backed plans, advanced billing dimensions, contract governance |

### Phase exit criteria

1. Phase 1 exit (MVP revenue)
   - Paid team can deploy proxy in less than 30 minutes (Profile C + proxy + optional executor compose).
   - Strict execution-risk preset blocks obvious exfiltration chains (**Sprint 1 shipped**; preset packaging in progress).
   - Baseline trust controls detect descriptor/hash mismatch events (**Sprint 1 shipped**).
   - Usage metering and tier gating are operational (**Phase B shipped** — [MCP_PROXY_PHASE_B.md](MCP_PROXY_PHASE_B.md)).
   - Durable audit export survives restart (**Phase B shipped** — `/admin/audit-export`).

2. Phase 2 exit (Team/Enterprise readiness)
   - SSO/RBAC and approval workflow are production-ready (**Sprint 4**).
   - Audit integrity and retention controls satisfy security review checklists (**Sprint 4**).
   - Sandbox attestation gate enforced for risky tools in production (**Sprint 2 shipped**; Phase A staged rollout).
   - At least one SIEM/SOAR integration validated end-to-end (**Sprint 5**).

3. Phase 3 exit (Enterprise scale)
   - Isolated executor architecture active for code-execution paths (**Sprint 3 + A1 reference shipped**; customer runtime swap + HA = Phase A / Sprint 5).
   - Signed policy bundle workflow enforced in change control (**Sprint 4**).
   - HA and SLO posture documented and validated under load (**Sprint 5**).
   - Enterprise compliance export and trust artifacts close procurement blockers (**Sprint 4–5**).

### Implementation note: selective native-code adoption (Rust or Go)

Native-code migration (Rust or Go) should be selective and profiling-driven, not a full
rewrite. Detailed gateway split, REST vs MCP surfaces, and sidecar options:
[MCP_PROXY_GO_REST_ARCHITECTURE.md](MCP_PROXY_GO_REST_ARCHITECTURE.md).

Rust migration should be selective and profiling-driven, not a full rewrite.

Recommended architecture split:

1. Keep in Python (control plane)
   - Policy editing and rollout workflows.
   - Admin APIs, integrations, and compliance/reporting orchestration.
   - UI-facing business logic that changes frequently during product iteration.

2. Candidate native-code targets (data-plane hot paths; Rust or Go)
   - High-volume request parsing and validation.
   - Pattern matching and normalization pipelines under sustained load.
   - Deterministic policy evaluation core where latency and memory safety matter most.
   - Event ingestion/aggregation components with high cardinality throughput.

3. Migration method
   - Start with a native sidecar service (Go or Rust) or FFI extension for one bottleneck at a time.
   - Keep API contracts stable and feature behavior identical.
   - Re-measure after each migration step before expanding scope.

4. Trigger conditions to justify Rust work
   - Repeated latency or CPU bottlenecks in production-like profiling.
   - Infrastructure cost pressure from Python hot paths.
   - SLO targets not met without disproportionate horizontal scaling.
   - Security requirement for stricter memory-safety guarantees in untrusted-input paths.

5. Cases where Rust migration should wait
   - Primary bottlenecks are product gaps (SSO/RBAC, audit durability, policy governance).
   - No measured hot-path pressure under realistic workload.
   - Team bandwidth is better spent on commercialization blockers.

Commercial rule of thumb:

- Prioritize feature and enterprise-readiness gaps first.
- Move only proven hot paths to Rust to improve margin and reliability.
- Avoid full-language rewrites during product-market-fit and early revenue phases.

### Latest QA validation log

This section records recent validation passes against the MCP proxy, sprint hardening, and related docs/UI flows.

**Consolidated proxy smoke (recommended one-command regression):**

- `bash tools/smoke_mcp_proxy.sh` — core gateway, discovery, tool-intent, LLM risk, Sprints 1–3, optional executor live + reverse-flow. Full reference: [MCP_PROXY_SMOKE_TEST.md](MCP_PROXY_SMOKE_TEST.md).

**Sprint hardening (E2E, no container restart):**

- Sprint 1: `tools/test_sprint1_no_restart.sh` — trusted servers, descriptor drift, execution profile (with `mcp_proxy_test_common.sh` auth and upstream key alignment).
- Sprint 2: `tools/test_sprint2_no_restart.sh` — sandbox attestation, dependency fail-safe (sandbox test disables `execution_tool_profile` so attestation gate is evaluated first).
- Sprint 3: `tools/test_sprint3_no_restart.sh` — isolated executor policy gates, runtime limits, filesystem restrictions, upstream provenance.

**Phase A1 isolated executor (live):**

- `tools/deploy_isolated_executor_a1.sh` + `tools/test_isolated_executor_live.sh` — included in smoke with `--with-isolated-executor`; `shell_exec` / `whoami` via executor returns `output: "executor"`, `uid: 1000`; benign WARN possible on stale `/recent-denied` entries.

**Phase B Core MVP (commercialization):**

- `tools/apply_mcp_proxy_phase_b.sh` + `tools/test_mcp_proxy_phase_b.sh` — presets (`core-balanced`, `core-strict`), `/admin/usage`, `/admin/entitlements`, `/admin/audit-export`, restart survival. Status: [MCP_PROXY_VERIFICATION_STATUS.md](MCP_PROXY_VERIFICATION_STATUS.md).

**Earlier UI and traffic validation:**

1. UI rebuild and runtime validation
   - Rebuilt and restarted the standalone proxy container with Docker Compose.
   - Confirmed the UI loads after rebuild and the live dashboards render without syntax/runtime errors.
   - Verified the time-scale selector and window label update correctly when switching between 5 min, 30 min, and 24 hours.

2. Time-window correctness validation
   - Confirmed the Persistence Log now changes with the selected window instead of remaining capped to a fixed recent slice.
   - Confirmed Live MCP JSON-RPC Calls and Live Security Output are filtered by the selected time window.
   - Verified empty-state messaging changes per window when there is no data in the selected range.

3. Synthetic traffic QA
   - Ran `tools/test_llm_risk_calls.sh` successfully to generate current proxy traffic.
   - Ran `tools/test_discovery_attack_pattern_denials.sh` successfully to generate denied events and trigger discovery alerts.
   - Confirmed discovery alert generation for `attack_pattern_denials` with observed count reaching threshold.

4. Stress/load validation
   - Ran a sustained proxy traffic burst for approximately 150 seconds.
   - Re-checked 5 min vs 30 min vs 24 hours windows after the burst.
   - Confirmed output divergence by time scale:
     - 5 min showed higher short-window allow/deny rates.
     - 30 min showed lower rates over the broader denominator.
     - 24 hours showed near-zero per-second rates while preserving the full recent event history.

5. Security-control validation
   - Verified that policy enforcement still responds with allow/deny/challenge behavior.
   - Verified LLM risk and tool-intent controls remain active in the proxy policy profile.
   - Confirmed discovery alert telemetry continues to record recent reason/tool patterns for SOC inspection.

6. Documentation validation
   - Updated the product strategy doc with commercialization guidance, the final gap-closure roadmap, and selective Rust migration guidance.
   - Added a concrete feature matrix with Phase 1/2/3 commercialization checkpoints and exit criteria.
   - Captured the Rust adoption decision framework so it is clear that only measured hot paths should move out of Python.

### QA takeaways

- Sprints 1–3 hardening is implemented and covered by E2E scripts; upstream API key alignment is required before drift/trust tests (`align_mcp_proxy_upstream_key.sh`).
- Phase A1 proves proxy → isolated-executor routing end-to-end; production still needs staged enforce rollout and optional stronger sandbox runtimes.
- Phase B (Phase 1 commercialization baseline) is shipped: Core presets, metering, audit export, deploy UX — verify with `bash tools/test_mcp_proxy_phase_b.sh`.
- The highest remaining gaps are **enterprise governance** (Sprint 4) and **SOC integration and HA** (Sprint 5)—not foundational proxy, Sprint 1–3 policy logic, or Phase B Core MVP.
- Rust migration should remain tactical and profiling-driven until a real bottleneck is proven.
