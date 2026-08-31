# AI Frameworks FAQ for SOC Automation

Questions and answers about framework choices for Wazuh MCP Server deployments.

This document summarizes the framework discussion around this project and explains where each option fits in a security operations architecture.

---

## 1) Should this project use LangGraph?

**Short answer:** Usually no for the core server.

This repository is a production MCP tool server focused on:
- MCP protocol compliance
- Authentication and authorization
- Input validation and rate limiting
- Safe execution of Wazuh tools

LangGraph is best for stateful, multi-step agent orchestration (branching workflows, checkpoints, human approval nodes). That is a different concern than serving MCP tools.

It is a good fit only if you need all of the following:
- explicit workflow state
- branching investigation logic
- resumable executions and checkpoints
- human approval steps inside an agent graph

**Recommendation:** If you need workflow orchestration, run LangGraph in a separate companion service that calls this MCP server.

**Why not in the core server:**
- It adds workflow complexity to a component that should stay protocol-focused.
- It introduces another stateful runtime into a service whose main job is exposing Wazuh tools reliably.
- It does not improve MCP compatibility, auth, or tool execution by itself.

**Decision rule:**
- If the client already chooses tools effectively, do not add LangGraph.
- If you need deterministic multi-step investigations or response workflows, add it outside the MCP server.

---

## 2) Should this project use LangChain?

**Short answer:** Not in the core MCP server.

LangChain can be useful for:
- Prompt templates
- Model/provider abstraction
- RAG pipelines
- Simple tool chains
- Output parsing and structured responses
- Lightweight retries and chain composition

But those concerns are client/orchestrator-side, not MCP server-side. Adding LangChain directly to the core server increases dependency and operational complexity without improving protocol serving.

**Recommendation:** Use LangChain in a separate orchestration app if needed.

**Where LangChain makes sense:**
- summarizing Wazuh investigations
- adding RAG over runbooks, playbooks, or internal docs
- normalizing access to different local or hosted model providers
- building simple analysis assistants on top of this MCP server

**Where it does not add much value here:**
- transport handling
- authentication
- tool catalog exposure
- Wazuh API execution safety

**Practical comparison with LangGraph:**
- Choose LangChain for lightweight composition, prompts, and RAG.
- Choose LangGraph when you need explicit workflow state and branching control.

---

## 3) What is OpenClaw and does it fit this project?

OpenClaw is an agentic SOC orchestration runtime. It can coordinate multi-step security workflows such as triage, investigation, and response planning.

**Fit with this repo:** Good as a companion layer.

- Keep this repository as the MCP backend exposing Wazuh tools.
- Use OpenClaw externally to orchestrate those tools into playbooks.

**Do not embed OpenClaw inside this MCP server.** Keep the boundaries clean:
- MCP server = tool surface and safety controls
- OpenClaw = orchestration and automation logic

**Why OpenClaw fits SOC needs well:**
- It maps more naturally to SOC workflows than general-purpose AI frameworks.
- It is better aligned with triage, investigation, case handling, and response planning.
- It can use this MCP server as a tool backend without changing the server's core design.

**Representative orchestration responsibilities:**
- alert triage
- correlation across related alerts
- multi-step investigation pivots
- response planning with rollback context
- reporting and case summaries

**Why it should remain separate:**
- It is stateful and workflow-heavy.
- It may use different runtime assumptions and dependencies than the Python MCP server.
- Keeping the MCP server independent preserves a clean fallback path for Open WebUI, Claude, or any other MCP client.

---

## 4) Can OpenClaw be fully offline (air-gapped)?

**Yes, with constraints.**

A fully offline deployment requires all critical parts to be local:
- Local model inference endpoint (for example Docker Model Runner, Ollama, vLLM, SGLang, or LM Studio)
- Local OpenClaw runtime
- Local Wazuh MCP Server
- Local storage/queue/state

Useful offline stack shape:
- OpenClaw local
- Wazuh MCP Server local
- Open WebUI local
- Docker Model Runner or another local model server
- All traffic restricted to localhost or a private Docker network

Disable internet-dependent features such as:
- External messaging channels
- Web search/browser/fetch tools
- Cloud model providers and cloud OAuth
- Remote skill registries and auto-update paths

**Important caveats:**
- Models must already be pulled or staged locally.
- Some optional features may be documented with internet-connected assumptions.
- Offline mode is viable, but often with a reduced feature set unless you replace cloud-facing components with local equivalents.

**Practical summary:** OpenClaw can be air-gapped in a meaningful SOC deployment if you deliberately keep models, tools, skills, and storage local and disable any internet-dependent integration paths.

---

## 5) What is DefenseClaw and how is it different from OpenClaw?

DefenseClaw is a governance and policy enforcement layer for agentic systems.

- OpenClaw focuses on orchestration and execution.
- DefenseClaw focuses on admission controls, policy checks, guardrails, and auditability.

Think of DefenseClaw as a security control plane around agents, not as a replacement for this MCP server.

**In practical terms:**
- OpenClaw decides what workflow to run.
- DefenseClaw decides what should be allowed, blocked, reviewed, or audited.

For a Wazuh environment, that distinction matters because this project exposes both read-only investigation tools and high-impact active response tools.

---

## 6) Should DefenseClaw be used with this project?

**It depends on autonomy and compliance requirements.**

Use DefenseClaw when:
- Agents can perform high-impact actions (block IP, isolate host, kill process, disable user)
- You need auditable approvals and policy enforcement
- You operate in regulated SOC environments
- You want explicit controls over which tools and arguments an agent may use

Skip or defer DefenseClaw when:
- You are in a small lab setup
- A human manually reviews every action in chat
- You do not need enterprise governance yet

**Why it can be valuable with this repo:**
- It is well matched to guardrails around active response.
- It can help enforce argument-level safety around sensitive Wazuh actions.
- It provides an evidence trail for agent decisions and tool use.

**Why it should not be embedded in this MCP server:**
- Governance belongs around the orchestrator or agent runtime.
- This server should remain the authoritative MCP tool backend, not become a policy engine for other runtimes.

---

## 7) Can DefenseClaw run fully offline?

**Generally yes, if deployed correctly.**

For air-gapped operation:
- Keep scanning, policy, storage, and telemetry local
- Disable cloud integrations
- Pre-bundle dependencies and policy artifacts

As with any governance platform, verify the exact feature set you enable does not require internet access.

**Offline expectation:**
- strong fit for internal or regulated SOC environments
- especially useful where agent actions need governance without cloud dependencies

---

## 8) What framework fits SOC needs best for this project?

**Best practical architecture is layered, not single-framework:**

1. **Core layer (this repo):** Wazuh MCP Server for secure tool serving
2. **Automation layer:** OpenClaw (or another orchestrator) for triage/investigation workflows
3. **Governance layer (optional but recommended for autonomy):** DefenseClaw for policy gates and audit trails

If choosing one addition first for SOC value, start with **OpenClaw** as a companion service.

**If forced to choose a single framework answer:**
- OpenClaw is the best fit for SOC workflow value.
- LangChain and LangGraph are more general-purpose building blocks.
- DefenseClaw is a governance layer, not the primary automation runtime.

---

## 9) When should I keep the current stack without adding frameworks?

Keep current architecture (Open WebUI + local model + Wazuh MCP Server) when:
- Team is chat-driven and human-in-the-loop
- Automation depth is low
- You prioritize simplicity and stability

This is often the right default for early-stage SOC AI adoption.

**This is especially sensible when:**
- you are still validating prompt quality and tool selection
- users mainly want conversational access to Wazuh data
- you do not want a second operationally complex AI service yet

---

## 10) What is a safe adoption path?

1. Start with MCP server + Open WebUI and validate tool quality.
2. Add orchestrator workflows for read-only tasks first (triage, enrichment, reporting).
3. Introduce write actions (active response) only behind approvals.
4. Add governance controls (DefenseClaw or equivalent) before broad autonomous response.
5. Keep offline mode strict by disabling internet-dependent features.

**Suggested maturity path:**
- Phase 1: Open WebUI + local model + Wazuh MCP Server
- Phase 2: Add orchestration for triage, enrichment, and reporting
  This phase should stay read-only and focus on analyst acceleration rather than autonomous action. Typical Phase 2 workflows include:
  - triaging fresh alerts by severity, rule group, agent, and time window via `triage_wazuh_alerts`
  - enriching alerts with related events, agent context, vulnerability context, and recent patterns via `enrich_wazuh_context`
  - correlating repeated activity such as brute-force attempts, web attack probes, or malware indicators across hosts
  - generating investigation summaries, case notes, and shift-handoff reports via `generate_soc_handoff_report`
  - producing daily or hourly SOC reports from Wazuh findings without executing active response

  Scripting demo (end-to-end Phase 2 orchestration):

  Run the built-in script to execute triage, enrichment, and report generation in sequence:

  ```bash
  chmod +x ./tools/demo_phase2_orchestration.sh
  ./tools/demo_phase2_orchestration.sh
  ```

  Example with explicit filters for recent activity:

  ```bash
  PHASE2_DEMO_TIME_RANGE=1h \
  PHASE2_DEMO_MIN_LEVEL=3 \
  PHASE2_DEMO_TRIAGE_LIMIT=5 \
  PHASE2_DEMO_ENRICH_QUERY="sqlmap OR nikto OR wp-login.php" \
  ./tools/demo_phase2_orchestration.sh
  ```

  The demo prints orchestration engine, model/status, counts, and short analysis previews for all three workflows.
- Phase 3: Add guarded write actions with approvals
- Phase 4: Add governance and policy enforcement for scaled autonomous operations

---

## 11) What is the recommended architectural boundary?

The clean separation is:

- **Wazuh MCP Server:** exposes secure, validated Wazuh tools
- **Open WebUI or Claude Desktop:** human-facing conversational clients
- **OpenClaw or another orchestrator:** automation and playbook execution
- **DefenseClaw or equivalent:** policy enforcement, admission control, and audit trail

This keeps the system understandable and easier to operate:
- if the orchestrator fails, the MCP server still works
- if governance rules change, the tool backend does not need redesign
- if clients change, the MCP server remains reusable

---

## 12) What are the main tradeoffs by framework?

### LangChain
- **Strengths:** simple composition, RAG, prompt tooling, model abstraction
- **Weaknesses:** not SOC-specific, limited value inside the MCP server itself

### LangGraph
- **Strengths:** explicit graph control, checkpoints, branching workflows, approval steps
- **Weaknesses:** more complexity, still requires you to build the SOC logic yourself

### OpenClaw
- **Strengths:** stronger alignment with SOC automation, triage, investigation, and response workflows
- **Weaknesses:** additional operational complexity, should remain a separate service

### DefenseClaw
- **Strengths:** governance, policy gates, argument-level guardrails, auditability
- **Weaknesses:** can be overkill for a small human-in-the-loop deployment

---

## 13) What is the simplest decision rule?

- If you want reliable MCP tool serving, keep this repo focused and do not add an AI framework in-core.
- If you want basic prompt pipelines or RAG, use LangChain externally.
- If you want stateful agent workflows, use LangGraph externally.
- If you want SOC-native automation first, choose OpenClaw externally.
- If agents will take risky actions, add DefenseClaw or an equivalent governance layer.

---

## 14) Can Phase 2 use LangChain, LangGraph, or OpenClaw?

Yes. All three can support Phase 2, but they solve different versions of the problem.

- **LangChain** fits Phase 2 when the workflow is mostly read-only enrichment, summarization, report generation, and optional RAG over runbooks or playbooks.
- **LangGraph** fits Phase 2 when the workflow needs explicit state, branching logic, resumability, or durable checkpoints.
- **OpenClaw** fits Phase 2 when you want a SOC-native companion runtime that can evolve into larger automation and investigation pipelines.

The main question is not whether they can be used. The real question is how much orchestration complexity Phase 2 actually needs.

---

## 15) Which framework was chosen for the implemented Phase 2 in this repository?

Phase 2 in this repository was migrated to a **LangChain-backed** solution.

The implementation keeps the Wazuh data collection deterministic and read-only, then uses LangChain to synthesize analyst-facing summaries when configured.

Current implementation characteristics:
- structured Wazuh retrieval still happens through the core MCP tool layer
- LangChain is used for the analyst-facing synthesis step
- output remains read-only
- if the Phase 2 LLM is not configured, the workflows fall back to deterministic summaries

This is intentionally a lightweight migration, not a full agent runtime embedded into the MCP server.

---

## 16) Why was LangChain chosen over LangGraph or OpenClaw for the in-repo Phase 2 implementation?

LangChain was the best fit for an in-repo migration because it provides the most value with the least architectural disruption.

Reasons:
- Phase 2 is still read-only and linear enough that a full graph runtime would be unnecessary overhead.
- The existing helper logic already collected the right Wazuh facts; what was missing was a better synthesis layer.
- LangChain makes it easy to connect to a local OpenAI-compatible endpoint and turn structured results into analyst summaries.
- It preserves the ability to move to LangGraph or OpenClaw later without discarding the underlying Wazuh tool logic.

In other words:
- **LangChain** is the smallest useful upgrade.
- **LangGraph** would make more sense if Phase 2 grows into a durable branching workflow engine.
- **OpenClaw** would make more sense if Phase 2 becomes part of a broader SOC automation platform.

---

## 17) What does the current LangChain-backed Phase 2 actually do?

The current Phase 2 implementation supports three read-only workflows:

- `triage_wazuh_alerts`
  Aggregates recent alerts by severity, rule, agent, and source IP, then produces an analyst-facing triage summary.

  ### Detailed Breakdown: `triage_wazuh_alerts`

  #### Workflow Diagram

  ```mermaid
  flowchart TD
      A[triage_wazuh_alerts invoked] --> B[Validate inputs]
      B --> C[Fetch recent alerts from Wazuh]
      C --> D[Aggregate and normalize]
      D --> D1[Severity buckets]
      D --> D2[Top rules]
      D --> D3[Top agents]
      D --> D4[Top source IPs]
      D --> D5[Optional agent health]
      D1 --> E[Build structured triage payload]
      D2 --> E
      D3 --> E
      D4 --> E
      D5 --> E
      E --> F[Generate analyst summary]
      F --> G{LangChain enabled?}
      G -- Yes --> H[LLM synthesis]
      G -- No --> I[Deterministic fallback summary]
      H --> J[Return data + analysis + orchestration]
      I --> J
  ```

  #### Code-level Walkthrough

  1. Entry and dispatch
  - Tool name `triage_wazuh_alerts` is dispatched by the Phase 2 MCP tool handler in [src/wazuh_mcp_server/mcp/tool_handlers/phase2.py](src/wazuh_mcp_server/mcp/tool_handlers/phase2.py).

  2. Core triage builder
  - The handler calls the triage builder in [src/wazuh_mcp_server/phase2.py](src/wazuh_mcp_server/phase2.py), where the read-only triage payload is assembled.

  3. Data collection
  - Recent alerts are retrieved using validated parameters such as `time_range`, `min_level`, and `limit`.

  4. Aggregation
  - Alerts are grouped into severity distribution.
  - Top triggered rules are counted.
  - Top affected agents are counted.
  - Top source IPs are counted.
  - Optional agent health is attached for highest-priority entities.

  5. Payload construction
  - A structured `data` payload is created for downstream automation and analyst consumption.
  - Deterministic recommended next steps are included.

  6. Analyst summary synthesis
  - If Phase 2 LLM synthesis is enabled, LangChain generates a concise analyst narrative.
  - If not enabled (or unavailable), deterministic fallback summary is returned.
  - The selected path is reflected in the `orchestration` block.

  7. Final output contract
  - Returns:
    - `data`: structured triage payload
    - `analysis`: analyst-facing summary text
    - `orchestration`: engine and status metadata

  #### Example Output Shape

  ```json
  {
    "data": {
      "workflow": "phase2_alert_triage",
      "time_range": "1h",
      "minimum_level": 3,
      "total_alerts": 12,
      "severity_breakdown": {"critical": 2, "high": 5, "medium": 3, "low": 2},
      "top_rules": [],
      "top_agents": [],
      "top_source_ips": [],
      "agent_health": [],
      "sample_alerts": [],
      "recommended_next_steps": []
    },
    "analysis": "Concise analyst summary from LangChain or deterministic fallback",
    "orchestration": {
      "engine": "langchain",
      "status": "enabled"
    }
  }
  ```

  References:
  - [src/wazuh_mcp_server/phase2.py](src/wazuh_mcp_server/phase2.py)
  - [src/wazuh_mcp_server/mcp/tool_handlers/phase2.py](src/wazuh_mcp_server/mcp/tool_handlers/phase2.py)

- `enrich_wazuh_context`
  Collects related alerts, patterns, threat context, agent health, and vulnerability context, then summarizes the investigation pivot.

  ### Detailed Breakdown: `enrich_wazuh_context`

  #### Workflow Diagram

  ```mermaid
  flowchart TD
      A[enrich_wazuh_context invoked] --> B[Validate inputs]
      B --> C[Collect base alerts and entities]
      C --> D[Expand investigation context]
      D --> D1[Related alerts and temporal patterns]
      D --> D2[Threat indicators and IOC-style signals]
      D --> D3[Agent context and health]
      D --> D4[Vulnerability context]
      D1 --> E[Assemble structured enrichment payload]
      D2 --> E
      D3 --> E
      D4 --> E
      E --> F[Generate investigation narrative]
      F --> G{LangChain enabled?}
      G -- Yes --> H[LLM synthesis]
      G -- No --> I[Deterministic fallback summary]
      H --> J[Return data + analysis + orchestration]
      I --> J
  ```

  #### Code-level Walkthrough

  1. Entry and dispatch
  - Tool name `enrich_wazuh_context` is dispatched via the Phase 2 handler in [src/wazuh_mcp_server/mcp/tool_handlers/phase2.py](src/wazuh_mcp_server/mcp/tool_handlers/phase2.py).

  2. Core enrichment builder
  - The handler calls the enrichment builder in [src/wazuh_mcp_server/phase2.py](src/wazuh_mcp_server/phase2.py).

  3. Context expansion
  - Starts from recent or query-matched alert context.
  - Collects correlated activity and patterns.
  - Adds agent-level operational context.
  - Adds vulnerability and threat-context overlays.

  4. Payload construction
  - Produces normalized `data` output for machine use and analyst review.
  - Adds deterministic recommendations focused on next investigation pivots.

  5. Analyst narrative synthesis
  - Uses LangChain when configured for concise enrichment narrative.
  - Falls back to deterministic summary when LLM synthesis is disabled or unavailable.

  6. Output contract
  - Returns `data`, `analysis`, and `orchestration` with engine/status metadata.

  #### Example Output Shape

  ```json
  {
    "data": {
      "workflow": "phase2_context_enrichment",
      "time_range": "1h",
      "query": "sqlmap OR nikto",
      "related_alerts": [],
      "patterns": [],
      "threat_context": [],
      "agent_health": [],
      "vulnerability_context": [],
      "recommended_next_steps": []
    },
    "analysis": "Concise enrichment narrative from LangChain or deterministic fallback",
    "orchestration": {
      "engine": "langchain",
      "status": "enabled"
    }
  }
  ```

  References:
  - [src/wazuh_mcp_server/phase2.py](src/wazuh_mcp_server/phase2.py)
  - [src/wazuh_mcp_server/mcp/tool_handlers/phase2.py](src/wazuh_mcp_server/mcp/tool_handlers/phase2.py)

- `generate_soc_handoff_report`
  Collects connection health, cluster status, running agents, threat summaries, manager errors, and vulnerability data, then generates a handoff-style summary.

  ### Detailed Breakdown: `generate_soc_handoff_report`

  #### Workflow Diagram

  ```mermaid
  flowchart TD
      A[generate_soc_handoff_report invoked] --> B[Validate inputs]
      B --> C[Collect operational SOC signals]
      C --> D[Gather report components]
      D --> D1[Connection and cluster health]
      D --> D2[Agent availability and status]
      D --> D3[Threat and alert summaries]
      D --> D4[Manager errors and notable failures]
      D --> D5[Vulnerability highlights]
      D1 --> E[Build structured handoff payload]
      D2 --> E
      D3 --> E
      D4 --> E
      D5 --> E
      E --> F[Generate handoff narrative]
      F --> G{LangChain enabled?}
      G -- Yes --> H[LLM synthesis]
      G -- No --> I[Deterministic fallback summary]
      H --> J[Return data + analysis + orchestration]
      I --> J
  ```

  #### Code-level Walkthrough

  1. Entry and dispatch
  - Tool name `generate_soc_handoff_report` is dispatched by the Phase 2 handler in [src/wazuh_mcp_server/mcp/tool_handlers/phase2.py](src/wazuh_mcp_server/mcp/tool_handlers/phase2.py).

  2. Core report builder
  - Report assembly logic is implemented in [src/wazuh_mcp_server/phase2.py](src/wazuh_mcp_server/phase2.py).

  3. Signal collection
  - Pulls platform/connection health details.
  - Pulls cluster and agent status snapshots.
  - Pulls notable threat summaries and manager-side errors.
  - Pulls vulnerability highlights relevant for shift handoff.

  4. Payload construction
  - Creates a structured `data` report suitable for automation, ticketing, and shift notes.
  - Includes deterministic actionable recommendations.

  5. Narrative synthesis
  - LangChain synthesis is used when configured.
  - Deterministic summary path is used as a fallback.

  6. Output contract
  - Returns `data`, `analysis`, and `orchestration` for transparent provenance.

  #### Example Output Shape

  ```json
  {
    "data": {
      "workflow": "phase2_soc_handoff",
      "time_range": "24h",
      "connection_health": {},
      "cluster_status": {},
      "running_agents": [],
      "threat_summary": [],
      "manager_errors": [],
      "vulnerability_summary": [],
      "recommended_next_steps": []
    },
    "analysis": "Concise SOC handoff narrative from LangChain or deterministic fallback",
    "orchestration": {
      "engine": "langchain",
      "status": "enabled"
    }
  }
  ```

  References:
  - [src/wazuh_mcp_server/phase2.py](src/wazuh_mcp_server/phase2.py)
  - [src/wazuh_mcp_server/mcp/tool_handlers/phase2.py](src/wazuh_mcp_server/mcp/tool_handlers/phase2.py)

Each workflow returns:
- structured raw data for machines and downstream tooling
- deterministic recommendations
- an `analysis` field containing analyst-facing summary text
- an `orchestration` block showing whether the output came from LangChain or deterministic fallback

---

## 18) How does the LangChain Phase 2 configuration work?

Phase 2 LangChain synthesis is controlled by environment variables:

- `PHASE2_LLM_ENABLED=true`
- `PHASE2_LLM_MODEL=<model-name>`
- `PHASE2_LLM_BASE_URL=<openai-compatible-base-url>`
- `PHASE2_LLM_API_KEY=<optional-key>`
- `PHASE2_LLM_TIMEOUT_SECONDS=<seconds>`

This design assumes a local or private OpenAI-compatible endpoint, such as:
- Docker Model Runner
- Open WebUI exposing an OpenAI-compatible API
- vLLM
- another compatible local inference service

If the Phase 2 LLM settings are incomplete or disabled, the Phase 2 tools continue to work using deterministic summaries. This keeps the MCP server operational even when no Phase 2 model endpoint is available.

---

## 19) What would a LangChain-based Phase 2 architecture look like?

LangChain Phase 2 is best understood as a synthesis layer on top of deterministic Wazuh retrieval.

Typical flow:
1. Query Wazuh data using the MCP server's validated tools.
2. Build a structured payload with alerts, patterns, agent context, and vulnerability context.
3. Send only those collected facts to a LangChain prompt.
4. Ask the model to produce a concise analyst summary and read-only next steps.
5. Return both the structured data and the synthesized summary.

This gives you a strong analyst experience without turning the MCP server into a general-purpose agent runtime.

---

## 20) What would LangGraph-based or OpenClaw-based Phase 2 look like instead?

### LangGraph Phase 2

Use LangGraph when Phase 2 needs:
- explicit branching between different investigation paths
- resumable workflow state
- durable checkpoints
- more formal handoff between steps

Example flow:
- ingest recent alerts
- classify severity and category
- branch into web attack, malware, brute force, or vulnerability investigation paths
- collect different enrichment depending on branch
- generate analyst report

This is stronger for deterministic workflows, but heavier than LangChain.

### OpenClaw Phase 2

Use OpenClaw when Phase 2 is part of a larger SOC-native automation roadmap.

Example flow:
- intake recent alerts
- triage and correlate them into cases
- enrich with Wazuh MCP tools
- generate handoff notes or case summaries

This is a better long-term SOC automation path than generic frameworks, but it should remain a companion service rather than a library embedded into the MCP server.

---

## 21) What are the practical tradeoffs for Phase 2 specifically?

| Phase 2 Approach | Best Use | Complexity | Offline Fit | Migration Effort |
|------|------|------|------|------|
| Current in-repo LangChain-backed design | Read-only enrichment and summaries with minimal disruption | Low-Medium | Strong | Implemented |
| LangGraph companion service | Branching and resumable workflows | Medium-High | Strong | Medium |
| OpenClaw companion service | SOC-native orchestration roadmap | Medium-High | Good-Strong | Medium |

Summary:
- choose **LangChain** if you want the least disruptive Phase 2 upgrade
- choose **LangGraph** if you need explicit state and branching soon
- choose **OpenClaw** if Phase 2 is only the first step toward a larger SOC automation platform

---

## 22) Does the LangChain migration change the architectural guidance?

Not materially.

The project still follows the same general rule:
- keep the MCP server focused on secure Wazuh tool serving
- avoid embedding a full agent runtime into the core server
- use orchestration carefully and incrementally

The LangChain-backed Phase 2 implementation is intentionally limited in scope:
- read-only workflows only
- deterministic Wazuh data collection
- model synthesis layered on top
- fallback behavior when the LLM endpoint is unavailable

That means the broader recommendation remains valid even after the migration.

---

## 23) How should Phase 3 be implemented (guarded write actions with approvals)?

Phase 3 should introduce active response in a controlled, auditable way.

Recommended stack for this phase:
- **Execution/orchestration:** OpenClaw (or LangGraph if you prefer custom workflow engineering)
- **Tool backend:** this Wazuh MCP Server
- **Approval mode:** human-in-the-loop before any write action
- **Rollback readiness:** always pair action tools with verification and rollback tools

### Phase 3 reference flow

1. Read-only triage decides a candidate action.
2. Orchestrator creates an approval request containing evidence.
3. Analyst approves or rejects.
4. If approved, orchestrator executes one write tool.
5. Orchestrator runs verification tool.
6. If verification fails or impact is unexpected, orchestrator runs rollback tool.
7. All decisions and tool calls are logged.

### Phase 3 use cases and examples

| Use case | Action tool | Verification tool | Rollback tool | Approval pattern |
|------|------|------|------|------|
| Block recurring brute-force IP | `wazuh_firewall_drop` | `wazuh_check_blocked_ip` | `wazuh_firewall_allow` | 1 analyst approval |
| Isolate compromised endpoint | `wazuh_isolate_host` | `wazuh_check_agent_isolation` | `wazuh_unisolate_host` | 2 analysts or SOC lead |
| Quarantine suspicious malware file | `wazuh_quarantine_file` | `wazuh_check_file_quarantine` | `wazuh_restore_file` | 1 analyst + ticket ID |

### Example Phase 3 approval payload

```json
{
  "ticket_id": "INC-2026-0416-0021",
  "requested_action": "wazuh_firewall_drop",
  "requested_args": {
    "agent_id": "002",
    "src_ip": "198.51.100.27",
    "duration": 3600
  },
  "reason": "Brute-force pattern exceeded threshold in 15m window",
  "evidence": {
    "rule_ids": ["5710", "5712"],
    "event_count": 47,
    "window": "15m"
  },
  "approval": {
    "required": true,
    "approved_by": "soc.analyst.01",
    "approved_at": "2026-04-16T12:10:00Z"
  }
}
```

### Example Phase 3 execution runbook

```text
IF threshold breached (read-only detection)
  THEN request approval
  IF approved
    EXECUTE write tool
    VERIFY effect
    IF verification fails OR blast radius exceeds policy
      EXECUTE rollback tool
```

Implementation notes:
- Keep write scopes separated (`wazuh:write`) and issue short-lived credentials for action-capable agents.
- Start with a narrow allowlist of write tools and expand only after repeated successful drills.
- Require rollback drills in non-production before enabling each write workflow in production.

---

## 24) How should Phase 4 be implemented (governance and policy enforcement at scale)?

Phase 4 adds a dedicated governance layer around orchestrators and action tools.

Recommended stack for this phase:
- **Execution/orchestration:** OpenClaw (or equivalent)
- **Governance/policy:** DefenseClaw (or equivalent control plane)
- **Tool backend:** this Wazuh MCP Server

### Phase 4 governance objectives

- enforce policy before action execution (admission control)
- enforce argument-level controls (for example CIDR allowlists/denylists)
- apply risk-tier handling (auto-allow, approval-required, blocked)
- ensure full audit trail for every decision
- support regulated SOC controls (separation of duties, evidence retention)

### Phase 4 use cases and examples

| Use case | Policy behavior | Example outcome |
|------|------|------|
| Low-risk temporary firewall drop on known bad IOC feed | Auto-allow if source and duration meet policy | Action runs immediately and logs policy decision |
| Host isolation in production during business hours | Require dual approval and incident ticket | Action delayed until two approvers confirm |
| Generic active response command with unknown arguments | Deny by default | Request blocked and escalated for review |
| Repeated action bursts on same agent | Rate limit and cool-down | Requests queued or denied to reduce blast radius |

### Example Phase 4 policy model (conceptual)

```yaml
policies:
  - id: allow-temp-ip-drop
    tool: wazuh_firewall_drop
    effect: allow
    conditions:
      max_duration_seconds: 3600
      src_ip_not_in: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

  - id: isolate-host-dual-approval
    tool: wazuh_isolate_host
    effect: require_approval
    approvals_required: 2
    requires_ticket: true

  - id: block-generic-active-response
    tool: wazuh_active_response
    effect: deny
```

### Example Phase 4 decision sequence

1. Orchestrator proposes write action.
2. Governance engine evaluates tool name, arguments, actor, environment, and current risk posture.
3. Governance returns `allow`, `require_approval`, or `deny`.
4. Orchestrator follows decision and records result.
5. Post-action verification and rollback checks are enforced by policy.

### Phase 4 operational controls checklist

- mandatory ticket/case ID for all write actions
- dual approval for high-impact actions (for example host isolation)
- emergency break-glass path with stronger audit and short time window
- periodic policy simulation against historical incidents before production rollout
- immutable audit logs for policy decisions and tool arguments

At this phase, the default pattern should be:
- OpenClaw handles orchestration logic
- DefenseClaw handles policy and governance decisions
- Wazuh MCP Server remains focused on secure tool execution

---

## 25) How do I redevelop Phase 2 and Phase 3 with LangGraph (practical blueprint)?

Yes, this is a valid redesign path if you want explicit state, branching, resumability, and approvals in one workflow runtime.

Recommended boundaries:
- Keep this repository as the MCP tool backend only.
- Build a separate LangGraph companion service for orchestration.
- Keep policy/governance external (DefenseClaw or equivalent) as Phase 4.

### Phase 2 + 3 target graph

```text
START
  -> ingest_alert_context
  -> correlate_frequency_sequence
  -> risk_score
  -> branch_by_risk
      low      -> phase2_triage_summary -> END
      medium   -> phase2_enrichment -> analyst_handoff -> END
      high     -> phase2_enrichment -> propose_action -> approval_gate
                    rejected -> analyst_handoff -> END
                    approved -> execute_write_action -> verify_action
                                  failed_verify -> rollback_action -> analyst_handoff -> END
                                  passed_verify -> analyst_handoff -> END
```

### Minimal LangGraph state schema

```json
{
  "incident_id": "INC-2026-0416-1021",
  "time_range": "1h",
  "entities": {
    "agent_id": "002",
    "src_ip": "198.51.100.27",
    "user": "unknown"
  },
  "signals": {
    "frequency_score": 0.0,
    "sequence_score": 0.0,
    "severity_score": 0.0,
    "risk_tier": "medium"
  },
  "phase2": {
    "triage": null,
    "enrichment": null,
    "handoff": null
  },
  "phase3": {
    "proposed_action": null,
    "approval": {
      "required": false,
      "status": "pending",
      "approved_by": []
    },
    "execution": {
      "tool": null,
      "args": {},
      "result": null,
      "verified": false,
      "rollback_result": null
    }
  },
  "audit": {
    "events": []
  }
}
```

### Node responsibilities mapped to existing tools

| LangGraph node | Purpose | MCP tools (examples) |
|------|------|------|
| `ingest_alert_context` | Fetch incident base context | `get_wazuh_alerts`, `get_wazuh_alert_summary` |
| `correlate_frequency_sequence` | Deterministic temporal correlation | `analyze_alert_patterns`, `search_security_events` |
| `phase2_triage_summary` | Read-only triage output | `triage_wazuh_alerts` |
| `phase2_enrichment` | Read-only context expansion | `enrich_wazuh_context` |
| `analyst_handoff` | Shift/case narrative output | `generate_soc_handoff_report` |
| `propose_action` | Choose candidate action + rollback pair | local decision logic + risk policy |
| `execute_write_action` | Execute approved action | `wazuh_firewall_drop`, `wazuh_isolate_host`, `wazuh_quarantine_file` |
| `verify_action` | Confirm action effect | `wazuh_check_blocked_ip`, `wazuh_check_agent_isolation`, `wazuh_check_file_quarantine` |
| `rollback_action` | Undo failed or unsafe execution | `wazuh_firewall_allow`, `wazuh_unisolate_host`, `wazuh_restore_file` |

### Risk-to-action routing example

| Risk tier | Behavior |
|------|------|
| `low` | Phase 2 only, no write action |
| `medium` | Phase 2 + action proposal, analyst approval required |
| `high` | Phase 2 + mandatory dual approval + verification + rollback on failure |

### Approval gate contract (Phase 3)

```json
{
  "incident_id": "INC-2026-0416-1021",
  "action": "wazuh_isolate_host",
  "args": {"agent_id": "002"},
  "why": "High-confidence compromise sequence",
  "evidence": {
    "sequence": ["web_scan", "credential_access", "privilege_event"],
    "window": "30m",
    "event_count": 64
  },
  "approval_required": 2
}
```

### Migration plan from current implementation

1. Keep existing Phase 2 tools untouched in this MCP server.
2. Build LangGraph service that calls MCP `tools/call` endpoints.
3. Port current Phase 2 flow into three read-only nodes first:
   - `triage_wazuh_alerts`
   - `enrich_wazuh_context`
   - `generate_soc_handoff_report`
4. Add deterministic risk and temporal correlation node before action proposals.
5. Add approval node and one guarded write workflow (for example firewall drop).
6. Add verify + rollback nodes and test failure paths.
7. Expand to additional write actions after successful drills.

### Testing strategy for LangGraph redesign

- Unit-test node logic (risk routing, approval decisions, rollback triggers).
- Integration-test MCP tool execution for every node path.
- Add chaos tests for failures between execute and verify nodes.
- Run replay tests on historical incidents to tune thresholds.

### Go/No-Go checklist for production cutover

- all high-risk branches require explicit approval
- every write action has a paired verify tool and rollback tool
- graph checkpoints enabled for resume after failure
- audit log captures node decisions, tool args, and actor identity
- blast-radius guardrails enforced (agent scope, IP scope, duration caps)

This approach gives you:
- LangGraph strengths for Phase 2/3 workflow control
- zero disruption to MCP server tool surface
- a clean path to Phase 4 governance controls around the graph runtime

---

## 26) Should I combine LangChain and LangGraph, or rewrite everything in LangGraph?

For this project, a hybrid approach is usually better first.

Recommended pattern:
- Use **LangGraph** for workflow control (state, branching, checkpoints, approvals).
- Use **LangChain** only inside selected nodes that need LLM synthesis (triage narrative, enrichment summary, handoff text).
- Keep MCP tool execution in this server unchanged.

Why hybrid first:
- lower migration risk and faster delivery
- reuses the existing LangChain-backed Phase 2 synthesis already in place
- lets you add Phase 3 controls now without delaying on a full rewrite

When a full LangGraph rewrite makes sense:
- you need a single runtime for all orchestration and LLM-related control paths
- mixed abstractions are causing recurring debugging or observability problems
- duplicated retry/error/telemetry logic becomes expensive to maintain

Practical rule:
- If current LangChain synthesis is stable, keep it and orchestrate with LangGraph.
- If operating two abstraction layers becomes a repeated operational burden, consolidate more logic into LangGraph.

---

## 27) Do I need dedicated tracing here?

No, it is not required to proceed.

Use dedicated tracing (for example, OSS Langfuse) when you specifically need:
- deep run trace visibility for LangChain/LangGraph workflows
- prompt/version evaluation and regression tracking
- faster debugging across high execution volume

For this repository and roadmap:
- Start without dedicated tracing.
- Add it only if troubleshooting and quality validation become a recurring bottleneck.

Air-gapped and strict data-residency note:
- Treat external SaaS tracing as optional.
- Prefer local observability first: structured logs, run IDs, tool-call audit trails, and replay tests.

Adoption threshold:
- If incident volume and workflow complexity are still manageable with local logs, skip it.
- If you repeatedly cannot explain graph/chain behavior quickly, add an OSS tracing stack such as Langfuse.

---

## 28) Is there a concrete LangGraph Phase 3 implementation in this repository?

Yes. A separate companion implementation is available with its own Docker service.

Included artifacts:
- Service source: `services/phase3_langgraph`
- Compose overlay: `compose.phase3.langgraph.yml`
- Demo script: `tools/demo_phase3_langgraph.sh`
- Full guide: `docs/LANGGRAPH_PHASE3_GUIDE.md`

What it implements:
- risk-tier branching (`low`, `medium`, `high`, `critical`)
- approval-gated write actions
- execute -> verify -> rollback flow
- analyst handoff output after each path

Start command:

```bash
docker compose -f compose.full.yml -f compose.phase3.langgraph.yml up -d --build phase3-langgraph
```

This preserves the recommended boundary:
- MCP server remains focused on secure tool execution
- LangGraph runs externally as the orchestration layer

---

## Quick Decision Matrix

| Need | Best Choice |
|------|-------------|
| Stable MCP tool server | Current architecture (no framework added in-core) |
| Basic chains, RAG, prompt tooling | LangChain companion service |
| Stateful branching agent workflows | LangGraph companion service |
| SOC-native autonomous playbooks | OpenClaw companion service |
| Enterprise policy gates + audit for agent actions | DefenseClaw around orchestrator |

---

---

## 26) Does it make sense to use OpenCTI in this project?

**Short answer:** Only if you plan to wire up external threat intelligence feeds. Without them, it adds significant overhead without unique value.

### What OpenCTI is designed for

- Storing and correlating **external threat intelligence** — threat actors, campaigns, TTPs, IOC feeds
- Sharing intel via STIX/TAXII with other organizations or teams
- Enriching raw alerts with CTI context (for example: "this IP is associated with APT29")

### What it currently does in this project

- Receives Wazuh alerts converted to STIX incidents — essentially duplicating data already in the Wazuh Indexer
- No external threat intel feeds configured
- No TAXII sharing set up
- The "incidents" are re-labeled Wazuh alerts with no enrichment added

### The redundancy problem

The same alert data already lives in multiple layers without OpenCTI:

| Layer | What it stores |
|-------|---------------|
| Wazuh Indexer (Elasticsearch) | Raw alert documents |
| PostgreSQL (phase4) | Incident tickets with SLA tracking |
| Neo4j ForensicGraph | Graph relationships: ALERT → IP_ADDRESS, USER, PROCESS, FILE |
| Wazuh Dashboard | Native visualization of all the above |

OpenCTI would add a fifth copy, backed by its own Elasticsearch instance, Redis, RabbitMQ queues, and MinIO storage — roughly 7 extra containers — for data that is already searchable and visualizable.

### When OpenCTI genuinely adds value

- You plug in MISP, VirusTotal, Shodan, AbuseIPDB, or GreyNoise connectors so alerts are enriched with external threat context on arrival
- You need to link Wazuh detections to known threat actor campaigns or CVEs in a structured, STIX-queryable way
- You share threat intel via TAXII with partner organizations or other SOC teams
- You consume commercial CTI feeds and need a standardized storage and query layer

### Decision rule

| Scenario | Recommendation |
|----------|---------------|
| Dev/demo environment, no external feeds | Skip OpenCTI — use Wazuh Dashboard + Neo4j |
| Production SOC with MISP or commercial CTI feeds | Add OpenCTI as the CTI layer |
| Need to share indicators with partner orgs | Add OpenCTI for TAXII publishing |
| Just want to visualize Wazuh alerts | Wazuh Dashboard already does this natively |

### Operational note

If you keep OpenCTI running, set `POLLER_MIN_LEVEL` to `3` or lower so the background alert poller captures a meaningful percentage of Wazuh events. The default `min_level=5` filters out most synthetic and low-severity alerts, resulting in very few incidents appearing in OpenCTI even when the pipeline is healthy.

---

## Summary

For this repository, the best practice is to keep the MCP server clean and stable, then add orchestration and governance as external layers based on SOC maturity and risk tolerance.

The strongest practical recommendation from this evaluation is:
- do not embed LangChain, LangGraph, OpenClaw, or DefenseClaw into the core MCP server
- keep this project as the secure Wazuh tool backend
- add orchestration and governance around it only when your SOC maturity and automation requirements justify the extra complexity
- add OpenCTI only when you have external threat intelligence feeds to enrich it with

For a complete record of the LangChain migration, runtime behavior, verification script usage, and step-by-step testing flow, see `LANGCHAIN_PHASE2_GUIDE.md`.
