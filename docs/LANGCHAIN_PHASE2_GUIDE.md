# LangChain Phase 2 Guide

Comprehensive record of the recent LangChain discussion and implementation decisions for Phase 2 SOC orchestration.

## Why this document exists

This guide captures the practical outcomes of the LangChain conversation:

- what LangChain does in this repository
- what LangChain does not do in this repository
- how the Phase 2 LLM path is configured
- how to verify whether a real LLM call happened
- how to test, troubleshoot, and automate verification

## Final architecture decision

LangChain is used as a focused synthesis layer for Phase 2 read-only workflows.

- Core MCP server responsibilities remain unchanged: protocol serving, authentication, validation, and tool execution.
- Wazuh data retrieval remains deterministic.
- LangChain is invoked only to generate analyst-facing summary text from the collected facts.
- If LangChain is unavailable or disabled, workflows fall back to deterministic summaries.

This keeps reliability high while improving analyst readability.

## What LangChain is doing here

LangChain is integrated into the Phase 2 workflow layer to summarize already-collected data.

The three Phase 2 tools are:

- triage_wazuh_alerts
- enrich_wazuh_context
- generate_soc_handoff_report

For each tool, the system:

1. gathers Wazuh data using normal tool logic
2. builds a structured payload
3. attempts LangChain synthesis when enabled/configured
4. returns both structured data and summary metadata

The output includes:

- data.analysis (analyst-facing summary)
- data.orchestration.engine (langchain or deterministic)
- data.orchestration.status (reason or mode)
- data.orchestration.model and base_url when LangChain succeeds

## What the LLM generates per tab

All three tools use the same LangChain chain structure. The system prompt is:

> You are a SOC analyst assistant. Summarize only the provided Wazuh facts. Do not invent additional events, hosts, or indicators. Keep the answer concise and operationally useful.

The human prompt template is:

> Workflow: {workflow} / Objective: {objective} / Provide: 1. A short analyst summary. 2. The most important findings. 3. Recommended read-only next steps only. / Facts: {payload}

The `{payload}` passed to the LLM differs per tool:

### triage_wazuh_alerts (Triage tab)

**Objective sent to LLM:** Prioritize recent Wazuh alerts for analyst review.

**Facts passed:** severity breakdown counts, top 5 rules (id/description/count), top 5 agents, top 5 source IPs, agent health statuses, 10 sample alerts.

**LLM output:** analyst summary of alert volume and severity mix, the most significant rules and agents, and read-only next steps. Displayed as the `📝 Triage Analysis` card.

Everything else in the tab (severity breakdown table, top rules table, top agents table, top source IPs table, agent health table, sample alerts table, recommended next steps list, CVE table) is deterministically computed in Python and does not involve the LLM.

### enrich_wazuh_context (Enrich tab)

**Objective sent to LLM:** Enrich a Wazuh investigation with related alert, agent, vulnerability, and indicator context.

**Facts passed:** matching alerts (up to 10), match count, applied filters (time_range, query, rule_id, agent_id, srcip), alert patterns, top threats, and — if `agent_id` was supplied — agent health and vulnerability list for that specific agent.

**LLM output:** contextual narrative tying together matching alerts, threat patterns, and (optionally) agent-specific CVE exposure. Displayed as the `📝 Enrichment Analysis` card.

Everything else in the tab (matching alerts table, top threats table, alert patterns, indicator context, recommended next steps, CVE table) is deterministic.

### generate_soc_handoff_report (SOC Report tab)

**Objective sent to LLM:** Generate a read-only SOC handoff report from Wazuh health, threat, and vulnerability signals.

**Facts passed:** connection status, cluster health, running agents list, alert summary by level, top 5 threat rules, manager error logs (last 20), and 10 critical CVEs.

**LLM output:** shift-handoff narrative covering the overall security posture across all collected data sources. Displayed as the `📝 Analysis` card.

Everything else in the report tab (executive summary bullets, recommendations list, alert breakdown, agents section, top threats section, critical vulnerabilities CVE table, manager section) is deterministic.

### When LLM is disabled

If `PHASE2_LLM_ENABLED=false` or LangChain is not configured, the `analysis` field falls back to a short deterministic string built from the same payload data. The `orchestration.engine` field shows `deterministic` instead of `langchain` so you can confirm which path ran.

## What LangChain is not doing here

LangChain is not replacing the MCP protocol layer.

It does not handle:

- transport
- token validation
- scope enforcement
- Wazuh API safety controls
- tool registration

Those remain in the core server.

## Does the flow query an LLM?

Yes, when the orchestration engine is langchain.

- A tools/call request to triage_wazuh_alerts triggers Phase 2 logic.
- If configuration is valid and dependencies are available, LangChain calls the configured OpenAI-compatible endpoint.
- If not, deterministic fallback is used.

How to verify quickly:

- data.orchestration.engine = langchain means an LLM path was used
- data.orchestration.engine = deterministic means fallback path was used

## Configuration used for LangChain Phase 2

Set these environment variables:

```env
PHASE2_LLM_ENABLED=true
PHASE2_LLM_MODEL=ai/gemma3-qat:latest
PHASE2_LLM_BASE_URL=http://model-runner.docker.internal/engines/v1
PHASE2_LLM_API_KEY=not-needed
PHASE2_LLM_TIMEOUT_SECONDS=45
```

Notes:

- The base URL is OpenAI-compatible and works with local model serving patterns.
- If any required setting is missing, fallback mode is used.

## Example call that triggers Phase 2 LangChain path

```bash
MCP_KEY=$(grep '^MCP_API_KEY=' .env | cut -d= -f2-)

curl -sS http://localhost:3000/ \
  -H "Authorization: Bearer $MCP_KEY" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"phase2-triage","method":"tools/call","params":{"name":"triage_wazuh_alerts","arguments":{"time_range":"24h","min_level":10,"limit":20,"include_agent_health":true}}}' \
  | python3 -m json.tool
```

## Run Phase 2 LangChain calls via Open WebUI

Yes. You can run the same Phase 2 tool flow from Open WebUI instead of using curl.

1. Start full stack:

```bash
./tools/project_start.sh --full
```

For real-data validation (without synthetic Apache demo alerts), use:

```bash
./tools/project_start.sh --full --no-demo
```

2. Open Open WebUI at http://localhost:3100 and sign in as admin.

3. Add the MCP server in Open WebUI:
- Admin Settings -> Tools -> Add MCP Server
- URL: `http://wazuh-mcp-server:3000/mcp`
- Auth type: Bearer
- Token: value of `MCP_API_KEY` from `.env`
- Save and enable the server

4. Open a new chat and make sure tool usage is enabled for the model.

5. Paste this prompt in chat:

```text
Run the MCP tool triage_wazuh_alerts with:
- time_range: 24h
- min_level: 10
- limit: 20
- include_agent_health: true

Then provide:
1) top security findings,
2) likely attack patterns,
3) prioritized SOC actions.
```

6. Confirm LangChain path was used by checking tool output metadata:
- `orchestration.engine` should be `langchain`
- `orchestration.status` should indicate LangChain synthesis enabled
- `analysis` should be present and non-empty

7. If it shows `deterministic`, troubleshoot with:
- `PHASE2_LLM_ENABLED=true`
- `PHASE2_LLM_MODEL` and `PHASE2_LLM_BASE_URL` values
- MCP logs: `docker compose -f compose.full.yml logs wazuh-mcp-server`

Expected indicators in the returned payload:

- isError: false
- analysis exists and is non-empty
- orchestration.engine: langchain
- orchestration.status: LangChain synthesis enabled

Fallback example:

```json
{
  "engine": "deterministic",
  "status": "PHASE2_LLM_ENABLED is false"
}
```

## Verifier script and smoke testing

Single-command verifier:

```bash
./tools/verify_phase2_langchain.sh
```

Setup-tolerant mode:

```bash
./tools/verify_phase2_langchain.sh --allow-deterministic
```

What the script validates:

1. MCP health endpoint
2. successful triage_wazuh_alerts call
3. parseable payload with analysis
4. expected orchestration engine mode

Supported options:

- --allow-deterministic
- --base-url
- --help

Environment overrides:

- MCP_API_KEY
- MCP_BASE_URL
- PHASE2_TEST_TIME_RANGE
- PHASE2_TEST_MIN_LEVEL
- PHASE2_TEST_LIMIT
- PHASE2_TEST_INCLUDE_AGENT_HEALTH

Exit codes:

- 0 success
- 2 missing dependency/config
- 3 request or tool-call failure
- 4 unexpected payload format
- 5 orchestration engine mismatch

## Step-by-step build/run/test flow

1. copy env template and set required values
2. enable PHASE2_LLM_* variables
3. build and start stack
4. verify /health
5. run verifier script
6. run manual triage/enrichment/report calls
7. confirm analysis and orchestration fields

Detailed flow is also available in TROUBLESHOOTING.md.

## Troubleshooting highlights from the implementation

If LangChain does not activate:

1. confirm PHASE2_LLM_ENABLED is true
2. confirm PHASE2_LLM_MODEL and PHASE2_LLM_BASE_URL are set
3. inspect orchestration.status in response
4. inspect MCP container logs for import/runtime errors

A previous runtime blocker encountered during migration was missing packaging dependency in the container environment, which prevented LangChain imports from loading.

## Relationship to framework strategy

This LangChain integration does not change the broader guidance:

- keep MCP server stable and security-focused
- use orchestration incrementally
- preserve clean fallback behavior
- evolve to larger orchestration patterns only when SOC workflow complexity requires it

See FRAMEWORKS_FAQ.md for broader LangChain vs LangGraph vs OpenClaw tradeoffs.
