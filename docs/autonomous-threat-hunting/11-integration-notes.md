# Integration Notes for This Repository

← [Back to index](../AUTONOMOUS_THREAT_HUNTING_LOCAL_LLM.md)

---

## 15. Integration Notes for This Repository

- Primary orchestration home: `services/phase3_langgraph/app/`
- Evidence retrieval path: MCP `tools/call` via `_mcp_call`
- Existing SOC synthesis/retrieval: `src/wazuh_mcp_server/phase2.py`
- Existing LLM observability: `src/wazuh_mcp_server/phase4/server.py`
- Existing SOC UI + API aggregation: `phase4-api`

This keeps implementation aligned with current architecture: LangGraph controls
stateful automation, local LLM supports reasoning, deterministic logic controls
risk, and MCP tools provide data/action boundaries.

---

