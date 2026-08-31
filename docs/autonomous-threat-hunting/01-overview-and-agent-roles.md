# Overview and Agent Roles

← [Back to index](../AUTONOMOUS_THREAT_HUNTING_LOCAL_LLM.md)

---

# Autonomous Threat Hunting with Local LLM

This document defines how to implement autonomous threat hunting in this
repository using a local LLM while preserving deterministic controls and
operator safety.

Quick links:

- [Pre-call risk scoring operator checklist (one-page)](#pre-call-risk-scoring-operator-checklist-one-page)

Build a repeatable, policy-governed threat hunting agent that:

- Uses a local LLM for planning and synthesis
- Uses MCP/REST tools for evidence collection
- Escalates to analyst or response workflows when justified

## 2. What the AI Agent Is in This Project
In this stack, the autonomous agent is not only the model.
policy gates + persistent workflow state.
### Runtime roles

- `phase3-langgraph` is the agent runtime (state machine, branching, retries,
  checkpoints, approval gates).
- Docker Model Runner local model is the reasoning engine (hypothesis planning,
  evidence synthesis).
- MCP tools are the execution surface (data retrieval and optional response
  actions).
- Deterministic policy logic is the final authority for high-impact actions.
## 3. Current Building Blocks Already Available

This repository already contains most required components:

- Local LLM via Docker Model Runner + Open WebUI integration
- Phase 3 LangGraph workflow runtime (`services/phase3_langgraph/`)
- Phase 2 and Phase 4 SOC retrieval/synthesis APIs
- LLM operational safety metrics in Phase 4:
  - fallback rate
  - verdict divergence

