<p align="center">
  <a href="https://github.com/marifort">
    <img src="docs/marifort-company-badge.png" alt="Marifort" width="128" height="128" />
  </a>
</p>
<p align="center">
  <strong>Marifort SOC Governance</strong>
</p>

# SOC Governance

Policy, human-gated response, and case/forensics around an agentic SIEM.

Language models can now **query a SIEM and fire active responses** (block an IP, isolate a host,
quarantine a file) through MCP. This repository adds the missing layer: **which caller may invoke
which tool, with which arguments; a human approval gate before writes; and an audit trail that
survives the call.**

It is **not** a from-scratch MCP SIEM server. The tool surface is a fork of
[gensecaihq/Wazuh-MCP-Server](https://github.com/gensecaihq/Wazuh-MCP-Server) at **v4.2.1** (MIT).
Everything listed under Original work below is Marifort's.

Related: [Marifort Gate](https://github.com/marifort/rag-protection) governs what an AI may **read**.
The MCP tool-call gateway lives in-tree at [`mcp-security-proxy/`](mcp-security-proxy/). This repo is
the full SOC stack around that gateway.

```text
MCP client (agent / LLM)
        │
        ▼
  MCP security proxy     allow | challenge | deny  + audit
        │
        ▼
  Wazuh MCP server       50+ SIEM / active-response tools  (fork)
        │
        ├── Phase 2 LangChain     read-only triage / enrich / handoff
        ├── Phase 3 LangGraph     propose → human approve → execute → verify
        └── Phase 4               incidents, Neo4j forensics, OpenCTI, ML
```

## Original work

| Layer | What it is |
|---|---|
| **MCP security proxy** (`mcp-security-proxy/`) | Per-call policy on MCP JSON-RPC: method allowlist, denied tools, argument inspection, tool-intent verification, shadow→enforce, versioned policy |
| **Phase 2** | LangChain analyst synthesis with deterministic fallback |
| **Phase 3** (`services/phase3_langgraph/`) | Guarded autonomous workflow with a **human approval gate** |
| **Phase 4** | Postgres incidents/SLA, Neo4j forensic graph, STIX/OpenCTI client, XGBoost models, SOC UI |
| **Isolated executor** | Sidecar for constrained tool execution (demo allow-list — not gVisor) |
| **AgentGuard** (`agentic-ai-firewall/`) | Inbound/outbound LLM firewall — **Apache-2.0**, not MIT |
| **Full-stack compose** | Local Wazuh + MCP + Open WebUI + overlays for Phase 3/4/OpenCTI |

The MCP Python package is still named `wazuh_mcp_server` so the fork stays import-compatible.

## Quick start (demo SIEM + MCP)

Docker Desktop 4.40+ with Model Runner enabled. Demo Wazuh credentials are the upstream image
defaults — **local only**.

```bash
cp .env.example .env
# set MCP_API_KEY (openssl rand -hex 32) before exposing anything
docker compose -f compose.full.yml up -d --build
```

- Open WebUI: http://localhost:3100
- Wazuh Dashboard: https://localhost:8443 (self-signed)
- MCP: http://localhost:3000/mcp

Forked MCP server walkthrough (tools, Claude Desktop, air-gap): [docs/WAZUH_MCP_FORK.md](docs/WAZUH_MCP_FORK.md).

### Overlays

```bash
# Human-gated write workflow
docker compose -f compose.full.yml -f compose.phase3.langgraph.yml up -d

# Incidents + Neo4j forensics + SOC UI (Neo4j Community)
docker compose -f compose.full.yml -f compose.phase4.yml up -d

# Optional OpenCTI (pulls published images; this repo does not vendor OpenCTI source)
docker compose -f compose.full.yml -f compose.phase4.yml -f compose.opencti.yml up -d
```

Phase 4 SOC UI: http://localhost:8082

### Proxy only

```bash
cd mcp-security-proxy
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn mcp_security_proxy.app:app --port 8090
```

Or run the gateway from this tree (`mcp-security-proxy/`) as above.

## Tests

```bash
cd mcp-security-proxy && pip install -r requirements.txt -r requirements-dev.txt && pytest -q
```

## Licence

**MIT** — Copyright (c) 2026 **Marifort Systems Inc.** and Copyright (c) 2024 **Wazuh MCP Server
Contributors**. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

`agentic-ai-firewall/` remains **Apache-2.0**.
