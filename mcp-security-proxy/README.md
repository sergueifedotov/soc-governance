# MCP Security Proxy

Policy enforcement for Model Context Protocol tool calls.

A reverse proxy that sits in front of any MCP server and decides — per call — whether a tool
invocation is allowed, challenged, or denied, then records the decision.

MCP servers expose real capability to language models: run a query, send a message, block an IP,
isolate a host. The protocol authenticates the *connection*, but it has no opinion about which caller
may invoke which tool, with which arguments. This proxy adds that layer without modifying the
upstream server.

```text
MCP client (agent / LLM)
        │
        ▼
  MCP Security Proxy  ──►  policy: method allowlist, tool deny, argument checks,
        │                          risk score, intent verification
        │                          → allow | challenge | deny  (+ audit event)
        ▼
  Upstream MCP server
```

## What it enforces

| Control | Behaviour |
|---|---|
| **Method allowlist** | Only permitted JSON-RPC methods reach the upstream server |
| **Tool deny list** | Named tools are blocked outright |
| **Argument inspection** | Suspicious argument patterns are blocked or challenged |
| **Risk scoring** | Optional model-based scoring of a call before it executes, with operator-set challenge and deny thresholds |
| **Tool Intent Verification** | Requires per-request intent metadata and validates it against the call; three independent deny paths |
| **Phased rollout** | Shadow (observe only) → 20% → 50% → 100% enforcement, so policy can be introduced without breaking a live deployment |
| **Policy versioning** | Every policy change is versioned with history and a proposal workflow |
| **Audit** | Denied and challenged calls are retained with provenance and surfaced in the console |

The default `config/policy.json` denies the destructive tools from a Wazuh MCP server (block IP,
isolate host, quarantine a file, …). That is an example policy, not a dependency — point
`MCP_PROXY_UPSTREAM_URL` at any MCP server and edit the deny list.

## Interfaces

| Path | Purpose |
|---|---|
| `/mcp` | Proxied MCP JSON-RPC endpoint |
| `/ui` | Operator console — policy editing, denied-call feed, rollout controls |
| `/docs` | OpenAPI documentation |
| `/metrics` | Prometheus metrics |

## Quick start

### Python

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn mcp_security_proxy.app:app --host 0.0.0.0 --port 8090
```

Open `http://localhost:8090/ui`.

### Docker

```bash
cp .env.example .env      # set MCP_PROXY_UPSTREAM_URL and the API keys
docker compose up --build
```

For the full SOC stack (Wazuh + Phase 4 Alerts), use repo-root
`bash tools/start-profile.sh C` after setting a valid `wazuh_` `MCP_API_KEY` in the
**repo** `.env`. See [../docs/OPERATIONS.md](../docs/OPERATIONS.md#first-run-local-stack).
The proxy compose project does not load that file unless the profile wrapper (or
`--env-file`) passes it.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `MCP_PROXY_UPSTREAM_URL` | `http://host.docker.internal:3000/mcp` | Upstream MCP server |
| `MCP_PROXY_API_KEY` | — | Bearer token clients must present to the proxy |
| `MCP_PROXY_UPSTREAM_API_KEY` | — | Bearer token the proxy presents upstream |
| `MCP_PROXY_POLICY_FILE` | `config/policy.json` | Policy file location |
| `MCP_PROXY_LLM_API_KEY` | — | Optional risk-scoring model credentials |

Replace every `*_change_me` placeholder before exposing this beyond localhost.

## Tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

## Origin

This proxy was developed while operating a deployment of the open-source
[Wazuh MCP Server](https://github.com/gensecaihq/Wazuh-MCP-Server), which exposes destructive security
actions — block an IP, isolate a host, kill a process, quarantine a file — as MCP tools. That is what
made per-call authorization the interesting problem. The proxy contains no upstream code and works in
front of any MCP server.

Related: [rag-protection](https://github.com/marifort/rag-protection) enforces identity-based document
authorization on AI *retrieval*. This proxy governs AI *actions*. The full SOC stack this proxy was
extracted from is [soc-governance](https://github.com/sergueifedotov/soc-governance) (Phase 2–4, LangGraph
approval gate, Neo4j/OpenCTI). Same pattern — identity and policy, decision, audit trail — at two
layers, plus the SIEM workflow around them.

## License

MIT — Copyright (c) 2026 [Serguei Fedotov](https://github.com/sergueifedotov)
