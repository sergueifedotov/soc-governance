# AgentGuard Architecture

## Threat Model

AgentGuard is designed against a specific class of attacks: **indirect prompt injection** and **agentic tool abuse**. The trust boundary is:

- **Trusted:** Your own system prompt, your own user (authenticated), your own tools (code you wrote).
- **Untrusted:** Anything the LLM ingests from the outside world — scraped pages, emails, PDFs, file uploads, third-party API responses, RAG documents from shared corpora, MCP tool outputs.

The threat model assumes:
1. The LLM has no semantic ability to tell trusted from untrusted text apart.
2. The LLM will follow plausible-sounding instructions found in any context window slot.
3. Tool outputs the LLM consumes can be adversarial (e.g. a webpage crafted by an attacker).

## Two Layers

### Layer 1 — Inbound Guardrails (Input Sanitization)

Every untrusted chunk of text passes through `/v1/scan/input` before it reaches the LLM.

```
untrusted text ──► PromptInjectionScanner ──► URLThreatScanner ──► MLClassifier ──► PIIScanner ──► SecretsScanner
                                                                                                       │
                                                                                                       ▼
                                                                                  sanitized text + verdict
```

Scanners are **explainable** — every finding carries scanner name, category, severity, and snippet. Verdict aggregation uses max-severity with a small bump when multiple high-severity findings co-occur.

### Layer 2 — Outbound Guardrails (Action Gating)

Every proposed tool call passes through `/v1/scan/tool-call` before execution.

```
agent proposes tool ──► tool-policy lookup ──► destructive-arg scan ──► URL scan ──► intent verification
                                                                                              │
                                                                                              ▼
                                                                       allow / challenge / block
                                                                       (+ optional approval token)
```

Policy is YAML — per-tool challenge/block thresholds and `require_approval` flag. Reload at runtime via `POST /v1/admin/reload-policy`.

## Deployment Modes

| Mode | How |
|---|---|
| **SDK** | `pip install agentguard`, decorate functions with `@guard`, call `client.scan_input(...)`. |
| **Sidecar proxy** | Run as Docker container next to your agent service. Agents call `http://agentguard:8088/v1/...`. |
| **Drop-in LLM proxy** | Point your OpenAI/Anthropic SDK at `http://agentguard:8088/v1/proxy/openai` — inbound and outbound scanning happens automatically. |
| **LangChain callback** | Add `AgentGuardCallback(...)` to your `AgentExecutor`. |
| **AutoGen wrapper** | `wrap_agent(assistant, endpoint=...)`. |

## Observability

- **Prometheus:** `/metrics` exposes per-scanner counters, decision counters, risk-score histograms, and proxy upstream errors.
- **Audit log:** In-memory ring buffer (default 1000 events) at `/audit/recent`. Forward to your SIEM via a simple polling sidecar.
- **Admin UI:** `/ui` shows live events, decision counts, and a one-click policy reload.

## Performance

Per-scan latency targets (single-threaded, 8KB input):

| Scanner | Typical |
|---|---|
| PromptInjection | < 2 ms |
| PII | < 1 ms |
| Secrets | < 1 ms |
| URLThreat | < 1 ms |
| ML classifier (remote) | network-bound; default 1.5s timeout |

Aggregate input scan: typically **< 5 ms** without ML, **< 50 ms** with a remote ML classifier.

## Extending

Drop a new scanner into `agentguard/scanners/` implementing `Scanner.scan(text) -> ScannerResult` and register it in the pipeline you care about (`guardrails/input_pipeline.py` or `output_pipeline.py`).
