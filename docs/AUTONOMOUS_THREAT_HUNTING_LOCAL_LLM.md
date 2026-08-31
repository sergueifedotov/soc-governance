# Autonomous Threat Hunting with Local LLM

This document is the **index** for the autonomous threat hunting documentation.
The content has been split into focused topic files for readability.
All files live in [`docs/autonomous-threat-hunting/`](autonomous-threat-hunting/).

---

## Topics

| # | File | What it covers |
|---|------|----------------|
| 1 | [Overview and Agent Roles](autonomous-threat-hunting/01-overview-and-agent-roles.md) | Goals, what the AI agent is, runtime roles (LangGraph, local LLM, MCP tools), current building blocks |
| 2 | [Reference Architecture](autonomous-threat-hunting/02-reference-architecture.md) | System architecture diagram, Rust vs Python trade-offs, detailed separated architecture, API contracts, metrics, port map |
| 3 | [Hunt Workflow and Safety Controls](autonomous-threat-hunting/03-hunt-workflow-and-safety.md) | Proposed LangGraph hunt workflow nodes, safety governance controls, circuit-breakers, local model guidance |
| 4 | [Implementation Plan and Hunt Playbooks](autonomous-threat-hunting/04-implementation-plan-and-playbooks.md) | Phased implementation plan (A–D), initial hunt playbooks, database and storage threat hunting coverage |
| 5 | [Adversarial Simulation Runbook](autonomous-threat-hunting/05-adversarial-simulation-runbook.md) | Safe testing objectives, test mode requirements, scenario families A (SQL injection) and B (MCP abuse), pass/fail criteria, metrics table, exit conditions |
| 6 | [MCP Security Proxy — Implementation and Observability](autonomous-threat-hunting/06-mcp-proxy-implementation.md) | Proxy service, policy file, telemetry namespace, Grafana dashboards, denied-call verification, Analyze Denied API and UI |
| 7 | [Pre-Call LLM Risk Scoring](autonomous-threat-hunting/07-llm-risk-scoring.md) | Scoring flow and thresholds, challenge vs deny semantics, operator rollout runbook, UI-only validation, pass/fail checklist, smoke test script, one-page operator checklist |
| 8 | [LLM Feature Catalog and PromQL Reference](autonomous-threat-hunting/08-llm-feature-catalog-and-promql.md) | Now/next/later LLM features for the proxy, LangChain vs LangGraph mapping, PromQL queries, recommended test cases, security controls to validate |
| 9 | [Automated Quarantining Capability](autonomous-threat-hunting/09-automated-quarantining.md) | Quarantine objective, trigger conditions, policy tiers, execution flow, tooling, failure handling, audit requirements, guardrail interaction |
| 10 | [Operational Validation and Command Appendix](autonomous-threat-hunting/10-operational-validation-and-appendix.md) | Operational validation checklist, minimal success criteria, command-oriented appendix for scenarios A and B |
| 11 | [Integration Notes](autonomous-threat-hunting/11-integration-notes.md) | Repository integration touchpoints and architecture alignment summary |
| 12 | [Analyze Denied — Incident Mechanics and Block-IP Justification](autonomous-threat-hunting/12-analyze-denied-and-block-ip.md) | When INC-proxy-deny-* IDs are created, when approval requests are created, block-IP target IP selection logic, analyst approval payload, known limitations |
| 13 | [Policy Tuning Recommendations API](autonomous-threat-hunting/13-policy-tuning-recommendations-api.md) | `POST /soc/proxy-policy-recommendations` endpoint, request/response format, examples, workflow integration, test script, acceptance criteria |

---

## Quick links

- [Pre-call risk scoring operator checklist](autonomous-threat-hunting/07-llm-risk-scoring.md#pre-call-risk-scoring-operator-checklist-one-page)
- [MCP proxy denied-call verification](autonomous-threat-hunting/06-mcp-proxy-implementation.md)
- [Analyze Denied mechanics](autonomous-threat-hunting/12-analyze-denied-and-block-ip.md)
- [Policy tuning recommendations API](autonomous-threat-hunting/13-policy-tuning-recommendations-api.md)
- [Adversarial simulation runbook](autonomous-threat-hunting/05-adversarial-simulation-runbook.md)
- [Automated quarantining](autonomous-threat-hunting/09-automated-quarantining.md)
- [Reference architecture and API contracts](autonomous-threat-hunting/02-reference-architecture.md)
