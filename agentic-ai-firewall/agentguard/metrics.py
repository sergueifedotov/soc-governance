"""Prometheus metrics for AgentGuard."""

from __future__ import annotations

from prometheus_client import Counter, Histogram

AG_SCANS_TOTAL = Counter(
    "agentguard_scans_total",
    "Total scans performed by AgentGuard.",
    ["kind", "decision"],
)

AG_FINDINGS_TOTAL = Counter(
    "agentguard_findings_total",
    "Total findings emitted by scanners.",
    ["scanner", "category"],
)

AG_SCAN_DURATION_SECONDS = Histogram(
    "agentguard_scan_duration_seconds",
    "End-to-end duration of a scan.",
    ["kind"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
)

AG_RISK_SCORE = Histogram(
    "agentguard_risk_score",
    "Distribution of risk scores (0..1).",
    ["kind", "decision"],
    buckets=(0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 1.0),
)

AG_PROXY_UPSTREAM_ERRORS = Counter(
    "agentguard_proxy_upstream_errors_total",
    "Upstream errors when proxying to LLM providers.",
    ["provider", "category"],
)

AG_TOOL_DECISIONS = Counter(
    "agentguard_tool_decisions_total",
    "Tool-call decisions taken.",
    ["tool", "decision"],
)
