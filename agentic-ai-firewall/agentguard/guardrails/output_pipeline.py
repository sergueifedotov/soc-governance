"""Output guardrail pipeline — scrub LLM outputs before they reach users/systems."""

from __future__ import annotations

import time
from typing import List

from agentguard.audit import record
from agentguard.config import Policy
from agentguard.guardrails.risk_scoring import aggregate_risk, decide
from agentguard.metrics import AG_FINDINGS_TOTAL, AG_RISK_SCORE, AG_SCAN_DURATION_SECONDS, AG_SCANS_TOTAL
from agentguard.models import AuditEvent, Finding, OutputScanRequest, OutputScanResponse, Verdict
from agentguard.scanners import PIIScanner, SecretsScanner, URLThreatScanner


def scan_output(req: OutputScanRequest, policy: Policy) -> OutputScanResponse:
    start = time.perf_counter()

    text = req.text
    findings: List[Finding] = []
    redactions = 0

    # Outputs: scrub leaked secrets/PII, flag risky URLs.
    for scanner in (
        SecretsScanner(),
        PIIScanner(),
        URLThreatScanner(
            allowed_domains=policy.network.allowed_domains,
            block_private_ranges=policy.network.block_private_ranges,
        ),
    ):
        result = scanner.scan(text)
        text = result.sanitized_text
        findings.extend(result.findings)
        redactions += result.redactions

    risk = aggregate_risk(findings)
    dec = decide(risk, policy.default_tool.challenge_threshold, policy.default_tool.block_threshold)
    reason = f"output scan: {', '.join(sorted({f.category for f in findings})) or 'clean'}"

    verdict = Verdict(decision=dec, risk_score=risk, reason=reason, findings=findings)

    AG_SCANS_TOTAL.labels(kind="output", decision=dec.value).inc()
    AG_SCAN_DURATION_SECONDS.labels(kind="output").observe(time.perf_counter() - start)
    AG_RISK_SCORE.labels(kind="output", decision=dec.value).observe(risk)
    for f in findings:
        AG_FINDINGS_TOTAL.labels(scanner=f.scanner, category=f.category).inc()

    record(AuditEvent(
        timestamp=time.time(),
        kind="scan_output",
        decision=dec,
        risk_score=risk,
        findings=findings,
        detail=reason,
    ))

    return OutputScanResponse(verdict=verdict, sanitized_text=text, redactions=redactions)
