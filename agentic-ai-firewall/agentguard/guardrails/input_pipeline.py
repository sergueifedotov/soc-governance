"""Input guardrail pipeline — sanitize untrusted text before it reaches the LLM."""

from __future__ import annotations

import time
from typing import List

from agentguard.audit import record
from agentguard.config import Policy
from agentguard.guardrails.risk_scoring import aggregate_risk, decide
from agentguard.metrics import AG_FINDINGS_TOTAL, AG_RISK_SCORE, AG_SCAN_DURATION_SECONDS, AG_SCANS_TOTAL
from agentguard.models import (
    AuditEvent,
    Decision,
    Finding,
    InputScanRequest,
    InputScanResponse,
    Verdict,
)
from agentguard.scanners import (
    MLClassifierScanner,
    PIIScanner,
    PromptInjectionScanner,
    SecretsScanner,
    URLThreatScanner,
)


def scan_input(req: InputScanRequest, policy: Policy) -> InputScanResponse:
    start = time.perf_counter()

    injector = PromptInjectionScanner(
        strip_hidden_chars=policy.input.strip_hidden_chars,
        strip_html_comments=policy.input.strip_html_comments,
    )
    url = URLThreatScanner(
        allowed_domains=policy.network.allowed_domains,
        block_private_ranges=policy.network.block_private_ranges,
    )
    ml = MLClassifierScanner()

    text = req.text
    findings: List[Finding] = []
    redactions = 0

    for scanner in (injector, url, ml):
        result = scanner.scan(text)
        text = result.sanitized_text
        findings.extend(result.findings)
        redactions += result.redactions

    if policy.input.redact_pii:
        result = PIIScanner().scan(text)
        text = result.sanitized_text
        findings.extend(result.findings)
        redactions += result.redactions

    if policy.input.redact_secrets:
        result = SecretsScanner().scan(text)
        text = result.sanitized_text
        findings.extend(result.findings)
        redactions += result.redactions

    risk = aggregate_risk(findings)
    if req.trusted:
        # In trusted mode we never block, but we still surface findings.
        dec = Decision.ALLOW
        reason = "trusted-source (informational findings only)"
    else:
        dec = decide(risk, policy.input.challenge_threshold, policy.input.block_threshold)
        reason = _reason_for(findings, dec)

    verdict = Verdict(decision=dec, risk_score=risk, reason=reason, findings=findings)

    # Metrics
    AG_SCANS_TOTAL.labels(kind="input", decision=dec.value).inc()
    AG_SCAN_DURATION_SECONDS.labels(kind="input").observe(time.perf_counter() - start)
    AG_RISK_SCORE.labels(kind="input", decision=dec.value).observe(risk)
    for f in findings:
        AG_FINDINGS_TOTAL.labels(scanner=f.scanner, category=f.category).inc()

    # Audit
    record(AuditEvent(
        timestamp=time.time(),
        kind="scan_input",
        decision=dec,
        risk_score=risk,
        source=req.source,
        findings=findings,
        detail=reason,
    ))

    return InputScanResponse(verdict=verdict, sanitized_text=text, redactions=redactions)


def _reason_for(findings: List[Finding], decision: Decision) -> str:
    if not findings:
        return "no findings"
    cats = sorted({f.category for f in findings})
    if decision == Decision.BLOCK:
        return f"blocked: {', '.join(cats)}"
    if decision == Decision.CHALLENGE:
        return f"sanitized + warning: {', '.join(cats)}"
    return f"allowed (informational): {', '.join(cats)}"
