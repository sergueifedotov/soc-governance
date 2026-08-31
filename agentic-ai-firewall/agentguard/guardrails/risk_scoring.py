"""Risk score aggregation across scanner findings."""

from __future__ import annotations

from typing import Iterable

from agentguard.models import Decision, Finding


def aggregate_risk(findings: Iterable[Finding]) -> float:
    """Return the aggregate risk in [0,1].

    Strategy: max severity, slightly bumped if multiple high-severity findings.
    """
    findings = list(findings)
    if not findings:
        return 0.0
    max_sev = max(f.severity for f in findings)
    n_high = sum(1 for f in findings if f.severity >= 0.7)
    bump = min(0.1 * (n_high - 1), 0.15) if n_high > 1 else 0.0
    return min(1.0, max_sev + bump)


def decide(risk: float, challenge_threshold: float, block_threshold: float) -> Decision:
    if risk >= block_threshold:
        return Decision.BLOCK
    if risk >= challenge_threshold:
        return Decision.CHALLENGE
    return Decision.ALLOW
