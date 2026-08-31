"""Tool-call policy gate.

Evaluates a proposed tool call from an agent against:
- The tool-specific policy (challenge/block thresholds, approval requirement)
- Intent verification (does declared_intent match arguments?)
- Argument heuristics (destructive args, suspicious paths/URLs)
"""

from __future__ import annotations

import re
import secrets as _secrets
import time
from typing import Any, Dict, List

from agentguard.audit import record
from agentguard.config import Policy
from agentguard.guardrails.risk_scoring import aggregate_risk, decide
from agentguard.metrics import AG_SCANS_TOTAL, AG_TOOL_DECISIONS, AG_RISK_SCORE, AG_SCAN_DURATION_SECONDS
from agentguard.models import (
    AuditEvent,
    Decision,
    Finding,
    ToolCallScanRequest,
    ToolCallScanResponse,
    Verdict,
)
from agentguard.scanners import URLThreatScanner


_DESTRUCTIVE_TOKENS = ("rm -rf", "drop table", "truncate", "delete from", "shutdown", "format ", "mkfs", ":(){:|:&};:")


def scan_tool_call(req: ToolCallScanRequest, policy: Policy) -> ToolCallScanResponse:
    start = time.perf_counter()
    findings: List[Finding] = []

    tp = policy.for_tool(req.tool)
    arg_blob = _flatten_args(req.arguments)

    # 1. Destructive token sniffing
    lowered = arg_blob.lower()
    for tok in _DESTRUCTIVE_TOKENS:
        if tok in lowered:
            findings.append(Finding(
                scanner="tool_policy",
                category="destructive_argument",
                severity=0.9,
                snippet=tok,
                detail=f"Argument to {req.tool} contains destructive token.",
            ))

    # 2. URL threats in arguments
    url_result = URLThreatScanner(
        allowed_domains=policy.network.allowed_domains,
        block_private_ranges=policy.network.block_private_ranges,
    ).scan(arg_blob)
    findings.extend(url_result.findings)

    # 3. Intent verification
    if req.declared_intent is not None:
        mismatch = _intent_mismatch(req.declared_intent, req.tool, arg_blob)
        if mismatch > 0:
            findings.append(Finding(
                scanner="intent_verification",
                category="intent_mismatch",
                severity=mismatch,
                detail=f"Declared intent does not reference tool '{req.tool}' or its arguments.",
            ))

    risk = aggregate_risk(findings)
    dec = decide(risk, tp.challenge_threshold, tp.block_threshold)

    requires_approval = tp.require_approval or dec == Decision.CHALLENGE
    approval_token = _secrets.token_urlsafe(16) if requires_approval and dec != Decision.BLOCK else None

    reason = _reason(findings, dec, req.tool, requires_approval)
    verdict = Verdict(decision=dec, risk_score=risk, reason=reason, findings=findings)

    AG_SCANS_TOTAL.labels(kind="tool_call", decision=dec.value).inc()
    AG_TOOL_DECISIONS.labels(tool=req.tool, decision=dec.value).inc()
    AG_SCAN_DURATION_SECONDS.labels(kind="tool_call").observe(time.perf_counter() - start)
    AG_RISK_SCORE.labels(kind="tool_call", decision=dec.value).observe(risk)

    record(AuditEvent(
        timestamp=time.time(),
        kind="scan_tool_call",
        decision=dec,
        risk_score=risk,
        tool=req.tool,
        agent_id=req.agent_id,
        session_id=req.session_id,
        findings=findings,
        detail=reason,
    ))

    return ToolCallScanResponse(
        verdict=verdict,
        requires_approval=requires_approval and dec != Decision.BLOCK,
        approval_token=approval_token,
    )


def _flatten_args(args: Dict[str, Any]) -> str:
    parts: List[str] = []
    def walk(v: Any) -> None:
        if isinstance(v, dict):
            for k, vv in v.items():
                parts.append(str(k))
                walk(vv)
        elif isinstance(v, (list, tuple)):
            for vv in v:
                walk(vv)
        else:
            parts.append(str(v))
    walk(args)
    return " ".join(parts)


_WORD_RE = re.compile(r"[a-z0-9_]+")


def _intent_mismatch(intent: str, tool: str, arg_blob: str) -> float:
    """Crude intent verification: declared intent should reference the tool or at least
    overlap meaningfully with arguments. Returns severity in [0,1]."""
    intent_lower = (intent or "").lower().strip()
    if not intent_lower:
        return 0.8  # empty intent on a tool call is suspicious

    intent_words = set(_WORD_RE.findall(intent_lower))
    tool_words = set(_WORD_RE.findall(tool.lower())) | set(_WORD_RE.findall(tool.replace("_", " ").lower()))
    arg_words = set(_WORD_RE.findall(arg_blob.lower()))

    if intent_words & tool_words:
        return 0.0
    if intent_words & arg_words:
        return 0.0
    return 0.6


def _reason(findings: List[Finding], decision: Decision, tool: str, approval: bool) -> str:
    if not findings:
        return f"{tool}: allow" if decision == Decision.ALLOW else f"{tool}: {decision.value} (no findings)"
    cats = sorted({f.category for f in findings})
    suffix = " [approval required]" if approval and decision != Decision.BLOCK else ""
    return f"{tool}: {decision.value} — {', '.join(cats)}{suffix}"
