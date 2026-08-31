"""Pydantic models for AgentGuard request/response schemas."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Decision(str, Enum):
    ALLOW = "allow"
    CHALLENGE = "challenge"
    BLOCK = "block"


class Finding(BaseModel):
    """A single security finding from a scanner."""

    scanner: str
    category: str  # e.g. "prompt_injection", "pii", "secret", "url"
    severity: float = Field(ge=0.0, le=1.0)
    snippet: Optional[str] = None
    detail: Optional[str] = None


class Verdict(BaseModel):
    """The aggregated decision returned by a scan."""

    decision: Decision
    risk_score: float = Field(ge=0.0, le=1.0)
    reason: str
    findings: List[Finding] = Field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.decision == Decision.BLOCK

    @property
    def needs_review(self) -> bool:
        return self.decision == Decision.CHALLENGE


# ---------------- Input scan ----------------


class InputScanRequest(BaseModel):
    text: str
    source: str = Field(default="unknown", description="e.g. 'email:inbound', 'web:scrape', 'pdf:upload'")
    trusted: bool = Field(default=False, description="If true, scanners run informationally only.")
    context: Dict[str, Any] = Field(default_factory=dict)


class InputScanResponse(BaseModel):
    verdict: Verdict
    sanitized_text: str
    redactions: int = 0


# ---------------- Output scan ----------------


class OutputScanRequest(BaseModel):
    text: str
    context: Dict[str, Any] = Field(default_factory=dict)


class OutputScanResponse(BaseModel):
    verdict: Verdict
    sanitized_text: str
    redactions: int = 0


# ---------------- Tool-call scan ----------------


class ToolCallScanRequest(BaseModel):
    tool: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    declared_intent: Optional[str] = Field(
        default=None,
        description="The LLM's natural-language description of what it wants to do.",
    )
    agent_id: Optional[str] = None
    session_id: Optional[str] = None
    context: Dict[str, Any] = Field(default_factory=dict)


class ToolCallScanResponse(BaseModel):
    verdict: Verdict
    requires_approval: bool = False
    approval_token: Optional[str] = None


# ---------------- Audit event ----------------


class AuditEvent(BaseModel):
    timestamp: float
    kind: str  # "scan_input" | "scan_output" | "scan_tool_call" | "proxy"
    decision: Decision
    risk_score: float
    tool: Optional[str] = None
    source: Optional[str] = None
    agent_id: Optional[str] = None
    session_id: Optional[str] = None
    findings: List[Finding] = Field(default_factory=list)
    detail: Optional[str] = None
