"""Base scanner interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List

from agentguard.models import Finding


@dataclass
class ScannerResult:
    """Result of scanning a piece of text.

    sanitized_text: same length-or-shorter version with hostile bits stripped/redacted.
    findings: list of findings.
    """

    sanitized_text: str
    findings: List[Finding] = field(default_factory=list)
    redactions: int = 0

    @property
    def max_severity(self) -> float:
        return max((f.severity for f in self.findings), default=0.0)


class Scanner(ABC):
    name: str = "scanner"

    @abstractmethod
    def scan(self, text: str) -> ScannerResult:
        """Scan a text. Must not raise on bad input; degrade gracefully."""
