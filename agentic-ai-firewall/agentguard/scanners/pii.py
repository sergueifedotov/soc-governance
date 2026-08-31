"""PII scanner — redacts emails, phones, SSNs, credit cards."""

from __future__ import annotations

import re
from typing import List, Tuple

from agentguard.models import Finding
from agentguard.scanners.base import Scanner, ScannerResult


_PATTERNS: List[Tuple[re.Pattern[str], str, str, float]] = [
    (re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), "email", "[REDACTED_EMAIL]", 0.3),
    (re.compile(r"\b(?:\+?\d{1,2}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b"), "phone", "[REDACTED_PHONE]", 0.3),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "ssn", "[REDACTED_SSN]", 0.7),
    # Credit card (loose Luhn-free check; replace with full Luhn in prod)
    (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "credit_card_candidate", "[REDACTED_CC]", 0.5),
]


class PIIScanner(Scanner):
    name = "pii"

    def scan(self, text: str) -> ScannerResult:
        if not isinstance(text, str):
            text = "" if text is None else str(text)

        findings: List[Finding] = []
        sanitized = text
        redactions = 0
        for regex, category, replacement, severity in _PATTERNS:
            matches = list(regex.finditer(sanitized))
            if not matches:
                continue
            # Extra Luhn check for credit cards
            if category == "credit_card_candidate":
                matches = [m for m in matches if _luhn_valid(re.sub(r"\D", "", m.group(0)))]
                if not matches:
                    continue
                category = "credit_card"
            for m in matches:
                findings.append(Finding(
                    scanner=self.name,
                    category=category,
                    severity=severity,
                    snippet=_mask(m.group(0)),
                ))
            sanitized = regex.sub(replacement, sanitized)
            redactions += len(matches)
        return ScannerResult(sanitized_text=sanitized, findings=findings, redactions=redactions)


def _luhn_valid(digits: str) -> bool:
    if not (13 <= len(digits) <= 19):
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _mask(s: str) -> str:
    if len(s) <= 4:
        return "*" * len(s)
    return s[:2] + "*" * (len(s) - 4) + s[-2:]
