"""Secrets scanner — API keys, tokens, private keys."""

from __future__ import annotations

import re
from typing import List, Tuple

from agentguard.models import Finding
from agentguard.scanners.base import Scanner, ScannerResult


_PATTERNS: List[Tuple[re.Pattern[str], str, float]] = [
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "openai_api_key", 0.95),
    (re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"), "anthropic_api_key", 0.95),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "aws_access_key", 0.95),
    (re.compile(r"\bghp_[A-Za-z0-9]{30,}\b"), "github_pat", 0.95),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "slack_token", 0.9),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----"), "private_key", 1.0),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "jwt_token", 0.6),
    (re.compile(r"(?i)\b(api[_-]?key|secret|password|passwd|pwd|token)\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{16,}[\"']?"), "credential_assignment", 0.7),
]


class SecretsScanner(Scanner):
    name = "secrets"

    def scan(self, text: str) -> ScannerResult:
        if not isinstance(text, str):
            text = "" if text is None else str(text)

        findings: List[Finding] = []
        sanitized = text
        redactions = 0
        for regex, category, severity in _PATTERNS:
            matches = list(regex.finditer(sanitized))
            if not matches:
                continue
            for m in matches:
                findings.append(Finding(
                    scanner=self.name,
                    category=category,
                    severity=severity,
                    snippet="[redacted:" + category + "]",
                ))
            sanitized = regex.sub(f"[REDACTED_{category.upper()}]", sanitized)
            redactions += len(matches)
        return ScannerResult(sanitized_text=sanitized, findings=findings, redactions=redactions)
