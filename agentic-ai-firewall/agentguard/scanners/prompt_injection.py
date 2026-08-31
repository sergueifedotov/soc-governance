"""Indirect prompt injection scanner.

Combines:
- Regex patterns for known instruction-override phrasings
- Hidden character detection (unicode tags, zero-width)
- HTML comment / markdown link injection
- Base64-encoded instruction detection
- Optional ML classifier hook (see ml_classifier.py)

This is intentionally conservative and explainable — every finding has a
snippet and category so analysts can audit decisions.
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import List, Tuple

from agentguard.models import Finding
from agentguard.scanners.base import Scanner, ScannerResult


# ---------- Pattern library ----------
# Each pattern: (regex, category, severity, description)
_PATTERNS: List[Tuple[re.Pattern[str], str, float, str]] = [
    # Direct instruction override
    (re.compile(r"\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all)\b[^.\n]{0,40}\b(instructions?|prompts?|rules?|directives?)\b", re.I),
     "instruction_override", 0.9, "Direct attempt to override prior instructions."),
    (re.compile(r"\b(you are|act as|pretend to be|roleplay as|from now on you('re| are))\b[^.\n]{0,60}\b(admin|root|developer|sudo|jailbroken|dan|unfiltered)\b", re.I),
     "role_hijack", 0.85, "Attempt to hijack the assistant's role."),
    (re.compile(r"\b(system|developer)\s*[:>]\s*", re.I),
     "fake_system_prompt", 0.7, "Embedded fake system/developer prefix."),
    (re.compile(r"<\s*\|?\s*(system|im_start|im_end|s)\s*\|?\s*>", re.I),
     "chat_template_injection", 0.85, "Chat-template control token injection."),
    # Exfiltration directives
    (re.compile(r"\b(send|forward|exfiltrate|leak|email|post|upload)\b[^.\n]{0,40}\b(to|at)\b\s+[\w.+-]+@[\w.-]+", re.I),
     "exfiltration_directive", 0.85, "Instruction to send data to an external address."),
    (re.compile(r"\b(curl|wget|fetch|http\.get)\b\s+[\"']?https?://", re.I),
     "exfiltration_directive", 0.7, "Embedded outbound HTTP call instruction."),
    # Destructive actions
    (re.compile(r"\b(delete|drop|truncate|wipe|destroy|rm\s+-rf)\b[^.\n]{0,40}\b(database|table|all|everything|users|files?)\b", re.I),
     "destructive_action", 0.9, "Destructive action directive."),
    # Credential / secret extraction
    (re.compile(r"\b(reveal|print|show|leak|dump|output|return)\b[^.\n]{0,40}\b(api[\s_-]?key|secret|password|token|env(ironment)?(\s+vars?)?|system\s+prompt)\b", re.I),
     "secret_extraction", 0.85, "Attempt to extract credentials or secrets."),
    # Encoded payload markers
    (re.compile(r"\b(decode|base64|rot13|hex)\b[^.\n]{0,40}\b(then|and)\b[^.\n]{0,40}\b(execute|run|do|follow|obey)\b", re.I),
     "obfuscated_payload", 0.8, "Instruction to decode-then-execute."),
]

# Hidden chars: zero-width, BOM, bidi controls, and Unicode tag chars (U+E0000–U+E007F,
# in the supplementary plane — must use \U00xxxxxx syntax).
_HIDDEN_CHAR_RE = re.compile(
    r"[\u200B-\u200D\uFEFF\u202A-\u202E]|[\U000E0000-\U000E007F]"
)
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
_MARKDOWN_HIDDEN_LINK_RE = re.compile(r"\[[^\]]*\]\(\s*javascript:[^)]+\)", re.I)


class PromptInjectionScanner(Scanner):
    name = "prompt_injection"

    def __init__(
        self,
        strip_hidden_chars: bool = True,
        strip_html_comments: bool = True,
        decode_base64_max_len: int = 4000,
    ) -> None:
        self.strip_hidden_chars = strip_hidden_chars
        self.strip_html_comments = strip_html_comments
        self.decode_base64_max_len = decode_base64_max_len

    def scan(self, text: str) -> ScannerResult:
        if not isinstance(text, str):
            text = "" if text is None else str(text)

        findings: List[Finding] = []
        sanitized = text
        redactions = 0

        # 1. Hidden chars
        if self.strip_hidden_chars:
            new, n = _HIDDEN_CHAR_RE.subn("", sanitized)
            if n > 0:
                findings.append(Finding(
                    scanner=self.name,
                    category="hidden_chars",
                    severity=0.6,
                    detail=f"Stripped {n} invisible/zero-width/tag characters.",
                ))
                redactions += n
                sanitized = new

        # 2. HTML comments — common smuggling vector in scraped pages
        if self.strip_html_comments:
            comments = _HTML_COMMENT_RE.findall(sanitized)
            for c in comments:
                # Only flag if the comment looks instructional
                if _looks_instructional(c):
                    findings.append(Finding(
                        scanner=self.name,
                        category="html_comment_injection",
                        severity=0.75,
                        snippet=_snippet(c),
                        detail="Instructional content inside HTML comment.",
                    ))
            sanitized = _HTML_COMMENT_RE.sub("", sanitized)

        # 3. Hidden markdown javascript links
        for m in _MARKDOWN_HIDDEN_LINK_RE.finditer(sanitized):
            findings.append(Finding(
                scanner=self.name,
                category="markdown_js_link",
                severity=0.7,
                snippet=_snippet(m.group(0)),
                detail="Markdown link with javascript: scheme.",
            ))
        sanitized = _MARKDOWN_HIDDEN_LINK_RE.sub("[link removed]", sanitized)

        # 4. Pattern library
        for regex, category, severity, detail in _PATTERNS:
            for m in regex.finditer(sanitized):
                findings.append(Finding(
                    scanner=self.name,
                    category=category,
                    severity=severity,
                    snippet=_snippet(m.group(0)),
                    detail=detail,
                ))

        # 5. Base64-encoded instructions (best-effort)
        if len(sanitized) <= self.decode_base64_max_len:
            for m in re.finditer(r"\b([A-Za-z0-9+/]{40,}={0,2})\b", sanitized):
                blob = m.group(1)
                try:
                    decoded = base64.b64decode(blob, validate=True).decode("utf-8", errors="ignore")
                except (binascii.Error, ValueError):
                    continue
                if _looks_instructional(decoded):
                    findings.append(Finding(
                        scanner=self.name,
                        category="base64_payload",
                        severity=0.8,
                        snippet=_snippet(decoded),
                        detail="Base64-encoded instruction-like payload.",
                    ))

        return ScannerResult(sanitized_text=sanitized, findings=findings, redactions=redactions)


def _snippet(text: str, max_len: int = 120) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= max_len else text[: max_len - 1] + "…"


def _looks_instructional(text: str) -> bool:
    """Cheap heuristic: does this text plausibly contain an instruction?"""
    lowered = text.lower()
    triggers = (
        "ignore", "disregard", "forget", "you are", "act as", "system:",
        "instruction", "execute", "run ", "delete", "drop ", "send to",
        "exfiltrate", "api key", "password", "secret", "print", "reveal",
        "from now on", "new rule", "override",
    )
    return any(t in lowered for t in triggers)
