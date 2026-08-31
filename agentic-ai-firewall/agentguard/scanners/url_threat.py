"""URL / domain threat scanner.

Blocks links to known-bad domains, raw IPs, private/loopback ranges,
and cloud metadata endpoints (a common SSRF target for compromised agents).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable, List, Optional, Set
from urllib.parse import urlparse

from agentguard.models import Finding
from agentguard.scanners.base import Scanner, ScannerResult


_URL_RE = re.compile(r"\bhttps?://[^\s<>\"'`]+", re.I)

_CLOUD_METADATA_HOSTS = {
    "169.254.169.254",         # AWS / GCP / Azure metadata
    "metadata.google.internal",
    "metadata",
}


class URLThreatScanner(Scanner):
    name = "url_threat"

    def __init__(
        self,
        allowed_domains: Optional[Iterable[str]] = None,
        block_private_ranges: bool = True,
        denylist: Optional[Iterable[str]] = None,
    ) -> None:
        self.allowed_domains: Set[str] = {d.lower().strip() for d in (allowed_domains or [])}
        self.block_private_ranges = block_private_ranges
        self.denylist: Set[str] = {d.lower().strip() for d in (denylist or [])}

    def scan(self, text: str) -> ScannerResult:
        if not isinstance(text, str):
            text = "" if text is None else str(text)

        findings: List[Finding] = []
        for m in _URL_RE.finditer(text):
            url = m.group(0)
            try:
                parsed = urlparse(url)
            except ValueError:
                continue
            host = (parsed.hostname or "").lower()
            if not host:
                continue

            # Cloud metadata
            if host in _CLOUD_METADATA_HOSTS:
                findings.append(Finding(
                    scanner=self.name,
                    category="cloud_metadata_url",
                    severity=1.0,
                    snippet=url,
                    detail="URL points to cloud instance metadata endpoint.",
                ))
                continue

            # Denylist
            if host in self.denylist or any(host.endswith("." + d) for d in self.denylist):
                findings.append(Finding(
                    scanner=self.name,
                    category="denied_domain",
                    severity=0.9,
                    snippet=url,
                ))
                continue

            # Private IP ranges
            if self.block_private_ranges:
                try:
                    ip = ipaddress.ip_address(host)
                    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                        findings.append(Finding(
                            scanner=self.name,
                            category="private_ip_url",
                            severity=0.85,
                            snippet=url,
                            detail="URL targets a private/loopback IP range.",
                        ))
                        continue
                except ValueError:
                    pass

            # Allowlist enforcement (only flag if allowlist is non-empty)
            if self.allowed_domains:
                allowed = host in self.allowed_domains or any(
                    host.endswith("." + d) for d in self.allowed_domains
                )
                if not allowed:
                    findings.append(Finding(
                        scanner=self.name,
                        category="domain_not_allowlisted",
                        severity=0.5,
                        snippet=url,
                        detail=f"Domain {host} is not on the allowlist.",
                    ))

        # We don't rewrite URLs by default — return text unchanged.
        return ScannerResult(sanitized_text=text, findings=findings, redactions=0)
