"""ML classifier scanner — optional hook for a remote or local model.

This ships as a hook so users can plug in their own classifier (e.g. a
fine-tuned DeBERTa for prompt injection detection on HuggingFace or
a self-hosted endpoint). Falls back to a no-op when no URL is set.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

import httpx

from agentguard.models import Finding
from agentguard.scanners.base import Scanner, ScannerResult


logger = logging.getLogger("agentguard.scanners.ml")


class MLClassifierScanner(Scanner):
    """POSTs `{"text": ...}` to a configured endpoint expecting
    `{"score": float in [0,1], "label": str}`.
    """

    name = "ml_classifier"

    def __init__(
        self,
        endpoint: Optional[str] = None,
        timeout_seconds: float = 1.5,
        threshold: float = 0.5,
    ) -> None:
        self.endpoint = endpoint or os.getenv("AGENTGUARD_ML_CLASSIFIER_URL") or ""
        self.timeout_seconds = timeout_seconds
        self.threshold = threshold

    def scan(self, text: str) -> ScannerResult:
        if not self.endpoint or not text:
            return ScannerResult(sanitized_text=text, findings=[])

        try:
            with httpx.Client(timeout=self.timeout_seconds) as client:
                resp = client.post(self.endpoint, json={"text": text})
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:  # noqa: BLE001 - never let the scanner break the request
            logger.warning("ML classifier unreachable: %s", exc)
            return ScannerResult(sanitized_text=text, findings=[])

        score = float(data.get("score", 0.0))
        label = str(data.get("label", "unknown"))
        if score < self.threshold:
            return ScannerResult(sanitized_text=text, findings=[])

        return ScannerResult(
            sanitized_text=text,
            findings=[
                Finding(
                    scanner=self.name,
                    category=f"ml:{label}",
                    severity=min(max(score, 0.0), 1.0),
                    detail=f"ML classifier flagged with score={score:.3f} label={label}",
                )
            ],
        )
