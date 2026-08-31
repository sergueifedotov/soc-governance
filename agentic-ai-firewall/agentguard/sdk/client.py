"""Synchronous HTTP client SDK for AgentGuard."""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

import httpx

from agentguard.models import (
    InputScanResponse,
    OutputScanResponse,
    ToolCallScanResponse,
    Verdict,
)


class AgentGuardError(Exception):
    """Raised when AgentGuard blocks an action or the proxy is unreachable."""

    def __init__(self, message: str, verdict: Optional[Verdict] = None) -> None:
        super().__init__(message)
        self.verdict = verdict


class AgentGuardClient:
    """Thin client over the AgentGuard HTTP API."""

    def __init__(
        self,
        endpoint: str = "http://localhost:8088",
        api_key: Optional[str] = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.timeout = timeout_seconds
        self._headers = {"content-type": "application/json"}
        if api_key:
            self._headers["authorization"] = f"Bearer {api_key}"

    # ---------------- Public methods ----------------

    def scan_input(
        self,
        text: str,
        source: str = "unknown",
        trusted: bool = False,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[str, Verdict]:
        """Scan untrusted text. Returns (sanitized_text, verdict)."""
        payload = {
            "text": text,
            "source": source,
            "trusted": trusted,
            "context": context or {},
        }
        data = self._post("/v1/scan/input", payload)
        resp = InputScanResponse.model_validate(data)
        return resp.sanitized_text, resp.verdict

    def scan_output(self, text: str, context: Optional[Dict[str, Any]] = None) -> Tuple[str, Verdict]:
        data = self._post("/v1/scan/output", {"text": text, "context": context or {}})
        resp = OutputScanResponse.model_validate(data)
        return resp.sanitized_text, resp.verdict

    def scan_tool_call(
        self,
        tool: str,
        arguments: Dict[str, Any],
        declared_intent: Optional[str] = None,
        agent_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> ToolCallScanResponse:
        payload = {
            "tool": tool,
            "arguments": arguments,
            "declared_intent": declared_intent,
            "agent_id": agent_id,
            "session_id": session_id,
        }
        data = self._post("/v1/scan/tool-call", payload)
        return ToolCallScanResponse.model_validate(data)

    # ---------------- Internals ----------------

    def _post(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(self.endpoint + path, json=body, headers=self._headers)
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPError as exc:
            raise AgentGuardError(f"AgentGuard request failed: {exc}") from exc
