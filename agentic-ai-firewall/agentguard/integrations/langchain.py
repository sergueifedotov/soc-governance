"""LangChain integration for AgentGuard.

Usage:
    from agentguard.integrations.langchain import AgentGuardCallback

    executor = AgentExecutor(
        agent=...,
        tools=...,
        callbacks=[AgentGuardCallback(endpoint="http://localhost:8088")],
    )

The callback intercepts:
- on_tool_start: scans the proposed tool call
- on_tool_end:   scans the tool output (untrusted external content)
- on_llm_end:    scans the LLM output (for PII/secret leakage)

If the AgentGuard verdict is BLOCK, the callback raises an exception that
propagates out of the AgentExecutor.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

try:
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.outputs import LLMResult
    _HAS_LANGCHAIN = True
except ImportError:  # pragma: no cover
    BaseCallbackHandler = object  # type: ignore
    LLMResult = None  # type: ignore
    _HAS_LANGCHAIN = False

from agentguard.models import Decision
from agentguard.sdk.client import AgentGuardClient, AgentGuardError


class AgentGuardCallback(BaseCallbackHandler):  # type: ignore[misc]
    """LangChain callback handler that enforces AgentGuard policy."""

    def __init__(
        self,
        endpoint: str = "http://localhost:8088",
        api_key: Optional[str] = None,
        block_on_challenge: bool = False,
    ) -> None:
        if not _HAS_LANGCHAIN:
            raise ImportError("langchain-core is not installed. `pip install agentguard[langchain]`")
        super().__init__()
        self.client = AgentGuardClient(endpoint=endpoint, api_key=api_key)
        self.block_on_challenge = block_on_challenge

    # --- Tool gates ---

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        *,
        run_id: Any,
        **kwargs: Any,
    ) -> None:
        tool_name = (serialized or {}).get("name", "unknown_tool")
        resp = self.client.scan_tool_call(
            tool=tool_name,
            arguments={"input": input_str},
            declared_intent=kwargs.get("metadata", {}).get("intent") if isinstance(kwargs.get("metadata"), dict) else None,
            session_id=str(run_id),
        )
        if resp.verdict.decision == Decision.BLOCK or (
            self.block_on_challenge and resp.verdict.decision == Decision.CHALLENGE
        ):
            raise AgentGuardError(
                f"AgentGuard blocked tool {tool_name}: {resp.verdict.reason}",
                verdict=resp.verdict,
            )

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        # Treat tool output as untrusted (e.g. scraped web content).
        sanitized, verdict = self.client.scan_input(
            text=output if isinstance(output, str) else str(output),
            source="langchain:tool_output",
        )
        if verdict.blocked:
            raise AgentGuardError(
                f"AgentGuard blocked tool output: {verdict.reason}", verdict=verdict
            )

    # --- LLM output scrubbing ---

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        try:
            generations = getattr(response, "generations", []) or []
            for gen_list in generations:
                for gen in gen_list:
                    text = getattr(gen, "text", None)
                    if isinstance(text, str):
                        _, verdict = self.client.scan_output(text=text)
                        if verdict.blocked:
                            raise AgentGuardError(
                                f"AgentGuard blocked LLM output: {verdict.reason}",
                                verdict=verdict,
                            )
        except AgentGuardError:
            raise
        except Exception:  # noqa: BLE001 - never break the chain on observability errors
            return
