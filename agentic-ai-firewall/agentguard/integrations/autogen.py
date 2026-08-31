"""AutoGen integration for AgentGuard.

Wraps an AutoGen ConversableAgent so every received message is scanned for
prompt injection and every proposed function call is policy-gated.

Usage:
    from agentguard.integrations.autogen import wrap_agent
    assistant = wrap_agent(assistant, endpoint="http://localhost:8088")
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from agentguard.models import Decision
from agentguard.sdk.client import AgentGuardClient, AgentGuardError


def wrap_agent(
    agent: Any,
    endpoint: str = "http://localhost:8088",
    api_key: Optional[str] = None,
    block_on_challenge: bool = False,
) -> Any:
    """Monkey-patch an AutoGen ConversableAgent with AgentGuard hooks.

    This works with both `pyautogen` and `autogen-agentchat` style agents
    that expose a `register_reply` mechanism or a `receive` method.
    """
    client = AgentGuardClient(endpoint=endpoint, api_key=api_key)

    original_receive = getattr(agent, "receive", None)
    if not callable(original_receive):
        raise TypeError("Agent does not expose a `receive` method; cannot wrap.")

    def guarded_receive(message: Any, sender: Any, *args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
        content = _extract_text(message)
        if content:
            sanitized, verdict = client.scan_input(
                text=content,
                source=f"autogen:{getattr(sender, 'name', 'peer')}",
            )
            if verdict.blocked or (block_on_challenge and verdict.needs_review):
                raise AgentGuardError(
                    f"AgentGuard blocked message: {verdict.reason}", verdict=verdict
                )
            _replace_text(message, sanitized)

            # Function-call gating, if the message proposes a tool call.
            fn_call = _extract_function_call(message)
            if fn_call:
                resp = client.scan_tool_call(
                    tool=fn_call.get("name", "unknown_tool"),
                    arguments=fn_call.get("arguments", {}) or {},
                    declared_intent=content,
                    agent_id=getattr(agent, "name", None),
                )
                if resp.verdict.decision == Decision.BLOCK or (
                    block_on_challenge and resp.verdict.decision == Decision.CHALLENGE
                ):
                    raise AgentGuardError(
                        f"AgentGuard blocked tool {fn_call.get('name')}: {resp.verdict.reason}",
                        verdict=resp.verdict,
                    )

        return original_receive(message, sender, *args, **kwargs)

    agent.receive = guarded_receive  # type: ignore[attr-defined]
    return agent


def _extract_text(message: Any) -> str:
    if isinstance(message, str):
        return message
    if isinstance(message, dict):
        c = message.get("content")
        if isinstance(c, str):
            return c
        if isinstance(c, list):
            return " ".join(p.get("text", "") for p in c if isinstance(p, dict))
    return ""


def _replace_text(message: Any, sanitized: str) -> None:
    if isinstance(message, dict) and isinstance(message.get("content"), str):
        message["content"] = sanitized


def _extract_function_call(message: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(message, dict):
        return None
    fc = message.get("function_call") or message.get("tool_calls")
    if isinstance(fc, dict):
        return fc
    if isinstance(fc, list) and fc:
        first = fc[0]
        if isinstance(first, dict):
            return first.get("function", first)
    return None
