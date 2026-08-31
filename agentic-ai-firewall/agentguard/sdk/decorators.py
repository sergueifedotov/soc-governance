"""Function decorator for guarding tool implementations."""

from __future__ import annotations

import functools
from typing import Any, Callable, Optional

from agentguard.models import Decision
from agentguard.sdk.client import AgentGuardClient, AgentGuardError


def guard(
    client: AgentGuardClient,
    tool: Optional[str] = None,
    declared_intent: Optional[str] = None,
    raise_on_challenge: bool = False,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Wrap a function so every invocation is checked by AgentGuard first.

    Example:
        @guard(client, tool="send_email")
        def send_email(to, subject, body):
            ...

    The decorator binds the call's keyword + positional args into a dict and
    sends them to /v1/scan/tool-call. If the verdict is BLOCK, raises
    AgentGuardError. If CHALLENGE and `raise_on_challenge=True`, also raises.
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        tool_name = tool or func.__name__

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            arg_dict: dict[str, Any] = dict(kwargs)
            if args:
                # Best-effort positional capture
                for i, a in enumerate(args):
                    arg_dict[f"arg{i}"] = a

            resp = client.scan_tool_call(
                tool=tool_name,
                arguments=arg_dict,
                declared_intent=declared_intent,
            )
            if resp.verdict.decision == Decision.BLOCK:
                raise AgentGuardError(
                    f"AgentGuard blocked {tool_name}: {resp.verdict.reason}",
                    verdict=resp.verdict,
                )
            if raise_on_challenge and resp.verdict.decision == Decision.CHALLENGE:
                raise AgentGuardError(
                    f"AgentGuard requires approval for {tool_name}: {resp.verdict.reason}",
                    verdict=resp.verdict,
                )
            return func(*args, **kwargs)

        return wrapper

    return decorator
