"""AgentGuard configuration loading."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict

import yaml


@dataclass
class ToolPolicy:
    challenge_threshold: float = 0.5
    block_threshold: float = 0.85
    require_approval: bool = False


@dataclass
class InputPolicy:
    challenge_threshold: float = 0.4
    block_threshold: float = 0.8
    strip_hidden_chars: bool = True
    strip_html_comments: bool = True
    redact_pii: bool = True
    redact_secrets: bool = True


@dataclass
class NetworkPolicy:
    allowed_domains: list[str] = field(default_factory=list)
    block_private_ranges: bool = True


@dataclass
class Policy:
    version: int = 1
    input: InputPolicy = field(default_factory=InputPolicy)
    default_tool: ToolPolicy = field(default_factory=ToolPolicy)
    tools: Dict[str, ToolPolicy] = field(default_factory=dict)
    network: NetworkPolicy = field(default_factory=NetworkPolicy)

    def for_tool(self, tool_name: str) -> ToolPolicy:
        return self.tools.get(tool_name, self.default_tool)


def load_policy(path: str | None = None) -> Policy:
    """Load policy from YAML. Returns defaults if file missing."""
    policy_path = path or os.getenv("AGENTGUARD_POLICY_FILE", "./policy.yaml")
    p = Path(policy_path)
    if not p.exists():
        return Policy()

    raw: Dict[str, Any] = yaml.safe_load(p.read_text()) or {}

    inp = raw.get("input", {}) or {}
    out = raw.get("output", {}) or {}
    net = raw.get("network", {}) or {}

    default_tp = out.get("default", {}) or {}
    tools_raw = out.get("tools", {}) or {}
    tools = {
        name: ToolPolicy(
            challenge_threshold=float(cfg.get("challenge_threshold", default_tp.get("challenge_threshold", 0.5))),
            block_threshold=float(cfg.get("block_threshold", default_tp.get("block_threshold", 0.85))),
            require_approval=bool(cfg.get("require_approval", False)),
        )
        for name, cfg in tools_raw.items()
    }

    return Policy(
        version=int(raw.get("version", 1)),
        input=InputPolicy(
            challenge_threshold=float(inp.get("challenge_threshold", 0.4)),
            block_threshold=float(inp.get("block_threshold", 0.8)),
            strip_hidden_chars=bool(inp.get("strip_hidden_chars", True)),
            strip_html_comments=bool(inp.get("strip_html_comments", True)),
            redact_pii=bool(inp.get("redact_pii", True)),
            redact_secrets=bool(inp.get("redact_secrets", True)),
        ),
        default_tool=ToolPolicy(
            challenge_threshold=float(default_tp.get("challenge_threshold", 0.5)),
            block_threshold=float(default_tp.get("block_threshold", 0.85)),
            require_approval=bool(default_tp.get("require_approval", False)),
        ),
        tools=tools,
        network=NetworkPolicy(
            allowed_domains=list(net.get("allowed_domains", []) or []),
            block_private_ranges=bool(net.get("block_private_ranges", True)),
        ),
    )
