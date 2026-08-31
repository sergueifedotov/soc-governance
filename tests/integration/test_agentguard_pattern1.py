#!/usr/bin/env python3
"""Unit tests for Pattern 1 AgentGuard reverse-proxy integration."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from types import SimpleNamespace

# Add src to path for local imports.
src_path = Path(__file__).parent.parent.parent / "src"
sys.path.insert(0, str(src_path))


def test_compose_full_has_agentguard_local_reverse_proxy() -> None:
    """compose.full.yml must define local AgentGuard service for Pattern 1."""
    compose_path = Path(__file__).parent.parent.parent / "compose.full.yml"
    content = compose_path.read_text(encoding="utf-8")

    assert re.search(r"^\s{2}agentguard:\s*$", content, re.MULTILINE)
    assert "build: ./agentic-ai-firewall" in content
    assert "container_name: agentguard" in content
    assert "- \"8088:8088\"" in content
    assert re.search(r"^\s{4}models:\s*$", content, re.MULTILINE)
    assert "endpoint_var: AGENTGUARD_OPENAI_UPSTREAM" in content
    assert "model_var: AGENTGUARD_DEFAULT_MODEL" in content
    assert "AGENTGUARD_POLICY_FILE: /app/policy.yaml" in content
    assert "./agentic-ai-firewall/policy.example.yaml:/app/policy.yaml:ro" in content


def test_phase2_langchain_uses_agentguard_proxy_base_url(monkeypatch) -> None:
    """Phase 2 ChatOpenAI client must use PHASE2_LLM_BASE_URL (AgentGuard URL)."""
    from wazuh_mcp_server import phase2 as phase2_module

    captured: dict = {}

    class DummyChatOpenAI:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    cfg = SimpleNamespace(
        PHASE2_LLM_ENABLED=True,
        PHASE2_LLM_MODEL="ai/gemma3-qat:latest",
        PHASE2_LLM_BASE_URL="http://agentguard:8088/v1/proxy/openai/v1",
        PHASE2_LLM_API_KEY="not-needed",
        PHASE2_LLM_TIMEOUT_SECONDS=45,
    )

    monkeypatch.setattr(phase2_module, "ChatOpenAI", DummyChatOpenAI)
    monkeypatch.setattr(phase2_module, "get_config", lambda: cfg)

    synthesizer = phase2_module.Phase2LangChainSynthesizer()
    synthesizer._create_model()

    assert captured["model"] == "ai/gemma3-qat:latest"
    assert captured["base_url"] == "http://agentguard:8088/v1/proxy/openai/v1"
    assert captured["temperature"] == 0
    assert captured["timeout"] == 45
    assert captured["max_retries"] == 0


def test_agentguard_normalizes_model_runner_v1_upstream() -> None:
    sys.path.insert(0, str(Path(__file__).parent.parent.parent / "agentic-ai-firewall"))
    from agentguard import app as agentguard_app

    original_openai = agentguard_app._OPENAI_UPSTREAM
    try:
        agentguard_app._OPENAI_UPSTREAM = "http://model-runner.docker.internal/v1/"
        upstream, target_path = agentguard_app._resolve_upstream("openai")
    finally:
        agentguard_app._OPENAI_UPSTREAM = original_openai

    assert upstream == "http://model-runner.docker.internal/v1"
    assert target_path == "/chat/completions"
