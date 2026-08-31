#!/usr/bin/env python3
"""Integration tests for Phase 4 proxy policy recommendation endpoint."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient


# Force a local SQLite DB so importing the Phase 4 app does not require Postgres.
os.environ.setdefault("DATABASE_URL", "sqlite:///./phase4_test.db")

# Add Phase 4 service path so local imports in server.py resolve correctly.
PHASE4_ROOT = Path(__file__).resolve().parents[2] / "src" / "wazuh_mcp_server" / "phase4"
sys.path.insert(0, str(PHASE4_ROOT))

import server as phase4_server  # type: ignore  # noqa: E402



def test_proxy_policy_recommendations_success(monkeypatch):
    """Endpoint returns structured recommendations and always requires review."""

    denied_payload = {
        "events": [
            {
                "timestamp": "2026-05-15T12:00:00Z",
                "tool": "write_alert",
                "reason": "tool_denied",
                "client_ip": "192.168.65.1",
                "metadata": {"labels": ["policy_probing"]},
            },
            {
                "timestamp": "2026-05-15T12:01:00Z",
                "tool": "write_alert",
                "reason": "tool_denied",
                "client_ip": "192.168.65.1",
                "metadata": {"labels": ["policy_probing"]},
            },
            {
                "timestamp": "2026-05-15T12:02:00Z",
                "tool": "bulk_operation",
                "reason": "rate_limit",
                "client_ip": "192.168.65.2",
                "metadata": {"labels": ["rate_abuse"]},
            },
        ]
    }

    class _FakeHTTPResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps(denied_payload).encode("utf-8")

    def _fake_urlopen(req, timeout=15):
        assert "/recent-denied" in req.full_url
        return _FakeHTTPResponse()

    monkeypatch.setattr(phase4_server.urllib_request, "urlopen", _fake_urlopen)

    async def _fake_execute_tool(self, tool_name, arguments):
        assert tool_name == "generate_proxy_policy_recommendations"
        assert arguments["focus"] == "all"
        assert arguments["time_range"] == "24h"
        return {
            "data": {
                "analysis": "LLM generated policy tuning review.",
                "orchestration": {"engine": "policy-deterministic", "status": "completed"},
                "recommendations": [
                    {
                        "title": "Mask secrets in write_alert payloads",
                        "action": "redact",
                        "target": "tool_arguments[write_alert]",
                        "rationale": "Repeated denials indicate sensitive fields should be masked.",
                        "confidence": 0.84,
                        "impact": "low",
                        "tool_scope": ["write_alert"],
                    }
                ],
            }
        }

    monkeypatch.setattr(phase4_server.MCPToolClient, "execute_tool", _fake_execute_tool)

    client = TestClient(phase4_server.app)
    response = client.post(
        "/soc/proxy-policy-recommendations",
        json={
            "time_range": "24h",
            "limit": 100,
            "focus": "all",
            "recommendation_types": ["masking", "discovery"],
        },
    )

    assert response.status_code == 200
    body = response.json()

    assert body["status"] == "ok"
    assert body["llm"]["invoked"] is True
    assert body["llm"]["engine"] == "policy-deterministic"
    assert body["human_review_required"] is True
    assert body["safety_model"] == "recommendations_only_no_auto_apply"
    assert body["summary"]["time_range"] == "24h"
    assert body["summary"]["focus"] == "all"
    assert body["summary"]["total_denied"] == 3

    assert isinstance(body["recommendations"], list)
    assert len(body["recommendations"]) >= 1
    assert body["recommendations"][0]["title"] == "Mask secrets in write_alert payloads"
    rec_types = {rec.get("type") for rec in body["recommendations"]}
    assert "masking" in rec_types or "discovery" in rec_types


def test_proxy_policy_recommendations_llm_fallback(monkeypatch):
    """Endpoint falls back to heuristics when the LLM report invocation fails."""

    denied_payload = {
        "events": [
            {
                "timestamp": "2026-05-15T12:00:00Z",
                "tool": "write_alert",
                "reason": "tool_denied",
                "client_ip": "192.168.65.1",
                "metadata": {"labels": ["policy_probing"]},
            },
            {
                "timestamp": "2026-05-15T12:01:00Z",
                "tool": "bulk_operation",
                "reason": "rate_limit",
                "client_ip": "192.168.65.2",
                "metadata": {"labels": ["rate_abuse"]},
            },
        ]
    }

    class _FakeHTTPResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps(denied_payload).encode("utf-8")

    def _fake_urlopen(req, timeout=15):
        assert "/recent-denied" in req.full_url
        return _FakeHTTPResponse()

    async def _failing_execute_tool(self, tool_name, arguments):
        raise RuntimeError("MCP unavailable")

    monkeypatch.setattr(phase4_server.urllib_request, "urlopen", _fake_urlopen)
    monkeypatch.setattr(phase4_server.MCPToolClient, "execute_tool", _failing_execute_tool)

    client = TestClient(phase4_server.app)
    response = client.post(
        "/soc/proxy-policy-recommendations",
        json={
            "time_range": "24h",
            "limit": 100,
            "focus": "all",
            "recommendation_types": ["masking", "discovery"],
        },
    )

    assert response.status_code == 200
    body = response.json()

    assert body["llm"]["invoked"] is False
    assert body["llm"]["fallback_used"] is True
    assert body["llm"]["engine"] == "deterministic"
    assert isinstance(body["recommendations"], list)
    assert len(body["recommendations"]) >= 1


def test_policy_recommendations_action_accept():
    """User can accept a recommendation via the action endpoint."""
    client = TestClient(phase4_server.app)
    
    sample_rec = {
        "type": "masking",
        "target": "client_ip",
        "action": "redact",
        "rationale": "Top offending client appears in 47 denied calls",
        "confidence": 0.7,
        "tool_scope": ["write_alert"],
        "impact": "low",
    }
    
    response = client.post(
        "/soc/policy-recommendations-action",
        json={
            "recommendation_index": 0,
            "action": "accept",
            "recommendation_data": sample_rec,
            "timestamp": "2026-05-15T12:00:00Z",
        },
    )
    
    assert response.status_code == 200
    body = response.json()
    
    assert body["status"] == "ok"
    assert body["action_recorded"] is True
    assert body["action"] == "accept"
    assert body["recommendation_index"] == 0
    assert "masking" in body["detail"].lower()


def test_policy_recommendations_action_reject():
    """User can reject a recommendation via the action endpoint."""
    client = TestClient(phase4_server.app)
    
    sample_rec = {
        "type": "discovery",
        "signal": "repeated_tool_denials",
        "action": "monitor",
        "confidence": 0.65,
    }
    
    response = client.post(
        "/soc/policy-recommendations-action",
        json={
            "recommendation_index": 2,
            "action": "reject",
            "recommendation_data": sample_rec,
            "timestamp": "2026-05-15T12:05:00Z",
        },
    )
    
    assert response.status_code == 200
    body = response.json()
    
    assert body["status"] == "ok"
    assert body["action_recorded"] is True
    assert body["action"] == "reject"
    assert body["recommendation_index"] == 2
    assert "discovery" in body["detail"].lower()


def test_policy_recommendations_action_invalid_action():
    """Invalid action is rejected."""
    client = TestClient(phase4_server.app)
    
    response = client.post(
        "/soc/policy-recommendations-action",
        json={
            "recommendation_index": 0,
            "action": "invalid_action",
            "recommendation_data": {},
        },
    )
    
    assert response.status_code == 400
    body = response.json()
    assert "accept" in body["detail"] or "reject" in body["detail"]

