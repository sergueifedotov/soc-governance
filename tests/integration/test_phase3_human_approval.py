#!/usr/bin/env python3
"""Integration tests for Phase 3 human approval pause/resume flow."""

from __future__ import annotations

import sys
from pathlib import Path

from fastapi.testclient import TestClient


# Add Phase 3 service path so we can import app.main as a namespace package module.
PHASE3_ROOT = Path(__file__).resolve().parents[2] / "services" / "phase3_langgraph"
sys.path.insert(0, str(PHASE3_ROOT))

from app import main as phase3_main  # type: ignore  # noqa: E402


async def _mock_mcp_call(base_url: str, api_key: str, tool_name: str, arguments: dict):
    """Return deterministic fake MCP responses for workflow nodes."""
    return {
        "jsonrpc": "2.0",
        "id": f"test-{tool_name}",
        "result": {
            "isError": False,
            "content": [
                {
                    "type": "text",
                    "text": (
                        '{"data":{"tool":"%s","arguments":%s},'
                        '"orchestration":{"summary":"ok"}}'
                    )
                    % (tool_name, arguments),
                }
            ],
        },
    }


def _build_request(incident_id: str) -> dict:
    return {
        "incident_id": incident_id,
        "risk_tier": "medium",
        "use_case": "block_ip",
        "time_range": "1h",
        "auto_approve": False,
        "action_args": {
            "agent_id": "002",
            "src_ip": "198.51.100.27",
            "duration": 1800,
        },
    }


def test_pending_approval_can_resume_approved(monkeypatch):
    monkeypatch.setattr(phase3_main, "_mcp_call", _mock_mcp_call)
    phase3_main.PENDING_APPROVALS.clear()

    client = TestClient(phase3_main.app)
    incident_id = "INC-test-pending-approve"

    run_response = client.post("/phase3/run", json=_build_request(incident_id))
    assert run_response.status_code == 200
    run_body = run_response.json()
    assert run_body["workflow_status"] == "pending_approval"
    assert run_body["approval"]["decision"] == "pending"

    pending_response = client.get(f"/phase3/approvals/{incident_id}")
    assert pending_response.status_code == 200
    pending_body = pending_response.json()
    assert pending_body["approval"]["decision"] == "pending"

    resume_response = client.post(
        f"/phase3/approvals/{incident_id}/resume",
        json={"decision": "approved", "actor": "soc-analyst"},
    )
    assert resume_response.status_code == 200
    resume_body = resume_response.json()
    assert resume_body["workflow_status"] == "completed_actioned"
    assert resume_body["approval"]["decision"] == "approved"
    assert resume_body["approval"]["actor"] == "soc-analyst"
    assert resume_body["outputs"]["execution"]["status"] == "passed"


def test_pending_approval_can_resume_rejected(monkeypatch):
    monkeypatch.setattr(phase3_main, "_mcp_call", _mock_mcp_call)
    phase3_main.PENDING_APPROVALS.clear()

    client = TestClient(phase3_main.app)
    incident_id = "INC-test-pending-reject"

    run_response = client.post("/phase3/run", json=_build_request(incident_id))
    assert run_response.status_code == 200
    assert run_response.json()["workflow_status"] == "pending_approval"

    resume_response = client.post(
        f"/phase3/approvals/{incident_id}/resume",
        json={"decision": "rejected", "actor": "soc-analyst"},
    )
    assert resume_response.status_code == 200
    resume_body = resume_response.json()
    assert resume_body["workflow_status"] == "completed_rejected"
    assert resume_body["approval"]["decision"] == "rejected"
    assert resume_body["outputs"]["execution"] is None


def test_resume_missing_incident_returns_404():
    phase3_main.PENDING_APPROVALS.clear()
    client = TestClient(phase3_main.app)

    missing_response = client.post(
        "/phase3/approvals/INC-missing/resume",
        json={"decision": "approved", "actor": "soc-analyst"},
    )
    assert missing_response.status_code == 404
