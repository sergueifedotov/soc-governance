#!/usr/bin/env python3
"""Integration tests for Phase 3 alert deduplication and incident grouping workflow."""

from __future__ import annotations

import sys
from pathlib import Path

from fastapi.testclient import TestClient


PHASE3_ROOT = Path(__file__).resolve().parents[2] / "services" / "phase3_langgraph"
sys.path.insert(0, str(PHASE3_ROOT))

from app import main as phase3_main  # type: ignore  # noqa: E402


def _alert(ts: str, rule_id: str, level: int, srcip: str, agent_id: str) -> dict:
    return {
        "timestamp": ts,
        "rule": {
            "id": rule_id,
            "level": level,
            "description": f"Rule {rule_id}",
        },
        "agent": {
            "id": agent_id,
            "name": f"agent-{agent_id}",
        },
        "data": {
            "srcip": srcip,
        },
    }


def test_grouping_clusters_related_alerts():
    phase3_main.PENDING_GROUPINGS.clear()
    client = TestClient(phase3_main.app)

    payload = {
        "incident_id": "INC-group-001",
        "confidence_threshold": 0.65,
        "window_minutes": 120,
        "alerts": [
            _alert("2026-01-01T10:00:00Z", "5710", 10, "203.0.113.5", "001"),
            _alert("2026-01-01T10:04:00Z", "5710", 10, "203.0.113.5", "001"),
            _alert("2026-01-01T10:07:00Z", "5710", 10, "203.0.113.5", "002"),
            _alert("2026-01-01T11:00:00Z", "9200", 7, "198.51.100.7", "003"),
        ],
    }

    response = client.post("/phase3/incident-grouping/run", json=payload)
    assert response.status_code == 200

    body = response.json()
    assert body["workflow_status"] == "completed_grouped"
    assert body["summary"]["total_alerts"] == 4
    assert body["summary"]["group_count"] == 2
    assert body["summary"]["deduplicated_alerts"] == 2
    assert body["groups"][0]["alert_count"] == 3


def test_grouping_respects_high_confidence_threshold():
    phase3_main.PENDING_GROUPINGS.clear()
    client = TestClient(phase3_main.app)

    payload = {
        "incident_id": "INC-group-002",
        "confidence_threshold": 0.9,
        "window_minutes": 120,
        "alerts": [
            _alert("2026-01-01T10:00:00Z", "5710", 10, "203.0.113.5", "001"),
            _alert("2026-01-01T10:04:00Z", "5710", 10, "203.0.113.5", "002"),
        ],
    }

    response = client.post("/phase3/incident-grouping/run", json=payload)
    assert response.status_code == 200

    body = response.json()
    assert body["workflow_status"] == "completed_grouped"
    assert body["summary"]["group_count"] == 2
    assert body["summary"]["deduplicated_alerts"] == 0


def test_grouping_pending_confirmation_and_resume():
    phase3_main.PENDING_GROUPINGS.clear()
    client = TestClient(phase3_main.app)

    payload = {
        "incident_id": "INC-group-003",
        "confidence_threshold": 0.65,
        "window_minutes": 120,
        "require_analyst_confirmation": True,
        "alerts": [
            _alert("2026-01-01T10:00:00Z", "5710", 10, "203.0.113.5", "001"),
            _alert("2026-01-01T10:04:00Z", "5710", 10, "203.0.113.5", "001"),
        ],
    }

    run_response = client.post("/phase3/incident-grouping/run", json=payload)
    assert run_response.status_code == 200
    run_body = run_response.json()
    assert run_body["workflow_status"] == "pending_confirmation"
    assert run_body["confirmation"]["decision"] == "pending"

    pending_response = client.get("/phase3/incident-grouping/pending/INC-group-003")
    assert pending_response.status_code == 200

    resume_response = client.post(
        "/phase3/incident-grouping/pending/INC-group-003/resume",
        json={"decision": "approved", "actor": "soc-analyst"},
    )
    assert resume_response.status_code == 200
    resume_body = resume_response.json()
    assert resume_body["workflow_status"] == "completed_grouped"
    assert resume_body["confirmation"]["decision"] == "approved"
    assert resume_body["summary"]["group_count"] == 1
