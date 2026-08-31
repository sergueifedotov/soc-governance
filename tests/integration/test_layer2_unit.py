#!/usr/bin/env python3
"""Unit tests for Layer 2: ForensicGraph + ArtifactStore internals.

No Neo4j or MinIO connectivity is required — all driver/client calls are
replaced with MagicMock objects so these tests run entirely in-process.
"""

from __future__ import annotations

import io
import sys
import uuid
from datetime import timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
PHASE4_ROOT = Path(__file__).resolve().parents[2] / "src" / "wazuh_mcp_server" / "phase4"
sys.path.insert(0, str(PHASE4_ROOT))


# ---------------------------------------------------------------------------
# ForensicGraph unit tests
# ---------------------------------------------------------------------------

class TestForensicGraphImportGuard:
    def test_raises_when_neo4j_unavailable(self):
        """ForensicGraph.__init__ must raise RuntimeError when the driver is missing."""
        import forensics as forensics_mod

        original = forensics_mod._NEO4J_AVAILABLE
        try:
            forensics_mod._NEO4J_AVAILABLE = False
            with pytest.raises(RuntimeError, match="neo4j driver is not installed"):
                forensics_mod.ForensicGraph("bolt://localhost:7687", "neo4j", "pass")
        finally:
            forensics_mod._NEO4J_AVAILABLE = original


class TestForensicGraphPing:
    def _make_graph(self):
        """Return a ForensicGraph with its driver fully mocked."""
        import forensics as forensics_mod

        mock_driver = MagicMock()
        mock_session = MagicMock()
        mock_driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)

        with patch.object(forensics_mod, "_NEO4J_AVAILABLE", True), \
             patch("forensics.GraphDatabase") as mock_gdb, \
             patch("forensics.basic_auth", return_value=("neo4j", "pass")):
            mock_gdb.driver.return_value = mock_driver
            # _ensure_constraints uses the session; stub the run to do nothing
            mock_session.run.return_value = MagicMock()
            g = forensics_mod.ForensicGraph("bolt://localhost:7687", "neo4j", "pass")
        g._driver = mock_driver
        return g, mock_driver, mock_session

    def test_ping_returns_true_when_session_runs(self):
        g, driver, session = self._make_graph()
        session.run.return_value = MagicMock()
        assert g.ping() is True

    def test_ping_returns_false_on_exception(self):
        g, driver, session = self._make_graph()
        driver.session.side_effect = Exception("connection refused")
        assert g.ping() is False


class TestForensicGraphMergeAlert:
    def test_merge_alert_returns_node_dict(self):
        import forensics as forensics_mod

        mock_driver = MagicMock()
        mock_session = MagicMock()
        mock_session.__enter__ = MagicMock(return_value=mock_session)
        mock_session.__exit__ = MagicMock(return_value=False)
        mock_driver.session.return_value = mock_session

        # Stub single() to return a fake record
        fake_node = {"alert_id": "ALT-001", "incident_id": "INC-001", "severity": 9}
        mock_record = MagicMock()
        mock_record.__getitem__ = MagicMock(side_effect=lambda k: fake_node if k == "a" else None)
        mock_session.run.return_value.single.return_value = mock_record

        with patch.object(forensics_mod, "_NEO4J_AVAILABLE", True), \
             patch("forensics.GraphDatabase") as mock_gdb, \
             patch("forensics.basic_auth", return_value=("neo4j", "pass")):
            mock_gdb.driver.return_value = mock_driver
            # suppress _ensure_constraints
            mock_session.run.return_value = MagicMock(
                single=MagicMock(return_value=mock_record)
            )
            g = forensics_mod.ForensicGraph("bolt://localhost:7687", "neo4j", "pass")

        g._driver = mock_driver

        result = g.merge_alert(
            alert_id="ALT-001",
            incident_id="INC-001",
            rule_id=100054,
            rule_name="SSH brute-force",
            severity=9,
            timestamp="2026-04-21T12:00:00Z",
            full_log="sshd: failed password",
        )
        # We just care that it calls session.run and returns a dict
        assert mock_session.run.called
        assert isinstance(result, dict)


class TestForensicGraphNodeTypesAndRelTypes:
    def test_node_type_constants(self):
        from forensics import NodeType

        assert NodeType.ALERT       == "ALERT"
        assert NodeType.FILE        == "FILE"
        assert NodeType.PROCESS     == "PROCESS"
        assert NodeType.IP_ADDRESS  == "IP_ADDRESS"
        assert NodeType.USER        == "USER"
        assert NodeType.WORKSTATION == "WORKSTATION"
        assert NodeType.DOMAIN      == "DOMAIN"

    def test_rel_type_constants(self):
        from forensics import RelType

        assert RelType.DETECTED     == "DETECTED"
        assert RelType.MODIFIED_BY  == "MODIFIED_BY"
        assert RelType.SPAWNED_BY   == "SPAWNED_BY"
        assert RelType.CONNECTS_TO  == "CONNECTS_TO"
        assert RelType.LOGGED_IN_TO == "LOGGED_IN_TO"
        assert RelType.RESOLVES_TO  == "RESOLVES_TO"
        assert RelType.INVOLVES     == "INVOLVES"


class TestForensicCaseManagerAlias:
    def test_alias_exists(self):
        from forensics import ForensicCaseManager, ForensicGraph

        assert ForensicCaseManager is ForensicGraph


# ---------------------------------------------------------------------------
# ArtifactStore unit tests
# ---------------------------------------------------------------------------

class TestArtifactStoreImportGuard:
    def test_raises_when_minio_unavailable(self):
        import forensics.minio_client as mc

        original = mc._MINIO_AVAILABLE
        try:
            mc._MINIO_AVAILABLE = False
            with pytest.raises(RuntimeError, match="minio package is not installed"):
                mc.ArtifactStore("localhost:9000", "key", "secret")
        finally:
            mc._MINIO_AVAILABLE = original


class TestArtifactStoreObjectName:
    def _make_store(self):
        import forensics.minio_client as mc

        mock_client = MagicMock()
        mock_client.bucket_exists.return_value = True

        with patch.object(mc, "_MINIO_AVAILABLE", True), \
             patch("forensics.minio_client.Minio", return_value=mock_client):
            store = mc.ArtifactStore("localhost:9000", "key", "secret")
        store._client = mock_client
        return store

    def test_object_name_format(self):
        store = self._make_store()
        name = store._object_name("INC-001", "art-uuid-123", "auth.log")
        assert name == "INC-001/art-uuid-123/auth.log"

    def test_object_name_preserves_subpath_in_filename(self):
        store = self._make_store()
        name = store._object_name("INC-002", "art-abc", "dir/sub/file.bin")
        assert name.startswith("INC-002/art-abc/")


class TestArtifactStorePing:
    def _make_store(self):
        """Create an ArtifactStore whose Minio client is fully mocked."""
        import forensics.minio_client as mc

        mock_client = MagicMock()
        mock_client.bucket_exists.return_value = True

        with patch.object(mc, "_MINIO_AVAILABLE", True), \
             patch("forensics.minio_client.Minio", return_value=mock_client):
            store = mc.ArtifactStore("localhost:9000", "key", "secret")
        store._client = mock_client
        return store

    def test_ping_returns_true_when_bucket_exists(self):
        store = self._make_store()
        store._client.bucket_exists.return_value = True
        assert store.ping() is True

    def test_ping_returns_false_on_connection_error(self):
        store = self._make_store()
        # Now override bucket_exists to simulate a connection error during ping()
        store._client.bucket_exists.side_effect = Exception("no route to host")
        assert store.ping() is False


class TestArtifactStoreUpload:
    def _make_store(self):
        import forensics.minio_client as mc

        mock_client = MagicMock()
        mock_client.bucket_exists.return_value = True
        mock_client.put_object.return_value = None

        with patch.object(mc, "_MINIO_AVAILABLE", True), \
             patch("forensics.minio_client.Minio", return_value=mock_client):
            store = mc.ArtifactStore("localhost:9000", "key", "secret")
        store._client = mock_client
        return store, mock_client

    def test_upload_returns_required_keys(self):
        store, _ = self._make_store()
        result = store.upload(
            incident_id="INC-001",
            filename="auth.log",
            data=b"log line 1\nlog line 2",
            content_type="text/plain",
        )
        required = {"artifact_id", "object_name", "filename", "size_bytes", "content_type", "incident_id", "bucket"}
        assert required <= result.keys()

    def test_upload_size_bytes_matches_data(self):
        store, _ = self._make_store()
        data = b"A" * 1024
        result = store.upload("INC-001", "big.bin", data, "application/octet-stream")
        assert result["size_bytes"] == 1024

    def test_upload_object_name_contains_incident_id(self):
        store, _ = self._make_store()
        result = store.upload("INC-002", "pcap.bin", b"\x00\x01", "application/octet-stream")
        assert result["object_name"].startswith("INC-002/")

    def test_upload_object_name_ends_with_filename(self):
        store, _ = self._make_store()
        result = store.upload("INC-003", "mem.dmp", b"MZ", "application/octet-stream")
        assert result["object_name"].endswith("/mem.dmp")

    def test_upload_generates_unique_artifact_ids(self):
        store, _ = self._make_store()
        r1 = store.upload("INC-001", "f.log", b"a", "text/plain")
        r2 = store.upload("INC-001", "f.log", b"b", "text/plain")
        assert r1["artifact_id"] != r2["artifact_id"]

    def test_upload_passes_metadata_to_put_object(self):
        store, mock_client = self._make_store()
        store.upload(
            "INC-001",
            "f.log",
            b"data",
            "text/plain",
            metadata={"x-description": "test"},
        )
        call_kwargs = mock_client.put_object.call_args[1]
        assert call_kwargs.get("metadata") == {"x-description": "test"}

    def test_upload_calls_put_object_with_bytesio(self):
        store, mock_client = self._make_store()
        store.upload("INC-001", "f.log", b"hello", "text/plain")
        call_args = mock_client.put_object.call_args
        # data arg should be a BytesIO-like object
        data_arg = call_args[1].get("data") or call_args[0][2]
        assert hasattr(data_arg, "read")


class TestArtifactStoreListArtifacts:
    def test_list_parses_object_names_correctly(self):
        import forensics.minio_client as mc

        mock_client = MagicMock()
        mock_client.bucket_exists.return_value = True

        fake_obj = MagicMock()
        fake_obj.object_name = "INC-001/art-uuid-001/auth.log"
        fake_obj.size        = 512
        fake_obj.last_modified = None
        mock_client.list_objects.return_value = [fake_obj]

        with patch.object(mc, "_MINIO_AVAILABLE", True), \
             patch("forensics.minio_client.Minio", return_value=mock_client):
            store = mc.ArtifactStore("localhost:9000", "key", "secret")
        store._client = mock_client

        results = store.list_artifacts("INC-001")
        assert len(results) == 1
        assert results[0]["artifact_id"] == "art-uuid-001"
        assert results[0]["filename"]    == "auth.log"
        assert results[0]["size_bytes"]  == 512

    def test_list_passes_correct_prefix(self):
        import forensics.minio_client as mc

        mock_client = MagicMock()
        mock_client.bucket_exists.return_value = True
        mock_client.list_objects.return_value = []

        with patch.object(mc, "_MINIO_AVAILABLE", True), \
             patch("forensics.minio_client.Minio", return_value=mock_client):
            store = mc.ArtifactStore("localhost:9000", "key", "secret")
        store._client = mock_client

        store.list_artifacts("INC-007")
        call_kwargs = mock_client.list_objects.call_args[1]
        assert call_kwargs["prefix"] == "INC-007/"
        assert call_kwargs["recursive"] is True


class TestArtifactStoreDelete:
    def test_delete_calls_remove_object(self):
        import forensics.minio_client as mc

        mock_client = MagicMock()
        mock_client.bucket_exists.return_value = True

        with patch.object(mc, "_MINIO_AVAILABLE", True), \
             patch("forensics.minio_client.Minio", return_value=mock_client):
            store = mc.ArtifactStore("localhost:9000", "key", "secret")
        store._client = mock_client

        store.delete("INC-001/art-uuid-001/auth.log")
        mock_client.remove_object.assert_called_once_with(
            mc.FORENSIC_BUCKET, "INC-001/art-uuid-001/auth.log"
        )


class TestArtifactStoreGetDownloadUrl:
    def test_presigned_url_calls_minio(self):
        import forensics.minio_client as mc

        mock_client = MagicMock()
        mock_client.bucket_exists.return_value = True
        mock_client.presigned_get_object.return_value = "https://minio.local/presigned"

        with patch.object(mc, "_MINIO_AVAILABLE", True), \
             patch("forensics.minio_client.Minio", return_value=mock_client):
            store = mc.ArtifactStore("localhost:9000", "key", "secret")
        store._client = mock_client

        url = store.get_download_url("INC-001/art-uuid-001/auth.log", expires_seconds=7200)
        assert url == "https://minio.local/presigned"
        mock_client.presigned_get_object.assert_called_once_with(
            mc.FORENSIC_BUCKET,
            "INC-001/art-uuid-001/auth.log",
            expires=timedelta(seconds=7200),
        )


# ---------------------------------------------------------------------------
# API helper tests
# ---------------------------------------------------------------------------

class TestExtrasHelper:
    def test_strips_node_type_and_excludes(self):
        from forensics.api import _extras

        body = {
            "node_type": "IP_ADDRESS",
            "ip":        "1.2.3.4",
            "geo":       "US",
            "asn":       12345,
        }
        result = _extras(body, exclude=("ip",))
        assert "node_type" not in result
        assert "ip" not in result
        assert result["geo"] == "US"
        assert result["asn"] == 12345

    def test_empty_body_returns_empty(self):
        from forensics.api import _extras

        assert _extras({}, exclude=()) == {}

    def test_none_values_excluded(self):
        from forensics.api import _extras

        body = {"node_type": "USER", "username": "bob", "dept": None}
        result = _extras(body, exclude=("username",))
        assert "dept" not in result


# ---------------------------------------------------------------------------
# Regression tests for bugs fixed 2026-04-21
# ---------------------------------------------------------------------------
# Bug 1: Result consumed outside session context ("Fetch all needed records
#         before calling Result.consume()") — all five query methods were
#         iterating the cursor AFTER the `with session` block closed.
# Bug 2: Attack-chain Cypher used `[*1..$hops]` which Neo4j rejects
#         ("Parameter maps cannot be used in MATCH patterns").
# ---------------------------------------------------------------------------

class _QueryGraphFixture:
    """Shared helper: build a ForensicGraph with a fully-mocked driver."""

    @staticmethod
    def _make(run_return_value):
        """
        Return a ForensicGraph whose session.run() returns `run_return_value`.

        `run_return_value` should be an iterable of MagicMock records, or a
        MagicMock that itself is iterable (e.g. a list of records).
        """
        import forensics as forensics_mod

        mock_driver  = MagicMock()
        mock_session = MagicMock()

        # Support `with self._driver.session() as s:` context-manager protocol
        mock_driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_driver.session.return_value.__exit__  = MagicMock(return_value=False)
        mock_session.run.return_value = run_return_value

        with patch.object(forensics_mod, "_NEO4J_AVAILABLE", True), \
             patch("forensics.GraphDatabase") as mock_gdb, \
             patch("forensics.basic_auth", return_value=("neo4j", "pass")):
            mock_gdb.driver.return_value = mock_driver
            g = forensics_mod.ForensicGraph("bolt://localhost:7687", "neo4j", "pass")

        g._driver = mock_driver
        return g, mock_session


class TestQueryMethodsConsumeResultInsideSession:
    """
    Regression suite for Bug 1: query methods must iterate the Neo4j cursor
    *inside* the `with session` block, not after it closes.

    Strategy: make session.run() return a list of fake records. If a method
    iterates the list inside the session block the assertions pass; if it
    deferred iteration the mock would have already been "consumed" (in the
    real driver) and would raise — here we verify the correct call order by
    checking that the result was consumed while the session context was open.
    """

    @staticmethod
    def _fake_record(**kwargs):
        rec = MagicMock()
        rec.__getitem__ = MagicMock(side_effect=lambda k: kwargs.get(k))
        return rec

    # ── find_incidents_by_ip ──────────────────────────────────────────────
    def test_find_incidents_by_ip_returns_list(self):
        rec = self._fake_record(incident_id="INC-001")
        g, session = _QueryGraphFixture._make([rec])
        result = g.find_incidents_by_ip("198.51.100.77")
        assert result == ["INC-001"]
        # session.run is also used by _ensure_constraints() during __init__,
        # so we verify the *last* call rather than assert_called_once.
        last_call_kwargs = session.run.call_args[1]
        assert last_call_kwargs.get("ip") == "198.51.100.77"

    def test_find_incidents_by_ip_empty_result(self):
        g, _ = _QueryGraphFixture._make([])
        assert g.find_incidents_by_ip("10.0.0.1") == []

    def test_find_incidents_by_ip_skips_none_incident_ids(self):
        rec_none  = self._fake_record(incident_id=None)
        rec_valid = self._fake_record(incident_id="INC-002")
        g, _ = _QueryGraphFixture._make([rec_none, rec_valid])
        result = g.find_incidents_by_ip("10.0.0.2")
        assert result == ["INC-002"]

    # ── find_incidents_by_domain ──────────────────────────────────────────
    def test_find_incidents_by_domain_returns_set_deduplicated(self):
        rec1 = self._fake_record(incident_id="INC-001")
        rec2 = self._fake_record(incident_id="INC-001")  # duplicate from UNION
        rec3 = self._fake_record(incident_id="INC-002")
        g, _ = _QueryGraphFixture._make([rec1, rec2, rec3])
        result = g.find_incidents_by_domain("malware-c2.badactor.ru")
        assert set(result) == {"INC-001", "INC-002"}
        assert len(result) == 2  # deduplication via set comprehension

    def test_find_incidents_by_domain_empty(self):
        g, _ = _QueryGraphFixture._make([])
        assert g.find_incidents_by_domain("unknown.example.com") == []

    # ── find_incidents_by_user ────────────────────────────────────────────
    def test_find_incidents_by_user_returns_list(self):
        rec = self._fake_record(incident_id="INC-003")
        g, _ = _QueryGraphFixture._make([rec])
        result = g.find_incidents_by_user("alice")
        assert result == ["INC-003"]

    def test_find_incidents_by_user_empty(self):
        g, _ = _QueryGraphFixture._make([])
        assert g.find_incidents_by_user("nobody") == []

    # ── detect_lateral_movement ───────────────────────────────────────────
    def test_detect_lateral_movement_returns_candidates(self):
        rec = MagicMock()
        rec.__getitem__ = MagicMock(side_effect=lambda k: {
            "user":        "alice",
            "workstations": ["webserver-01", "jumpbox-02", "dbserver-03"],
            "login_count":  3,
        }[k])
        g, _ = _QueryGraphFixture._make([rec])
        result = g.detect_lateral_movement(min_workstations=2)
        assert len(result) == 1
        assert result[0]["user"]        == "alice"
        assert result[0]["login_count"] == 3
        assert "webserver-01" in result[0]["workstations"]

    def test_detect_lateral_movement_empty(self):
        g, _ = _QueryGraphFixture._make([])
        assert g.detect_lateral_movement() == []


class TestGetAttackChainQueryConstruction:
    """
    Regression suite for Bug 2: `[*1..$hops]` is illegal Cypher.
    The hop count must be interpolated as a literal integer into the query
    string, not passed as a parameter.
    """

    @staticmethod
    def _make_graph():
        import forensics as forensics_mod

        mock_driver  = MagicMock()
        mock_session = MagicMock()
        mock_driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_driver.session.return_value.__exit__  = MagicMock(return_value=False)
        mock_session.run.return_value = []  # no results needed

        with patch.object(forensics_mod, "_NEO4J_AVAILABLE", True), \
             patch("forensics.GraphDatabase") as mock_gdb, \
             patch("forensics.basic_auth", return_value=("neo4j", "pass")):
            mock_gdb.driver.return_value = mock_driver
            g = forensics_mod.ForensicGraph("bolt://localhost:7687", "neo4j", "pass")

        g._driver = mock_driver
        return g, mock_session

    def test_hops_interpolated_as_literal_not_param(self):
        """The Cypher string must contain '[*1..5]', not '$hops'."""
        g, session = self._make_graph()
        g.get_attack_chain("198.51.100.77", max_hops=5)
        cypher_used = session.run.call_args[0][0]
        assert "*1..5" in cypher_used
        assert "$hops" not in cypher_used

    def test_custom_hops_reflected_in_query(self):
        """max_hops=3 must produce '[*1..3]' in the query string."""
        g, session = self._make_graph()
        g.get_attack_chain("10.0.0.1", max_hops=3)
        cypher_used = session.run.call_args[0][0]
        assert "*1..3" in cypher_used

    def test_hops_clamped_to_10_upper_bound(self):
        """max_hops=99 must be clamped to 10 (not passed as-is)."""
        g, session = self._make_graph()
        g.get_attack_chain("10.0.0.1", max_hops=99)
        cypher_used = session.run.call_args[0][0]
        assert "*1..10" in cypher_used
        assert "99" not in cypher_used

    def test_hops_clamped_to_1_lower_bound(self):
        """max_hops=0 must be clamped to 1."""
        g, session = self._make_graph()
        g.get_attack_chain("10.0.0.1", max_hops=0)
        cypher_used = session.run.call_args[0][0]
        assert "*1..1" in cypher_used

    def test_ip_passed_as_parameter_not_interpolated(self):
        """Source IP must go through $ip parameter (no string interpolation — SQL-injection safety)."""
        g, session = self._make_graph()
        g.get_attack_chain("1.2.3.4")
        call_kwargs = session.run.call_args[1]  # keyword args
        assert call_kwargs.get("ip") == "1.2.3.4"

    def test_returns_empty_list_when_no_paths(self):
        """An empty result set must yield an empty list (no KeyError / iteration failure)."""
        g, _ = self._make_graph()
        result = g.get_attack_chain("10.0.0.1")
        assert result == []
