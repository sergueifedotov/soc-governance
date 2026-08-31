"""Layer 2: Case Management & Evidence REST API.

Graph operations (Neo4j)
------------------------
POST   /cases/alerts                               Ingest alert as graph node
POST   /cases/entities                             Create / merge entity node
POST   /cases/relationships                        Link two existing nodes
GET    /cases/{incident_id}/timeline               Chronological event timeline
GET    /cases/{incident_id}/graph                  Full subgraph (nodes + edges)
GET    /cases/query/by-ip/{ip}                     Incidents touching an IP
GET    /cases/query/by-domain/{domain}             Incidents touching a domain (C2)
GET    /cases/query/by-user/{username}             Incidents involving a user
GET    /cases/query/lateral-movement               Lateral-movement candidates
GET    /cases/query/attack-chain/{ip}              Kill-chain trace from an IP

Artifact operations (MinIO)
---------------------------
POST   /cases/{incident_id}/artifacts              Upload artifact file
GET    /cases/{incident_id}/artifacts              List artifacts
GET    /cases/{incident_id}/artifacts/{id}/url     Presigned download URL
DELETE /cases/{incident_id}/artifacts/{id}         Delete artifact
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared helper — push a raw alert dict to OpenCTI without Neo4j
# ---------------------------------------------------------------------------

def _push_alert_to_opencti(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Convert *alert* to a STIX2 bundle and push it to OpenCTI.

    Returns a status dict suitable for embedding in a larger response.
    Never raises — errors are captured and returned in the dict so that the
    caller's primary operation (graph write) is not affected.
    """
    import os
    opencti_url   = os.getenv("OPENCTI_URL",      "").strip()
    opencti_token = os.getenv("OPENCTI_API_TOKEN", "").strip()
    if not opencti_url or not opencti_token:
        return {"pushed": False, "reason": "OPENCTI_URL / OPENCTI_API_TOKEN not configured"}
    try:
        from forensics.opencti_client import OpenCTIClient
        from forensics.wazuh_stix import alert_to_stix_bundle
    except ImportError as exc:
        return {"pushed": False, "reason": str(exc)}
    try:
        bundle = alert_to_stix_bundle(alert)
        result = OpenCTIClient(opencti_url, opencti_token).push_bundle(bundle)
        return {
            "pushed":        True,
            "bundle_id":     bundle.get("id"),
            "stix2_objects": len(bundle.get("objects", [])),
            "response":      result,
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("OpenCTI push failed (non-fatal): %s", exc)
        return {"pushed": False, "reason": str(exc)}


# ---------------------------------------------------------------------------
# Router factory — caller supplies initialised ForensicGraph + ArtifactStore
# (either can be None when the backing service is unavailable)
# ---------------------------------------------------------------------------

def create_forensics_router(graph, store) -> APIRouter:
    """Return an APIRouter with all case-management and artifact endpoints.

    Parameters
    ----------
    graph : ForensicGraph | None
    store : ArtifactStore | None
    """

    router = APIRouter(prefix="/cases", tags=["Layer 2: Case Management & Evidence"])

    # ------------------------------------------------------------------
    # Dependency-availability guards
    # ------------------------------------------------------------------

    def _require_graph():
        if graph is None:
            raise HTTPException(503, "Graph database (Neo4j) unavailable")

    def _require_store():
        if store is None:
            raise HTTPException(503, "Artifact store (MinIO) unavailable")

    # ===================================================================
    # Graph — alert ingestion
    # ===================================================================

    @router.post("/alerts", status_code=201, summary="Ingest alert into forensic graph")
    async def ingest_alert(
        body: Dict[str, Any] = Body(...),
        push_opencti: bool = Query(False, description="Also push this alert to OpenCTI as STIX2"),
    ):
        """Create or update an ALERT node and auto-link it to IPs / users.

        Required fields: ``alert_id``, ``incident_id``
        Optional:  ``rule_id``, ``rule_name``, ``severity``, ``timestamp``,
                   ``full_log``, ``src_ip``, ``dest_ip``, ``username``

        Set ``?push_opencti=true`` to also push the alert to OpenCTI as a STIX2
        bundle (requires ``OPENCTI_URL`` and ``OPENCTI_API_TOKEN`` env vars).
        """
        _require_graph()
        alert_id    = body.get("alert_id")
        incident_id = body.get("incident_id")
        if not alert_id or not incident_id:
            raise HTTPException(422, "alert_id and incident_id are required")

        try:
            node = graph.merge_alert(
                alert_id    = str(alert_id),
                incident_id = str(incident_id),
                rule_id     = int(body.get("rule_id", 0)),
                rule_name   = str(body.get("rule_name", "")),
                severity    = int(body.get("severity", 0)),
                timestamp   = str(body.get("timestamp", "")),
                full_log    = str(body.get("full_log", "")),
            )

            links_created = []

            # Auto-link src_ip
            if body.get("src_ip"):
                graph.merge_ip(body["src_ip"])
                graph.link_alert_ip(str(alert_id), str(body["src_ip"]), role="src")
                links_created.append({"IP_ADDRESS": body["src_ip"], "role": "src"})

            # Auto-link dest_ip
            if body.get("dest_ip"):
                graph.merge_ip(body["dest_ip"])
                graph.link_alert_ip(str(alert_id), str(body["dest_ip"]), role="dst")
                links_created.append({"IP_ADDRESS": body["dest_ip"], "role": "dst"})

            # Auto-link username
            if body.get("username"):
                graph.merge_user(body["username"])
                graph.link_alert_user(str(alert_id), str(body["username"]))
                links_created.append({"USER": body["username"]})

            result: Dict[str, Any] = {
                "status":        "ok",
                "node":          node,
                "links_created": links_created,
            }

            # Optional OpenCTI push
            if push_opencti:
                result["opencti"] = _push_alert_to_opencti(body)

            return result
        except Exception as exc:
            logger.error("ingest_alert failed: %s", exc)
            raise HTTPException(500, f"Graph write failed: {exc}") from exc

    # ===================================================================
    # Graph — generic entity creation
    # ===================================================================

    @router.post("/entities", status_code=201, summary="Create / merge entity node")
    async def create_entity(body: Dict[str, Any] = Body(...)):
        """Merge an entity node into the graph.

        Required: ``node_type`` (ALERT|FILE|PROCESS|IP_ADDRESS|USER|WORKSTATION|DOMAIN)
        Required per type: providing the uniqueness key (``ip``, ``path``,
        ``pid_host``, ``username``, ``hostname``, ``name``)
        """
        _require_graph()
        node_type = str(body.get("node_type", "")).upper()

        handlers: Dict[str, Any] = {
            "IP_ADDRESS":  lambda: graph.merge_ip(body["ip"],             **_extras(body, ("ip",))),
            "DOMAIN":      lambda: graph.merge_domain(body["name"],       **_extras(body, ("name",))),
            "USER":        lambda: graph.merge_user(body["username"],     **_extras(body, ("username",))),
            "WORKSTATION": lambda: graph.merge_workstation(body["hostname"], **_extras(body, ("hostname",))),
            "PROCESS":     lambda: graph.merge_process(
                               body["pid_host"],
                               name=str(body.get("name", "")),
                               cmdline=str(body.get("cmdline", "")),
                               **_extras(body, ("pid_host", "name", "cmdline")),
                           ),
            "FILE":        lambda: graph.merge_file(body["path"],         **_extras(body, ("path",))),
        }
        if node_type not in handlers:
            raise HTTPException(422, f"Unknown node_type '{node_type}'. "
                                     f"Valid: {sorted(handlers)}")
        try:
            node = handlers[node_type]()
            return {"status": "ok", "node_type": node_type, "node": node}
        except KeyError as exc:
            raise HTTPException(422, f"Missing required field for {node_type}: {exc}") from exc
        except Exception as exc:
            raise HTTPException(500, f"Graph write failed: {exc}") from exc

    # ===================================================================
    # Graph — generic relationship creation
    # ===================================================================

    @router.post("/relationships", status_code=201, summary="Link two graph nodes")
    async def create_relationship(body: Dict[str, Any] = Body(...)):
        """Merge a named relationship between two existing nodes.

        Required fields: ``from_label``, ``from_key``, ``from_value``,
                         ``to_label``,   ``to_key``,   ``to_value``,
                         ``rel_type``
        Optional:  ``props`` (dict of edge properties)
        """
        _require_graph()
        required = ("from_label", "from_key", "from_value", "to_label", "to_key", "to_value", "rel_type")
        missing  = [k for k in required if not body.get(k)]
        if missing:
            raise HTTPException(422, f"Missing required fields: {missing}")

        ok = graph.create_relationship(
            from_label = str(body["from_label"]).upper(),
            from_key   = str(body["from_key"]),
            from_val   = str(body["from_value"]),
            to_label   = str(body["to_label"]).upper(),
            to_key     = str(body["to_key"]),
            to_val     = str(body["to_value"]),
            rel_type   = str(body["rel_type"]).upper(),
            props      = body.get("props") or {},
        )
        if not ok:
            raise HTTPException(
                404,
                f"One or both nodes not found: "
                f"{body['from_label']}({body['from_key']}={body['from_value']}) / "
                f"{body['to_label']}({body['to_key']}={body['to_value']})",
            )
        return {"status": "ok", "relationship": body["rel_type"]}

    # ===================================================================
    # Graph — timeline + subgraph
    # ===================================================================

    @router.get("/{incident_id}/timeline", summary="Forensic event timeline")
    async def get_timeline(incident_id: str):
        """Return chronological alert events + their graph links for an incident."""
        _require_graph()
        try:
            events = graph.get_incident_timeline(incident_id)
        except Exception as exc:
            raise HTTPException(500, f"Graph query failed: {exc}") from exc
        return {"incident_id": incident_id, "events": events, "count": len(events)}

    @router.get("/{incident_id}/graph", summary="Forensic subgraph for visualisation")
    async def get_graph(incident_id: str):
        """Return all nodes and edges for the incident subgraph (up to 4 hops)."""
        _require_graph()
        try:
            data = graph.get_incident_graph(incident_id)
        except Exception as exc:
            raise HTTPException(500, f"Graph query failed: {exc}") from exc
        return {
            "incident_id": incident_id,
            "nodes":       data["nodes"],
            "edges":       data["edges"],
            "node_count":  len(data["nodes"]),
            "edge_count":  len(data["edges"]),
        }

    # ===================================================================
    # Graph — entity queries
    # ===================================================================

    @router.get("/query/by-ip/{ip}", summary="Incidents involving a source/dest IP")
    async def query_by_ip(ip: str):
        _require_graph()
        try:
            incidents = graph.find_incidents_by_ip(ip)
        except Exception as exc:
            raise HTTPException(500, f"Graph query failed: {exc}") from exc
        return {"ip": ip, "incident_ids": incidents, "count": len(incidents)}

    @router.get("/query/by-domain/{domain:path}", summary="Incidents involving a domain (C2 lookup)")
    async def query_by_domain(domain: str):
        """Find all incidents whose alert graph touches a given domain — useful
        for C2 indicator pivot queries."""
        _require_graph()
        try:
            incidents = graph.find_incidents_by_domain(domain)
        except Exception as exc:
            raise HTTPException(500, f"Graph query failed: {exc}") from exc
        return {"domain": domain, "incident_ids": incidents, "count": len(incidents)}

    @router.get("/query/by-user/{username}", summary="Incidents involving a user account")
    async def query_by_user(username: str):
        _require_graph()
        try:
            incidents = graph.find_incidents_by_user(username)
        except Exception as exc:
            raise HTTPException(500, f"Graph query failed: {exc}") from exc
        return {"username": username, "incident_ids": incidents, "count": len(incidents)}

    @router.get("/query/lateral-movement", summary="Detect lateral movement candidates")
    async def lateral_movement(
        min_workstations: int = Query(2, ge=2, le=20, description="Min distinct workstations"),
    ):
        """Return users that logged into ≥ ``min_workstations`` different hosts."""
        _require_graph()
        try:
            results = graph.detect_lateral_movement(min_workstations)
        except Exception as exc:
            raise HTTPException(500, f"Graph query failed: {exc}") from exc
        return {"candidates": results, "count": len(results)}

    @router.get("/query/attack-chain/{ip}", summary="Trace attack chain from a source IP")
    async def attack_chain(
        ip: str,
        max_hops: int = Query(5, ge=1, le=10, description="Max traversal depth"),
    ):
        _require_graph()
        try:
            chains = graph.get_attack_chain(ip, max_hops)
        except Exception as exc:
            raise HTTPException(500, f"Graph query failed: {exc}") from exc
        return {"source_ip": ip, "chains": chains, "path_count": len(chains)}

    # ===================================================================
    # Artifacts — MinIO
    # ===================================================================

    @router.post("/{incident_id}/artifacts", status_code=201, summary="Upload forensic artifact")
    async def upload_artifact(
        incident_id:  str,
        file:         UploadFile = File(...),
        content_type: Optional[str] = Form(None),
        description:  Optional[str] = Form(None),
    ):
        """Upload a binary artifact (log file, pcap, memory dump, …) to MinIO.

        Returns ``artifact_id`` and ``object_name`` for subsequent operations.
        """
        _require_store()
        data = await file.read()
        if not data:
            raise HTTPException(422, "Uploaded file is empty")

        ct = content_type or file.content_type or "application/octet-stream"
        meta: Dict[str, str] = {}
        if description:
            meta["x-description"] = description[:256]

        try:
            result = store.upload(
                incident_id  = incident_id,
                filename     = file.filename or "artifact",
                data         = data,
                content_type = ct,
                metadata     = meta or None,
            )
        except Exception as exc:
            raise HTTPException(500, f"MinIO upload failed: {exc}") from exc

        return {"status": "uploaded", **result}

    @router.get("/{incident_id}/artifacts", summary="List artifacts for an incident")
    async def list_artifacts(incident_id: str):
        _require_store()
        try:
            artifacts = store.list_artifacts(incident_id)
        except Exception as exc:
            raise HTTPException(500, f"MinIO list failed: {exc}") from exc
        return {"incident_id": incident_id, "artifacts": artifacts, "count": len(artifacts)}

    @router.get("/{incident_id}/artifacts/{artifact_id}/url", summary="Get presigned download URL")
    async def get_artifact_url(
        incident_id: str,
        artifact_id: str,
        expires:     int = Query(3600, ge=60, le=86400, description="URL TTL in seconds"),
    ):
        """Generate a time-limited presigned URL for direct artifact download.

        The caller must provide the ``object_name`` from the upload response,
        or pass it as a query parameter.  Because we don't persist a mapping
        to a DB, the caller supplies the exact object_name.
        """
        _require_store()
        # Accept object_name from path or query param
        raise HTTPException(
            422,
            "Pass object_name as query parameter: GET …/url?object_name=<value>",
        )

    @router.get("/{incident_id}/artifacts/{artifact_id}/download-url",
                summary="Get presigned download URL (object_name required)")
    async def get_artifact_download_url(
        incident_id:  str,
        artifact_id:  str,
        object_name:  str = Query(..., description="Full object path from upload response"),
        expires:      int = Query(3600, ge=60, le=86400),
    ):
        _require_store()
        try:
            url = store.get_download_url(object_name, expires_seconds=expires)
        except Exception as exc:
            raise HTTPException(500, f"MinIO presigned URL failed: {exc}") from exc
        return {
            "artifact_id": artifact_id,
            "incident_id": incident_id,
            "url":         url,
            "expires_in":  expires,
        }

    @router.delete("/{incident_id}/artifacts/{artifact_id}", status_code=200,
                   summary="Delete artifact")
    async def delete_artifact(
        incident_id: str,
        artifact_id: str,
        object_name: str = Query(..., description="Full object path from upload response"),
    ):
        _require_store()
        try:
            store.delete(object_name)
        except Exception as exc:
            raise HTTPException(500, f"MinIO delete failed: {exc}") from exc
        return {"status": "deleted", "artifact_id": artifact_id, "object_name": object_name}

    # ===================================================================
    # STIX2 bundle export + ingest
    # ===================================================================

    @router.get("/stix2/bundle/{incident_id}", summary="Export incident as STIX2 2.1 bundle")
    async def export_stix2_bundle(incident_id: str):
        """Build and return a STIX2 2.1 bundle from the incident's forensic subgraph.

        Every node (ALERT, IP_ADDRESS, DOMAIN, USER, PROCESS, FILE, WORKSTATION)
        is converted to the matching SCO/SDO type; every relationship is emitted
        as a STIX2 ``relationship`` object.  An ``x-wazuh-incident`` grouping
        object is appended as the final entry.
        """
        _require_graph()
        try:
            bundle = graph.get_incident_stix2_bundle(incident_id)
        except Exception as exc:
            raise HTTPException(500, f"STIX2 export failed: {exc}") from exc
        return bundle

    @router.post("/stix2/ingest", status_code=201,
                 summary="Ingest a STIX2 bundle into the forensic graph")
    async def ingest_stix2(body: Dict[str, Any] = Body(...)):
        """Parse a STIX2 2.1 bundle and write its objects into the forensic graph.

        Supported STIX2 types (mapped to internal labels):

        | STIX2 type       | ForensicGraph label |
        |------------------|---------------------|
        | observed-data    | ALERT               |
        | ipv4-addr        | IP_ADDRESS          |
        | domain-name      | DOMAIN              |
        | user-account     | USER                |
        | process          | PROCESS             |
        | file             | FILE                |
        | infrastructure   | WORKSTATION         |

        ``relationship`` and unknown custom objects are silently skipped.
        """
        _require_graph()
        if body.get("type") != "bundle":
            raise HTTPException(422, "Body must be a STIX2 bundle (type='bundle')")
        try:
            from forensics.stix2_mapper import ingest_stix2_bundle as _parse_bundle
        except ImportError:
            raise HTTPException(503, "stix2_mapper module not available") from None

        items  = _parse_bundle(body)
        written: List[Dict] = []
        errors: List[Dict]  = []

        for item in items:
            try:
                label = item["label"]
                props = dict(item["props"])  # copy so pops don't mutate
                if label == "IP_ADDRESS":
                    graph.merge_ip(props.pop("ip", ""), **props)
                elif label == "DOMAIN":
                    graph.merge_domain(props.pop("name", ""), **props)
                elif label == "USER":
                    graph.merge_user(props.pop("username", ""), **props)
                elif label == "WORKSTATION":
                    graph.merge_workstation(props.pop("hostname", ""), **props)
                elif label == "PROCESS":
                    graph.merge_process(props.pop("pid_host", ""), **props)
                elif label == "FILE":
                    graph.merge_file(props.pop("path", ""), **props)
                elif label == "ALERT":
                    graph.merge_alert(
                        alert_id    = props.pop("alert_id",    ""),
                        incident_id = props.pop("incident_id", ""),
                        rule_id     = int(props.pop("rule_id",    0)),
                        rule_name   = props.pop("rule_name",   ""),
                        severity    = int(props.pop("severity",   0)),
                        timestamp   = props.pop("timestamp",   ""),
                        full_log    = props.pop("full_log",    ""),
                    )
                written.append({"label": label})
            except Exception as exc:
                errors.append({"label": item.get("label"), "error": str(exc)})

        return {
            "written":      len(written),
            "errors":       len(errors),
            "nodes":        written,
            "error_detail": errors,
        }

    # ===================================================================
    # OpenCTI integration
    # ===================================================================

    @router.post("/opencti/ingest-alert",
                 status_code=202,
                 summary="Convert a raw Wazuh alert to STIX2 and push to OpenCTI")
    async def opencti_ingest_alert(body: Dict[str, Any] = Body(...)):
        """Accept a raw Wazuh alert (Indexer ``_source`` or MCP compact format),
        convert it to a STIX 2.1 bundle, and push it directly to OpenCTI.

        No Neo4j graph is required — this is the lightweight real-time path.

        The body is the raw alert dict.  Useful fields (auto-detected in both
        Indexer-nested and MCP-flat shapes):

        * ``rule.id`` / ``rule_id``
        * ``data.srcip`` / ``src_ip``
        * ``data.dstip`` / ``dest_ip``
        * ``data.srcuser`` / ``username``
        * ``syscheck.path``, ``syscheck.sha256_after``
        * ``agent.name`` / ``agent_name``

        Requires ``OPENCTI_URL`` and ``OPENCTI_API_TOKEN`` environment variables.
        """
        import os
        opencti_url   = os.getenv("OPENCTI_URL",       "").strip()
        opencti_token = os.getenv("OPENCTI_API_TOKEN",  "").strip()
        if not opencti_url or not opencti_token:
            raise HTTPException(
                503,
                "OPENCTI_URL and OPENCTI_API_TOKEN environment variables are not set.",
            )
        try:
            from forensics.opencti_client import OpenCTIClient
            from forensics.wazuh_stix import alert_to_stix_bundle
        except ImportError as exc:
            raise HTTPException(503, f"Required module unavailable: {exc}") from exc

        bundle = alert_to_stix_bundle(body)
        client = OpenCTIClient(opencti_url, opencti_token)
        try:
            result = client.push_bundle(bundle)
        except RuntimeError as exc:
            raise HTTPException(502, f"OpenCTI push failed: {exc}") from exc

        return {
            "status":           "accepted",
            "bundle_id":        bundle.get("id"),
            "stix2_objects":    len(bundle.get("objects", [])),
            "opencti_response": result,
        }

    @router.get("/opencti/status", summary="Check OpenCTI connectivity")
    async def opencti_status():
        """Return whether the configured OpenCTI instance is reachable.

        Configure via ``OPENCTI_URL`` and ``OPENCTI_API_TOKEN`` environment
        variables on the phase4-api container.
        """
        import os
        opencti_url   = os.getenv("OPENCTI_URL",       "").strip()
        opencti_token = os.getenv("OPENCTI_API_TOKEN",  "").strip()
        if not opencti_url:
            return {"configured": False, "reachable": False, "url": ""}
        try:
            from forensics.opencti_client import OpenCTIClient
        except ImportError:
            return {
                "configured": True,
                "reachable":  False,
                "url":        opencti_url,
                "error":      "opencti_client module not available",
            }
        client    = OpenCTIClient(opencti_url, opencti_token)
        reachable = client.ping()
        return {"configured": True, "reachable": reachable, "url": opencti_url}

    @router.post("/opencti/sync-alerts", status_code=202,
                 summary="Bulk sync Wazuh alerts → OpenCTI + Neo4j")
    async def opencti_sync_alerts(
        hours:      int = Query(24,  ge=1,  le=720,  description="Hours back to look for alerts"),
        min_level:  int = Query(5,   ge=1,  le=15,   description="Minimum Wazuh rule level"),
        batch_size: int = Query(200, ge=1,  le=1000, description="Max alerts to sync"),
    ):
        """Fetch recent Wazuh alerts from the Indexer, convert to STIX 2.1,
        push to OpenCTI, and write each alert into the Neo4j forensic graph.

        Returns a summary with ``fetched``, ``pushed``, ``skipped``, ``errors``.
        """
        try:
            from forensics.opencti_sync import sync_alerts
        except ImportError:
            raise HTTPException(503, "opencti_sync module not available") from None
        result = await sync_alerts(
            hours=hours, min_level=min_level, batch_size=batch_size, graph=graph
        )
        if not result.get("ok", True):
            raise HTTPException(503, result.get("reason", "sync failed"))
        return result

    @router.get("/opencti/poller/status", summary="OpenCTI background poller stats")
    async def opencti_poller_status(request: Request):
        """Return live statistics from the continuous Wazuh→OpenCTI alert poller."""
        try:
            poller = getattr(request.app.state, "opencti_poller", None)
        except Exception:
            poller = None
        if poller is None:
            return {"running": False, "note": "Poller not initialised yet"}
        return {"running": True, **poller.stats}

    @router.post("/opencti/push/{incident_id}",
                 summary="Push incident forensic graph to OpenCTI as STIX2")
    async def push_to_opencti(incident_id: str):
        """Export the incident subgraph as a STIX2 2.1 bundle and ingest it into OpenCTI.

        Requires ``OPENCTI_URL`` and ``OPENCTI_API_TOKEN`` to be set in the
        phase4-api container environment.  Start OpenCTI with
        ``docker compose -f compose.phase4.yml -f compose.opencti.yml up -d``.
        """
        _require_graph()
        import os
        opencti_url   = os.getenv("OPENCTI_URL",       "").strip()
        opencti_token = os.getenv("OPENCTI_API_TOKEN",  "").strip()
        if not opencti_url or not opencti_token:
            raise HTTPException(
                503,
                "OPENCTI_URL and OPENCTI_API_TOKEN environment variables are not set. "
                "Add them to phase4-api in compose.phase4.yml and restart.",
            )
        try:
            from forensics.opencti_client import OpenCTIClient
        except ImportError:
            raise HTTPException(503, "opencti_client module not available") from None

        try:
            bundle = graph.get_incident_stix2_bundle(incident_id)
        except Exception as exc:
            raise HTTPException(500, f"STIX2 export failed: {exc}") from exc

        client = OpenCTIClient(opencti_url, opencti_token)
        try:
            result = client.push_bundle(bundle)
        except RuntimeError as exc:
            raise HTTPException(502, f"OpenCTI push failed: {exc}") from exc

        return {
            "status":           "pushed",
            "incident_id":      incident_id,
            "bundle_id":        bundle.get("id"),
            "stix2_objects":    len(bundle.get("objects", [])),
            "opencti_response": result,
        }

    @router.get("/opencti/query-indicators",
                summary="Query OpenCTI observables by value")
    async def opencti_query_indicators(
        value: str = Query(..., description="Observable value (IP/domain/hash/etc.)"),
        limit: int = Query(20, ge=1, le=100, description="Maximum results"),
    ):
        """Read-back endpoint for OpenCTI observable enrichment lookup."""
        import os
        opencti_url = os.getenv("OPENCTI_URL", "").strip()
        opencti_token = os.getenv("OPENCTI_API_TOKEN", "").strip()
        if not opencti_url:
            raise HTTPException(503, "OPENCTI_URL is not configured")
        try:
            from forensics.opencti_client import OpenCTIClient
            client = OpenCTIClient(opencti_url, opencti_token)
            return client.search_observables(value=value.strip(), limit=limit)
        except Exception as exc:
            raise HTTPException(502, f"OpenCTI lookup failed: {exc}") from exc

    @router.get("/opencti/observable",
                summary="Get one enriched observable from OpenCTI")
    async def opencti_get_observable(
        value: str = Query(..., description="Observable value (IP/domain/hash/etc.)"),
    ):
        """Fetch one observable with labels, markings, and linked indicators."""
        import os
        opencti_url = os.getenv("OPENCTI_URL", "").strip()
        opencti_token = os.getenv("OPENCTI_API_TOKEN", "").strip()
        if not opencti_url:
            raise HTTPException(503, "OPENCTI_URL is not configured")
        try:
            from forensics.opencti_client import OpenCTIClient
            client = OpenCTIClient(opencti_url, opencti_token)
            return client.get_observable(value=value.strip())
        except Exception as exc:
            raise HTTPException(502, f"OpenCTI observable lookup failed: {exc}") from exc

    @router.get("/opencti/incident/{stix_id}",
                summary="Get enriched OpenCTI incident/case by STIX ID")
    async def opencti_get_incident(stix_id: str):
        """Fetch one OpenCTI case/incident object with linked entities."""
        import os
        opencti_url = os.getenv("OPENCTI_URL", "").strip()
        opencti_token = os.getenv("OPENCTI_API_TOKEN", "").strip()
        if not opencti_url:
            raise HTTPException(503, "OPENCTI_URL is not configured")
        try:
            from forensics.opencti_client import OpenCTIClient
            client = OpenCTIClient(opencti_url, opencti_token)
            return client.get_incident(stix_id=stix_id.strip())
        except Exception as exc:
            raise HTTPException(502, f"OpenCTI incident lookup failed: {exc}") from exc

    @router.get("/opencti/cases",
                summary="List recent OpenCTI cases")
    async def opencti_list_cases(
        hours: int = Query(24, ge=1, le=8760, description="Time window in hours"),
        min_confidence: int = Query(0, ge=0, le=100, description="Minimum confidence"),
        limit: int = Query(20, ge=1, le=100, description="Maximum results"),
    ):
        """List recent OpenCTI cases for reverse-flow investigation."""
        import os
        opencti_url = os.getenv("OPENCTI_URL", "").strip()
        opencti_token = os.getenv("OPENCTI_API_TOKEN", "").strip()
        if not opencti_url:
            raise HTTPException(503, "OPENCTI_URL is not configured")
        try:
            from forensics.opencti_client import OpenCTIClient
            client = OpenCTIClient(opencti_url, opencti_token)
            return client.list_cases(hours=hours, min_confidence=min_confidence, limit=limit)
        except Exception as exc:
            raise HTTPException(502, f"OpenCTI case listing failed: {exc}") from exc

    @router.get("/neo4j/attack-chain",
                summary="Read attack chain from Neo4j forensic graph")
    async def neo4j_attack_chain(
        ip: str = Query("", description="Starting IP address (optional if alert_id is provided)"),
        alert_id: str = Query("", description="Starting alert_id (optional if ip is provided)"),
        max_hops: int = Query(5, ge=1, le=6, description="Maximum graph traversal depth"),
    ):
        """Read-only attack-chain query backed by Neo4j HTTP transaction API."""
        try:
            from forensics.neo4j_read import _default_client
            client = _default_client()
            result = client.attack_chain(ip=ip.strip(), alert_id=alert_id.strip(), max_hops=max_hops)
            return {
                "ip": ip.strip() or None,
                "alert_id": alert_id.strip() or None,
                "max_hops": max_hops,
                "path_count": len(result),
                "chains": result,
            }
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        except Exception as exc:
            raise HTTPException(502, f"Neo4j attack-chain query failed: {exc}") from exc

    @router.get("/neo4j/lateral-movement",
                summary="Detect lateral movement via Neo4j read model")
    async def neo4j_lateral_movement(
        hours: int = Query(24, ge=1, le=720, description="Time window in hours"),
        min_machines: int = Query(2, ge=2, le=100, description="Minimum distinct hosts"),
    ):
        """Return users observed on multiple workstations."""
        try:
            from forensics.neo4j_read import _default_client
            client = _default_client()
            rows = client.lateral_movement(hours=hours, min_machines=min_machines)
            return {
                "hours": hours,
                "min_machines": min_machines,
                "count": len(rows),
                "candidates": rows,
            }
        except Exception as exc:
            raise HTTPException(502, f"Neo4j lateral movement query failed: {exc}") from exc

    @router.get("/neo4j/ip-context/{ip}",
                summary="Get full IP context from Neo4j forensic graph")
    async def neo4j_ip_context(ip: str):
        """Return linked alerts and entities for one IP address."""
        try:
            from forensics.neo4j_read import _default_client
            client = _default_client()
            return client.ip_context(ip=ip.strip())
        except Exception as exc:
            raise HTTPException(502, f"Neo4j IP-context query failed: {exc}") from exc

    @router.post("/neo4j/query",
                 summary="Run read-only Cypher query against Neo4j")
    async def neo4j_query(body: Dict[str, Any] = Body(...)):
        """Execute read-only Cypher (MATCH/RETURN) with optional params."""
        cypher = str((body or {}).get("cypher", "")).strip()
        if not cypher:
            raise HTTPException(422, "'cypher' is required")
        params = (body or {}).get("params") or {}
        if not isinstance(params, dict):
            raise HTTPException(422, "'params' must be a JSON object")
        try:
            from forensics.neo4j_read import _default_client
            client = _default_client()
            rows = client.run_read_query(cypher=cypher, params=params)
            return {"rows": rows, "count": len(rows)}
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        except Exception as exc:
            raise HTTPException(502, f"Neo4j read query failed: {exc}") from exc

    # ===================================================================
    # Health
    # ===================================================================

    @router.get("/health", summary="Layer 2 health (Neo4j + MinIO)", tags=["health"])
    async def health():
        return {
            "neo4j": {
                "available": graph is not None,
                "connected": graph.ping() if graph else False,
            },
            "minio": {
                "available": store is not None,
                "connected": store.ping() if store else False,
            },
        }

    return router


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extras(body: Dict[str, Any], exclude: tuple) -> Dict[str, Any]:
    """Return body fields that are not node-type keys and not the reserved ones."""
    reserved = {"node_type"} | set(exclude)
    return {k: v for k, v in body.items() if k not in reserved and v is not None}
