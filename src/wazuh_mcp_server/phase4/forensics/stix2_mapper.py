"""STIX2 2.1 mapper for ForensicGraph nodes and edges.

Maps internal node labels and relationship types to STIX2 SCO/SDO types,
generates deterministic STIX2 IDs (UUID v5), and serializes / deserializes
STIX2 bundles.  No external 'stix2' library required — uses stdlib only.

STIX2 type mapping
------------------
  ALERT        → observed-data  (SDO)
  IP_ADDRESS   → ipv4-addr      (SCO)
  DOMAIN       → domain-name    (SCO)
  USER         → user-account   (SCO)
  PROCESS      → process        (SCO)
  FILE         → file           (SCO)
  WORKSTATION  → infrastructure (SDO)

All nodes are tagged with ``stix2_type`` and ``stix2_id`` when written to
Neo4j so that every graph object carries its STIX2 identity persistently.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# STIX2 2.1 deterministic-ID namespace (official, from the spec)
# ---------------------------------------------------------------------------

STIX2_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


# ---------------------------------------------------------------------------
# Type mappings
# ---------------------------------------------------------------------------

STIX2_TYPE_MAP: Dict[str, str] = {
    "ALERT":       "observed-data",
    "IP_ADDRESS":  "ipv4-addr",
    "DOMAIN":      "domain-name",
    "USER":        "user-account",
    "PROCESS":     "process",
    "FILE":        "file",
    "WORKSTATION": "infrastructure",
}

STIX2_REL_MAP: Dict[str, str] = {
    "INVOLVES":     "related-to",
    "DETECTED":     "related-to",
    "MODIFIED_BY":  "related-to",
    "SPAWNED_BY":   "related-to",
    "CONNECTS_TO":  "communicates-with",
    "LOGGED_IN_TO": "uses",
    "RESOLVES_TO":  "resolves-to",
}

# Node label → primary uniqueness key property (mirrors Neo4j uniqueness constraints)
NODE_KEY_MAP: Dict[str, str] = {
    "ALERT":       "alert_id",
    "IP_ADDRESS":  "ip",
    "DOMAIN":      "name",
    "USER":        "username",
    "PROCESS":     "pid_host",
    "FILE":        "path",
    "WORKSTATION": "hostname",
}


# ---------------------------------------------------------------------------
# ID generation
# ---------------------------------------------------------------------------

def make_stix2_id(stix_type: str, unique_value: str) -> str:
    """Generate a deterministic STIX2 2.1 ID using UUID v5."""
    uid = uuid.uuid5(STIX2_NAMESPACE, f"{stix_type}:{unique_value}")
    return f"{stix_type}--{uid}"


def node_stix2_id(label: str, props: Dict[str, Any]) -> str:
    """Return the STIX2 ID for a graph node (cached or freshly derived)."""
    if props.get("stix2_id"):
        return str(props["stix2_id"])
    stix_type = STIX2_TYPE_MAP.get(label, "x-custom-node")
    key_field = NODE_KEY_MAP.get(label, "id")
    key_value = str(props.get(key_field, ""))
    return make_stix2_id(stix_type, key_value)


# ---------------------------------------------------------------------------
# Node serialization  (ForensicGraph node → STIX2 object dict)
# ---------------------------------------------------------------------------

def node_to_stix2(label: str, props: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Convert a ForensicGraph node to a STIX2 2.1 object dict.

    Returns ``None`` if the label has no STIX2 mapping.
    """
    stix_type = STIX2_TYPE_MAP.get(label)
    if not stix_type:
        return None

    stix_id = node_stix2_id(label, props)
    now = _iso_now()

    obj: Dict[str, Any] = {
        "type":         stix_type,
        "id":           stix_id,
        "spec_version": "2.1",
    }

    if label == "IP_ADDRESS":
        obj["value"] = str(props.get("ip", ""))

    elif label == "DOMAIN":
        obj["value"] = str(props.get("name", ""))

    elif label == "USER":
        obj["user_id"] = str(props.get("username", ""))
        if props.get("display_name"):
            obj["display_name"] = str(props["display_name"])

    elif label == "PROCESS":
        pid_str = str(props.get("pid_host", "")).split("@")[0]
        try:
            obj["pid"] = int(pid_str)
        except (ValueError, TypeError):
            pass
        if props.get("name"):
            obj["name"] = str(props["name"])
        if props.get("cmdline"):
            obj["command_line"] = str(props["cmdline"])[:1000]

    elif label == "FILE":
        path = str(props.get("path", ""))
        obj["name"]   = path.rsplit("/", 1)[-1] or path
        obj["x_path"] = path
        hashes: Dict[str, str] = {}
        if props.get("hash_sha256"):
            hashes["SHA-256"] = str(props["hash_sha256"])
        if hashes:
            obj["hashes"] = hashes
        if props.get("size_bytes") is not None:
            try:
                obj["size"] = int(props["size_bytes"])
            except (ValueError, TypeError):
                pass

    elif label == "WORKSTATION":
        obj["name"]                 = str(props.get("hostname", ""))
        obj["infrastructure_types"] = ["workstation"]
        obj["created"]              = now
        obj["modified"]             = now
        if props.get("os"):
            obj["labels"] = [str(props["os"])]

    elif label == "ALERT":
        ts = str(props.get("timestamp", now))
        obj["first_observed"]       = ts
        obj["last_observed"]        = ts
        obj["number_observed"]      = 1
        obj["created"]              = ts
        obj["modified"]             = ts
        # object_refs is required in STIX2; bundle builder fills it in
        obj["object_refs"]          = []
        # Wazuh-specific custom properties (x_ prefix per STIX2 custom-property spec)
        obj["x_wazuh_alert_id"]     = str(props.get("alert_id",   ""))
        obj["x_wazuh_incident_id"]  = str(props.get("incident_id",""))
        obj["x_wazuh_rule_id"]      = int(props.get("rule_id",    0) or 0)
        obj["x_wazuh_rule_name"]    = str(props.get("rule_name",  ""))
        obj["x_wazuh_severity"]     = int(props.get("severity",   0) or 0)

    return obj


# ---------------------------------------------------------------------------
# Relationship serialization  (graph edge → STIX2 relationship SDO)
# ---------------------------------------------------------------------------

def edge_to_stix2(
    rel_type:  str,
    source_id: str,
    target_id: str,
    props: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Convert an internal relationship to a STIX2 2.1 relationship SDO."""
    stix_rel_type = STIX2_REL_MAP.get(rel_type.upper(), "related-to")
    rel_id        = make_stix2_id(
        "relationship",
        f"{source_id}:{stix_rel_type}:{target_id}",
    )
    now = _iso_now()
    obj: Dict[str, Any] = {
        "type":              "relationship",
        "id":                rel_id,
        "spec_version":      "2.1",
        "relationship_type": stix_rel_type,
        "source_ref":        source_id,
        "target_ref":        target_id,
        "created":           now,
        "modified":          now,
    }
    if props:
        obj["x_props"] = {str(k): v for k, v in props.items()}
    return obj


# ---------------------------------------------------------------------------
# Bundle builder  (subgraph dict → STIX2 bundle)
# ---------------------------------------------------------------------------

def build_stix2_bundle(
    nodes:       List[Dict[str, Any]],
    edges:       List[Dict[str, Any]],
    incident_id: str = "",
) -> Dict[str, Any]:
    """Build a STIX2 2.1 bundle from a ForensicGraph ``get_incident_graph()`` result.

    Parameters
    ----------
    nodes:
        ``[{"id": neo4j_element_id, "labels": [...], "props": {...}}, ...]``
    edges:
        ``[{"id": ..., "type": rel_type, "from": element_id, "to": element_id, "props": {...}}, ...]``
    incident_id:
        When provided, an ``x-wazuh-incident`` grouping object is appended.
    """
    objects: List[Dict[str, Any]] = []
    # Neo4j element_id → STIX2 id (so we can resolve edge endpoints)
    eid_to_stix: Dict[str, str] = {}

    for node in nodes:
        labels   = node.get("labels") or []
        props    = node.get("props")  or {}
        label    = labels[0] if labels else ""
        stix_obj = node_to_stix2(label, props)
        if stix_obj:
            eid_to_stix[node["id"]] = stix_obj["id"]
            objects.append(stix_obj)

    # Fill observed-data object_refs (must reference ≥1 SCO per STIX2 spec)
    sco_types = {"ipv4-addr", "domain-name", "user-account", "process", "file"}
    sco_ids   = [o["id"] for o in objects if o["type"] in sco_types]
    for o in objects:
        if o["type"] == "observed-data" and not o.get("object_refs"):
            o["object_refs"] = sco_ids if sco_ids else [o["id"]]

    # Incident-level grouping object (custom SDO)
    if incident_id:
        inc_id      = make_stix2_id("x-wazuh-incident", incident_id)
        all_obj_ids = [o["id"] for o in objects]
        objects.append({
            "type":        "x-wazuh-incident",
            "id":          inc_id,
            "spec_version":"2.1",
            "incident_id": incident_id,
            "object_refs": all_obj_ids,
        })

    # Graph edges → STIX2 relationship objects
    for edge in edges:
        src_stix = eid_to_stix.get(edge.get("from", ""))
        tgt_stix = eid_to_stix.get(edge.get("to",   ""))
        if src_stix and tgt_stix:
            objects.append(edge_to_stix2(
                rel_type  = str(edge.get("type", "INVOLVES")),
                source_id = src_stix,
                target_id = tgt_stix,
                props     = edge.get("props"),
            ))

    return {
        "type":         "bundle",
        "id":           f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects":      objects,
    }


# ---------------------------------------------------------------------------
# Bundle ingest  (STIX2 bundle → ForensicGraph node dicts)
# ---------------------------------------------------------------------------

def ingest_stix2_bundle(bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Parse a STIX2 bundle and return node dicts ready for ForensicGraph ingestion.

    Returns a list of ``{"label": str, "props": dict}`` items.
    ``relationship`` and unknown custom objects are silently skipped.
    """
    stix_to_label = {v: k for k, v in STIX2_TYPE_MAP.items()}
    results: List[Dict[str, Any]] = []

    for obj in bundle.get("objects", []):
        stix_type = obj.get("type", "")
        label     = stix_to_label.get(stix_type)
        if not label:
            continue

        props: Dict[str, Any] = {
            "stix2_type": stix_type,
            "stix2_id":   str(obj.get("id", "")),
        }

        if stix_type == "ipv4-addr":
            props["ip"] = str(obj.get("value", ""))

        elif stix_type == "domain-name":
            props["name"] = str(obj.get("value", ""))

        elif stix_type == "user-account":
            props["username"] = str(obj.get("user_id", ""))
            if obj.get("display_name"):
                props["display_name"] = str(obj["display_name"])

        elif stix_type == "process":
            pid  = obj.get("pid", 0)
            name = str(obj.get("name", ""))
            props["pid_host"] = f"{pid}@{name or 'unknown'}"
            props["name"]     = name
            props["cmdline"]  = str(obj.get("command_line", ""))

        elif stix_type == "file":
            props["path"]       = str(obj.get("x_path", obj.get("name", "")))
            hashes = obj.get("hashes", {})
            if hashes.get("SHA-256"):
                props["hash_sha256"] = str(hashes["SHA-256"])
            if obj.get("size"):
                props["size_bytes"] = int(obj["size"])

        elif stix_type == "infrastructure":
            props["hostname"] = str(obj.get("name", ""))

        elif stix_type == "observed-data":
            props["alert_id"]    = str(obj.get("x_wazuh_alert_id",  obj.get("id", "")))
            props["incident_id"] = str(obj.get("x_wazuh_incident_id", ""))
            props["rule_id"]     = int(obj.get("x_wazuh_rule_id",   0) or 0)
            props["rule_name"]   = str(obj.get("x_wazuh_rule_name", ""))
            props["severity"]    = int(obj.get("x_wazuh_severity",  0) or 0)
            props["timestamp"]   = str(obj.get("first_observed",    ""))

        results.append({"label": label, "props": props})

    return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
