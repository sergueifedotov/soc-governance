"""Convert a raw Wazuh alert to a STIX 2.1 bundle for OpenCTI ingestion.

Accepts alert dicts in two common shapes:

1. **Wazuh Indexer (_source)** — nested, e.g.:
   ``{"_id": "…", "rule": {"id": "…", "level": 5}, "data": {"srcip": "…"}}``

2. **MCP compact** — flattened, e.g.:
   ``{"alert_id": "…", "rule_id": "…", "severity": 5, "src_ip": "…"}``

Produced STIX 2.1 objects
--------------------------
* ``identity``         — Wazuh SIEM as the reporting source (singleton, deterministic ID)
* ``incident``         — one per alert (deterministic ID, keyed on alert ID)
* ``ipv4-addr``        — src/dst IPs when present (deterministic)
* ``network-traffic``  — when both src and dst IP are present
* ``user-account``     — src/dst user when present
* ``domain-name``      — hostname/domain when present and contains a dot
* ``file``             — syscheck or data hash fields (md5/sha1/sha256)
* ``url``              — data.url when present
* ``relationship``     — links each observable back to the incident
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Namespace — shared with stix2_mapper.py (do not change)
# ---------------------------------------------------------------------------

_NS = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")

# TLP:WHITE marking definition (built-in OpenCTI / STIX 2.1 value)
_TLP_WHITE = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"

# Wazuh identity — deterministic, stable across all bundles
_WAZUH_IDENTITY_ID = f"identity--{uuid.uuid5(_NS, 'identity:wazuh-siem')}"


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def alert_to_stix_bundle(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Return a STIX 2.1 bundle dict for the given Wazuh alert.

    Parameters
    ----------
    alert:
        Raw Wazuh alert dict (Indexer ``_source`` or MCP compact format).

    Returns
    -------
    dict
        A ``{"type": "bundle", "spec_version": "2.1", "objects": [...]}`` dict
        ready for ``OpenCTIClient.push_bundle()``.
    """
    objects: List[Dict] = [_wazuh_identity()]

    # ── Normalise fields ──────────────────────────────────────────────────
    rule_id, rule_name, rule_level = _extract_rule(alert)
    agent_id, agent_name           = _extract_agent(alert)
    timestamp                      = _extract_timestamp(alert)
    alert_id                       = _extract_alert_id(alert, rule_id, timestamp)
    src_ip, dst_ip                 = _extract_ips(alert)
    src_user, dst_user             = _extract_users(alert)
    domain                         = _extract_domain(alert)
    file_hashes                    = _extract_hashes(alert)
    file_path                      = _extract_file_path(alert)
    url                            = _extract_url(alert)
    full_log                       = str(alert.get("full_log", ""))

    # ── Incident SDO ──────────────────────────────────────────────────────
    incident_id = f"incident--{uuid.uuid5(_NS, f'incident:wazuh:{alert_id}')}"
    description = (
        f"Wazuh rule {rule_id} (level {rule_level}) fired on agent "
        f"{agent_name or agent_id or 'unknown'}."
    )
    if full_log:
        description += f"\n\n```\n{full_log[:1500]}\n```"

    incident: Dict[str, Any] = {
        "type":                 "incident",
        "spec_version":         "2.1",
        "id":                   incident_id,
        "created":              timestamp,
        "modified":             timestamp,
        "name":                 f"[Wazuh] {rule_name}",
        "description":          description,
        "incident_type":        "alert",
        "severity":             _level_to_severity(rule_level),
        "confidence":           50,
        "created_by_ref":       _WAZUH_IDENTITY_ID,
        "object_marking_refs":  [_TLP_WHITE],
        "extensions": {
            "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba": {
                "extension_type": "property-extension",
                "wazuh_rule_id":    rule_id,
                "wazuh_rule_level": rule_level,
                "wazuh_agent_id":   agent_id,
                "wazuh_agent_name": agent_name,
            }
        },
    }
    objects.append(incident)

    # ── IP addresses ─────────────────────────────────────────────────────
    src_ip_id = dst_ip_id = None

    if _valid_ip(src_ip):
        src_ip_id = f"ipv4-addr--{uuid.uuid5(_NS, f'ipv4-addr:{src_ip}')}"
        objects.append(_ipv4(src_ip_id, src_ip))
        objects.append(_rel("related-to", incident_id, src_ip_id, timestamp))

    if _valid_ip(dst_ip) and dst_ip != src_ip:
        dst_ip_id = f"ipv4-addr--{uuid.uuid5(_NS, f'ipv4-addr:{dst_ip}')}"
        objects.append(_ipv4(dst_ip_id, dst_ip))
        objects.append(_rel("related-to", incident_id, dst_ip_id, timestamp))

    # ── Network traffic ───────────────────────────────────────────────────
    if src_ip_id and dst_ip_id:
        dst_port = _extract_port(alert, "dst")
        nt_id = f"network-traffic--{uuid.uuid5(_NS, f'network-traffic:{src_ip}->{dst_ip}:{dst_port}')}"
        nt: Dict[str, Any] = {
            "type":         "network-traffic",
            "spec_version": "2.1",
            "id":           nt_id,
            "src_ref":      src_ip_id,
            "dst_ref":      dst_ip_id,
            "protocols":    ["tcp"],
        }
        if dst_port:
            nt["dst_port"] = dst_port
        objects.append(nt)
        objects.append(_rel("related-to", incident_id, nt_id, timestamp))

    # ── User accounts ─────────────────────────────────────────────────────
    for username in {u for u in (src_user, dst_user) if u}:
        uid = f"user-account--{uuid.uuid5(_NS, f'user-account:{username}')}"
        objects.append({
            "type":         "user-account",
            "spec_version": "2.1",
            "id":           uid,
            "user_id":      username,
        })
        objects.append(_rel("related-to", incident_id, uid, timestamp))

    # ── Domain name ───────────────────────────────────────────────────────
    if domain and "." in domain:
        dom_id = f"domain-name--{uuid.uuid5(_NS, f'domain-name:{domain}')}"
        objects.append({
            "type":         "domain-name",
            "spec_version": "2.1",
            "id":           dom_id,
            "value":        domain,
        })
        objects.append(_rel("related-to", incident_id, dom_id, timestamp))

    # ── File (syscheck / hashes) ──────────────────────────────────────────
    if file_hashes or file_path:
        # Deterministic key: prefer SHA256 > SHA1 > MD5 > path
        key = (file_hashes.get("SHA-256") or file_hashes.get("SHA-1")
               or file_hashes.get("MD5") or file_path or "unknown")
        f_id = f"file--{uuid.uuid5(_NS, f'file:{key}')}"
        f_obj: Dict[str, Any] = {
            "type":         "file",
            "spec_version": "2.1",
            "id":           f_id,
        }
        if file_hashes:
            f_obj["hashes"] = file_hashes
        if file_path:
            f_obj["name"] = file_path.split("/")[-1] or file_path
            f_obj["parent_directory_ref"] = None  # omit — OpenCTI ignores None values
            # Drop None values
            f_obj = {k: v for k, v in f_obj.items() if v is not None}
        objects.append(f_obj)
        objects.append(_rel("related-to", incident_id, f_id, timestamp))

    # ── URL ───────────────────────────────────────────────────────────────
    if url and url.startswith(("http://", "https://")):
        url_id = f"url--{uuid.uuid5(_NS, f'url:{url}')}"
        objects.append({
            "type":         "url",
            "spec_version": "2.1",
            "id":           url_id,
            "value":        url[:2048],
        })
        objects.append(_rel("related-to", incident_id, url_id, timestamp))

    return {
        "type":         "bundle",
        "id":           f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects":      objects,
    }


# ---------------------------------------------------------------------------
# Field extractors
# ---------------------------------------------------------------------------

def _extract_rule(alert: Dict) -> Tuple[str, str, int]:
    rule      = alert.get("rule", {})
    rule_id   = str(rule.get("id",          alert.get("rule_id",   "")))
    rule_name = str(rule.get("description", alert.get("rule_name", "Wazuh Alert")))
    level     = int(rule.get("level",       alert.get("severity",  alert.get("level", 0))) or 0)
    return rule_id, rule_name, level


def _extract_agent(alert: Dict) -> Tuple[str, str]:
    agent = alert.get("agent", {})
    a_id  = str(agent.get("id",   alert.get("agent_id",   "")))
    a_name= str(agent.get("name", alert.get("agent_name", "")))
    return a_id, a_name


def _extract_timestamp(alert: Dict) -> str:
    ts = alert.get("timestamp") or alert.get("@timestamp") or ""
    if ts:
        ts = str(ts)
        # OpenCTI's GraphQL DateTime scalar requires the Z suffix for UTC.
        # Wazuh Indexer emits +0000 or +00:00 — normalise both.
        for suffix in ("+0000", "+00:00"):
            if ts.endswith(suffix):
                return ts[:-len(suffix)] + "Z"
        return ts
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _extract_alert_id(alert: Dict, rule_id: str, timestamp: str) -> str:
    for key in ("_id", "id", "alert_id"):
        v = alert.get(key)
        if v:
            return str(v)
    import hashlib
    return hashlib.sha256(f"{rule_id}{timestamp}".encode()).hexdigest()[:24]


def _extract_ips(alert: Dict) -> Tuple[Optional[str], Optional[str]]:
    data    = alert.get("data", {})
    src_ip  = (data.get("srcip")  or data.get("src_ip")  or alert.get("src_ip"))
    dst_ip  = (data.get("dstip")  or data.get("dst_ip")  or alert.get("dest_ip")
               or alert.get("dst_ip"))
    return src_ip or None, dst_ip or None


def _extract_users(alert: Dict) -> Tuple[Optional[str], Optional[str]]:
    data     = alert.get("data", {})
    src_user = (data.get("srcuser") or data.get("src_user") or alert.get("username"))
    dst_user = (data.get("dstuser") or data.get("dst_user"))
    return src_user or None, dst_user or None


def _extract_domain(alert: Dict) -> Optional[str]:
    data = alert.get("data", {})
    return (data.get("hostname") or data.get("domain")
            or alert.get("hostname"))


def _extract_hashes(alert: Dict) -> Dict[str, str]:
    hashes: Dict[str, str] = {}
    data    = alert.get("data", {})
    syscheck = alert.get("syscheck", {})
    for stix_alg, fields in (
        ("MD5",    ("md5",    "syscheck.md5_after",  "md5_after")),
        ("SHA-1",  ("sha1",   "syscheck.sha1_after", "sha1_after")),
        ("SHA-256",("sha256", "syscheck.sha256_after","sha256_after")),
    ):
        for field in fields:
            v = (data.get(field) or syscheck.get(field.replace("syscheck.", ""))
                 or alert.get(field))
            if v and isinstance(v, str) and len(v) in (32, 40, 64):
                hashes[stix_alg] = v.lower()
                break
    return hashes


def _extract_file_path(alert: Dict) -> Optional[str]:
    syscheck = alert.get("syscheck", {})
    return syscheck.get("path") or alert.get("file_path") or None


def _extract_url(alert: Dict) -> Optional[str]:
    data = alert.get("data", {})
    return data.get("url") or alert.get("url") or None


def _extract_port(alert: Dict, direction: str) -> Optional[int]:
    data = alert.get("data", {})
    key  = f"{direction}port"
    raw  = data.get(key) or alert.get(key)
    if raw:
        try:
            p = int(raw)
            return p if 1 <= p <= 65535 else None
        except (TypeError, ValueError):
            pass
    return None


# ---------------------------------------------------------------------------
# STIX helpers
# ---------------------------------------------------------------------------

def _wazuh_identity() -> Dict:
    return {
        "type":           "identity",
        "spec_version":   "2.1",
        "id":             _WAZUH_IDENTITY_ID,
        "name":           "Wazuh SIEM",
        "identity_class": "system",
        "description":    "Wazuh Security Information and Event Management platform",
        "created":        "2020-01-01T00:00:00Z",
        "modified":       "2020-01-01T00:00:00Z",
    }


def _ipv4(stix_id: str, ip: str) -> Dict:
    return {
        "type":         "ipv4-addr",
        "spec_version": "2.1",
        "id":           stix_id,
        "value":        ip,
    }


def _rel(rel_type: str, src: str, tgt: str, ts: str) -> Dict:
    return {
        "type":               "relationship",
        "spec_version":       "2.1",
        "id":                 f"relationship--{uuid.uuid4()}",
        "created":            ts,
        "modified":           ts,
        "relationship_type":  rel_type,
        "source_ref":         src,
        "target_ref":         tgt,
        "created_by_ref":     _WAZUH_IDENTITY_ID,
        "object_marking_refs": [_TLP_WHITE],
    }


def _valid_ip(ip: Optional[str]) -> bool:
    if not ip:
        return False
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


_SEVERITY_MAP = {
    0: "low", 1: "low", 2: "low", 3: "low", 4: "low",
    5: "medium", 6: "medium", 7: "medium", 8: "medium",
    9: "high", 10: "high", 11: "critical", 12: "critical",
    13: "critical", 14: "critical", 15: "critical",
}


def _level_to_severity(level: int) -> str:
    return _SEVERITY_MAP.get(level, "medium")
