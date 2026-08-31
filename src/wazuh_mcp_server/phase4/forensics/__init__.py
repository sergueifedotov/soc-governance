"""Layer 2: Case Management & Evidence (Neo4j + MinIO)

Graph schema
============
Nodes: ALERT, FILE, PROCESS, IP_ADDRESS, USER, WORKSTATION, DOMAIN
Edges:
  (ALERT)-[:INVOLVES]->(IP_ADDRESS | USER)
  (ALERT)-[:DETECTED]->(FILE)
  (FILE)-[:MODIFIED_BY]->(PROCESS)
  (PROCESS)-[:SPAWNED_BY]->(PROCESS)
  (PROCESS)-[:CONNECTS_TO]->(IP_ADDRESS)
  (USER)-[:LOGGED_IN_TO]->(WORKSTATION)
  (IP_ADDRESS)-[:RESOLVES_TO]->(DOMAIN)

Query examples
==============
  graph.find_incidents_by_domain("evil.example.com")   # C2 lookup
  graph.detect_lateral_movement()                       # pivot detection
  graph.get_attack_chain("198.51.100.1")               # kill-chain trace
  graph.get_incident_graph("INC-2026-00003")           # visualisation data
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    from neo4j import GraphDatabase, basic_auth           # type: ignore
    _NEO4J_AVAILABLE = True
except ImportError:                                        # pragma: no cover
    _NEO4J_AVAILABLE = False
    logger.warning("neo4j driver not installed; ForensicGraph disabled")

try:
    from . import stix2_mapper as _stix                   # STIX2 ID tagging
    _STIX2_AVAILABLE = True
except ImportError:                                        # pragma: no cover
    _STIX2_AVAILABLE = False
    logger.warning("stix2_mapper not found; STIX2 tagging disabled")


# ---------------------------------------------------------------------------
# Node / Relationship type constants
# ---------------------------------------------------------------------------

class NodeType:
    ALERT       = "ALERT"
    FILE        = "FILE"
    PROCESS     = "PROCESS"
    IP_ADDRESS  = "IP_ADDRESS"
    USER        = "USER"
    WORKSTATION = "WORKSTATION"
    DOMAIN      = "DOMAIN"


class RelType:
    DETECTED     = "DETECTED"
    MODIFIED_BY  = "MODIFIED_BY"
    SPAWNED_BY   = "SPAWNED_BY"
    CONNECTS_TO  = "CONNECTS_TO"
    LOGGED_IN_TO = "LOGGED_IN_TO"
    RESOLVES_TO  = "RESOLVES_TO"
    INVOLVES     = "INVOLVES"


# ---------------------------------------------------------------------------
# ForensicGraph
# ---------------------------------------------------------------------------

class ForensicGraph:
    """Neo4j-backed forensic graph for case management and attack correlation."""

    def __init__(self, uri: str, user: str, password: str):
        if not _NEO4J_AVAILABLE:
            raise RuntimeError("neo4j driver is not installed")
        self._driver = GraphDatabase.driver(uri, auth=basic_auth(user, password))
        self._ensure_constraints()

    def close(self) -> None:
        self._driver.close()

    def ping(self) -> bool:
        try:
            with self._driver.session() as s:
                s.run("RETURN 1")
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Schema bootstrap
    # ------------------------------------------------------------------

    def _ensure_constraints(self) -> None:
        """Create uniqueness constraints and STIX2 index (idempotent)."""
        constraints = [
            ("ALERT",       "alert_id"),
            ("FILE",        "path"),
            ("PROCESS",     "pid_host"),
            ("IP_ADDRESS",  "ip"),
            ("USER",        "username"),
            ("WORKSTATION", "hostname"),
            ("DOMAIN",      "name"),
        ]
        with self._driver.session() as s:
            for label, prop in constraints:
                try:
                    s.run(
                        f"CREATE CONSTRAINT {label.lower()}_{prop}_unique IF NOT EXISTS "
                        f"FOR (n:{label}) REQUIRE n.{prop} IS UNIQUE"
                    )
                except Exception as exc:
                    logger.debug("Constraint skip (%s.%s): %s", label, prop, exc)
            # Range index so STIX2 ID lookups stay fast across all labels
            try:
                s.run(
                    "CREATE INDEX stix2_id_idx IF NOT EXISTS "
                    "FOR (n) ON (n.stix2_id)"
                )
            except Exception as exc:
                logger.debug("STIX2 index skip: %s", exc)

    # ------------------------------------------------------------------
    # Merge helpers — MERGE = create if absent, otherwise update
    # ------------------------------------------------------------------

    def merge_alert(
        self,
        alert_id: str,
        incident_id: str,
        rule_id: int,
        rule_name: str,
        severity: int,
        timestamp: str,
        full_log: str = "",
    ) -> Dict:
        stix_type = "observed-data"
        stix_id   = _stix.make_stix2_id(stix_type, alert_id) if _STIX2_AVAILABLE else ""
        with self._driver.session() as s:
            rec = s.run(
                """
                MERGE (a:ALERT {alert_id: $alert_id})
                SET   a.incident_id = $incident_id,
                      a.rule_id     = $rule_id,
                      a.rule_name   = $rule_name,
                      a.severity    = $severity,
                      a.timestamp   = $timestamp,
                      a.full_log    = $full_log,
                      a.stix2_type  = $stix2_type,
                      a.stix2_id    = $stix2_id
                RETURN a
                """,
                alert_id=alert_id,
                incident_id=incident_id,
                rule_id=rule_id,
                rule_name=rule_name,
                severity=severity,
                timestamp=timestamp,
                full_log=full_log[:2000],
                stix2_type=stix_type,
                stix2_id=stix_id,
            ).single()
        return dict(rec["a"]) if rec else {}

    def merge_ip(self, ip: str, **props: Any) -> Dict:
        if _STIX2_AVAILABLE:
            props.setdefault("stix2_type", "ipv4-addr")
            props.setdefault("stix2_id",   _stix.make_stix2_id("ipv4-addr", ip))
        with self._driver.session() as s:
            rec = s.run(
                "MERGE (n:IP_ADDRESS {ip: $ip}) SET n += $props RETURN n",
                ip=ip, props=props,
            ).single()
        return dict(rec["n"]) if rec else {}

    def merge_domain(self, name: str, **props: Any) -> Dict:
        if _STIX2_AVAILABLE:
            props.setdefault("stix2_type", "domain-name")
            props.setdefault("stix2_id",   _stix.make_stix2_id("domain-name", name))
        with self._driver.session() as s:
            rec = s.run(
                "MERGE (n:DOMAIN {name: $name}) SET n += $props RETURN n",
                name=name, props=props,
            ).single()
        return dict(rec["n"]) if rec else {}

    def merge_user(self, username: str, **props: Any) -> Dict:
        if _STIX2_AVAILABLE:
            props.setdefault("stix2_type", "user-account")
            props.setdefault("stix2_id",   _stix.make_stix2_id("user-account", username))
        with self._driver.session() as s:
            rec = s.run(
                "MERGE (n:USER {username: $username}) SET n += $props RETURN n",
                username=username, props=props,
            ).single()
        return dict(rec["n"]) if rec else {}

    def merge_workstation(self, hostname: str, **props: Any) -> Dict:
        if _STIX2_AVAILABLE:
            props.setdefault("stix2_type", "infrastructure")
            props.setdefault("stix2_id",   _stix.make_stix2_id("infrastructure", hostname))
        with self._driver.session() as s:
            rec = s.run(
                "MERGE (n:WORKSTATION {hostname: $hostname}) SET n += $props RETURN n",
                hostname=hostname, props=props,
            ).single()
        return dict(rec["n"]) if rec else {}

    def merge_process(self, pid_host: str, name: str = "", cmdline: str = "", **props: Any) -> Dict:
        if _STIX2_AVAILABLE:
            props.setdefault("stix2_type", "process")
            props.setdefault("stix2_id",   _stix.make_stix2_id("process", pid_host))
        with self._driver.session() as s:
            rec = s.run(
                """
                MERGE (n:PROCESS {pid_host: $pid_host})
                SET   n.name    = $name,
                      n.cmdline = $cmdline,
                      n        += $props
                RETURN n
                """,
                pid_host=pid_host,
                name=name,
                cmdline=cmdline[:500],
                props=props,
            ).single()
        return dict(rec["n"]) if rec else {}

    def merge_file(self, path: str, **props: Any) -> Dict:
        if _STIX2_AVAILABLE:
            props.setdefault("stix2_type", "file")
            props.setdefault("stix2_id",   _stix.make_stix2_id("file", path))
        with self._driver.session() as s:
            rec = s.run(
                "MERGE (n:FILE {path: $path}) SET n += $props RETURN n",
                path=path, props=props,
            ).single()
        return dict(rec["n"]) if rec else {}

    # ------------------------------------------------------------------
    # Relationship creation
    # ------------------------------------------------------------------

    def link_alert_ip(self, alert_id: str, ip: str, role: str = "src") -> None:
        with self._driver.session() as s:
            s.run(
                """
                MATCH (a:ALERT {alert_id: $alert_id}), (ip:IP_ADDRESS {ip: $ip})
                MERGE (a)-[r:INVOLVES {role: $role}]->(ip)
                """,
                alert_id=alert_id, ip=ip, role=role,
            )

    def link_alert_user(self, alert_id: str, username: str) -> None:
        with self._driver.session() as s:
            s.run(
                """
                MATCH (a:ALERT {alert_id: $alert_id}), (u:USER {username: $username})
                MERGE (a)-[:INVOLVES]->(u)
                """,
                alert_id=alert_id, username=username,
            )

    def link_alert_file(self, alert_id: str, path: str) -> None:
        with self._driver.session() as s:
            s.run(
                """
                MATCH (a:ALERT {alert_id: $alert_id}), (f:FILE {path: $path})
                MERGE (a)-[:DETECTED]->(f)
                """,
                alert_id=alert_id, path=path,
            )

    def link_file_process(self, path: str, pid_host: str) -> None:
        with self._driver.session() as s:
            s.run(
                """
                MATCH (f:FILE {path: $path}), (p:PROCESS {pid_host: $pid_host})
                MERGE (f)-[:MODIFIED_BY]->(p)
                """,
                path=path, pid_host=pid_host,
            )

    def link_process_ip(self, pid_host: str, ip: str) -> None:
        with self._driver.session() as s:
            s.run(
                """
                MATCH (p:PROCESS {pid_host: $pid_host}), (ip:IP_ADDRESS {ip: $ip})
                MERGE (p)-[:CONNECTS_TO]->(ip)
                """,
                pid_host=pid_host, ip=ip,
            )

    def link_user_workstation(self, username: str, hostname: str, timestamp: str = "") -> None:
        with self._driver.session() as s:
            s.run(
                """
                MATCH (u:USER {username: $username}), (ws:WORKSTATION {hostname: $hostname})
                MERGE (u)-[r:LOGGED_IN_TO]->(ws)
                SET r.last_seen = $timestamp
                """,
                username=username, hostname=hostname, timestamp=timestamp,
            )

    def link_ip_domain(self, ip: str, domain: str) -> None:
        with self._driver.session() as s:
            s.run(
                """
                MATCH (ip:IP_ADDRESS {ip: $ip}), (d:DOMAIN {name: $domain})
                MERGE (ip)-[:RESOLVES_TO]->(d)
                """,
                ip=ip, domain=domain,
            )

    def link_child_process(self, parent_pid_host: str, child_pid_host: str) -> None:
        with self._driver.session() as s:
            s.run(
                """
                MATCH (parent:PROCESS {pid_host: $parent}),
                      (child:PROCESS  {pid_host: $child})
                MERGE (child)-[:SPAWNED_BY]->(parent)
                """,
                parent=parent_pid_host, child=child_pid_host,
            )

    # ------------------------------------------------------------------
    # Generic relationship (used by the API's free-form endpoint)
    # ------------------------------------------------------------------

    def create_relationship(
        self,
        from_label: str,
        from_key: str,
        from_val: str,
        to_label: str,
        to_key: str,
        to_val: str,
        rel_type: str,
        props: Optional[Dict] = None,
    ) -> bool:
        """MERGE a relationship between two existing nodes. Returns True if found."""
        with self._driver.session() as s:
            result = s.run(
                f"""
                MATCH (a:{from_label} {{{from_key}: $from_val}}),
                      (b:{to_label}   {{{to_key}:   $to_val}})
                MERGE (a)-[r:{rel_type}]->(b)
                SET   r += $props
                RETURN count(r) AS cnt
                """,
                from_val=from_val,
                to_val=to_val,
                props=props or {},
            )
            rec = result.single()
        return bool(rec and rec["cnt"] > 0)

    # ------------------------------------------------------------------
    # Query: Forensic timeline for an incident
    # ------------------------------------------------------------------

    def get_incident_timeline(self, incident_id: str) -> List[Dict]:
        """Return all alert nodes + their direct links, ordered by timestamp."""
        with self._driver.session() as s:
            result = s.run(
                """
                MATCH (a:ALERT {incident_id: $incident_id})
                OPTIONAL MATCH (a)-[r]->(entity)
                RETURN a,
                       collect({
                           rel_type: type(r),
                           entity:   properties(entity),
                           labels:   labels(entity)
                       }) AS links
                ORDER BY a.timestamp ASC
                """,
                incident_id=incident_id,
            )
            rows = []
            for rec in result:
                links = [
                    {
                        "rel":    lnk["rel_type"],
                        "labels": list(lnk["labels"] or []),
                        "entity": dict(lnk["entity"] or {}),
                    }
                    for lnk in rec["links"]
                    if lnk.get("entity") is not None
                ]
                rows.append({"alert": dict(rec["a"]), "links": links})
        return rows

    # ------------------------------------------------------------------
    # Query: Full subgraph for incident (nodes + edges for visualisation)
    # ------------------------------------------------------------------

    def get_incident_graph(self, incident_id: str) -> Dict:
        """Return nodes and edges for the incident subgraph (up to 4 hops)."""
        with self._driver.session() as s:
            result = s.run(
                """
                MATCH (a:ALERT {incident_id: $incident_id})
                OPTIONAL MATCH path = (a)-[*1..4]->(entity)
                WITH a,
                     collect(DISTINCT entity)                              AS entities,
                     collect(DISTINCT relationships(path))                 AS rel_lists
                UNWIND (CASE WHEN size(rel_lists) = 0 THEN [[]] ELSE rel_lists END) AS rels
                UNWIND (CASE WHEN size(rels) = 0     THEN [null] ELSE rels  END) AS rel
                RETURN
                    a,
                    entities,
                    collect(DISTINCT rel) AS edges
                """,
                incident_id=incident_id,
            )

            nodes_map: Dict[str, Dict] = {}
            edges: List[Dict] = []

            for rec in result:
                a = rec["a"]
                aid = a.element_id
                if aid not in nodes_map:
                    nodes_map[aid] = {
                        "id":     aid,
                        "labels": list(a.labels),
                        "props":  dict(a),
                    }
                for entity in (rec["entities"] or []):
                    if entity is None:
                        continue
                    eid = entity.element_id
                    if eid not in nodes_map:
                        nodes_map[eid] = {
                            "id":     eid,
                            "labels": list(entity.labels),
                            "props":  dict(entity),
                        }
                for edge in (rec["edges"] or []):
                    if edge is None:
                        continue
                    edges.append({
                        "id":    edge.element_id,
                        "type":  edge.type,
                        "from":  edge.start_node.element_id,
                        "to":    edge.end_node.element_id,
                        "props": dict(edge),
                    })

        return {"nodes": list(nodes_map.values()), "edges": edges}

    # ------------------------------------------------------------------
    # Query: Entity lookup — incidents touching a given IP / domain / user
    # ------------------------------------------------------------------

    def find_incidents_by_ip(self, ip: str) -> List[str]:
        with self._driver.session() as s:
            result = s.run(
                """
                MATCH (a:ALERT)-[:INVOLVES]->(ip:IP_ADDRESS {ip: $ip})
                RETURN DISTINCT a.incident_id AS incident_id
                ORDER BY incident_id
                """,
                ip=ip,
            )
            return [r["incident_id"] for r in result if r["incident_id"]]

    def find_incidents_by_domain(self, domain: str) -> List[str]:
        """Return incident IDs for all alerts touching a C2 domain."""
        with self._driver.session() as s:
            result = s.run(
                """
                MATCH (a:ALERT)-[:INVOLVES]->(ip:IP_ADDRESS)-[:RESOLVES_TO]->(d:DOMAIN {name: $domain})
                RETURN DISTINCT a.incident_id AS incident_id
                UNION
                MATCH (a:ALERT)-[:INVOLVES]->(ip:IP_ADDRESS {domain: $domain})
                RETURN DISTINCT a.incident_id AS incident_id
                """,
                domain=domain,
            )
            return list({r["incident_id"] for r in result if r["incident_id"]})

    def find_incidents_by_user(self, username: str) -> List[str]:
        with self._driver.session() as s:
            result = s.run(
                """
                MATCH (a:ALERT)-[:INVOLVES]->(u:USER {username: $username})
                RETURN DISTINCT a.incident_id AS incident_id
                """,
                username=username,
            )
            return [r["incident_id"] for r in result if r["incident_id"]]

    # ------------------------------------------------------------------
    # Query: Lateral movement detection
    # ------------------------------------------------------------------

    def detect_lateral_movement(self, min_workstations: int = 2) -> List[Dict]:
        """Find users logged into ≥ min_workstations different workstations."""
        with self._driver.session() as s:
            result = s.run(
                """
                MATCH (u:USER)-[:LOGGED_IN_TO]->(ws:WORKSTATION)
                WITH  u, collect(DISTINCT ws.hostname) AS workstations,
                         count(DISTINCT ws) AS cnt
                WHERE cnt >= $min_ws
                RETURN u.username AS user, workstations, cnt AS login_count
                ORDER BY cnt DESC
                """,
                min_ws=min_workstations,
            )
            return [
                {
                    "user":         r["user"],
                    "workstations": list(r["workstations"]),
                    "login_count":  r["login_count"],
                }
                for r in result
            ]

    # ------------------------------------------------------------------
    # Query: Attack chain from a source IP (up to N hops)
    # ------------------------------------------------------------------

    def get_attack_chain(self, source_ip: str, max_hops: int = 5) -> List[Dict]:
        """Trace lateral/pivoting paths starting from an IP address."""
        # Cypher range literals do not accept parameters — interpolate the int directly.
        hops = max(1, min(int(max_hops), 10))
        cypher = f"""
                MATCH path = (ip:IP_ADDRESS {{ip: $ip}})-[*1..{hops}]->(entity)
                RETURN [n IN nodes(path) | {{labels: labels(n), props: properties(n)}}] AS chain,
                       [r IN relationships(path) | type(r)]                             AS rel_types,
                       length(path)                                                      AS depth
                ORDER BY depth
                """
        with self._driver.session() as s:
            result = s.run(cypher, ip=source_ip)
            return [
                {
                    "chain": [
                        {"labels": list(n["labels"]), "props": dict(n["props"])}
                        for n in r["chain"]
                    ],
                    "relationships": list(r["rel_types"]),
                    "depth": r["depth"],
                }
                for r in result
            ]


    # ------------------------------------------------------------------
    # STIX2 bundle export
    # ------------------------------------------------------------------

    def get_incident_stix2_bundle(self, incident_id: str) -> Dict:
        """Export the incident subgraph as a STIX2 2.1 bundle.

        Calls ``get_incident_graph()`` then converts every node and edge to
        the corresponding STIX2 SCO/SDO/relationship object.  Returns a
        ``{"type": "bundle", ...}`` dict ready to be serialised as JSON or
        pushed directly to OpenCTI.
        """
        if not _STIX2_AVAILABLE:
            raise RuntimeError("stix2_mapper module is not available")
        data = self.get_incident_graph(incident_id)
        return _stix.build_stix2_bundle(
            nodes       = data["nodes"],
            edges       = data["edges"],
            incident_id = incident_id,
        )


# ---------------------------------------------------------------------------
# Backwards-compat alias (old code imported ForensicCaseManager)
# ---------------------------------------------------------------------------
ForensicCaseManager = ForensicGraph
