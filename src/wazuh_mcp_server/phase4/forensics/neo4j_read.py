"""Read-only Neo4j client using the HTTP transaction API.

Uses stdlib ``urllib`` only — no ``neo4j`` driver dependency.

Neo4j HTTP transaction endpoint:
    POST  /db/neo4j/tx/commit   — execute one or more Cypher statements

Authentication: HTTP Basic auth (``Authorization: Basic <base64>``).

All public methods enforce read-only access by rejecting any Cypher that
contains write-operation keywords (CREATE, MERGE, SET, DELETE, REMOVE, DROP,
DETACH).
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Keywords that indicate a write operation — reject if found anywhere in the
# query (case-insensitive word-boundary match).
_WRITE_OP_RE = re.compile(
    r"\b(CREATE|MERGE|SET|DELETE|REMOVE|DROP|DETACH)\b",
    re.IGNORECASE,
)

# Hard cap on variable-length path hops to avoid runaway queries.
_MAX_HOPS = 6
# Hard cap on rows returned by passthrough queries.
_PASSTHROUGH_ROW_LIMIT = 500


class Neo4jReadClient:
    """Read-only access to the Neo4j forensic graph via the HTTP API."""

    def __init__(self, http_url: str, user: str, password: str) -> None:
        self.http_url = http_url.rstrip("/")
        _creds = base64.b64encode(f"{user}:{password}".encode()).decode()
        self._auth_header = f"Basic {_creds}"

    def _candidate_base_urls(self) -> list[str]:
        """Return connection candidates, including safe localhost fallback.

        If configured with Docker DNS (``phase4-neo4j``) but MCP runs on the
        host, name resolution fails. In that case we also try
        ``http://localhost:7474``.
        """
        candidates = [self.http_url]
        parsed = urllib.parse.urlparse(self.http_url)
        if parsed.hostname == "phase4-neo4j":
            localhost = urllib.parse.urlunparse(
                (parsed.scheme or "http", "localhost:7474", "", "", "", "")
            )
            if localhost not in candidates:
                candidates.append(localhost)
        return candidates

    @staticmethod
    def _is_name_resolution_error(exc: urllib.error.URLError) -> bool:
        reason = str(getattr(exc, "reason", exc)).lower()
        return (
            "name does not resolve" in reason
            or "temporary failure in name resolution" in reason
            or "nodename nor servname provided" in reason
            or "errno -2" in reason
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run(
        self,
        cypher: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Execute a single Cypher statement and return rows as a list of dicts."""
        payload = json.dumps(
            {"statements": [{"statement": cypher, "parameters": parameters or {}}]}
        ).encode("utf-8")

        result = None
        last_exc: Exception | None = None
        candidates = self._candidate_base_urls()
        for idx, base_url in enumerate(candidates):
            req = urllib.request.Request(
                f"{base_url}/db/neo4j/tx/commit",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": self._auth_header,
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    result = json.loads(resp.read())
                break
            except urllib.error.HTTPError as exc:
                body = exc.read().decode(errors="replace")
                raise RuntimeError(
                    f"Neo4j HTTP {exc.code}: {body[:300]}"
                ) from exc
            except urllib.error.URLError as exc:
                last_exc = exc
                if idx < len(candidates) - 1 and self._is_name_resolution_error(exc):
                    logger.debug("Neo4j DNS resolution failed for %s, trying fallback", base_url)
                    continue
                raise RuntimeError(
                    f"Neo4j unreachable ({base_url}): {exc.reason}"
                ) from exc

        if result is None and last_exc is not None:
            raise RuntimeError(f"Neo4j unreachable ({self.http_url}): {last_exc}") from last_exc

        if result.get("errors"):
            msgs = "; ".join(
                e.get("message", str(e)) for e in result["errors"]
            )
            raise RuntimeError(f"Neo4j query error: {msgs}")

        if not result.get("results"):
            return []

        res0 = result["results"][0]
        columns = res0.get("columns", [])
        return [
            dict(zip(columns, datum.get("row", [])))
            for datum in res0.get("data", [])
        ]

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def ping(self) -> bool:
        """Return ``True`` if Neo4j responds to a trivial query."""
        try:
            self._run("RETURN 1 AS ok")
            return True
        except Exception as exc:  # noqa: BLE001
            logger.debug("Neo4j ping failed: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Named read operations
    # ------------------------------------------------------------------

    def attack_chain(
        self,
        ip: str = "",
        alert_id: str = "",
        max_hops: int = 5,
    ) -> List[Dict[str, Any]]:
        """Return all multi-hop paths reachable from an IP or alert node.

        Each row contains:
        - ``chain``: ordered list of ``{labels, props}`` dicts for every
          node in the path.
        - ``rels``: ordered list of relationship type strings.
        - ``depth``: path length (number of relationships).

        At most 50 paths are returned.
        """
        hops = max(1, min(max_hops, _MAX_HOPS))
        if ip:
            cypher = (
                "MATCH path = (n:IP_ADDRESS {ip: $ip})-[*1.."
                + str(hops)
                + "]->(e) "
                "RETURN [x IN nodes(path) | {labels: labels(x), props: properties(x)}] AS chain, "
                "       [r IN relationships(path) | type(r)] AS rels, "
                "       length(path) AS depth "
                "ORDER BY depth LIMIT 50"
            )
            return self._run(cypher, {"ip": ip})
        elif alert_id:
            cypher = (
                "MATCH (a:ALERT {alert_id: $alert_id}) "
                "OPTIONAL MATCH path = (a)-[*1.."
                + str(hops)
                + "]->(e) "
                "RETURN [x IN nodes(path) | {labels: labels(x), props: properties(x)}] AS chain, "
                "       [r IN relationships(path) | type(r)] AS rels, "
                "       length(path) AS depth "
                "ORDER BY depth LIMIT 50"
            )
            return self._run(cypher, {"alert_id": alert_id})
        else:
            raise ValueError("Either 'ip' or 'alert_id' must be provided")

    def lateral_movement(
        self,
        hours: int = 24,
        min_machines: int = 2,
    ) -> List[Dict[str, Any]]:
        """Return users observed on multiple workstations within the last *hours*.

        Each row: ``{username, machines (list), cnt}``.
        """
        hours = max(1, min(hours, 720))
        min_machines = max(2, min_machines)
        # Neo4j doesn't support interval arithmetic on plain string timestamps,
        # so we filter client-side after fetching all candidate rows.
        cypher = (
            "MATCH (u:USER)-[:LOGGED_IN_TO]->(ws:WORKSTATION) "
            "WITH u, collect(DISTINCT ws.hostname) AS machines, count(DISTINCT ws) AS cnt "
            "WHERE cnt >= $min_machines "
            "RETURN u.username AS username, machines, cnt "
            "ORDER BY cnt DESC LIMIT 50"
        )
        return self._run(cypher, {"min_machines": min_machines})

    def ip_context(self, ip: str) -> Dict[str, Any]:
        """Return all graph context for a given IP address.

        Returns a dict with:
        - ``ip``: the queried IP.
        - ``alerts``: alerts that involve this IP.
        - ``related_entities``: other nodes (users, domains, processes, …)
          directly linked to this IP.
        """
        alerts_cypher = (
            "MATCH (a:ALERT)-[:INVOLVES]->(ip:IP_ADDRESS {ip: $ip}) "
            "RETURN a.alert_id AS alert_id, a.rule_name AS rule_name, "
            "       a.severity AS severity, a.timestamp AS timestamp "
            "ORDER BY a.timestamp DESC LIMIT 100"
        )
        related_cypher = (
            "MATCH (ip:IP_ADDRESS {ip: $ip})-[r]-(entity) "
            "WHERE NOT entity:IP_ADDRESS "
            "RETURN labels(entity)[0] AS type, "
            "       coalesce(entity.username, entity.name, entity.path, "
            "                entity.hostname, entity.ip) AS value, "
            "       type(r) AS relationship "
            "LIMIT 100"
        )
        return {
            "ip": ip,
            "alerts": self._run(alerts_cypher, {"ip": ip}),
            "related_entities": self._run(related_cypher, {"ip": ip}),
        }

    def run_read_query(
        self,
        cypher: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Execute an arbitrary read-only Cypher query.

        Raises ``ValueError`` if the query contains write-operation keywords.
        Appends ``LIMIT {_PASSTHROUGH_ROW_LIMIT}`` when no LIMIT clause is
        present to prevent unbounded scans.
        """
        if _WRITE_OP_RE.search(cypher):
            raise ValueError(
                "Query contains a write-operation keyword "
                "(CREATE, MERGE, SET, DELETE, REMOVE, DROP, DETACH). "
                "Only read-only MATCH queries are permitted via this tool."
            )
        # Inject a LIMIT if none present
        if not re.search(r"\bLIMIT\b", cypher, re.IGNORECASE):
            cypher = cypher.rstrip().rstrip(";") + f" LIMIT {_PASSTHROUGH_ROW_LIMIT}"
        return self._run(cypher, params)


# ---------------------------------------------------------------------------
# Factory — resolve from environment variables
# ---------------------------------------------------------------------------

def _default_client() -> Neo4jReadClient:
    """Build a client from standard environment variables."""
    http_url = os.getenv("NEO4J_HTTP_URL", "http://phase4-neo4j:7474")
    user     = os.getenv("NEO4J_USER",     "neo4j")
    password = os.getenv("NEO4J_PASSWORD", "phase4_admin")
    return Neo4jReadClient(http_url, user, password)
