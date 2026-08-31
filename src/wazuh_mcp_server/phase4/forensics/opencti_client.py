"""Minimal OpenCTI API client for pushing STIX2 bundles.

Uses stdlib ``urllib`` only — no ``pycti`` dependency.

OpenCTI GraphQL endpoint (all data operations):
    POST  /graphql   — GraphQL queries and mutations

    Mutation used for bundle ingestion:
        stixBundlePush(connectorId: ID!, bundle: String!): Boolean

    The ``bundle`` argument must be a JSON *string* (not an object).
    ``connectorId`` must match an ``INTERNAL_IMPORT_FILE`` connector
    registered in OpenCTI — typically the ``ImportFileStix2`` connector
    whose ID is set via ``OPENCTI_CONNECTOR_IMPORT_STIX2_ID`` in ``.env``.

Health probe:
    GET   /api/about  — returns platform version info (no auth required)

Authentication: ``Authorization: Bearer <API token>``
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict

logger = logging.getLogger(__name__)

_DEFAULT_CONNECTOR_ID = os.getenv(
    "OPENCTI_CONNECTOR_IMPORT_STIX2_ID",
    "11111111-2222-3333-4444-555555555555",
)

_PUSH_MUTATION = """
mutation StixBundlePush($connectorId: String!, $bundle: String!) {
  stixBundlePush(connectorId: $connectorId, bundle: $bundle)
}
"""


class OpenCTIClient:
    """Push STIX2 2.1 bundles to an OpenCTI instance via its GraphQL API."""

    def __init__(self, url: str, api_token: str,
                 connector_id: str = _DEFAULT_CONNECTOR_ID) -> None:
        self.url          = url.rstrip("/")
        self.api_token    = api_token.strip()
        self.connector_id = connector_id or _DEFAULT_CONNECTOR_ID

    def _candidate_base_urls(self) -> list[str]:
        """Return connection candidates, including safe localhost fallback.

        If the configured URL uses Docker-internal DNS (``opencti-platform``)
        but the MCP server is running on the host machine, name resolution can
        fail. In that case we also try ``http://localhost:8083``.
        """
        candidates = [self.url]
        parsed = urllib.parse.urlparse(self.url)
        if parsed.hostname == "opencti-platform":
            localhost = urllib.parse.urlunparse(
                (parsed.scheme or "http", "localhost:8083", "", "", "", "")
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
    # Bundle import
    # ------------------------------------------------------------------

    def push_bundle(self, bundle: Dict[str, Any]) -> Dict[str, Any]:
        """Push a STIX2 bundle to OpenCTI via the ``stixBundlePush`` GraphQL mutation.

        The bundle is serialised to a JSON string and submitted via the
        ``INTERNAL_IMPORT_FILE`` connector (``ImportFileStix2``).  The worker
        then processes the bundle asynchronously from the RabbitMQ queue.

        Returns the parsed GraphQL response dict.
        Raises ``RuntimeError`` on HTTP or network errors, or on GraphQL errors.
        """
        payload = {
            "query": _PUSH_MUTATION,
            "variables": {
                "connectorId": self.connector_id,
                "bundle":      json.dumps(bundle),
            },
        }
        data = json.dumps(payload).encode("utf-8")
        result = None
        last_exc: Exception | None = None
        candidates = self._candidate_base_urls()
        for idx, base_url in enumerate(candidates):
            req  = urllib.request.Request(
                f"{base_url}/graphql",
                data    = data,
                headers = {
                    "Content-Type":  "application/json",
                    "Authorization": f"Bearer {self.api_token}",
                },
                method = "POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    result = json.loads(resp.read())
                break
            except urllib.error.HTTPError as exc:
                body = exc.read().decode(errors="replace")
                raise RuntimeError(
                    f"OpenCTI GraphQL HTTP {exc.code}: {body[:500]}"
                ) from exc
            except urllib.error.URLError as exc:
                last_exc = exc
                # Only attempt fallback for DNS resolution errors.
                if idx < len(candidates) - 1 and self._is_name_resolution_error(exc):
                    logger.debug("OpenCTI DNS resolution failed for %s, trying fallback", base_url)
                    continue
                raise RuntimeError(
                    f"OpenCTI unreachable ({base_url}): {exc.reason}"
                ) from exc

        if result is None and last_exc is not None:
            raise RuntimeError(f"OpenCTI unreachable ({self.url}): {last_exc}") from last_exc

        if "errors" in result:
            msgs = "; ".join(e.get("message", str(e)) for e in result["errors"])
            raise RuntimeError(f"OpenCTI GraphQL error: {msgs}")

        return result

    # ------------------------------------------------------------------
    # Health probe
    # ------------------------------------------------------------------

    def ping(self) -> bool:
        """Return ``True`` if OpenCTI responds to ``GET /api/about``."""
        for idx, base_url in enumerate(self._candidate_base_urls()):
            try:
                req = urllib.request.Request(
                    f"{base_url}/api/about",
                    headers = {"Authorization": f"Bearer {self.api_token}"},
                    method  = "GET",
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    resp.read()
                return True
            except urllib.error.URLError as exc:
                if idx < len(self._candidate_base_urls()) - 1 and self._is_name_resolution_error(exc):
                    continue
                logger.debug("OpenCTI ping failed for %s: %s", base_url, exc)
            except Exception as exc:
                logger.debug("OpenCTI ping failed for %s: %s", base_url, exc)
        return False

    # ------------------------------------------------------------------
    # Generic read helper
    # ------------------------------------------------------------------

    def _graphql_read(
        self,
        query: str,
        variables: "Dict[str, Any] | None" = None,
    ) -> "Dict[str, Any]":
        """Execute an arbitrary GraphQL read query and return the parsed response.

        Raises ``RuntimeError`` on HTTP/network errors or GraphQL errors.
        Returns the full response dict (caller reads ``result["data"]``).
        """
        payload = json.dumps(
            {"query": query, "variables": variables or {}}
        ).encode("utf-8")
        result = None
        last_exc: Exception | None = None
        candidates = self._candidate_base_urls()
        for idx, base_url in enumerate(candidates):
            req = urllib.request.Request(
                f"{base_url}/graphql",
                data    = payload,
                headers = {
                    "Content-Type":  "application/json",
                    "Authorization": f"Bearer {self.api_token}",
                },
                method = "POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    result = json.loads(resp.read())
                break
            except urllib.error.HTTPError as exc:
                body = exc.read().decode(errors="replace")
                raise RuntimeError(
                    f"OpenCTI GraphQL HTTP {exc.code}: {body[:300]}"
                ) from exc
            except urllib.error.URLError as exc:
                last_exc = exc
                if idx < len(candidates) - 1 and self._is_name_resolution_error(exc):
                    logger.debug("OpenCTI DNS resolution failed for %s, trying fallback", base_url)
                    continue
                raise RuntimeError(
                    f"OpenCTI unreachable ({base_url}): {exc.reason}"
                ) from exc

        if result is None and last_exc is not None:
            raise RuntimeError(f"OpenCTI unreachable ({self.url}): {last_exc}") from last_exc

        if "errors" in result:
            msgs = "; ".join(e.get("message", str(e)) for e in result["errors"])
            raise RuntimeError(f"OpenCTI GraphQL error: {msgs}")

        return result

    # ------------------------------------------------------------------
    # Read: observables / indicators
    # ------------------------------------------------------------------

    def search_observables(
        self,
        value: str,
        limit: int = 20,
    ) -> "Dict[str, Any]":
        """Search STIX cyber-observables by their primary value.

        Searches across IPv4 addresses, domain names, file hashes, and
        other observable types.  Returns matching observables with
        confidence scores, TLP markings, labels, and linked indicators.

        ``value`` is matched as a substring against the observable value
        field (case-insensitive contains search).
        """
        query = """
query SearchObservables($filters: FilterGroup, $first: Int) {
  stixCyberObservables(filters: $filters, first: $first) {
    edges {
      node {
        id
        entity_type
        observable_value
        created_at
        updated_at
        objectLabel {
                    value
                    color
        }
        objectMarking {
                    definition
                    definition_type
        }
        indicators {
          edges {
            node {
              name
              pattern_type
              valid_from
              valid_until
              confidence
            }
          }
        }
      }
    }
  }
}
"""
        variables = {
            "first": max(1, min(limit, 100)),
            "filters": {
                "mode": "and",
                "filters": [
                    {"key": "value", "values": [value], "operator": "contains"}
                ],
                "filterGroups": [],
            },
        }
        result = self._graphql_read(query, variables)
        edges  = (
            result.get("data", {})
            .get("stixCyberObservables", {})
            .get("edges", [])
        )
        return {
            "query": value,
            "total": len(edges),
            "observables": [
                _flatten_observable(e["node"]) for e in edges if e.get("node")
            ],
        }

    def get_observable(self, value: str) -> "Dict[str, Any]":
        """Return full detail for a single observable identified by its value.

        Returns the first match if multiple observables share the same value.
        """
        result = self.search_observables(value, limit=1)
        observables = result.get("observables", [])
        if not observables:
            return {"found": False, "value": value}
        return {"found": True, "value": value, "observable": observables[0]}

    # ------------------------------------------------------------------
    # Read: cases / incidents
    # ------------------------------------------------------------------

    def list_cases(
        self,
        hours: int = 24,
        min_confidence: int = 0,
        limit: int = 20,
    ) -> "Dict[str, Any]":
        """List recent CaseIncident objects ordered by creation date (newest first).

        Filters to cases created within the last *hours* hours and with
        confidence >= *min_confidence*.
        """
        from datetime import datetime, timedelta, timezone
        since = (
            datetime.now(timezone.utc) - timedelta(hours=max(1, min(hours, 8760)))
        ).strftime("%Y-%m-%dT%H:%M:%SZ")

        query = """
query ListCases($filters: FilterGroup, $first: Int, $orderBy: CaseIncidentsOrdering) {
  caseIncidents(filters: $filters, first: $first, orderBy: $orderBy, orderMode: desc) {
    edges {
      node {
        id
        name
        description
        confidence
        severity
        created_at
        updated_at
        status {
          template { name }
        }
        objectAssignee {
                    name
        }
        objectLabel {
                    value
        }
      }
    }
  }
}
"""
        confidence_filters: "list[dict]" = []
        if min_confidence > 0:
            confidence_filters.append(
                {"key": "confidence", "values": [str(min_confidence)], "operator": "gte"}
            )

        variables = {
            "first": max(1, min(limit, 100)),
            "orderBy": "created_at",
            "filters": {
                "mode": "and",
                "filters": [
                    {"key": "created_at", "values": [since], "operator": "gte"},
                    *confidence_filters,
                ],
                "filterGroups": [],
            },
        }
        result = self._graphql_read(query, variables)
        edges  = (
            result.get("data", {})
            .get("caseIncidents", {})
            .get("edges", [])
        )
        return {
            "since": since,
            "total": len(edges),
            "cases": [_flatten_case(e["node"]) for e in edges if e.get("node")],
        }

    def get_incident(self, stix_id: str) -> "Dict[str, Any]":
        """Fetch a single CaseIncident (or any STIX domain object) by its STIX ID.

        Returns the object with all linked observables and analyst notes.
        """
        query = """
query GetIncident($id: String!) {
  stixDomainObject(id: $id) {
    id
    entity_type
    created_at
    updated_at
    confidence
    objectLabel {
            value
    }
    objectMarking {
            definition
    }
    ... on CaseIncident {
      name
      description
      severity
      status { template { name } }
            objectAssignee { name }
      objectsLinked {
        edges {
          node {
            id
            entity_type
            ... on StixCyberObject { observable_value }
          }
        }
      }
    }
  }
}
"""
        result   = self._graphql_read(query, {"id": stix_id})
        obj      = result.get("data", {}).get("stixDomainObject")
        if obj is None:
            return {"found": False, "id": stix_id}
        return {"found": True, "incident": _flatten_domain_object(obj)}


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

def _extract_nodes(value: "Any") -> "list[Dict[str, Any]]":
    """Return node dicts from either GraphQL connection or plain list shapes."""
    if value is None:
        return []
    if isinstance(value, dict):
        edges = value.get("edges")
        if isinstance(edges, list):
            return [e.get("node") for e in edges if isinstance(e, dict) and e.get("node")]
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []

def _flatten_observable(node: "Dict[str, Any]") -> "Dict[str, Any]":
    """Convert a raw GraphQL observable node into a flat dict."""
    labels = _extract_nodes(node.get("objectLabel"))
    markings = _extract_nodes(node.get("objectMarking"))
    indicators = _extract_nodes(node.get("indicators"))
    return {
        "id":            node.get("id"),
        "entity_type":   node.get("entity_type"),
        "value":         node.get("observable_value"),
        "confidence":    node.get("confidence"),
        "created_at":    node.get("created_at"),
        "updated_at":    node.get("updated_at"),
        "labels":        [
            label.get("value")
            for label in labels
            if label.get("value")
        ],
        "markings":      [
            marking.get("definition")
            for marking in markings
            if marking.get("definition")
        ],
        "indicators":    [
            {
                "name":        indicator.get("name"),
                "pattern_type": indicator.get("pattern_type"),
                "valid_from":  indicator.get("valid_from"),
                "valid_until": indicator.get("valid_until"),
                "confidence":  indicator.get("confidence"),
            }
            for indicator in indicators
        ],
    }


def _flatten_case(node: "Dict[str, Any]") -> "Dict[str, Any]":
    """Convert a raw GraphQL case node into a flat dict."""
    assignees = _extract_nodes(node.get("objectAssignee"))
    labels = _extract_nodes(node.get("objectLabel"))
    status_name = None
    status = node.get("status") or {}
    tmpl   = status.get("template") or {}
    status_name = tmpl.get("name")

    return {
        "id":          node.get("id"),
        "name":        node.get("name"),
        "description": node.get("description"),
        "confidence":  node.get("confidence"),
        "severity":    node.get("severity"),
        "status":      status_name,
        "created_at":  node.get("created_at"),
        "updated_at":  node.get("updated_at"),
        "assignees":   [
            assignee.get("name")
            for assignee in assignees
            if assignee.get("name")
        ],
        "labels":      [
            label.get("value")
            for label in labels
            if label.get("value")
        ],
    }


def _flatten_domain_object(node: "Dict[str, Any]") -> "Dict[str, Any]":
    """Convert a raw GraphQL stixDomainObject node into a flat dict."""
    assignee_nodes = _extract_nodes(node.get("objectAssignee"))
    label_nodes = _extract_nodes(node.get("objectLabel"))
    marking_nodes = _extract_nodes(node.get("objectMarking"))
    linked_nodes = _extract_nodes(node.get("objectsLinked"))

    assignees = [
        assignee.get("name")
        for assignee in assignee_nodes
        if assignee.get("name")
    ]
    labels = [
        label.get("value")
        for label in label_nodes
        if label.get("value")
    ]
    markings = [
        marking.get("definition")
        for marking in marking_nodes
        if marking.get("definition")
    ]
    linked = [
        {
            "id":          linked_node.get("id"),
            "entity_type": linked_node.get("entity_type"),
            "value":       linked_node.get("observable_value"),
        }
        for linked_node in linked_nodes
    ]
    status_name = None
    status = node.get("status") or {}
    tmpl   = status.get("template") or {}
    status_name = tmpl.get("name")

    return {
        "id":            node.get("id"),
        "entity_type":   node.get("entity_type"),
        "name":          node.get("name"),
        "description":   node.get("description"),
        "confidence":    node.get("confidence"),
        "severity":      node.get("severity"),
        "status":        status_name,
        "created_at":    node.get("created_at"),
        "updated_at":    node.get("updated_at"),
        "labels":        labels,
        "markings":      markings,
        "assignees":     assignees,
        "linked_objects": linked,
    }

