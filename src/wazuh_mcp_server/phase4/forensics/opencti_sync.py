"""Wazuh → OpenCTI alert synchronisation helpers.

Two modes
---------
1. **Bulk backfill** (one-shot): ``sync_alerts(hours, min_level, batch_size)``
   Pulls up to *batch_size* alerts from the Wazuh Indexer that fall in the
   requested time window, converts each to STIX 2.1, and pushes them to
   OpenCTI.  Skips alerts that are already in OpenCTI (detected by a
   deterministic ``incident--<uuid5>`` ID returned as a GraphQL error meaning
   "duplicate").

2. **Continuous poller** (background): ``AlertPoller``
   An asyncio task that runs indefinitely, waking every ``interval`` seconds
   to fetch alerts newer than a watermark timestamp and push them to OpenCTI.
   The watermark advances after each successful batch so no alert is pushed
   twice.  Designed to be started from a FastAPI ``on_event("startup")``
   handler.

Both helpers share the same Wazuh Indexer client and OpenCTI client creation
logic, resolved from environment variables so no extra configuration is needed
beyond what is already required for ``/cases/opencti/ingest-alert``.
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Environment helpers
# ---------------------------------------------------------------------------

def _opencti_env() -> Tuple[str, str]:
    url   = os.getenv("OPENCTI_URL",      "").strip()
    token = os.getenv("OPENCTI_API_TOKEN", "").strip()
    return url, token


def _indexer_env() -> Tuple[str, int, str, str]:
    host = os.getenv("WAZUH_INDEXER_HOST", "").strip()
    port = int(os.getenv("WAZUH_INDEXER_PORT", "9200"))
    user = os.getenv("WAZUH_INDEXER_USER", "admin").strip()
    pw   = os.getenv("WAZUH_INDEXER_PASS", "").strip()
    return host, port, user, pw


# ---------------------------------------------------------------------------
# Core: push a list of raw Wazuh alert dicts to OpenCTI
# ---------------------------------------------------------------------------

def _write_alert_to_graph(graph: Any, alert: Dict[str, Any]) -> None:
    """Best-effort Neo4j write for a single alert.  Never raises.

    Writes all forensic observables that can be extracted from the alert:

    Nodes
    -----
    ALERT        — always
    IP_ADDRESS   — src / dst IPs when present
    USER         — src / dst users when present
    DOMAIN       — hostname / domain when present
    FILE         — syscheck path + hashes when present
    WORKSTATION  — Wazuh agent name (the machine that fired the alert)
    PROCESS      — auditd exe + pid when present

    Relationships
    -------------
    (ALERT)-[:INVOLVES {role}]->(IP_ADDRESS)
    (ALERT)-[:INVOLVES]->(USER)
    (IP_ADDRESS)-[:RESOLVES_TO]->(DOMAIN)
    (ALERT)-[:DETECTED]->(FILE)
    (USER)-[:LOGGED_IN_TO]->(WORKSTATION)
    (FILE)-[:MODIFIED_BY]->(PROCESS)
    (PROCESS)-[:CONNECTS_TO]->(IP_ADDRESS)
    """
    try:
        from forensics.wazuh_stix import (
            _extract_alert_id,
            _extract_agent,
            _extract_domain,
            _extract_file_path,
            _extract_hashes,
            _extract_ips,
            _extract_rule,
            _extract_timestamp,
            _extract_users,
        )

        rule_id, rule_name, level = _extract_rule(alert)
        agent_id, agent_name      = _extract_agent(alert)
        timestamp                 = _extract_timestamp(alert)
        alert_id                  = _extract_alert_id(alert, rule_id, timestamp)
        incident_id               = agent_name or agent_id or alert_id
        src_ip, dst_ip            = _extract_ips(alert)
        src_user, dst_user        = _extract_users(alert)
        domain                    = _extract_domain(alert)
        file_path                 = _extract_file_path(alert)
        file_hashes               = _extract_hashes(alert)

        # ── ALERT ──────────────────────────────────────────────────────────
        graph.merge_alert(
            alert_id=alert_id,
            incident_id=incident_id,
            rule_id=int(rule_id) if str(rule_id).isdigit() else 0,
            rule_name=rule_name,
            severity=level,
            timestamp=timestamp,
            full_log=str(alert.get("full_log", ""))[:2000],
        )

        # ── IP_ADDRESS nodes (src / dst with roles) ────────────────────────
        for role, ip in (("src", src_ip), ("dst", dst_ip)):
            if ip:
                graph.merge_ip(ip)
                graph.link_alert_ip(alert_id, ip, role=role)

        # ── USER nodes ─────────────────────────────────────────────────────
        for user in filter(None, (src_user, dst_user)):
            graph.merge_user(user)
            graph.link_alert_user(alert_id, user)

        # ── DOMAIN node — linked to dst_ip when possible ───────────────────
        if domain and "." in domain:
            graph.merge_domain(domain)
            if dst_ip:
                graph.link_ip_domain(dst_ip, domain)

        # ── FILE node (syscheck / hashes) ──────────────────────────────────
        path_key = file_path or (
            list(file_hashes.values())[0] if file_hashes else None
        )
        if path_key:
            hash_props = {
                k: v for k, v in {
                    "md5":    file_hashes.get("MD5", ""),
                    "sha1":   file_hashes.get("SHA-1", ""),
                    "sha256": file_hashes.get("SHA-256", ""),
                }.items() if v
            }
            graph.merge_file(path_key, **hash_props)
            graph.link_alert_file(alert_id, path_key)

        # ── WORKSTATION node — Wazuh agent == the monitored machine ───────
        hostname = agent_name or agent_id
        if hostname and hostname != alert_id:
            graph.merge_workstation(hostname)
            for user in filter(None, (src_user, dst_user)):
                graph.link_user_workstation(user, hostname, timestamp)

        # ── PROCESS node (auditd / syscall alerts) ─────────────────────────
        audit = (
            alert.get("data", {}).get("audit", {})
            or alert.get("audit", {})
        )
        exe  = audit.get("exe", "") or audit.get("file", {}).get("name", "")
        pid  = str(audit.get("pid", "") or audit.get("id", ""))
        if exe and pid and hostname:
            pid_host = f"{pid}@{hostname}"
            cmdline  = audit.get("command", exe)
            graph.merge_process(
                pid_host,
                name=exe.split("/")[-1],
                cmdline=cmdline[:500],
            )
            if path_key:
                graph.link_file_process(path_key, pid_host)
            if src_ip:
                graph.link_process_ip(pid_host, src_ip)

    except Exception as exc:  # noqa: BLE001
        logger.debug("Neo4j write failed (non-fatal): %s", exc)


def _push_alerts_batch(
    alerts: List[Dict[str, Any]],
    opencti_url: str,
    opencti_token: str,
    graph: Any = None,
) -> Tuple[int, int, List[str]]:
    """Push *alerts* to OpenCTI one bundle per alert, and optionally to Neo4j.

    Returns ``(pushed, skipped, errors)`` where *pushed* is the count of
    successfully accepted bundles, *skipped* counts alerts that produced no
    STIX objects (empty bundle), and *errors* is a list of short error strings
    for failed pushes.
    """
    from forensics.opencti_client import OpenCTIClient
    from forensics.wazuh_stix import alert_to_stix_bundle

    client = OpenCTIClient(opencti_url, opencti_token)
    pushed = skipped = 0
    errors: List[str] = []

    for alert in alerts:
        # Neo4j write is independent of OpenCTI — always attempt it so the
        # forensic graph stays current even when OpenCTI is unavailable.
        if graph is not None:
            _write_alert_to_graph(graph, alert)

        try:
            bundle = alert_to_stix_bundle(alert)
            objects = bundle.get("objects", [])
            if not objects:
                skipped += 1
                continue
            client.push_bundle(bundle)
            pushed += 1
        except RuntimeError as exc:
            msg = str(exc)
            # OpenCTI returns a GraphQL error for pure-duplicate bundles;
            # treat as a soft skip rather than a hard error.
            if "already exists" in msg.lower() or "duplicate" in msg.lower():
                skipped += 1
            else:
                errors.append(msg[:200])
        except Exception as exc:  # noqa: BLE001
            errors.append(str(exc)[:200])

    return pushed, skipped, errors


# ---------------------------------------------------------------------------
# 1. Bulk backfill
# ---------------------------------------------------------------------------

async def sync_alerts(
    hours: int = 24,
    min_level: int = 5,
    batch_size: int = 200,
    graph: Any = None,
) -> Dict[str, Any]:
    """Fetch recent Wazuh alerts and push them all to OpenCTI.

    Parameters
    ----------
    hours:
        How many hours back to look.  Default 24.
    min_level:
        Minimum Wazuh rule level to include.  Default 5.
    batch_size:
        Maximum number of alerts to fetch from the Indexer.  Default 200.

    Returns
    -------
    A summary dict with ``fetched``, ``pushed``, ``skipped``, ``errors`` keys.
    """
    opencti_url, opencti_token = _opencti_env()
    if not opencti_url or not opencti_token:
        return {"ok": False, "reason": "OPENCTI_URL / OPENCTI_API_TOKEN not configured"}

    host, port, user, pw = _indexer_env()
    if not host:
        return {"ok": False, "reason": "WAZUH_INDEXER_HOST not configured"}

    try:
        from wazuh_mcp_server.api.wazuh_indexer import WazuhIndexerClient
    except ImportError:
        from api.wazuh_indexer import WazuhIndexerClient  # phase4-api container (PYTHONPATH=/app)

    client = WazuhIndexerClient(host=host, port=port, username=user, password=pw, verify_ssl=False)
    try:
        await client.initialize()
        start_ts = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
        result = await client.get_alerts(
            limit=batch_size,
            level=str(min_level),
            timestamp_start=start_ts,
        )
    except Exception as exc:
        return {"ok": False, "reason": f"Wazuh Indexer query failed: {exc}"}
    finally:
        await client.close()

    alerts = result.get("data", {}).get("affected_items", [])
    if not alerts:
        return {"ok": True, "fetched": 0, "pushed": 0, "skipped": 0, "errors": []}

    pushed, skipped, errors = _push_alerts_batch(alerts, opencti_url, opencti_token, graph)

    return {
        "ok": True,
        "fetched":  len(alerts),
        "pushed":   pushed,
        "skipped":  skipped,
        "errors":   errors[:20],   # cap to avoid huge responses
    }


# ---------------------------------------------------------------------------
# 2. Continuous poller
# ---------------------------------------------------------------------------

class AlertPoller:
    """Background asyncio task that continuously syncs Wazuh alerts to OpenCTI.

    Usage (inside a FastAPI ``on_event("startup")`` handler)::

        poller = AlertPoller()
        asyncio.create_task(poller.run())

    The poller can be stopped gracefully::

        await poller.stop()
    """

    def __init__(
        self,
        interval: int = 60,
        min_level: int = 5,
        batch_size: int = 100,
        lookback_minutes: int = 5,
        graph: Any = None,
    ) -> None:
        """
        Parameters
        ----------
        interval:
            Seconds between polls.  Default 60.
        min_level:
            Minimum Wazuh rule level.  Default 5.
        batch_size:
            Alerts fetched per poll cycle.  Default 100.
        lookback_minutes:
            On first startup, how many minutes back to look for the initial
            watermark.  Default 5 (only very recent alerts on first run).
        """
        self.interval        = interval
        self.min_level       = min_level
        self.batch_size      = batch_size
        self.lookback_minutes = lookback_minutes
        self._stop_event     = asyncio.Event()
        self._watermark: Optional[datetime] = None   # last successfully-seen timestamp
        self.stats           = {"cycles": 0, "pushed": 0, "skipped": 0, "errors": 0}
        self.graph           = graph

    async def stop(self) -> None:
        """Signal the poller to stop and wait for it to exit."""
        self._stop_event.set()

    async def run(self) -> None:
        """Poll loop — runs until ``stop()`` is called."""
        opencti_url, opencti_token = _opencti_env()
        indexer_host, indexer_port, indexer_user, indexer_pw = _indexer_env()

        if not opencti_url or not opencti_token:
            logger.warning("AlertPoller: OPENCTI_URL / OPENCTI_API_TOKEN not set — poller disabled")
            return
        if not indexer_host:
            logger.warning("AlertPoller: WAZUH_INDEXER_HOST not set — poller disabled")
            return

        logger.info(
            "AlertPoller starting: interval=%ds min_level=%d batch_size=%d",
            self.interval, self.min_level, self.batch_size,
        )

        try:
            from wazuh_mcp_server.api.wazuh_indexer import WazuhIndexerClient
        except ImportError:
            from api.wazuh_indexer import WazuhIndexerClient  # phase4-api container (PYTHONPATH=/app)

        indexer = WazuhIndexerClient(
            host=indexer_host, port=indexer_port,
            username=indexer_user, password=indexer_pw,
            verify_ssl=False,
        )
        try:
            await indexer.initialize()
        except Exception as exc:
            logger.error("AlertPoller: Wazuh Indexer init failed: %s — poller disabled", exc)
            return

        while not self._stop_event.is_set():
            try:
                await self._poll_once(indexer, opencti_url, opencti_token)
            except Exception as exc:  # noqa: BLE001
                logger.warning("AlertPoller: cycle error (will retry): %s", exc)
                self.stats["errors"] += 1

            try:
                await asyncio.wait_for(
                    asyncio.shield(self._stop_event.wait()),
                    timeout=self.interval,
                )
            except asyncio.TimeoutError:
                pass  # normal — time for next poll

        await indexer.close()
        logger.info("AlertPoller stopped after %d cycles", self.stats["cycles"])

    async def _poll_once(
        self,
        indexer: Any,
        opencti_url: str,
        opencti_token: str,
    ) -> None:
        now = datetime.now(timezone.utc)

        if self._watermark is None:
            self._watermark = now - timedelta(minutes=self.lookback_minutes)

        # fetch alerts newer than the watermark
        start_ts = self._watermark.strftime("%Y-%m-%dT%H:%M:%SZ")
        result = await indexer.get_alerts(
            limit=self.batch_size,
            level=str(self.min_level),
            timestamp_start=start_ts,
        )
        alerts: List[Dict[str, Any]] = result.get("data", {}).get("affected_items", [])

        self.stats["cycles"] += 1

        if not alerts:
            logger.debug("AlertPoller: cycle %d — no new alerts", self.stats["cycles"])
            self._watermark = now
            return

        # push in a thread-pool executor so urllib blocking calls don't block the event loop
        loop = asyncio.get_event_loop()
        pushed, skipped, errors = await loop.run_in_executor(
            None,
            _push_alerts_batch,
            alerts,
            opencti_url,
            opencti_token,
            self.graph,
        )

        self.stats["pushed"]  += pushed
        self.stats["skipped"] += skipped
        self.stats["errors"]  += len(errors)

        if errors:
            logger.warning("AlertPoller: cycle %d — %d errors: %s",
                           self.stats["cycles"], len(errors), errors[:3])

        logger.info(
            "AlertPoller: cycle %d — fetched=%d pushed=%d skipped=%d errors=%d",
            self.stats["cycles"], len(alerts), pushed, skipped, len(errors),
        )

        # advance watermark to the latest alert timestamp seen
        latest = _latest_timestamp(alerts)
        if latest:
            # add 1 ms to avoid re-fetching the boundary alert
            self._watermark = latest + timedelta(milliseconds=1)
        else:
            self._watermark = now


def _latest_timestamp(alerts: List[Dict[str, Any]]) -> Optional[datetime]:
    """Return the latest ``timestamp`` found in *alerts*, or None."""
    latest: Optional[datetime] = None
    for alert in alerts:
        ts_str = alert.get("timestamp")
        if not ts_str:
            continue
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            if latest is None or ts > latest:
                latest = ts
        except ValueError:
            pass
    return latest
