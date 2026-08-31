"""Lightweight Phase 4 threat intel worker entrypoint for container runtime."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
from datetime import datetime, timezone

from apscheduler.schedulers.background import BackgroundScheduler

logging.basicConfig(
    level=os.getenv("PHASE4_THREAT_INTEL_LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s [phase4-threat-intel] %(message)s",
)
logger = logging.getLogger(__name__)


class _WorkerState:
    running = True


def _register_signal_handlers(state: _WorkerState) -> None:
    def _handle_signal(signum, _frame):
        logger.info("Received signal %s, shutting down", signum)
        state.running = False

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)


def _build_scheduler() -> BackgroundScheduler:
    scheduler = BackgroundScheduler(timezone="UTC")

    def _heartbeat() -> None:
        logger.info("Threat intel worker heartbeat at %s", datetime.now(timezone.utc).isoformat())

    scheduler.add_job(
        _heartbeat,
        "interval",
        minutes=int(os.getenv("PHASE4_THREAT_INTEL_HEARTBEAT_MINUTES", "5")),
        id="phase4-threat-intel-heartbeat",
        replace_existing=True,
    )
    return scheduler


async def _run() -> int:
    state = _WorkerState()
    _register_signal_handlers(state)

    scheduler = _build_scheduler()
    scheduler.start()
    logger.info("Threat intel worker started")

    try:
        while state.running:
            await asyncio.sleep(1)
    finally:
        scheduler.shutdown(wait=False)
        logger.info("Threat intel worker stopped")

    return 0


def main() -> int:
    try:
        return asyncio.run(_run())
    except KeyboardInterrupt:
        return 0
    except Exception as exc:  # pragma: no cover
        logger.exception("Threat intel worker failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
