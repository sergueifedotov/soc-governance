"""Minimal weekly Phase 4 model training worker entrypoint."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
from datetime import datetime, timezone

logging.basicConfig(
    level=os.getenv("PHASE4_ML_TRAINER_LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s [phase4-ml-trainer] %(message)s",
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


async def _run_training_loop() -> int:
    state = _WorkerState()
    _register_signal_handlers(state)

    interval_hours = int(os.getenv("PHASE4_ML_TRAIN_INTERVAL_HOURS", "168"))
    logger.info("ML trainer worker started (interval=%sh)", interval_hours)

    next_run = 0.0
    while state.running:
        now = asyncio.get_running_loop().time()
        if now >= next_run:
            logger.info("Training cycle started at %s", datetime.now(timezone.utc).isoformat())
            # Placeholder for model training pipeline invocation.
            logger.info("Training cycle completed")
            next_run = now + interval_hours * 3600
        await asyncio.sleep(1)

    logger.info("ML trainer worker stopped")
    return 0


def main() -> int:
    try:
        return asyncio.run(_run_training_loop())
    except KeyboardInterrupt:
        return 0
    except Exception as exc:  # pragma: no cover
        logger.exception("ML trainer worker failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
