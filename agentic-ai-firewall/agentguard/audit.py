"""In-memory audit log with ring-buffer semantics."""

from __future__ import annotations

import os
import threading
import time
from collections import deque
from typing import Deque, List

from agentguard.models import AuditEvent


_AUDIT_BUFFER_SIZE = int(os.getenv("AGENTGUARD_AUDIT_BUFFER_SIZE", "1000"))

_lock = threading.Lock()
_events: Deque[AuditEvent] = deque(maxlen=_AUDIT_BUFFER_SIZE)


def record(event: AuditEvent) -> None:
    if event.timestamp <= 0:
        event.timestamp = time.time()
    with _lock:
        _events.append(event)


def recent(limit: int = 100) -> List[AuditEvent]:
    with _lock:
        items = list(_events)
    return list(reversed(items[-limit:]))


def clear() -> None:
    with _lock:
        _events.clear()
