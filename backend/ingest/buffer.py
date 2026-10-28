"""In-memory ring buffer with a time and a size limit (matches only, RAM only)."""
from __future__ import annotations

import time
from collections import deque

from backend.config import settings
from backend.ingest.models import FlowRecord


class RingBuffer:
    def __init__(self) -> None:
        self._items: deque[FlowRecord] = deque()

    def add(self, record: FlowRecord) -> None:
        self._items.append(record)
        self._evict()

    def _evict(self) -> None:
        # Time based: drop everything older than retention_minutes.
        cutoff = time.time() - settings.retention_minutes * 60
        items = self._items
        while items and items[0].received_at < cutoff:
            items.popleft()
        # Size safety net.
        cap = settings.buffer_max_records
        while len(items) > cap:
            items.popleft()

    def snapshot(self) -> list[FlowRecord]:
        self._evict()
        return list(self._items)

    def clear(self) -> None:
        self._items.clear()

    def __len__(self) -> int:
        return len(self._items)
