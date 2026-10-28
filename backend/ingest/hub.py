"""Ingest hub, multi-user: one isolated **view** per WebSocket session.

There used to be ONE global filter. Now every user works in parallel and independently:
each WS connection registers a :class:`View` with its **own** filter, its **own** ring
buffer and its **own** send queue. An incoming line is parsed ONCE (and only if some view
wants it at all) and then handed to every matching view.

On top of that the hub keeps a **feed diagnostic** (are all fields arriving?), kept cheap
on the hot path: line and field-count counters on every line, column fill rate only on a
sample.

Everything runs in the same asyncio loop as the TCP listeners and the WS endpoints, so no
locks are needed (synchronous methods, no await).
"""
from __future__ import annotations

import asyncio
import time
from collections import deque

from backend.config import FEED_COLUMNS
from backend.ingest import parser
from backend.ingest.buffer import RingBuffer
from backend.ingest.models import FilterGroup, FilterOp, FilterSpec, FlowRecord
from backend.logging_config import get_logger

log = get_logger("ingest.hub")

# Maximum queue depth per view. If a client is too slow, new records for it are dropped
# (memory protection) instead of letting the server fill up.
_SUB_QUEUE_MAX = 5000

# Every 16th line per feed is evaluated for the column fill rate (diagnostics).
_SAMPLE_MASK = 0x0F

# Global sample buffer: sampled, parsed records for field value suggestions and the live
# preview in the chip editor ("view"). Deliberately small ("the last few thousand") and
# sampled (every 16th line) so the hot loop stays cheap. It is filled even without an
# active filter, so you can see what is currently coming in while building a chip.
_RECENT_SAMPLE_MASK = 0x0F
_RECENT_MAX = 2000


class FeedStat:
    """Diagnostics per feed: are all expected columns arriving?"""

    def __init__(self, feed: str, columns: tuple[str, ...]) -> None:
        self.feed = feed
        self.columns = columns
        self.lines = 0
        self.last_field_count = 0
        self.field_count_min: int | None = None
        self.field_count_max = 0
        self.short_lines = 0  # lines with fewer fields than expected
        self.sampled = 0
        self._nonempty = [0] * len(columns)
        self.last_seen: float = 0.0

    def observe(self, fields: list[str], now: float) -> None:
        self.lines += 1
        self.last_seen = now
        n = len(fields)
        self.last_field_count = n
        self.field_count_max = max(self.field_count_max, n)
        self.field_count_min = n if self.field_count_min is None else min(self.field_count_min, n)
        if n < len(self.columns):
            self.short_lines += 1
        if self.lines & _SAMPLE_MASK == 0:
            self.sampled += 1
            cols = self.columns
            for i in range(len(cols)):
                if i < n and fields[i].strip():
                    self._nonempty[i] += 1

    def health(self) -> dict:
        s = self.sampled or 0
        return {
            "feed": self.feed,
            "lines": self.lines,
            "expected_cols": len(self.columns),
            "last_field_count": self.last_field_count,
            "field_count_min": self.field_count_min or 0,
            "field_count_max": self.field_count_max,
            "short_lines": self.short_lines,
            "sampled": s,
            "last_seen": self.last_seen,
            "columns": [
                {
                    "name": c,
                    "index": i,
                    "fill_pct": round(100 * self._nonempty[i] / s, 1) if s else None,
                }
                for i, c in enumerate(self.columns)
            ],
        }


class View:
    """Isolated view belonging to a single user / WS session."""

    __slots__ = (
        "_buffer", "_groups", "_join", "_feeds", "_compiled", "queue", "_matched", "_dropped_slow", "created_at",
    )

    def __init__(self) -> None:
        self._buffer = RingBuffer()
        self._groups: list[FilterGroup] = []
        self._join: FilterOp = FilterOp.AND
        # Which feeds (type tags) this view wants to see. None = all of them.
        self._feeds: frozenset[str] | None = None
        self._compiled: list = []
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=_SUB_QUEUE_MAX)
        self._matched = 0
        self._dropped_slow = 0
        self.created_at = time.time()

    def set_filters(
        self,
        groups: list[FilterGroup] | list[FilterSpec],
        join: FilterOp = FilterOp.AND,
        feeds: frozenset[str] | None = None,
    ) -> None:
        """Set the filters. A flat spec list is read as ONE OR group (the old behaviour),
        so callers that do not know about groups yet keep working.
        ``feeds`` holds the wanted type tags; ``None``, or every known feed, means no
        restriction at all."""
        if groups and isinstance(groups[0], FilterSpec):
            groups = [FilterGroup(op=FilterOp.OR, items=list(groups))]  # type: ignore[arg-type]
        self._groups = [g.normalized() for g in groups]  # type: ignore[union-attr]
        self._groups = [g for g in self._groups if g.items]
        self._join = join
        self._feeds = None if feeds is None or feeds >= set(FEED_COLUMNS) else frozenset(feeds)
        self._compiled = parser.compile_groups(self._groups)
        if self._join is FilterOp.AND and len(self._compiled) < len(self._groups):
            # Same reasoning as inside an AND group (see parser.compile_groups): a group
            # discarded by the server protection would leave the AND join matching MORE
            # broadly than was asked for. Better no match at all than silently too many.
            log.warning("filter.and_join_incomplete",
                        kept=len(self._compiled), wanted=len(self._groups))
            self._compiled = []
        self._buffer.clear()
        self._matched = 0
        self._dropped_slow = 0
        # Drain the queue so no leftovers from the old filter slip through.
        while not self.queue.empty():
            try:
                self.queue.get_nowait()
            except asyncio.QueueEmpty:
                break

    @property
    def has_filters(self) -> bool:
        return bool(self._compiled)

    def wants(self, fields: list[str]) -> bool:
        return bool(self._compiled) and parser.wants(fields, self._compiled, self._join.value, self._feeds)

    def deliver(self, record: FlowRecord, payload: dict) -> None:
        self._buffer.add(record)
        self._matched += 1
        try:
            self.queue.put_nowait(payload)
        except asyncio.QueueFull:
            self._dropped_slow += 1

    def snapshot(self) -> list[dict]:
        return [r.as_dict() for r in self._buffer.snapshot()]

    def stats(self) -> dict:
        return {
            # Flat list (counters/display) plus the actual group structure.
            "filters": [
                {"field": s.field.value, "value": s.value} for g in self._groups for s in g.items
            ],
            "groups": [
                {"op": g.op.value, "items": [{"field": s.field.value, "value": s.value} for s in g.items]}
                for g in self._groups
            ],
            "join": self._join.value,
            "feeds": sorted(self._feeds if self._feeds is not None else FEED_COLUMNS),
            "buffered": len(self._buffer),
            "matched": self._matched,
            "dropped_slow": self._dropped_slow,
        }


class Hub:
    def __init__(self) -> None:
        self._views: set[View] = set()
        self._seq = 0
        self._total_lines = 0
        self._feeds: dict[str, FeedStat] = {
            feed: FeedStat(feed, columns) for feed, columns in FEED_COLUMNS.items()
        }
        self._other_lines = 0
        self._recent: deque = deque(maxlen=_RECENT_MAX)

    # ── Views (WebSocket sessions) ────────────────────────────────
    def register(self) -> View:
        view = View()
        self._views.add(view)
        return view

    def unregister(self, view: View) -> None:
        self._views.discard(view)

    # ── Intake (from the TCP listeners) ───────────────────────────
    def handle_fields(self, fields: list[str]) -> None:
        """Process one line that has already been split on tabs.

        Order: (1) cheap diagnostic counters, (2) which views want the line? (3) only if
        needed, parse it once and hand it to the matching views.
        """
        self._total_lines += 1
        now = time.time()
        typ = fields[0].strip().lower() if fields else ""
        fs = self._feeds.get(typ)
        if fs is not None:
            fs.observe(fields, now)
        else:
            self._other_lines += 1

        # Sampled example records for field value suggestions and the chip preview,
        # independent of active filters (so you can see what is there while building a chip).
        if fs is not None and (self._total_lines & _RECENT_SAMPLE_MASK) == 0:
            self._seq += 1
            sample = parser.parse(fields, self._seq, now)
            if sample is not None:
                self._recent.append(sample)

        views = self._views
        if not views:
            return
        wanted = [v for v in views if v.wants(fields)]
        if not wanted:
            return
        self._seq += 1
        record = parser.parse(fields, self._seq, now)
        if record is None:
            return
        payload = record.as_dict()
        for v in wanted:
            v.deliver(record, payload)

    # ── Metrics (admin overview / diagnostics) ────────────────────
    def global_stats(self) -> dict:
        return {
            "total_lines": self._total_lines,
            "other_lines": self._other_lines,
            "active_views": len(self._views),
            # Total number of matches currently held across all active views.
            "buffered": sum(len(v._buffer) for v in self._views),
        }

    def feed_health(self) -> list[dict]:
        return [fs.health() for fs in self._feeds.values()]

    def recent_samples(self, limit: int = 2000) -> list[dict]:
        """Most recent sampled records (field value suggestions and chip editor preview)."""
        items = list(self._recent)
        if limit and len(items) > limit:
            items = items[-limit:]
        return [r.as_dict() for r in items]


_hub: Hub | None = None


def get_hub() -> Hub:
    global _hub
    if _hub is None:
        _hub = Hub()
    return _hub
