"""The per-view ring buffer: the two limits, and what they do at the edges.

Retention is RAM only, so these two limits are the only thing between a busy feed and the
process running out of memory. Both are read fresh from the settings on every eviction,
which is what makes them take effect without a restart.
"""
from __future__ import annotations

import time

import pytest

from backend.config import settings
from backend.ingest.buffer import RingBuffer
from backend.ingest.hub import Hub, _SUB_QUEUE_MAX
from backend.ingest.models import FilterField, FilterSpec, FlowRecord


def _rec(i: int, received_at: float) -> FlowRecord:
    return FlowRecord(id=i, received_at=received_at, logtype="web", ts="")


@pytest.fixture
def limits(monkeypatch):
    def apply(*, retention_minutes: int = 30, max_records: int = 1_000) -> None:
        monkeypatch.setattr(settings, "retention_minutes", retention_minutes)
        monkeypatch.setattr(settings, "buffer_max_records", max_records)

    apply()
    return apply


# ── The record ceiling ─────────────────────────────────────────────


def test_the_ceiling_is_exact(limits):
    limits(max_records=10)
    buf = RingBuffer()
    now = time.time()
    for i in range(10):
        buf.add(_rec(i, now))
    assert len(buf) == 10          # the tenth still fits
    buf.add(_rec(10, now))
    assert len(buf) == 10          # the eleventh pushes the oldest out
    assert [r.id for r in buf.snapshot()] == list(range(1, 11))


def test_the_ceiling_holds_under_a_burst(limits):
    limits(max_records=100)
    buf = RingBuffer()
    now = time.time()
    for i in range(10_000):
        buf.add(_rec(i, now))
    assert len(buf) == 100
    # The newest survive: a ring buffer that kept the oldest would be useless live.
    assert [r.id for r in buf.snapshot()] == list(range(9_900, 10_000))


def test_lowering_the_ceiling_takes_effect_without_a_restart(limits):
    limits(max_records=1_000)
    buf = RingBuffer()
    now = time.time()
    for i in range(500):
        buf.add(_rec(i, now))
    assert len(buf) == 500
    limits(max_records=100)
    buf.add(_rec(500, now))
    assert len(buf) == 100


# ── Eviction by age ────────────────────────────────────────────────


def test_the_age_boundary(limits):
    """A record exactly at the cutoff is still inside the window and stays."""
    limits(retention_minutes=1)
    buf = RingBuffer()
    now = time.time()
    buf.add(_rec(1, now - 61))     # outside
    buf.add(_rec(2, now - 60))     # exactly on the boundary
    buf.add(_rec(3, now - 59))     # inside
    assert [r.id for r in buf.snapshot()] == [2, 3]


def test_age_eviction_also_happens_on_read(limits):
    """No new line may arrive for minutes, and a snapshot must not serve stale records."""
    limits(retention_minutes=1)
    buf = RingBuffer()
    buf.add(_rec(1, time.time()))
    buf._items[0].received_at = time.time() - 3_600
    assert buf.snapshot() == []
    assert len(buf) == 0


def test_clear_releases_everything(limits):
    buf = RingBuffer()
    now = time.time()
    for i in range(500):
        buf.add(_rec(i, now))
    buf.clear()
    assert len(buf) == 0 and buf.snapshot() == []


# ── Readers and writers ────────────────────────────────────────────


def test_a_snapshot_is_not_disturbed_by_later_eviction(limits):
    """``snapshot()`` hands out a copy: the caller iterating it must not see the deque
    change underneath, which would be a RuntimeError in the middle of a response."""
    limits(max_records=50)
    buf = RingBuffer()
    now = time.time()
    for i in range(50):
        buf.add(_rec(i, now))
    snap = buf.snapshot()
    for i in range(50, 200):
        buf.add(_rec(i, now))
    assert len(snap) == 50
    assert [r.id for r in snap] == list(range(50))


def test_views_evict_independently(limits):
    """Two views hold the same record object. One dropping it must not affect the other."""
    limits(max_records=1)
    hub = Hub()
    a, b = hub.register(), hub.register()
    spec = [FilterSpec(field=FilterField.SRC_IP, value="10.0.0.1")]
    a.set_filters(spec)
    b.set_filters(spec)
    line = ["web", "10.0.0.1", "1.1.1.1", "u@x", "HQ"] + ["x"] * 34
    hub.handle_fields(line)
    a._buffer.clear()
    assert len(a.snapshot()) == 0
    assert len(b.snapshot()) == 1
    # And each view serializes its own dict, so one cannot edit the other's record.
    hub.handle_fields(line)
    assert b.snapshot()[0] is not a.snapshot()[0]


def test_a_slow_consumer_is_dropped_not_queued_forever():
    """Backpressure: once the send queue is full, further records are counted as dropped
    instead of growing the queue until the process dies."""
    hub = Hub()
    view = hub.register()
    view.set_filters([FilterSpec(field=FilterField.SRC_IP, value="10.0.0.1")])
    line = ["web", "10.0.0.1", "1.1.1.1", "u@x", "HQ"] + ["x"] * 34
    for _ in range(_SUB_QUEUE_MAX + 250):
        hub.handle_fields(line)
    stats = view.stats()
    assert view.queue.qsize() == _SUB_QUEUE_MAX
    assert stats["dropped_slow"] == 250
    assert stats["matched"] == _SUB_QUEUE_MAX + 250


def test_setting_a_filter_empties_the_buffer_and_the_queue():
    """Leftovers from the previous filter must not leak into the new view."""
    hub = Hub()
    view = hub.register()
    view.set_filters([FilterSpec(field=FilterField.SRC_IP, value="10.0.0.1")])
    line = ["web", "10.0.0.1", "1.1.1.1", "u@x", "HQ"] + ["x"] * 34
    hub.handle_fields(line)
    assert view.queue.qsize() == 1
    view.set_filters([FilterSpec(field=FilterField.SRC_IP, value="10.0.0.2")])
    assert view.queue.qsize() == 0
    assert view.snapshot() == []
    assert view.stats()["matched"] == 0
