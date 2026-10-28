"""Feed timestamps → epoch.

The core of these tests: the web feed delivers local time WITHOUT a zone marker. Read as
UTC, the web logs run ahead by the zone offset (Berlin in summer: +2 h) while the
firewall logs (epoch) stay correct. That is exactly the symptom that motivated this code.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from backend.config import settings
from backend.ingest import timestamps
from backend.ingest.timestamps import to_epoch


@pytest.fixture(autouse=True)
def _berlin(monkeypatch):
    monkeypatch.setattr(settings, "feed_timezone", "Europe/Berlin")
    timestamps.reset_cache()
    yield
    timestamps.reset_cache()


def _utc(y, mo, d, h, mi, s) -> float:
    return datetime(y, mo, d, h, mi, s, tzinfo=timezone.utc).timestamp()


# ── Web: asctime = local time in the feed zone ─────────────────────
def test_asctime_summer_is_local_not_utc():
    # 09:12:47 Berlin summer time (CEST, +02:00) == 07:12:47 UTC
    assert to_epoch("Thu Jul 23 09:12:47 2026") == _utc(2026, 7, 23, 7, 12, 47)


def test_asctime_winter_uses_cet():
    # 09:12:47 Berlin winter time (CET, +01:00) == 08:12:47 UTC
    assert to_epoch("Tue Jan 20 09:12:47 2026") == _utc(2026, 1, 20, 8, 12, 47)


def test_asctime_after_dst_switch():
    # 2026-03-29 is the switch day; 03:30 is already in summer time.
    assert to_epoch("Sun Mar 29 03:30:00 2026") == _utc(2026, 3, 29, 1, 30, 0)


def test_asctime_ambiguous_hour_takes_first_occurrence():
    # 2026-10-25 02:30 exists twice; we take the first one (still CEST).
    assert to_epoch("Sun Oct 25 02:30:00 2026") == _utc(2026, 10, 25, 0, 30, 0)


def test_asctime_independent_of_process_locale():
    # Month names come from our own table, not from strptime or the locale.
    assert to_epoch("Wed Jul 22 11:53:51 2026") == _utc(2026, 7, 22, 9, 53, 51)


# ── Firewall: epoch is absolute, the zone plays no role ────────────
def test_epoch_millis():
    ms = int(_utc(2026, 7, 23, 7, 12, 44) * 1000)
    assert to_epoch(str(ms)) == _utc(2026, 7, 23, 7, 12, 44)


def test_epoch_seconds():
    assert to_epoch(str(int(_utc(2026, 7, 23, 7, 12, 44)))) == _utc(2026, 7, 23, 7, 12, 44)


def test_epoch_ignores_feed_timezone(monkeypatch):
    ms = int(_utc(2026, 7, 23, 7, 12, 44) * 1000)
    before = to_epoch(str(ms))
    monkeypatch.setattr(settings, "feed_timezone", "America/New_York")
    timestamps.reset_cache()
    assert to_epoch(str(ms)) == before


# ── ISO ────────────────────────────────────────────────────────────
def test_iso_without_zone_is_feed_local():
    assert to_epoch("2026-07-23 09:12:47") == _utc(2026, 7, 23, 7, 12, 47)


def test_iso_with_offset_is_absolute():
    assert to_epoch("2026-07-23T07:12:47+00:00") == _utc(2026, 7, 23, 7, 12, 47)


# ── Bad input ──────────────────────────────────────────────────────
@pytest.mark.parametrize("raw", ["", "   ", "n/a", "not a date", "0", "12345"])
def test_undeutbar_gives_none(raw):
    assert to_epoch(raw) is None


def test_zone_change_invalidates_memo(monkeypatch):
    raw = "Thu Jul 23 09:12:47 2026"
    assert to_epoch(raw) == _utc(2026, 7, 23, 7, 12, 47)
    monkeypatch.setattr(settings, "feed_timezone", "UTC")
    assert to_epoch(raw) == _utc(2026, 7, 23, 9, 12, 47)


def test_unknown_zone_falls_back_to_utc(monkeypatch):
    monkeypatch.setattr(settings, "feed_timezone", "Europe/Nowhere")
    timestamps.reset_cache()
    assert to_epoch("Thu Jul 23 09:12:47 2026") == _utc(2026, 7, 23, 9, 12, 47)


# ── Wiring in the parser ───────────────────────────────────────────
def test_parser_sets_ts_epoch_for_both_feeds():
    from backend.ingest import parser

    web = ["web", "10.0.0.1", "1.1.1.1", "a@b", "HQ", "Thu Jul 23 09:12:47 2026"]
    fw = ["fw", "10.0.0.1", "1.1.1.1", "a@b", "HQ", str(int(_utc(2026, 7, 23, 7, 12, 47) * 1000))]
    rec_web = parser.parse(web, seq=1, received_at=0.0)
    rec_fw = parser.parse(fw, seq=2, received_at=0.0)
    # Same moment, two formats, so the epoch must be identical.
    assert rec_web.ts_epoch == rec_fw.ts_epoch == _utc(2026, 7, 23, 7, 12, 47)
    # The raw value is kept for diagnostics.
    assert rec_web.ts == "Thu Jul 23 09:12:47 2026"
    assert rec_web.as_dict()["ts_epoch"] == rec_web.ts_epoch
