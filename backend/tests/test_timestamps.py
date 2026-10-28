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


# ── A digit string that int() cannot read ──────────────────────────
# ``str.isdigit()`` is true for characters such as the superscript two, which ``int()``
# and ``float()`` then refuse. A feed line whose time column holds such a character (a
# shifted column, text that landed in the wrong position) must still produce a record
# with ``ts_epoch = None``, not blow the line up: ``to_epoch`` promises None for anything
# it cannot interpret.
@pytest.mark.parametrize("raw", ["\u00b2" * 13, "\u00b2" * 9, "\u00b2\u00b3\u00b9"])
def test_non_decimal_digit_string_is_not_interpretable(raw):
    assert raw.isdigit()          # precondition: it reaches the epoch branch
    assert to_epoch(raw) is None  # must not raise


def test_arabic_indic_digits_still_read_as_epoch():
    """Those ARE decimal digits and int() accepts them, so they must keep working."""
    native = "1784628000000".translate(str.maketrans("0123456789", "\u0660\u0661\u0662\u0663\u0664\u0665\u0666\u0667\u0668\u0669"))
    assert to_epoch(native) == 1784628000.0


def test_parse_keeps_the_record_when_the_timestamp_is_unreadable():
    """The record still has to reach the user; only ``ts_epoch`` is unknown."""
    from backend.ingest import parser

    line = ["web", "10.0.0.1", "1.1.1.1", "a@b", "HQ", "\u00b2" * 13]
    rec = parser.parse(line, seq=1, received_at=0.0)
    assert rec is not None
    assert rec.ts_epoch is None
    assert rec.ts == "\u00b2" * 13   # the raw value is kept for diagnostics
