"""Feed timestamps → absolute epoch (seconds).

The two NSS feeds deliver the log time in **different** formats:

* Firewall: ``%d{epochtime}`` → epoch milliseconds, absolute and zone independent.
* Web:      ``%s{time}``     → asctime (``Wed Jul 22 11:53:51 2026``), i.e. local time in
  the feed zone configured in the Zscaler console, **without** any zone marker in the string.

The zone is therefore feed knowledge and belongs in the backend next to the ports and the
column layout (``FEED_TIMEZONE``). That is why we resolve the timestamp right here: the
frontend only ever receives an absolute number and never has to interpret a time string.
This runs exclusively on the *filtered* path (``wants()`` prefilters beforehand), so it is
not part of the firehose hot loop.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from backend.config import settings
from backend.logging_config import get_logger

log = get_logger("ingest.timestamps")

_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

# "Wed Jul 22 11:53:51 2026": deliberately a regex instead of strptime, because %a/%b are
# locale dependent and would fail under a non-English locale.
_ASCTIME_RE = re.compile(r"^\w{3}\s+(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})$")
# "2026-07-22 11:53:51" / "2026-07-22T11:53:51.123": ISO WITHOUT a zone marker.
# Strings WITH an offset or Z deliberately do not match here and go to fromisoformat.
_ISO_NAIVE_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?$")

# From this digit count on, a pure digit string means milliseconds rather than seconds
# (epoch seconds stay 10 digits until 2286, epoch ms have been 13 digits since 2001).
_MS_DIGITS = 13
_MIN_EPOCH_DIGITS = 9

# Memo for resolved wall-clock strings. Within one second the same asctime string repeats
# across many records, so the cache saves the zone arithmetic.
_CACHE_MAX = 4096
_memo: dict[str, float | None] = {}
_memo_zone: str = ""
# (configured name, resolved zone, did the resolution succeed?)
_zone_cache: tuple[str, tzinfo, bool] | None = None


def _zone_name() -> str:
    return settings.feed_timezone.strip() or "UTC"


def _resolve() -> tuple[str, tzinfo, bool]:
    global _zone_cache
    name = _zone_name()
    if _zone_cache is not None and _zone_cache[0] == name:
        return _zone_cache
    try:
        zone: tzinfo = ZoneInfo(name)
        ok = True
    except (ZoneInfoNotFoundError, ValueError):
        # No hard abort: logs with UTC time beat no logs at all during an incident. So
        # that the error does not stay silent, it shows up in the startup log AND as a
        # marker in the admin view (zone_label()).
        log.error("feed.timezone_unknown", value=name, fallback="UTC",
                  hint="Check the IANA name (e.g. Europe/Berlin); is the 'tzdata' package installed?")
        zone = timezone.utc
        ok = False
    _zone_cache = (name, zone, ok)
    return _zone_cache


def feed_zone() -> tzinfo:
    """The configured feed zone. An unknown name falls back to UTC (and logs an error)."""
    return _resolve()[1]


def zone_label() -> str:
    """Display value for the admin view, with a warning marker if it cannot be resolved."""
    name, _, ok = _resolve()
    return name if ok else f"{name} (UNKNOWN, using UTC!)"


def _from_wall_clock(y: int, mo: int, d: int, h: int, mi: int, s: int) -> float | None:
    """Local time in the feed zone → epoch. Ambiguous times (the clocks going back) are
    read as the first of the two readings (DST, ``fold=0``)."""
    try:
        return datetime(y, mo, d, h, mi, s, tzinfo=feed_zone()).timestamp()
    except (ValueError, OverflowError, OSError):
        return None


def to_epoch(raw: str) -> float | None:
    """Feed timestamp → epoch seconds, or ``None`` if it cannot be interpreted."""
    s = raw.strip()
    if not s:
        return None

    # 1) Pure digits = epoch (firewall). Absolute, so the zone is irrelevant and no memo needed.
    # isdecimal(), not isdigit(): isdigit() is also true for characters such as the
    # superscript two, which int() and float() then refuse with a ValueError. isdecimal()
    # is exactly the set those two accept, so a shifted column cannot blow up the line.
    if s.isdecimal():
        if len(s) >= _MS_DIGITS:
            return int(s) / 1000.0
        if len(s) >= _MIN_EPOCH_DIGITS:
            return float(s)
        return None

    global _memo_zone
    zone = _zone_name()
    if zone != _memo_zone:  # zone changed → the old resolutions are worthless
        _memo.clear()
        _memo_zone = zone
    if s in _memo:
        return _memo[s]

    # 2) asctime (web).
    out: float | None = None
    m = _ASCTIME_RE.match(s)
    if m:
        month = _MONTHS.get(m.group(1).lower())
        if month:
            out = _from_wall_clock(int(m[6]), month, int(m[2]), int(m[3]), int(m[4]), int(m[5]))
    else:
        # 3) ISO without a zone → also the feed zone.
        iso = _ISO_NAIVE_RE.match(s)
        if iso:
            out = _from_wall_clock(int(iso[1]), int(iso[2]), int(iso[3]), int(iso[4]),
                                   int(iso[5]), int(iso[6] or 0))
        else:
            # 4) ISO WITH an offset or Z → absolute, exactly as given.
            try:
                dt = datetime.fromisoformat(s)
            except ValueError:
                dt = None
            if dt is not None:
                # A naive date that only gets this far is feed local time as well.
                out = dt.replace(tzinfo=dt.tzinfo or feed_zone()).timestamp()

    if len(_memo) >= _CACHE_MAX:
        _memo.clear()
    _memo[s] = out
    return out


def reset_cache() -> None:
    """Drop the memo and the zone cache (tests or a zone change)."""
    global _memo_zone, _zone_cache
    _memo.clear()
    _memo_zone = ""
    _zone_cache = None
