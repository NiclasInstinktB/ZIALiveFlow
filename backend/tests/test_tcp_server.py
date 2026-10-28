"""TCP feed listener: the source allowlist, line framing and the idle watchdog.

The listener is the only thing standing between a raw socket and the hub, so the parts
worth pinning down are the ones that are invisible when they go wrong: a source that is
silently refused, a line that is silently invented, a dead connection that is silently
kept.

The read loop is driven through a stub reader rather than a real socket. ``_handle_client``
only ever calls ``reader.read(_CHUNK)``, so a list of byte strings is exactly "what arrived
in which TCP segment", and the test stays deterministic instead of depending on how the
kernel happens to split the stream.
"""
from __future__ import annotations

import asyncio

import pytest

from backend.config import settings
from backend.ingest import hub as hub_module
from backend.ingest import tcp_server
from backend.ingest.hub import Hub
from backend.ingest.models import FilterField, FilterSpec


# ── Source allowlist ───────────────────────────────────────────────


@pytest.fixture
def allowlist(monkeypatch):
    def apply(value: str) -> None:
        monkeypatch.setattr(settings, "ingest_allowed_ips", value)

    return apply


def test_allowlist_accepts_a_listed_source(allowlist):
    allowlist("10.20.30.0/24, 192.0.2.7")
    assert tcp_server._peer_allowed(("10.20.30.9", 5141))
    assert tcp_server._peer_allowed(("192.0.2.7", 5141))


def test_allowlist_refuses_an_unlisted_source(allowlist):
    allowlist("10.20.30.0/24")
    assert not tcp_server._peer_allowed(("10.20.31.9", 5141))


def test_empty_allowlist_accepts_everyone(allowlist):
    allowlist("")
    assert tcp_server._peer_allowed(("198.51.100.1", 5141))


def test_allowlist_refuses_a_peer_it_cannot_read(allowlist):
    """Fail closed: no peer address, or one that is not an address at all."""
    allowlist("10.20.30.0/24")
    assert not tcp_server._peer_allowed(None)
    assert not tcp_server._peer_allowed(("", 0))
    assert not tcp_server._peer_allowed(("not-an-ip", 1))


def test_allowlist_accepts_an_ipv4_source_on_a_dual_stack_listener(allowlist):
    """``INGEST_BIND_HOST=::`` makes the kernel report an IPv4 client as ``::ffff:a.b.c.d``.

    What arrives: NSS connects from 10.20.30.9 to a listener bound to ``::``. The peer
    name the socket reports is ``::ffff:10.20.30.9``, which is not inside the configured
    IPv4 network ``10.20.30.0/24``, so the connection is refused.
    What the operator sees: ``ingest.rejected ... reason=not_in_allowlist`` and a feed
    that never delivers a line, with an allowlist that looks exactly right.
    What they should see: the connection accepted, because the source address really is
    10.20.30.9.
    """
    allowlist("10.20.30.0/24")
    assert tcp_server._peer_allowed(("::ffff:10.20.30.9", 5141, 0, 0))


def test_allowlist_still_refuses_a_mapped_source_outside_the_range(allowlist):
    allowlist("10.20.30.0/24")
    assert not tcp_server._peer_allowed(("::ffff:10.20.31.9", 5141, 0, 0))


def test_allowlist_handles_a_real_ipv6_source(allowlist):
    allowlist("2001:db8::/64")
    assert tcp_server._peer_allowed(("2001:db8::5", 5141, 0, 0))
    assert not tcp_server._peer_allowed(("2001:db9::5", 5141, 0, 0))


# ── Line framing ───────────────────────────────────────────────────


class _Reader:
    """Hands out one prepared TCP segment per ``read()``, then EOF."""

    def __init__(self, segments: list[bytes]) -> None:
        self._segments = list(segments)

    async def read(self, _n: int) -> bytes:
        return self._segments.pop(0) if self._segments else b""


class _Writer:
    """The little of ``StreamWriter`` that ``_handle_client`` touches."""

    def __init__(self, peer=("10.0.0.5", 5141)) -> None:
        self._peer = peer
        self.closed = False
        self.transport = None

    def get_extra_info(self, name: str):
        return self._peer if name == "peername" else None

    def close(self) -> None:
        self.closed = True


def _web(src: str = "10.20.30.40") -> bytes:
    """One web line (39 fields, the order matching WEB_COLUMNS)."""
    return "\t".join(["web", src, "1.1.1.1", "a@b", "HQ"] + ["x"] * 34).encode("utf-8")


@pytest.fixture
def feed(monkeypatch):
    """A fresh hub with one view filtering on 10.20.30.40, plus a segment driver."""
    monkeypatch.setattr(settings, "ingest_allowed_ips", "")
    monkeypatch.setattr(settings, "ingest_tcp_keepalive", False)
    monkeypatch.setattr(settings, "ingest_idle_timeout_seconds", 0)
    hub = Hub()
    monkeypatch.setattr(hub_module, "_hub", hub)
    view = hub.register()
    view.set_filters([FilterSpec(field=FilterField.SRC_IP, value="10.20.30.40")])

    def run(segments: list[bytes]):
        asyncio.run(tcp_server._handle_client(_Reader(segments), _Writer(), "web"))
        return hub, view

    return run


def test_a_line_split_across_segments_is_reassembled(feed):
    raw = _web()
    hub, view = feed([raw[:10], raw[10:40], raw[40:] + b"\n"])
    assert hub.global_stats()["total_lines"] == 1
    assert view.stats()["matched"] == 1


def test_several_lines_in_one_segment(feed):
    hub, view = feed([_web() + b"\n" + _web("10.0.0.9") + b"\n" + _web() + b"\n"])
    assert hub.global_stats()["total_lines"] == 3
    assert view.stats()["matched"] == 2


def test_crlf_line_endings_are_accepted(feed):
    hub, view = feed([_web() + b"\r\n"])
    assert view.stats()["matched"] == 1


def test_a_trailing_partial_line_is_not_delivered(feed):
    """No newline yet means the line is not complete, so it must wait, not be guessed."""
    hub, _view = feed([_web() + b"\n" + _web()[:20]])
    assert hub.global_stats()["total_lines"] == 1


def test_an_empty_line_is_skipped(feed):
    hub, _view = feed([b"\n\n" + _web() + b"\n"])
    assert hub.global_stats()["total_lines"] == 1


def test_an_overlong_line_is_dropped_whole(feed):
    """A line past the 512 KB limit is discarded, and so is the rest of it.

    What arrives: a feed (or something else that found the port) sends more than
    ``_LINE_LIMIT`` bytes with no separator, and the next segment carries the remainder of
    that same line followed by a proper line.
    What happens: the head is dropped, but the remainder is then treated as a line in its
    own right. It is counted in the feed diagnostics and run through every view's filter,
    so a line nobody ever sent shows up in "lines" and "other lines" under Admin, Overview.
    What should happen: the whole over-long line disappears and only the following real
    line is counted.
    """
    hub, view = feed([b"A" * (tcp_server._LINE_LIMIT + 10), b"-tail\n" + _web() + b"\n"])
    assert hub.global_stats()["total_lines"] == 1
    assert hub.global_stats()["other_lines"] == 0
    assert view.stats()["matched"] == 1


def test_recovery_after_an_overlong_line(feed):
    """The connection keeps working: the lines after the dropped one still arrive."""
    hub, view = feed([
        b"A" * (tcp_server._LINE_LIMIT + 10),
        b"-tail\n",
        _web() + b"\n" + _web() + b"\n",
    ])
    assert view.stats()["matched"] == 2


def test_a_long_but_legal_line_still_gets_through(feed):
    """Under the limit, a long URL is normal traffic and must not be touched."""
    long_url = "https://host/" + "p" * 100_000
    fields = ["web", "10.20.30.40", "1.1.1.1", "a@b", "HQ"] + ["x"] * 9 + [long_url] + ["x"] * 24
    hub, view = feed(["\t".join(fields).encode("utf-8") + b"\n"])
    assert view.stats()["matched"] == 1
    assert view.snapshot()[0]["target"] == long_url


def test_a_broken_line_does_not_kill_the_connection(feed):
    """One unusable line must never cost the lines behind it."""
    hub, view = feed([b"\xff\xfe not a feed line at all\n" + _web() + b"\n"])
    assert view.stats()["matched"] == 1


def test_a_refused_source_is_never_read(monkeypatch):
    monkeypatch.setattr(settings, "ingest_allowed_ips", "10.20.30.0/24")
    monkeypatch.setattr(settings, "ingest_idle_timeout_seconds", 0)
    hub = Hub()
    monkeypatch.setattr(hub_module, "_hub", hub)
    writer = _Writer(peer=("198.51.100.1", 5141))
    asyncio.run(tcp_server._handle_client(_Reader([_web() + b"\n"]), writer, "web"))
    assert hub.global_stats()["total_lines"] == 0
    assert writer.closed


# ── Idle watchdog ──────────────────────────────────────────────────


class _Transport:
    def __init__(self) -> None:
        self.aborted = False

    def abort(self) -> None:
        self.aborted = True


def _run_watchdog(monkeypatch, timeout: int, idle_for: float) -> _Transport:
    """Drive the watchdog without really sleeping.

    The watchdog's own tick is at least five seconds, so a real sleep would make the suite
    pay for it. Only the sleep is replaced; the timing arithmetic is the code under test.
    """
    monkeypatch.setattr(settings, "ingest_idle_timeout_seconds", timeout)
    writer = _Writer()
    writer.transport = _Transport()
    ticks: list[float] = []

    class _Enough(Exception):
        """Raised to leave a watchdog that is correctly still waiting."""

    async def fake_sleep(delay: float) -> None:
        ticks.append(delay)
        if len(ticks) > 5:
            raise _Enough

    import time as _time

    start = _time.monotonic()
    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    async def drive() -> None:
        try:
            await tcp_server._idle_watchdog(
                writer, {"last_data": start - idle_for}, "web", "peer"
            )
        except _Enough:
            pass

    asyncio.run(drive())
    return writer.transport


def test_a_silent_connection_is_dropped(monkeypatch):
    """A client that connects and then says nothing must not hold the slot forever."""
    transport = _run_watchdog(monkeypatch, timeout=600, idle_for=601)
    assert transport.aborted


def test_a_busy_connection_is_left_alone(monkeypatch):
    transport = _run_watchdog(monkeypatch, timeout=600, idle_for=0)
    assert not transport.aborted


def test_idle_timeout_zero_switches_the_watchdog_off(monkeypatch):
    transport = _run_watchdog(monkeypatch, timeout=0, idle_for=10_000)
    assert not transport.aborted


# ── TCP keepalive ──────────────────────────────────────────────────


class _KeepaliveWriter(_Writer):
    def __init__(self, sock) -> None:
        super().__init__()
        self._sock = sock

    def get_extra_info(self, name: str):
        if name == "socket":
            return self._sock
        return super().get_extra_info(name)


def test_keepalive_is_switched_on_for_the_connection():
    """The other half of dead connection detection: the idle timeout acts from this side,
    keepalive asks the kernel to prod the other one."""
    import socket as _socket

    sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    try:
        tcp_server._enable_keepalive(_KeepaliveWriter(sock), "web")
        assert sock.getsockopt(_socket.SOL_SOCKET, _socket.SO_KEEPALIVE) != 0
    finally:
        sock.close()


def test_keepalive_tuning_is_skipped_where_the_platform_lacks_it():
    """IDLE/INTVL/CNT do not exist everywhere. A missing option must cost the connection
    nothing: keepalive is a safety net, not a requirement."""

    class _Fussy:
        """Accepts SO_KEEPALIVE and refuses everything else, like an older kernel."""

        def __init__(self):
            self.calls = []

        def setsockopt(self, level, opt, value):
            import socket as _socket

            self.calls.append(opt)
            if opt != _socket.SO_KEEPALIVE:
                raise OSError("not supported")

    fussy = _Fussy()
    tcp_server._enable_keepalive(_KeepaliveWriter(fussy), "web")  # must not raise
    import socket as _socket

    assert _socket.SO_KEEPALIVE in fussy.calls


def test_keepalive_without_a_socket_is_a_no_op():
    tcp_server._enable_keepalive(_Writer(), "web")  # get_extra_info("socket") is None
