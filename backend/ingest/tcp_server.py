"""Asyncio TCP listener for the NSS feeds (web, firewall, DNS).

Every line is tab separated and terminated by ``\\n``. We read line by line, split on
tabs and hand the fields to the hub (which does a cheap prefilter first). The type
(web/fw/dns) sits in column 0 of the line itself (feed output format).

This is the **reference implementation in Python**. For the 1M/min load, phase P1 puts
a Go/Rust edge in front of it that takes over the hot path and forwards only matches to
the app (see PLAN.md).
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import time

from backend.config import settings
from backend.ingest.hub import get_hub
from backend.logging_config import get_logger

log = get_logger("ingest.tcp")


def _peer_allowed(peer: object) -> bool:
    """May this peer deliver feeds? An empty allowlist means everyone is allowed.

    Defense in depth on the app side, on top of the firewall: only source IPs listed in
    ``INGEST_ALLOWED_IPS`` (single IPs or CIDRs) are accepted.
    """
    nets = settings.ingest_allowed_networks
    if not nets:
        return True
    host = peer[0] if isinstance(peer, (tuple, list)) and peer else ""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    # A dual-stack listener (INGEST_BIND_HOST="::") reports an IPv4 client as
    # ::ffff:10.0.0.5. Compare the address it really came from, otherwise an IPv4
    # allowlist entry refuses the feed and the rejection log looks plainly wrong.
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return any(ip in net for net in nets)

# Line limit for the StreamReader (URLs can be long). 512 KB is generous.
_LINE_LIMIT = 512 * 1024

_servers: list[asyncio.AbstractServer] = []
# feed → is the listener currently listening? (for the admin status overview)
_listening: dict[str, bool] = {"web": False, "fw": False, "dns": False}


def listening() -> dict[str, bool]:
    """Current listening state per feed (a copy)."""
    return dict(_listening)


# Size of the read chunks. We deliberately read in large blocks and split the lines
# ourselves: that saves the per-line readline() overhead (an async call plus a buffer
# scan) and carries the 1M/min load on a single core (see benchmark.py).
_CHUNK = 256 * 1024


def _enable_keepalive(writer: asyncio.StreamWriter, feed: str) -> None:
    """Turn on TCP keepalive for the accepted connection.

    The kernel then prods the other side itself and tears the connection down when it
    stops answering. Without that, a half open connection (a firewall or NAT idle
    timeout) sits there unnoticed and simply never delivers data again. The fine tuning
    (IDLE/INTVL/CNT) exists on Linux only; elsewhere the OS default applies, which is why
    every field is guarded individually.
    """
    sock = writer.get_extra_info("socket")
    if sock is None:
        return
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        for name, value in (
            ("TCP_KEEPIDLE", settings.ingest_keepalive_idle_seconds),
            ("TCP_KEEPINTVL", settings.ingest_keepalive_interval_seconds),
            ("TCP_KEEPCNT", settings.ingest_keepalive_count),
        ):
            opt = getattr(socket, name, None)
            if opt is not None:
                sock.setsockopt(socket.IPPROTO_TCP, opt, value)
    except OSError as exc:
        # Keepalive is a safety net, not a requirement: a connection without it still
        # beats no connection at all.
        log.warning("ingest.keepalive_failed", feed=feed, error=str(exc))


async def _idle_watchdog(writer: asyncio.StreamWriter, state: dict, feed: str, peer: str) -> None:
    """Closes the connection when no line has arrived for too long.

    Deliberately a task of its own instead of a ``wait_for`` around every read: the read
    loop carries the full feed load, where a timer per read would be noticeable. Here it
    costs one assignment per chunk plus one sleeping task per connection.

    ``abort()`` rather than ``close()``: a clean shutdown can itself wait on the dead
    peer, which is exactly what we are trying to avoid.
    """
    timeout = settings.ingest_idle_timeout_seconds
    if timeout <= 0:
        return
    # Check often enough not to wait up to twice the timeout.
    tick = max(5.0, timeout / 4)
    while True:
        await asyncio.sleep(tick)
        idle = time.monotonic() - state["last_data"]
        if idle >= timeout:
            log.warning(
                "ingest.idle_timeout", feed=feed, peer=peer, idle_seconds=round(idle),
                hint="No more lines received, dropping the connection so NSS reconnects.",
            )
            transport = writer.transport
            if transport is not None:
                transport.abort()
            return


async def _handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, feed: str) -> None:
    peer = writer.get_extra_info("peername")
    if not _peer_allowed(peer):
        log.warning("ingest.rejected", feed=feed, peer=str(peer), reason="not_in_allowlist")
        try:
            writer.close()
        except Exception:  # noqa: BLE001
            pass
        return
    log.info("ingest.connect", feed=feed, peer=str(peer))
    if settings.ingest_tcp_keepalive:
        _enable_keepalive(writer, feed)
    hub = get_hub()
    handle = hub.handle_fields  # a local reference saves an attribute lookup in the hot loop
    buf = b""
    # True while the tail of an over-long line is still arriving: it belongs to a line
    # that has already been discarded, so it must not be handed on as a line of its own.
    discarding = False
    # Read by the watchdog; in the read loop keeping it current costs one assignment
    # per chunk.
    state = {"last_data": time.monotonic()}
    watchdog = asyncio.create_task(_idle_watchdog(writer, state, feed, str(peer)))
    try:
        while True:
            chunk = await reader.read(_CHUNK)
            if not chunk:
                break  # EOF
            state["last_data"] = time.monotonic()
            buf += chunk
            if b"\n" not in buf:
                # Safety net against an endless line without a separator.
                if len(buf) > _LINE_LIMIT:
                    log.warning("ingest.line_too_long", feed=feed, peer=str(peer))
                    buf = b""
                    discarding = True
                continue
            *lines, buf = buf.split(b"\n")  # the last (partial) remainder stays in the buffer
            if discarding:
                # Everything up to the first separator is the rest of the line that was
                # dropped above, not a line anyone sent.
                lines = lines[1:]
                discarding = False
            for raw in lines:
                if not raw:
                    continue
                fields = raw.decode("utf-8", errors="replace").rstrip("\r").split("\t")
                try:
                    handle(fields)
                except Exception:  # noqa: BLE001 - one broken line must never kill the feed
                    log.warning("ingest.parse_error", feed=feed)
    except (ConnectionResetError, asyncio.IncompleteReadError):
        pass
    finally:
        watchdog.cancel()
        log.info("ingest.disconnect", feed=feed, peer=str(peer))
        try:
            writer.close()
        except Exception:  # noqa: BLE001
            pass


async def start_ingest() -> None:
    """Starts the feed listeners (each one as long as its port is > 0)."""
    if not settings.ingest_enabled:
        log.info("ingest.disabled")
        return

    async def _listen(port: int, feed: str) -> None:
        if port <= 0:
            return
        server = await asyncio.start_server(
            lambda r, w: _handle_client(r, w, feed),
            host=settings.ingest_bind_host,
            port=port,
            limit=_LINE_LIMIT,
        )
        _servers.append(server)
        _listening[feed] = True
        log.info("ingest.listening", feed=feed, host=settings.ingest_bind_host, port=port)

    await _listen(settings.ingest_web_port, "web")
    await _listen(settings.ingest_fw_port, "fw")
    await _listen(settings.ingest_dns_port, "dns")


async def stop_ingest() -> None:
    for server in _servers:
        server.close()
    for server in _servers:
        try:
            await server.wait_closed()
        except Exception:  # noqa: BLE001
            pass
    _servers.clear()
    for feed in _listening:
        _listening[feed] = False
    log.info("ingest.stopped")
