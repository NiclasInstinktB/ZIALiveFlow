"""Live stream over WebSocket: one isolated view per connection.

Multi-user: each user sets their filter **on their own WS connection** (the
``set_filters`` message) and receives only their own matches. Other users see nothing of
it. That lets several people work on different logs at the same time.

Two access levels (a permission on the account, see ``auth/models.py``):
  * ``logs``     → clear text, all fields, all filter fields.
  * ``logs_obf`` → anonymized: personal fields are masked **on the server**
    (``ingest/redact.py``) and the ``user`` filter is blocked. Searching then goes via the
    source IP. Anyone holding both permissions sees clear text.

Filters are **two-level**: groups of conditions, each group with its own operator, and the
``join`` between them. That makes ``(source A OR source B) AND destination C`` just as
expressible as ``source A OR (source B AND destination C)``. If a client only sends the
old flat ``filters`` list, it counts as ONE OR group.

Protocol (JSON text frames):
  Client → Server:  {"type":"set_filters","join":"and","groups":[
                       {"op":"or","items":[{"field":"src_ip","value":"…"}]},
                       {"op":"or","items":[{"field":"dst_ip","value":"…"}]}],
                     "feeds":["web","fw","dns"]}            (optional, absent = all feeds)
                    {"type":"ping"}
  Server → Client:  {"type":"snapshot","records":[…],"stats":{…}}   (after connect and every filter set)
                    {"type":"record","record":{…}}                   (every new match)
                    {"type":"stats","stats":{…}}                     (periodically)
"""
from __future__ import annotations

import asyncio
import json
import time

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from pydantic import ValidationError

from backend import audit
from backend.auth.deps import principal_from_cookie, require_any_permission
from backend.auth.models import PERM_LOGS, PERM_LOGS_OBF, Principal
from backend.config import FEED_COLUMNS, settings
from backend.ingest.hub import get_hub
from backend.ingest.models import FilterField, FilterGroup, FilterOp, FilterSpec
from backend.ingest.redact import redact, redact_all
from backend.logging_config import get_logger

router = APIRouter(prefix="/api/stream", tags=["stream"])

# Close reasons sent alongside code 1008. The client branches on these, so they are a
# wire contract: do not reword them.
_WS_UNAUTHORIZED = "unauthorized"
_WS_NO_LOG_PERMISSION = "no_log_permission"
log = get_logger("api.stream")


def _feed_state() -> dict:
    """Is the NSS feed still alive? Belongs in EVERY stats message.

    The indicator in the live view used to show only that the WebSocket was up, meaning
    the browser to backend link. With the feed standing still (a dead TCP connection, a
    blocked kernel, NSS switched off) it stayed green anyway, and the empty table looked
    like "no matches" instead of "nothing is arriving". That confusion is what costs the
    most time when something is being tracked down.
    """
    health = get_hub().feed_health()
    last = max((f.get("last_seen") or 0.0) for f in health) if health else 0.0
    if not last:
        # Not a single line since the process started, which is a different thing from
        # "quiet for a while" and is named differently in the UI.
        return {"ever": False, "stale": False, "idle_seconds": 0}
    idle = max(0.0, time.time() - last)
    return {
        "ever": True,
        "stale": idle >= settings.feed_stale_after_seconds,
        "idle_seconds": int(idle),
    }


@router.get("/samples")
async def recent_samples(
    limit: int = 2000,
    principal: Principal = Depends(require_any_permission(PERM_LOGS, PERM_LOGS_OBF)),
) -> dict:
    """The most recent sampled example logs (the last few thousand), used for the field
    value suggestions and the live preview in the chip editor ("view").

    Masked for anonymized users: otherwise the clear-text names that are being blacked out
    in the live flow could just be fetched from here instead."""
    records = get_hub().recent_samples(max(1, min(2000, limit)))
    if principal.logs_obfuscated:
        records = redact_all(records)
    return {"records": records}

_MAX_FILTERS = 20
_MAX_GROUPS = 10
_MAX_VALUE_LEN = 256
_STATS_INTERVAL_S = 2.5

# Filter fields denied to an anonymized session. Without this block the masking would be
# worthless: you could filter on a guessed address and infer the person from whether any
# matches come back, using the stream as an oracle.
_OBF_DENIED_FIELDS = frozenset({FilterField.USER})

_OP_LABEL = {FilterOp.AND: "AND", FilterOp.OR: "OR"}


def _parse_op(raw: object, default: FilterOp) -> FilterOp:
    try:
        return FilterOp(str(raw).lower())
    except ValueError:
        return default


def _parse_specs(
    raw: object, obfuscated: bool, budget: int, denied: list[str]
) -> list[FilterSpec]:
    """Raw spec list → validated specs; denied fields end up in ``denied``."""
    specs: list[FilterSpec] = []
    if not isinstance(raw, list):
        return specs
    for item in raw[:budget]:
        if not isinstance(item, dict):
            continue
        value = str(item.get("value", ""))[:_MAX_VALUE_LEN]
        try:
            spec = FilterSpec(field=item.get("field"), value=value)
        except (ValidationError, ValueError, TypeError):
            continue
        if obfuscated and spec.field in _OBF_DENIED_FIELDS:
            denied.append(spec.field.value)
            continue
        specs.append(spec)
    return specs


def _parse_filters(msg: dict, obfuscated: bool = False) -> tuple[list[FilterGroup], FilterOp, list[str]]:
    """``set_filters`` message → groups plus join plus the fields that were dropped.

    If the client does not know about groups yet (only ``filters``), the flat list is read
    as ONE OR group, which is exactly the old behaviour.
    """
    denied: list[str] = []
    join = _parse_op(msg.get("join"), FilterOp.AND)
    raw_groups = msg.get("groups")
    if not isinstance(raw_groups, list):
        specs = _parse_specs(msg.get("filters"), obfuscated, _MAX_FILTERS, denied)
        return ([FilterGroup(op=FilterOp.OR, items=specs)] if specs else []), join, denied

    groups: list[FilterGroup] = []
    budget = _MAX_FILTERS
    for raw in raw_groups[:_MAX_GROUPS]:
        if not isinstance(raw, dict) or budget <= 0:
            continue
        items = _parse_specs(raw.get("items"), obfuscated, budget, denied)
        if not items:
            continue  # empty (or entirely denied) → the group drops out
        budget -= len(items)
        groups.append(FilterGroup(op=_parse_op(raw.get("op"), FilterOp.OR), items=items))
    return groups, join, denied


def _parse_feeds(msg: dict) -> frozenset[str] | None:
    """The wanted feeds out of ``set_filters``. If the field is missing (an older
    client) or nothing survives the comparison with the known feeds, it means all."""
    raw = msg.get("feeds")
    if not isinstance(raw, list):
        return None
    feeds = frozenset(str(f).lower() for f in raw) & FEED_COLUMNS.keys()
    return feeds or None


def _describe(groups: list[FilterGroup], join: FilterOp) -> str:
    """Readable form for the audit log, e.g. ``(src_ip=10.0.0.0/24 OR src_ip=…) AND (dst_ip=…)``."""
    parts = [
        "(" + f" {_OP_LABEL[g.op]} ".join(f"{s.field.value}={s.value}" for s in g.items) + ")"
        for g in groups
    ]
    return f" {_OP_LABEL[join]} ".join(parts)


@router.websocket("/ws")
async def ws_stream(websocket: WebSocket) -> None:
    # Auth through the same session cookie as the REST endpoints.
    token = websocket.cookies.get(settings.session_cookie_name)
    principal = principal_from_cookie(token)
    if principal is None or not principal.can_read_logs:
        # Same close code either way, but the reason says which one it was. Without it
        # the client cannot tell "sign in again" from "you lost the log permission" and
        # just sits there showing a dead connection.
        reason = _WS_UNAUTHORIZED if principal is None else _WS_NO_LOG_PERMISSION
        await websocket.close(code=1008, reason=reason)
        return
    client_host = websocket.client.host if websocket.client else ""
    ip = audit.client_ip(websocket.headers, client_host)

    await websocket.accept()
    hub = get_hub()
    view = hub.register()
    send_lock = asyncio.Lock()  # serializes sends coming from several tasks
    revoked = False  # True → the session was revoked or expired mid-stream (close 1008)
    revoked_reason = _WS_UNAUTHORIZED
    # Anonymized? Re-evaluated on the re-auth tick, so that a permission change (clear
    # text revoked) masks a RUNNING stream immediately as well.
    obfuscated = principal.logs_obfuscated
    # The last set_filters message, kept so the filters can be re-applied under the new
    # rules when the session loses the clear-text permission mid-stream.
    last_filters: dict | None = None

    async def send(msg: dict) -> None:
        async with send_lock:
            await websocket.send_json(msg)

    def view_snapshot() -> list[dict]:
        records = view.snapshot()
        return redact_all(records) if obfuscated else records

    async def record_sender() -> None:
        # Records trickle in over the (bounded) view queue, which gives natural backpressure.
        while True:
            payload = await view.queue.get()
            # Mask only here: the hub hands ONE payload dict to all views, so a copy per
            # anonymized session leaves the others untouched.
            await send({"type": "record", "record": redact(payload) if obfuscated else payload})

    async def stats_sender() -> None:
        # The 2.5s tick doubles as a re-auth: authorizing only at the handshake would let
        # a running stream continue after permissions are revoked, the account is disabled
        # or the token expires. principal_from_cookie() rechecks the token signature and
        # expiry and reads account status and permissions fresh from the store, so
        # disabling, deleting or de-permissioning hits the open WS within about 2.5s.
        nonlocal revoked, revoked_reason, obfuscated
        while True:
            await asyncio.sleep(_STATS_INTERVAL_S)
            current = principal_from_cookie(token)
            if current is None or not current.can_read_logs:
                # The session being gone means sign in again. Merely losing the log
                # permission does not, the person is still signed in and the rest of
                # the app still works for them.
                revoked_reason = _WS_UNAUTHORIZED if current is None else _WS_NO_LOG_PERMISSION
                revoked = True
                log.info("stream.ws_revoked", user=principal.username, reason=revoked_reason)
                return
            if current.logs_obfuscated != obfuscated:
                # Clear-text permission revoked (or granted): mask from now on, or stop
                # masking.
                obfuscated = current.logs_obfuscated
                log.info("stream.ws_obfuscation_changed", user=principal.username, obfuscated=obfuscated)
                if obfuscated and last_filters is not None:
                    # Masking alone is not enough. A user filter set while clear text was
                    # still allowed would keep running, and that is exactly the oracle the
                    # filter block exists to prevent: every record that arrives belongs to
                    # the named person, and source IP, device and target are not masked.
                    # Re-apply the stored message under the new rules and drop what is
                    # denied, then send the (now empty) snapshot so the client matches.
                    groups, join, denied = _parse_filters(last_filters, True)
                    if denied:
                        log.warning(
                            "stream.filter_denied", user=principal.username, fields=",".join(denied)
                        )
                        view.set_filters(groups, join, _parse_feeds(last_filters))
                        await send({
                            "type": "snapshot",
                            "records": view_snapshot(),
                            "stats": {**view.stats(), "feed": _feed_state()},
                            "denied_fields": denied,
                        })
            await send({"type": "stats", "stats": {**view.stats(), "feed": _feed_state()}})

    async def receiver() -> None:
        nonlocal last_filters
        while True:
            # Not receive_text(): that reads message["text"], which a binary frame does
            # not have, so one such frame raised KeyError in here, killed this task and
            # left the socket open but answering nothing. The browser kept showing a
            # live view that would never update again.
            message = await websocket.receive()
            if message["type"] != "websocket.receive":
                return  # the client went away
            raw = message.get("text")
            if raw is None:
                continue  # a binary frame carries no protocol message
            try:
                msg = json.loads(raw)
            except (ValueError, TypeError):
                continue
            mtype = msg.get("type") if isinstance(msg, dict) else None
            if mtype == "set_filters":
                last_filters = msg
                groups, join, denied = _parse_filters(msg, obfuscated)
                if denied:
                    # The UI hides the field, so only a tampered client gets here. Log it
                    # anyway so it stays traceable.
                    log.warning("stream.filter_denied", user=principal.username, fields=",".join(denied))
                    audit.record(
                        audit.SEARCH, user=principal.username, ip=ip,
                        detail=f"rejected (anonymized): {', '.join(denied)}",
                    )
                feeds = _parse_feeds(msg)
                view.set_filters(groups, join, feeds)
                if groups:
                    detail = _describe(groups, join)
                    if feeds is not None:
                        detail += f" [feeds: {', '.join(sorted(feeds))}]"
                    audit.record(
                        audit.SEARCH,
                        user=principal.username,
                        ip=ip,
                        detail=detail,
                    )
                await send({
                    "type": "snapshot",
                    "records": view_snapshot(),
                    "stats": {**view.stats(), "feed": _feed_state()},
                    "denied_fields": denied,
                })
            # "ping" and anything else just keeps the connection alive.

    # The (empty) snapshot first, then the three tasks run.
    await send({"type": "snapshot", "records": view_snapshot(), "stats": {**view.stats(), "feed": _feed_state()}})
    log.info("stream.ws_connect", views=len(hub._views))
    tasks = [asyncio.create_task(coro()) for coro in (record_sender, stats_sender, receiver)]
    try:
        _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        if revoked:
            # Session revoked or expired mid-stream: close cleanly with 1008.
            try:
                await websocket.close(code=1008, reason=revoked_reason)
            except RuntimeError:  # pragma: no cover - the socket may already be closed
                pass
    except WebSocketDisconnect:
        pass
    finally:
        for task in tasks:
            task.cancel()
        hub.unregister(view)
        log.info("stream.ws_disconnect", views=len(hub._views))
