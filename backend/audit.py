"""Audit log: who signs in when, and what is being filtered or searched for.

Persistent, append-only **JSONL files per day** under ``backend/data/audit/``
(``audit-YYYY-MM-DD.jsonl``). Files older than ``AUDIT_RETENTION_DAYS`` (default 30) are
deleted (``prune()`` at startup and on each query). Deliberately plain (no database): a
handful of events for an internal tool, traceable for up to 30 days.

What is stored is **metadata** (user, IP, event, filter text), **not** the log payloads
themselves, which stay RAM only (see the README and the data protection notes).
"""
from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Mapping

from backend.config import PROJECT_ROOT, settings
from backend.logging_config import get_logger

log = get_logger("audit")

_DIR = PROJECT_ROOT / "backend" / "data" / "audit"
_lock = threading.Lock()
_MAX_DETAIL = 500

# Event types (stable strings, used for filtering in the UI).
LOGIN_OK = "login_success"
LOGIN_FAIL = "login_failure"
LOGOUT = "logout"
SEARCH = "search"


def client_ip(headers: Mapping[str, str], fallback: str = "") -> str:
    """Client IP: the peer address the server itself observed.

    ``X-Forwarded-For`` is deliberately NOT read here. It is an ordinary request header
    that every client can set freely, so an entry built from it proves nothing, and the
    login brake keyed on it (``api/auth_routes``) could be stepped around by sending a
    different value on every attempt.

    Behind a reverse proxy the real client address still arrives: the server is started
    with ``serve.py --proxy-headers --forwarded-allow-ips <proxy>`` (see
    ``deploy/zscaler-admin-ui.service``), and uvicorn then resolves the forwarded header
    into the peer address, but only for connections coming from a proxy that was
    explicitly trusted. That trust decision belongs there, not in this function, which
    cannot tell a proxy from an arbitrary caller.

    ``headers`` stays in the signature: callers pass the request headers, and the
    parameter documents at the call site that the header was considered and rejected.
    """
    return (fallback or "")[:64]


def _day(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d")


def record(event: str, *, user: str = "", ip: str = "", detail: str = "", ts: float | None = None) -> None:
    """Append one event (a no-op when AUDIT_ENABLED=false)."""
    if not settings.audit_enabled:
        return
    when = ts if ts is not None else time.time()
    entry = {
        "ts": round(when, 3),
        "event": str(event)[:40],
        "user": str(user)[:120],
        "ip": str(ip)[:64],
        "detail": str(detail)[:_MAX_DETAIL],
    }
    path = _DIR / f"audit-{_day(when)}.jsonl"
    try:
        with _lock:
            _DIR.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        log.warning("audit.write_failed", event=event)


def prune() -> int:
    """Delete daily files older than the retention window. Returns the number deleted."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=settings.audit_retention_days)).strftime("%Y-%m-%d")
    removed = 0
    if not _DIR.exists():
        return 0
    with _lock:
        for p in _DIR.glob("audit-*.jsonl"):
            day = p.stem.replace("audit-", "")
            if day < cutoff:
                try:
                    p.unlink()
                    removed += 1
                except OSError:
                    pass
    if removed:
        log.info("audit.pruned", files=removed)
    return removed


def query(
    *,
    limit: int = 500,
    event: str | None = None,
    user: str | None = None,
    since_days: int | None = None,
) -> list[dict]:
    """Most recent entries across all daily files, optionally filtered (newest first)."""
    if not _DIR.exists():
        return []
    files = sorted(_DIR.glob("audit-*.jsonl"), reverse=True)  # newest days first
    cutoff_ts = time.time() - since_days * 86400 if since_days else None
    ev = event.strip().lower() if event else None
    us = user.strip().lower() if user else None
    out: list[dict] = []
    with _lock:
        for p in files:
            try:
                lines = p.read_text(encoding="utf-8").splitlines()
            except OSError:
                continue
            for line in reversed(lines):  # within the file, newest first
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if cutoff_ts is not None and float(e.get("ts", 0)) < cutoff_ts:
                    continue
                if ev and e.get("event", "") != ev:
                    continue
                if us and us not in str(e.get("user", "")).lower():
                    continue
                out.append(e)
                if len(out) >= limit:
                    return out
    return out


def stats() -> dict:
    """Metrics for the admin view (files, entries, retention)."""
    if not _DIR.exists():
        return {"files": 0, "entries": 0, "retention_days": settings.audit_retention_days, "enabled": settings.audit_enabled}
    files = list(_DIR.glob("audit-*.jsonl"))
    entries = 0
    with _lock:
        for p in files:
            try:
                with p.open("r", encoding="utf-8") as f:
                    entries += sum(1 for ln in f if ln.strip())
            except OSError:
                pass
    return {
        "files": len(files),
        "entries": entries,
        "retention_days": settings.audit_retention_days,
        "enabled": settings.audit_enabled,
    }
