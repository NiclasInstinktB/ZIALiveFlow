"""The most recent errors, kept in memory so they can be read without SSH.

Logs used to go to stdout and from there into the service journal. Anyone without server
access saw only the short message in the user interface when something failed; the line
naming the actual reason (``crypto.decrypt_failed``, ``ldap.bind_failed``) stayed
invisible. Exactly those lines land here in a ring buffer and can be read under
Settings → Logs.

Deliberately **RAM only**: an error buffer is a diagnostic aid for running operations,
not an archive. The audit log and the system service journal cover that. After a restart
it is empty, and that is correct.

It is filled from **two** sources, otherwise half of it would be missing:
  * structlog (everything the application logs itself),
  * the standard logging library (uvicorn, httpx, tracebacks from FastAPI).
"""
from __future__ import annotations

import logging
import threading
from collections import deque
from datetime import datetime, timezone
from typing import Any

# 300 instead of 50: the UI shows the last 50, but someone filtering by level should not
# come up empty just because 50 warnings arrived afterwards.
_CAPACITY = 300

LEVELS: dict[str, int] = {
    "debug": 10, "info": 20, "warning": 30, "warn": 30, "error": 40,
    "critical": 50, "fatal": 50, "exception": 40,
}

# Keys whose value must never reach the buffer. A log line is written quickly, and a
# token inside one would be readable through the API by anyone allowed to see the
# settings. The list matches on substrings of the key name, so it keeps the German
# spelling "passwort" alongside the English one.
_SECRET_HINTS = ("token", "secret", "password", "passwort", "authorization", "api_key", "apikey", "bind_pw")

_lock = threading.Lock()
_buffer: deque[dict[str, Any]] = deque(maxlen=_CAPACITY)
_seq = 0


def _redact(key: str, value: Any) -> Any:
    if any(hint in key.lower() for hint in _SECRET_HINTS):
        return "***"
    text = value if isinstance(value, (str, int, float, bool)) or value is None else repr(value)
    if isinstance(text, str) and len(text) > 2000:
        return text[:2000] + " …"
    return text


def record(
    *, level: str, event: str, logger: str = "", timestamp: str = "", fields: dict | None = None
) -> None:
    """Store one entry. Everything below WARNING is discarded."""
    if LEVELS.get((level or "").lower(), 0) < LEVELS["warning"]:
        return
    global _seq
    with _lock:
        _seq += 1
        _buffer.append(
            {
                "id": _seq,
                "ts": timestamp or datetime.now(timezone.utc).isoformat(),
                "level": (level or "error").lower(),
                "logger": logger or "",
                "event": str(event or "")[:500],
                "fields": {k: _redact(k, v) for k, v in (fields or {}).items()},
            }
        )


def recent(limit: int = 50, level: str = "warning") -> list[dict]:
    """Newest entries first: when you are looking for something, the latest matters most."""
    floor = LEVELS.get((level or "warning").lower(), LEVELS["warning"])
    with _lock:
        items = [e for e in _buffer if LEVELS.get(e["level"], 0) >= floor]
    return list(reversed(items))[: max(1, min(int(limit or 50), _CAPACITY))]


def counts() -> dict[str, int]:
    with _lock:
        items = list(_buffer)
    return {
        "total": len(items),
        "errors": sum(1 for e in items if LEVELS.get(e["level"], 0) >= LEVELS["error"]),
        "warnings": sum(1 for e in items if LEVELS.get(e["level"], 0) == LEVELS["warning"]),
        "capacity": _CAPACITY,
    }


def clear() -> int:
    with _lock:
        size = len(_buffer)
        _buffer.clear()
    return size


# ── Hook into structlog ─────────────────────────────────────────────


def structlog_processor(_logger: Any, _name: str, event_dict: dict) -> dict:
    """Install this as the second-to-last processor, after level, time and traceback.

    Returns ``event_dict`` unchanged: the buffer only listens in, it does not interfere
    with the output.
    """
    level = str(event_dict.get("level") or "info")
    if LEVELS.get(level.lower(), 0) >= LEVELS["warning"]:
        fields = {
            k: v for k, v in event_dict.items()
            if k not in ("event", "level", "timestamp", "logger", "logger_name")
        }
        record(
            level=level,
            event=str(event_dict.get("event") or ""),
            logger=str(event_dict.get("logger") or event_dict.get("logger_name") or ""),
            timestamp=str(event_dict.get("timestamp") or ""),
            fields=fields,
        )
    return event_dict


# ── Hook into the standard logging library ──────────────────────────


class BufferHandler(logging.Handler):
    """Catches what does not go through structlog: uvicorn errors and tracebacks."""

    def emit(self, log_record: logging.LogRecord) -> None:  # pragma: no cover - trivial
        try:
            fields: dict[str, Any] = {}
            if log_record.exc_info:
                fields["exception"] = self.format(log_record)[:4000]
            record(
                level=log_record.levelname,
                event=log_record.getMessage(),
                logger=log_record.name,
                timestamp=datetime.fromtimestamp(log_record.created, timezone.utc).isoformat(),
                fields=fields,
            )
        except Exception:  # noqa: BLE001 - logging must never disturb the application
            pass
