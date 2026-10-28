"""Error ring buffer: what gets in, and what stays out.

The buffer is readable through the API (Settings → Logs), so the same rule applies to it
as to any other output: **no secrets in it**. A log line is written quickly, and a token
in ``fields`` would afterwards be readable by anyone allowed to see the settings.
"""
from __future__ import annotations

import logging

from backend import log_buffer


def setup_function() -> None:
    log_buffer.clear()


def test_only_warnings_and_worse_are_kept():
    """Info lines are normal operation: they would fill the buffer instantly."""
    log_buffer.record(level="info", event="all good")
    log_buffer.record(level="debug", event="details")
    log_buffer.record(level="warning", event="ldap.server_unreachable")
    log_buffer.record(level="error", event="crypto.decrypt_failed")
    events = [e["event"] for e in log_buffer.recent()]
    assert events == ["crypto.decrypt_failed", "ldap.server_unreachable"]  # newest first


def test_filtering_by_level():
    log_buffer.record(level="warning", event="a warning")
    log_buffer.record(level="error", event="an error")
    assert [e["event"] for e in log_buffer.recent(level="error")] == ["an error"]
    assert len(log_buffer.recent(level="warning")) == 2


def test_secrets_are_replaced_before_they_land_in_the_buffer():
    log_buffer.record(
        level="error",
        event="ldap.credentials_failed",
        fields={"token": "top-secret", "password": "abc", "url": "https://wiki.example.com/x"},
    )
    entry = log_buffer.recent()[0]
    assert entry["fields"]["token"] == "***"
    assert entry["fields"]["password"] == "***"
    # Anything that is not a secret stays readable, otherwise the entry is worthless.
    assert entry["fields"]["url"] == "https://wiki.example.com/x"


def test_the_ring_stays_bounded():
    for i in range(log_buffer._CAPACITY + 50):
        log_buffer.record(level="error", event=f"error-{i}")
    counts = log_buffer.counts()
    assert counts["total"] == log_buffer._CAPACITY
    # The newest survives, the oldest drops out.
    assert log_buffer.recent(limit=1)[0]["event"] == f"error-{log_buffer._CAPACITY + 49}"


def test_structlog_processor_passes_the_event_through_unchanged():
    """The buffer only listens in: it must not alter the output."""
    event_dict = {"event": "ldap.server_unreachable", "level": "warning", "url": "https://x"}
    result = log_buffer.structlog_processor(None, "warning", dict(event_dict))
    assert result == event_dict
    assert log_buffer.recent()[0]["fields"]["url"] == "https://x"


def test_stdlib_handler_catches_tracebacks():
    """uvicorn and FastAPI do not log through structlog, so the key lines would be missing."""
    handler = log_buffer.BufferHandler(level=logging.WARNING)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger = logging.getLogger("test.uvicorn")
    logger.addHandler(handler)
    try:
        try:
            raise ValueError("broken")
        except ValueError:
            logger.exception("Aborted while fetching")
    finally:
        logger.removeHandler(handler)

    entry = log_buffer.recent()[0]
    assert entry["event"] == "Aborted while fetching"
    assert entry["level"] == "error"
    assert "ValueError: broken" in str(entry["fields"].get("exception"))
