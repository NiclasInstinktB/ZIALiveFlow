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


def test_level_aliases_are_counted_as_the_level_they_mean():
    """structlog and the standard library do not agree on the spelling."""
    log_buffer.record(level="WARNING", event="upper case")
    log_buffer.record(level="warn", event="short form")
    log_buffer.record(level="CRITICAL", event="critical")
    log_buffer.record(level="exception", event="exception")
    counts = log_buffer.counts()
    assert counts["total"] == 4
    assert counts["warnings"] == 2
    assert counts["errors"] == 2
    assert [e["level"] for e in log_buffer.recent()] == ["exception", "critical", "warn", "warning"]


def test_an_unknown_level_is_not_let_in():
    """Anything the level table does not know counts as below warning, or a typo in a
    caller would quietly fill the buffer with routine chatter."""
    log_buffer.record(level="notice", event="nothing to see")
    log_buffer.record(level="", event="no level at all")
    assert log_buffer.counts()["total"] == 0


def test_the_level_filter_is_applied_before_the_limit():
    """The point of the 300 slot buffer: one error behind 60 warnings must still be
    findable by filtering, not pushed out of the window first."""
    log_buffer.record(level="error", event="the one error")
    for i in range(60):
        log_buffer.record(level="warning", event=f"warning-{i}")
    assert [e["event"] for e in log_buffer.recent(limit=50, level="error")] == ["the one error"]


def test_the_limit_is_kept_inside_sane_bounds():
    for i in range(10):
        log_buffer.record(level="error", event=f"error-{i}")
    assert len(log_buffer.recent(limit=0)) == 10       # 0 means the default, not nothing
    assert len(log_buffer.recent(limit=-5)) == 1       # never negative slicing
    assert len(log_buffer.recent(limit=10_000)) == 10  # never more than there is


def test_a_secret_is_masked_whatever_the_key_is_called():
    log_buffer.record(
        level="error",
        event="sso.exchange_failed",
        fields={
            "Authorization": "Bearer abc", "client_secret": "s3cr3t", "api_key": "k",
            "refresh_token": "r", "bind_pw": "p", "benutzer_passwort": "q",
        },
    )
    assert set(log_buffer.recent()[0]["fields"].values()) == {"***"}


def test_a_non_scalar_field_does_not_break_the_entry():
    log_buffer.record(level="error", event="x", fields={"nets": [1, 2], "when": None})
    entry = log_buffer.recent()[0]
    assert entry["fields"]["when"] is None
    assert "1" in str(entry["fields"]["nets"])


def test_an_enormous_field_is_truncated():
    log_buffer.record(level="error", event="y", fields={"body": "z" * 10_000})
    assert len(log_buffer.recent()[0]["fields"]["body"]) < 2_100


def test_clear_reports_what_it_removed():
    for i in range(5):
        log_buffer.record(level="error", event=f"e{i}")
    assert log_buffer.clear() == 5
    assert log_buffer.counts()["total"] == 0
