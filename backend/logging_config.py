"""Minimal structlog setup: console or JSON output depending on the environment."""
from __future__ import annotations

import logging
import sys

import structlog

from backend import log_buffer
from backend.config import settings

_CONFIGURED = False


def setup_logging() -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level)

    # Second source for the error buffer: everything that does NOT go through
    # structlog, i.e. uvicorn errors and tracebacks raised inside FastAPI. Without
    # this, the log view would hide exactly the cases where something really blew up.
    handler = log_buffer.BufferHandler(level=logging.WARNING)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logging.getLogger().addHandler(handler)

    renderer = (
        structlog.processors.JSONRenderer()
        if settings.log_format == "json"
        else structlog.dev.ConsoleRenderer()
    )
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            # Taps the event before rendering: afterwards the entry is just a
            # string and the individual fields could no longer be inspected.
            log_buffer.structlog_processor,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
    _CONFIGURED = True


def get_logger(name: str = "app") -> structlog.stdlib.BoundLogger:
    # The name is bound explicitly: ``PrintLoggerFactory`` does not record it
    # anywhere, so the error buffer would end up without an origin.
    return structlog.get_logger(name).bind(logger=name)
