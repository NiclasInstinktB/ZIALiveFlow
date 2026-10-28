"""Global query chips: locked quick filters managed by an admin.

A chip is a stored query (the frontend mini query language) with a label and a color.
**Global** chips apply to ALL users and are read-only for viewers: they can only show,
hide and reorder them (which lives in the personal prefs). **Personal** chips, by
contrast, live entirely in the account prefs (see ``prefs_routes``) and can be edited and
deleted freely.

Storage: ``backend/data/global_chips.json`` (written atomically). On first start the
former verdict quick filters (Allowed, Blocked and so on) are created as the default
global chips, so the chip bar is usefully filled from the start.
"""
from __future__ import annotations

import json
import os
import re
import threading

from backend.config import PROJECT_ROOT
from backend.logging_config import get_logger

log = get_logger("chips.store")

_PATH = PROJECT_ROOT / "backend" / "data" / "global_chips.json"
_lock = threading.Lock()

_MAX_CHIPS = 50
_MAX_LABEL = 40
_MAX_QUERY = 200
# Color: a preset name (backwards compatible) OR a free hex value (#rgb / #rrggbb / #rrggbbaa).
_COLORS = ("good", "bad", "warn", "info")
_HEX_RE = re.compile(r"^#[0-9a-fA-F]{3,8}$")
_ID_RE = re.compile(r"[^a-zA-Z0-9_-]")


def _clean_color(value) -> str:
    c = str(value).strip()
    return c if (c in _COLORS or _HEX_RE.match(c)) else "info"

# Default chips = the migrated verdict quick filters (label, query, color).
# The queries use the field aliases from query.ts. "verdict" is the primary alias;
# the parser also accepts localised ones, but the shipped defaults stay English.
_DEFAULTS: tuple[tuple[str, str, str], ...] = (
    ("Allowed", "verdict=allowed", "good"),
    ("Blocked", "verdict=blocked", "bad"),
    ("No return traffic", "verdict=no_response", "warn"),
    ("SSL failed", "verdict=ssl_failed", "warn"),
    ("HTTP error", "verdict=http_error", "warn"),
    ("DNS error", "verdict=dns_error", "warn"),
    ("Unclear", "verdict=unknown", "info"),
)


def _sanitize(chip: dict, idx: int) -> dict | None:
    """Trim a chip dict down to the allowed fields and limits (or drop it with None)."""
    label = str(chip.get("label", "")).strip()[:_MAX_LABEL]
    query = str(chip.get("query", "")).strip()[:_MAX_QUERY]
    if not label or not query:
        return None
    color = _clean_color(chip.get("color", "info"))
    cid = _ID_RE.sub("", str(chip.get("id", "")).strip())[:40]
    if not cid:
        cid = f"g_{idx}"
    return {"id": cid, "label": label, "query": query, "color": color}


def _load() -> list[dict]:
    if not _PATH.exists():
        return []
    try:
        data = json.loads(_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        log.warning("chips.load_failed", path=str(_PATH))
        return []
    out: list[dict] = []
    for i, c in enumerate(data.get("chips", [])):
        s = _sanitize(c, i) if isinstance(c, dict) else None
        if s:
            out.append(s)
    return out


def _save(chips: list[dict]) -> None:
    _PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = _PATH.with_suffix(_PATH.suffix + ".tmp")
    tmp.write_text(json.dumps({"chips": chips}, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, _PATH)


def seed_if_empty() -> None:
    """On first start, create the verdict filters as the default global chips."""
    with _lock:
        if _PATH.exists():
            return
        chips = [
            {"id": f"g_{k}", "label": lbl, "query": q, "color": col}
            for k, (lbl, q, col) in enumerate(_DEFAULTS)
        ]
        _save(chips)
        log.info("chips.seeded_defaults", count=len(chips))


def list_global() -> list[dict]:
    with _lock:
        return _load()


def replace_global(chips: list) -> list[dict]:
    """Replace the entire global list (validated, deduplicated, capped)."""
    if not isinstance(chips, list):
        raise ValueError("chips must be a list.")
    cleaned: list[dict] = []
    seen: set[str] = set()
    for i, c in enumerate(chips[:_MAX_CHIPS]):
        if not isinstance(c, dict):
            continue
        s = _sanitize(c, i)
        if not s:
            continue
        if s["id"] in seen:
            s["id"] = f"{s['id']}_{i}"
        seen.add(s["id"])
        cleaned.append(s)
    with _lock:
        _save(cleaned)
    log.info("chips.replaced", count=len(cleaned))
    return cleaned
