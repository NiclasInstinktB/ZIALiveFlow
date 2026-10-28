"""Tests for the global query chip store (seeding, sanitizing, dedup, replacing)."""
from __future__ import annotations

import pytest

from backend import chips_store


def _use_tmp(tmp_path, monkeypatch):
    p = tmp_path / "global_chips.json"
    monkeypatch.setattr(chips_store, "_PATH", p)
    return p


def test_seed_creates_defaults(tmp_path, monkeypatch):
    p = _use_tmp(tmp_path, monkeypatch)
    assert not p.exists()
    chips_store.seed_if_empty()
    assert p.exists()
    chips = chips_store.list_global()
    assert len(chips) == len(chips_store._DEFAULTS)
    labels = {c["label"] for c in chips}
    assert {"Allowed", "Blocked", "HTTP error"} <= labels
    for c in chips:
        assert c["id"] and c["label"] and c["query"]
        assert c["color"] in ("good", "bad", "warn", "info")


def test_seed_is_noop_if_present(tmp_path, monkeypatch):
    _use_tmp(tmp_path, monkeypatch)
    chips_store.replace_global([{"id": "x", "label": "L", "query": "q=1", "color": "good"}])
    chips_store.seed_if_empty()  # must NOT overwrite
    chips = chips_store.list_global()
    assert len(chips) == 1 and chips[0]["label"] == "L"


def test_replace_sanitizes_and_dedups(tmp_path, monkeypatch):
    _use_tmp(tmp_path, monkeypatch)
    result = chips_store.replace_global(
        [
            {"id": "a", "label": "  Allowed  ", "query": "verdict=allowed", "color": "good"},
            {"id": "a", "label": "Dup-ID", "query": "x=1", "color": "nope"},  # dup id + invalid color
            {"label": "", "query": "empty"},  # dropped (no label)
            {"id": "b", "label": "NoQuery", "query": "   "},  # dropped (no query)
            "broken",  # not a dict, so ignored
        ]
    )
    assert len(result) == 2
    assert result[0]["label"] == "Allowed"  # trimmed
    assert result[0]["id"] == "a"
    assert result[1]["id"] != "a"  # deduplicated
    assert result[1]["color"] == "info"  # invalid color falls back to info
    # persistence round trip
    assert chips_store.list_global() == result


def test_replace_accepts_hex_and_preset_colors(tmp_path, monkeypatch):
    _use_tmp(tmp_path, monkeypatch)
    result = chips_store.replace_global(
        [
            {"id": "a", "label": "Purple", "query": "x=1", "color": "#8b5cf6"},
            {"id": "b", "label": "Preset", "query": "y=2", "color": "warn"},
            {"id": "c", "label": "Broken", "query": "z=3", "color": "notacolor"},
        ]
    )
    assert result[0]["color"] == "#8b5cf6"  # a free hex value is kept
    assert result[1]["color"] == "warn"  # a preset name stays
    assert result[2]["color"] == "info"  # invalid, so the fallback applies


def test_replace_rejects_non_list(tmp_path, monkeypatch):
    _use_tmp(tmp_path, monkeypatch)
    with pytest.raises(ValueError):
        chips_store.replace_global({"not": "a list"})


def test_replace_caps_length(tmp_path, monkeypatch):
    _use_tmp(tmp_path, monkeypatch)
    many = [{"id": f"c{i}", "label": f"L{i}", "query": "x=1", "color": "info"} for i in range(200)]
    result = chips_store.replace_global(many)
    assert len(result) == chips_store._MAX_CHIPS


# ── A damaged file must not take the chip bar down with it ─────────
def test_list_survives_a_file_that_is_not_an_object(tmp_path, monkeypatch):
    p = _use_tmp(tmp_path, monkeypatch)
    p.write_text("[1, 2, 3]", encoding="utf-8")
    assert chips_store.list_global() == []


def test_list_survives_a_chips_value_that_is_not_a_list(tmp_path, monkeypatch):
    p = _use_tmp(tmp_path, monkeypatch)
    p.write_text('{"chips": 5}', encoding="utf-8")
    assert chips_store.list_global() == []


def test_replace_keeps_ids_unique_when_the_renamed_id_is_taken(tmp_path, monkeypatch):
    """The dedup rename must not collide with an id that is already in the list.

    Chip ids key the per-account show/hide and order prefs, so two chips sharing one id
    cannot be hidden or reordered independently.
    """
    _use_tmp(tmp_path, monkeypatch)
    result = chips_store.replace_global(
        [
            {"id": "a", "label": "First", "query": "x=1", "color": "info"},
            {"id": "a_2", "label": "Second", "query": "y=2", "color": "info"},
            {"id": "a", "label": "Third", "query": "z=3", "color": "info"},
        ]
    )
    assert len(result) == 3
    assert len({c["id"] for c in result}) == 3
