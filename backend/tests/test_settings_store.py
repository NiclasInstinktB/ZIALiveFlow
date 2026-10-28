"""Runtime settings: what lands in the override file, and when.

The file is meant to record ONLY what an operator changed in the admin backend. Two
earlier bugs are pinned down here:

* Saving used to write the complete settings set, so the first save froze every value
  from the env file into the override file. After that, editing the env file had no
  effect any more and nothing said so.
* Updating validated and assigned in the same pass, so a batch with a bad value at the
  end left the earlier values applied in memory while the caller got an error and
  nothing was written.
"""
from __future__ import annotations

import json

import pytest

from backend import settings_store
from backend.config import settings


@pytest.fixture
def store(tmp_path, monkeypatch):
    """Point the override file at a temp path so tests never touch backend/data."""
    path = tmp_path / "runtime_settings.json"
    monkeypatch.setattr(settings_store, "_PATH", path)
    return path


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


# ── What gets written ──────────────────────────────────────────────


def test_save_writes_only_the_changed_key(store):
    settings_store.update({"retention_minutes": 7})
    assert read(store) == {"retention_minutes": 7}


def test_second_save_keeps_the_first_key(store):
    settings_store.update({"retention_minutes": 7})
    settings_store.update({"app_name": "Acme Console"})
    assert read(store) == {"retention_minutes": 7, "app_name": "Acme Console"}


def test_unchanged_value_writes_nothing(store):
    current = settings.retention_minutes
    _, pending = settings_store.update({"retention_minutes": current})
    assert not store.exists()
    assert pending == []


def test_unchanged_value_does_not_touch_an_existing_file(store):
    settings_store.update({"retention_minutes": 7})
    before = store.read_text(encoding="utf-8")
    settings_store.update({"retention_minutes": 7})
    assert store.read_text(encoding="utf-8") == before


# ── All or nothing ─────────────────────────────────────────────────


def test_invalid_value_applies_nothing_and_writes_nothing(store):
    before_retention = settings.retention_minutes
    before_name = settings.app_name
    with pytest.raises(ValueError):
        settings_store.update(
            {"retention_minutes": 9, "app_name": "Acme Console", "default_language": "xx"}
        )
    # The two valid values came first in the batch and must not have been applied.
    assert settings.retention_minutes == before_retention
    assert settings.app_name == before_name
    assert not store.exists()


def test_invalid_value_leaves_an_earlier_save_intact(store):
    settings_store.update({"retention_minutes": 7})
    with pytest.raises(ValueError):
        settings_store.update({"app_name": "Acme Console", "feed_timezone": "Mars/Olympus"})
    assert read(store) == {"retention_minutes": 7}
    assert settings.app_name != "Acme Console"


# ── Reading the file back ──────────────────────────────────────────


def test_load_applies_only_what_is_in_the_file(store):
    store.write_text(json.dumps({"retention_minutes": 11}), encoding="utf-8")
    settings_store.load_and_apply()
    assert settings.retention_minutes == 11


def test_load_survives_a_corrupt_file(store):
    store.write_text("{not json", encoding="utf-8")
    settings_store.load_and_apply()  # must not raise


def test_load_survives_a_file_that_is_not_an_object(store):
    store.write_text("[1, 2, 3]", encoding="utf-8")
    settings_store.load_and_apply()  # must not raise


def test_load_skips_a_value_that_no_longer_validates(store):
    store.write_text(
        json.dumps({"retention_minutes": 11, "default_language": "xx"}), encoding="utf-8"
    )
    settings_store.load_and_apply()
    assert settings.retention_minutes == 11
    assert settings.default_language != "xx"


def test_env_value_stays_changeable_after_a_save(store):
    """The regression the first bug caused: an unrelated setting must not be frozen.

    Saving one setting used to write all of them, so a later env change to any other
    setting was overridden by the file on the next start.
    """
    settings_store.update({"retention_minutes": 7})
    assert "ingest_dns_port" not in read(store)

    # Simulate the operator changing it in the env file and restarting.
    monkey_value = 5999
    settings.ingest_dns_port = monkey_value
    settings_store.load_and_apply()
    assert settings.ingest_dns_port == monkey_value
