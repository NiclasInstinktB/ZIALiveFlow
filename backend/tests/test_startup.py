"""Startup: the hardening checks, and what happens when a step fails.

The lifespan applies the stored settings, then checks them, then builds everything the
app needs. Two properties matter: a check that is supposed to stop the start really
stops it, and a step that fails does not leave a half-built app answering requests.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend import audit, chips_store, ldap_config, oidc_config, settings_store
from backend.auth import store as store_module
from backend.auth.store import AdminStore
from backend.config import DEFAULT_JWT_SECRET, settings


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """Point every file the lifespan touches at a temp directory."""
    monkeypatch.setattr(settings, "admin_store_path", str(tmp_path / "admins.json"))
    monkeypatch.setattr(settings, "audit_enabled", False)
    monkeypatch.setattr(settings, "ingest_enabled", False)
    monkeypatch.setattr(audit, "_DIR", tmp_path / "audit")
    monkeypatch.setattr(chips_store, "_PATH", tmp_path / "global_chips.json")
    monkeypatch.setattr(ldap_config, "_PATH", tmp_path / "ldap_config.json")
    monkeypatch.setattr(oidc_config, "_PATH", tmp_path / "oidc_config.json")
    monkeypatch.setattr(settings_store, "_PATH", tmp_path / "runtime_settings.json")
    monkeypatch.setattr(store_module, "_store", AdminStore())
    return tmp_path


def test_app_starts_in_development(isolated):
    from backend.main import app

    with TestClient(app) as client:
        assert client.get("/api/health").json()["status"] == "ok"


def test_production_with_the_placeholder_secret_refuses_to_start(isolated, monkeypatch):
    """The whole point of the check: a signing key everyone knows means forgeable sessions."""
    from backend.main import app

    monkeypatch.setattr(settings, "app_env", "prod")
    monkeypatch.setattr(settings, "jwt_secret", DEFAULT_JWT_SECRET)
    assert settings.is_production and settings.jwt_secret_is_default
    with pytest.raises(RuntimeError, match="JWT_SECRET"):
        with TestClient(app):
            pass


def test_production_with_a_real_secret_starts(isolated, monkeypatch):
    from backend.main import app

    monkeypatch.setattr(settings, "app_env", "prod")
    monkeypatch.setattr(settings, "jwt_secret", "a-genuinely-long-and-random-value-for-this-test")
    with TestClient(app) as client:
        assert client.get("/api/health").status_code == 200


def test_stored_settings_are_applied_before_the_checks_run(isolated, monkeypatch):
    """``load_and_apply`` has to come first, or every later step reads the env file.

    The health answer reports the app name, so a stored value that shows up there proves
    the override was applied before anything read it.
    """
    import json

    from backend.main import app

    settings_store._PATH.write_text(json.dumps({"app_name": "Stored Name"}), encoding="utf-8")
    with TestClient(app) as client:
        assert client.get("/api/health").json()["app_name"] == "Stored Name"


def test_a_failing_startup_step_leaves_nothing_serving(isolated, monkeypatch):
    """A half-started app is worse than one that refuses: it answers, badly."""
    from backend import main

    async def boom() -> None:
        raise RuntimeError("the feed listeners could not bind")

    monkeypatch.setattr(main, "start_ingest", boom)
    with pytest.raises(RuntimeError, match="could not bind"):
        with TestClient(main.app):
            pass
