"""The three backend decisions taken after the audit.

Each of these was a demonstrated defect that was deliberately left open, because fixing
it changes documented behaviour rather than repairing a mistake. The calls were made,
these pin them down.
"""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from backend import settings_store
from backend.auth import store as store_module
from backend.auth.deps import _slide_session
from backend.auth.models import PERM_ACCOUNTS, Principal
from backend.auth.store import AdminStore, get_admin_store
from backend.auth.tokens import create_session_token, decode_session_token
from backend.config import settings

PW = "correct-horse-battery"


# ── A directory session cannot renew itself for ever ───────────────


class _Resp:
    """Just enough of a Response to see whether a fresh cookie was set."""

    def __init__(self):
        self.cookie = None

    def set_cookie(self, **kw):
        self.cookie = kw


def _ad_principal():
    return Principal(
        username="max", display_name="Max", permissions=frozenset({"logs"}), source="ad"
    )


def _slide(payload, principal):
    r = _Resp()
    _slide_session(payload, principal, r)
    return r.cookie


def test_directory_session_renews_inside_the_cap(monkeypatch):
    monkeypatch.setattr(settings, "session_ttl_minutes", 60)
    now = int(time.time())
    # Signed in 40 minutes ago, past half of the lifetime, so a renewal is due.
    payload = {"iat": now - 40 * 60, "exp": now + 20 * 60, "sst": now - 40 * 60}
    assert _slide(payload, _ad_principal()) is not None


def test_directory_session_stops_renewing_at_the_cap(monkeypatch):
    """The whole point: 'takes effect at the next sign-in' has to actually arrive."""
    monkeypatch.setattr(settings, "session_ttl_minutes", 60)
    now = int(time.time())
    # Renewed repeatedly: iat is recent, but the sign-in was 61 minutes ago.
    payload = {"iat": now - 40 * 60, "exp": now + 20 * 60, "sst": now - 61 * 60}
    assert _slide(payload, _ad_principal()) is None


def test_local_session_still_renews_past_the_cap(monkeypatch):
    """Local accounts recompute permissions from the groups on every renewal, so a
    revocation lands by itself and there is no reason to cut them off."""
    monkeypatch.setattr(settings, "session_ttl_minutes", 60)
    now = int(time.time())
    payload = {"iat": now - 40 * 60, "exp": now + 20 * 60, "sst": now - 300 * 60}
    local = Principal(username="root", display_name="Root", permissions=frozenset({"logs"}))
    assert _slide(payload, local) is not None


def test_renewal_carries_the_original_sign_in_time(monkeypatch):
    monkeypatch.setattr(settings, "session_ttl_minutes", 60)
    now = int(time.time())
    start = now - 40 * 60
    cookie = _slide({"iat": start, "exp": now + 20 * 60, "sst": start}, _ad_principal())
    assert decode_session_token(cookie["value"])["sst"] == start


def test_a_fresh_token_starts_its_own_clock():
    token = create_session_token("max", "Max", "ad", ["logs"])
    payload = decode_session_token(token)
    assert abs(payload["sst"] - payload["iat"]) <= 1


def test_a_token_from_before_this_change_still_works(monkeypatch):
    """No 'sst' claim: fall back to 'iat' rather than refusing to renew."""
    monkeypatch.setattr(settings, "session_ttl_minutes", 60)
    now = int(time.time())
    assert _slide({"iat": now - 40 * 60, "exp": now + 20 * 60}, _ad_principal()) is not None


# ── A failed rename leaves the permissions alone ───────────────────


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "admin_store_path", str(tmp_path / "admins.json"))
    monkeypatch.setattr(settings, "audit_enabled", False)
    monkeypatch.setattr(store_module, "_store", AdminStore())
    store = get_admin_store()
    store.create("root", PW, "Root")
    # root has to hold everything it hands out below, the escalation brake sees to that.
    store.create_group("Admins", {PERM_ACCOUNTS, "logs", "settings", "overview"},
                       members=[{"type": "local", "ref": "root"}])
    store.create_group("Taken", {"logs"})
    from backend.main import app

    c = TestClient(app)
    assert c.post("/api/auth/login", json={"username": "root", "password": PW}).status_code == 200
    return c


def test_rename_conflict_does_not_apply_the_permission_change(client):
    r = client.put("/api/admins/groups/Admins", json={"permissions": ["settings"], "name": "taken"})
    assert r.status_code == 400
    assert "exists" in r.json()["detail"].lower()
    group = next(g for g in get_admin_store().list_groups() if g["name"] == "Admins")
    assert set(group["permissions"]) == {PERM_ACCOUNTS, "logs", "settings", "overview"}


def test_rename_and_permissions_together_still_work(client):
    r = client.put("/api/admins/groups/Taken", json={"permissions": ["overview"], "name": "Renamed"})
    assert r.status_code == 200
    group = next(g for g in get_admin_store().list_groups() if g["name"] == "Renamed")
    assert group["permissions"] == ["overview"]


def test_empty_new_name_is_rejected_before_anything_changes(client):
    r = client.put("/api/admins/groups/Taken", json={"permissions": ["overview"], "name": "  "})
    assert r.status_code == 400
    group = next(g for g in get_admin_store().list_groups() if g["name"] == "Taken")
    assert group["permissions"] == ["logs"]


# ── The restart notice survives a reload ───────────────────────────


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(settings_store, "_PATH", tmp_path / "runtime_settings.json")
    settings_store.mark_boot_state()
    yield
    settings_store._BOOT_RESTART_VALUES = {}


def test_nothing_pending_right_after_boot(store):
    assert settings_store.restart_pending() == []


def test_a_restart_setting_stays_pending_after_other_saves(store):
    settings_store.update({"app_port": 9099})
    assert settings_store.restart_pending() == ["app_port"]
    # Saving an unrelated live setting must not clear it. This is the reload case: the
    # old code only reported what the current request happened to change.
    settings_store.update({"retention_minutes": 7})
    assert settings_store.restart_pending() == ["app_port"]


def test_a_live_setting_is_never_pending(store):
    settings_store.update({"retention_minutes": 11})
    assert settings_store.restart_pending() == []


def test_setting_it_back_clears_the_notice(store):
    was = settings.app_port
    settings_store.update({"app_port": 9099})
    assert settings_store.restart_pending() == ["app_port"]
    settings_store.update({"app_port": was})
    assert settings_store.restart_pending() == []


def test_the_api_still_reports_the_restart_after_a_reload(client, store):
    """The actual bug: GET always said nothing was pending.

    The notice only ever existed in the reply to the save that caused it, so changing
    anything else, or simply reloading the page, made an outstanding restart invisible.
    """
    saved = client.put("/api/admin/settings", json={"app_port": 9099})
    assert saved.status_code == 200
    assert saved.json()["restart_pending"] == ["app_port"]

    # An unrelated live setting must not clear it.
    client.put("/api/admin/settings", json={"retention_minutes": 7})

    # And this is the reload: a plain GET has to still say so.
    assert client.get("/api/admin/settings").json()["restart_pending"] == ["app_port"]
