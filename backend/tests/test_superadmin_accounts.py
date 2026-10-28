"""Only a superadmin may manage a superadmin account.

The audit showed a manager holding nothing but ``accounts`` could disable, delete or
repassword the configured break-glass account, all with HTTP 200. The lockout guard
never fired, because the manager keeps their own ``accounts`` permission the whole
time. Since a superadmin always holds every permission, taking over that account is
a straight escalation.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.auth import store as store_module
from backend.auth.models import ALL_PERMISSIONS, PERM_ACCOUNTS
from backend.auth.store import AdminStore, get_admin_store
from backend.config import settings

EMERGENCY = "emergency"
MANAGER = "mgr"
PW = "correct-horse-battery"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "admin_store_path", str(tmp_path / "admins.json"))
    monkeypatch.setattr(settings, "audit_enabled", False)
    monkeypatch.setattr(store_module, "_store", AdminStore())
    # "emergency" is the break-glass account, named in the configuration.
    monkeypatch.setattr(settings, "superadmin_users", EMERGENCY)

    store = get_admin_store()
    store.create(EMERGENCY, PW, "Break glass")
    store.create(MANAGER, PW, "Account manager")
    # The manager holds accounts and nothing else. That is the whole point.
    store.create_group("Managers", {PERM_ACCOUNTS}, members=[{"type": "local", "ref": MANAGER}])

    from backend.main import app

    return TestClient(app)


def login(client, username):
    r = client.post("/api/auth/login", json={"username": username, "password": PW})
    assert r.status_code == 200, r.text
    return r


# ── The manager is kept out ────────────────────────────────────────


def test_manager_cannot_disable_the_superadmin(client):
    login(client, MANAGER)
    r = client.put(f"/api/admins/{EMERGENCY}", json={"enabled": False})
    assert r.status_code == 403
    assert "superadmin" in r.json()["detail"].lower()
    # And the account still works.
    assert get_admin_store().verify_login(EMERGENCY, PW) is not None


def test_manager_cannot_repassword_the_superadmin(client):
    login(client, MANAGER)
    r = client.put(f"/api/admins/{EMERGENCY}", json={"password": "attacker-chosen-pw"})
    assert r.status_code == 403
    assert get_admin_store().verify_login(EMERGENCY, PW) is not None
    assert get_admin_store().verify_login(EMERGENCY, "attacker-chosen-pw") is None


def test_manager_cannot_delete_the_superadmin(client):
    login(client, MANAGER)
    r = client.delete(f"/api/admins/{EMERGENCY}")
    assert r.status_code == 403
    assert any(a["username"] == EMERGENCY for a in get_admin_store().list())


def test_manager_cannot_create_a_new_superadmin(client, monkeypatch):
    """Creating an account whose name is in the list hands it every permission at once."""
    monkeypatch.setattr(settings, "superadmin_users", f"{EMERGENCY}, second-root")
    login(client, MANAGER)
    r = client.post("/api/admins", json={"username": "second-root", "password": PW})
    assert r.status_code == 403
    assert not any(a["username"] == "second-root" for a in get_admin_store().list())


# ── A superadmin is not blocked ────────────────────────────────────


def test_superadmin_may_manage_another_superadmin(client, monkeypatch):
    monkeypatch.setattr(settings, "superadmin_users", f"{EMERGENCY}, second-root")
    login(client, EMERGENCY)
    assert client.post("/api/admins", json={"username": "second-root", "password": PW}).status_code == 200
    assert client.put("/api/admins/second-root", json={"display_name": "Second"}).status_code == 200
    assert client.delete("/api/admins/second-root").status_code == 200


def test_superadmin_may_still_manage_itself(client):
    """The guard must not lock a superadmin out of its own account."""
    login(client, EMERGENCY)
    r = client.put(f"/api/admins/{EMERGENCY}", json={"display_name": "Renamed"})
    assert r.status_code == 200
    assert r.json()["display_name"] == "Renamed"


# ── Ordinary accounts are unaffected ───────────────────────────────


def test_manager_can_still_manage_an_ordinary_account(client):
    login(client, MANAGER)
    assert client.post("/api/admins", json={"username": "normal", "password": PW}).status_code == 200
    assert client.put("/api/admins/normal", json={"enabled": False}).status_code == 200
    assert client.delete("/api/admins/normal").status_code == 200


def test_guard_is_case_insensitive(client):
    """SUPERADMIN_USERS is matched case insensitively everywhere else, so here too."""
    login(client, MANAGER)
    assert client.delete(f"/api/admins/{EMERGENCY.upper()}").status_code == 403


def test_nothing_is_blocked_when_no_superadmin_is_configured(client, monkeypatch):
    monkeypatch.setattr(settings, "superadmin_users", "")
    login(client, MANAGER)
    # "emergency" is now an ordinary account like any other.
    assert client.put(f"/api/admins/{EMERGENCY}", json={"display_name": "Plain"}).status_code == 200


# ── The other half of the rule, already in place ───────────────────


def test_manager_still_cannot_grant_what_it_does_not_hold(client):
    """Nobody may hand out more than they hold. Pinned here so the two rules stay together."""
    login(client, MANAGER)
    r = client.post("/api/admins/groups", json={"name": "Sneaky", "permissions": sorted(ALL_PERMISSIONS)})
    assert r.status_code == 403
    r = client.post("/api/admins/groups", json={"name": "Sneakier", "all_permissions": True})
    assert r.status_code == 403
