"""HTTP layer of account and group management: routing of the member and directory
endpoints, plus the escalation brake (you may only grant or assign permissions you hold
yourself)."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.auth import store as store_module
from backend.auth.models import ALL_PERMISSIONS
from backend.auth.store import AdminStore, get_admin_store
from backend.config import settings


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "admin_store_path", str(tmp_path / "admins.json"))
    monkeypatch.setattr(settings, "audit_enabled", False)
    monkeypatch.setattr(store_module, "_store", AdminStore())
    s = get_admin_store()
    # Full admin (local) via a group.
    s.create("admin", "password1")
    s.create_group("Administrators", ALL_PERMISSIONS, members=[{"type": "local", "ref": "admin"}])
    from backend.main import app

    c = TestClient(app)
    assert c.post("/api/auth/login", json={"username": "admin", "password": "password1"}).status_code == 200
    return c, s


def test_group_member_lifecycle(env):
    c, s = env
    s.create("alice", "password1")
    # Create a group, set permissions, add a local and an AD member.
    assert c.post("/api/admins/groups", json={"name": "Log-Readers", "permissions": ["logs"]}).status_code == 200
    r = c.post("/api/admins/groups/Log-Readers/members", json={"type": "local", "ref": "alice"})
    assert r.status_code == 200 and {"type": "local", "ref": "alice"} in r.json()["members"]
    r = c.post("/api/admins/groups/Log-Readers/members", json={"type": "ad_group", "ref": "ZS-Net"})
    assert {"type": "ad_group", "ref": "ZS-Net"} in r.json()["members"]
    # alice now effectively holds 'logs'.
    assert set(s.get_active("alice")["permissions"]) == {"logs"}
    # Remove the member again (via query params).
    r = c.request("DELETE", "/api/admins/groups/Log-Readers/members", params={"type": "local", "ref": "alice"})
    assert r.status_code == 200 and set(s.get_active("alice")["permissions"]) == set()


def test_group_rename_keeps_permissions_and_members(env):
    c, s = env
    s.create("alice", "password1")
    c.post("/api/admins/groups", json={"name": "Log-Readers", "permissions": ["logs"]})
    c.post("/api/admins/groups/Log-Readers/members", json={"type": "local", "ref": "alice"})
    r = c.put("/api/admins/groups/Log-Readers", json={"name": "Network-Team"})
    assert r.status_code == 200
    assert r.json()["name"] == "Network-Team"
    assert r.json()["permissions"] == ["logs"]
    assert {"type": "local", "ref": "alice"} in r.json()["members"]
    # The members keep their permissions; the account shows the new group name.
    assert set(s.get_active("alice")["permissions"]) == {"logs"}
    assert s.get_active("alice")["groups"] == ["Network-Team"]
    # The old name is gone, and the new name does not collide with itself (case insensitive).
    assert c.put("/api/admins/groups/Log-Readers", json={"name": "X"}).status_code == 404
    assert c.put("/api/admins/groups/Network-Team", json={"name": "network-team"}).status_code == 200


def test_group_rename_conflict_rejected(env):
    c, _ = env
    c.post("/api/admins/groups", json={"name": "A", "permissions": []})
    c.post("/api/admins/groups", json={"name": "B", "permissions": []})
    assert c.put("/api/admins/groups/A", json={"name": "b"}).status_code == 400
    # Without "permissions" in the body the permissions stay untouched.
    r = c.put("/api/admins/groups/Administrators", json={"name": "Admins"})
    assert r.status_code == 200 and set(r.json()["permissions"]) == set(ALL_PERMISSIONS)


def test_invalid_member_type_rejected(env):
    c, _ = env
    c.post("/api/admins/groups", json={"name": "G", "permissions": []})
    assert c.post("/api/admins/groups/G/members", json={"type": "bogus", "ref": "x"}).status_code == 400


def test_ad_identities_endpoint(env):
    c, s = env
    s.create_group("Log-Readers", {"logs"}, members=[{"type": "ad_user", "ref": "max"}])
    s.record_ad_login("max", "Max Example")
    r = c.get("/api/admins/identities")
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 1
    assert body[0]["username"] == "max" and body[0]["display_name"] == "Max Example"
    assert body[0]["groups"] == ["Log-Readers"] and len(body[0]["id"]) == 36
    # The entry is information only: deleting it leaves the group authorization untouched.
    assert c.delete("/api/admins/identities/max").status_code == 200
    assert c.get("/api/admins/identities").json() == []
    assert s.effective_for_ad("max", set()) == frozenset({"logs"})
    assert c.delete("/api/admins/identities/max").status_code == 404


def test_directory_endpoint_mocked(env, monkeypatch):
    c, _ = env
    from backend.api import auth_routes

    monkeypatch.setattr(
        auth_routes, "search_directory",
        lambda q, kind, limit=200: {
            "status": "ok", "detail": "",
            "entries": [{"type": "ad_user", "ref": "max", "display": "Max Example"}],
        },
    )
    r = c.get("/api/admins/directory", params={"q": "max", "kind": "user"})
    assert r.status_code == 200 and r.json()["entries"][0]["ref"] == "max"


def test_directory_reports_missing_service_account(env, monkeypatch):
    # Without a service account there is an UNAMBIGUOUS reason instead of "no hits".
    c, _ = env
    monkeypatch.setattr(settings, "ldap_bind_user", "")
    monkeypatch.setattr(settings, "ldap_base_dn", "")
    r = c.get("/api/admins/directory", params={"q": "*connect*", "kind": "group"})
    assert r.status_code == 200
    assert r.json()["status"] == "no_service_account" and r.json()["entries"] == []


def test_directory_rejects_too_short_query(env):
    c, _ = env
    r = c.get("/api/admins/directory", params={"q": "*", "kind": "group"})
    assert r.status_code == 200 and r.json()["status"] == "too_short"


def test_escalation_blocked_for_partial_manager(env):
    c, s = env
    # A manager who holds ONLY 'accounts'.
    s.create("mgr", "password1")
    s.create_group("Managers", {"accounts"}, members=[{"type": "local", "ref": "mgr"}])
    mgr = TestClient(get_app())
    assert mgr.post("/api/auth/login", json={"username": "mgr", "password": "password1"}).status_code == 200
    # Must not create a group with permissions they do not hold themselves.
    assert mgr.post("/api/admins/groups", json={"name": "X", "permissions": ["logs"]}).status_code == 403
    # Must not add anyone to the full-admin group (its permissions exceed theirs).
    assert mgr.post(
        "/api/admins/groups/Administrators/members", json={"type": "ad_user", "ref": "evil"}
    ).status_code == 403


def get_app():
    from backend.main import app
    return app
