"""Security features: session revocation against the store, the login brake, the ingest
source allowlist, and the wildcard limit (ReDoS protection)."""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from backend.api.auth_routes import _ensure_grantable
from backend.auth import deps
from backend.auth.models import (
    ALL_PERMISSIONS,
    PERM_ACCOUNTS,
    PERM_LDAP,
    PERM_LOGS,
    PERM_UPDATE,
    VIEWER_PERMISSIONS,
    Principal,
)
from backend.auth.store import AdminStore
from backend.auth.throttle import LoginThrottle
from backend.auth.tokens import create_session_token
from backend.config import settings
from backend.ingest import parser, tcp_server
from backend.ingest.models import FilterField, FilterSpec


@pytest.fixture
def store(tmp_path, monkeypatch):
    p = tmp_path / "admins.json"
    monkeypatch.setattr(settings, "admin_store_path", str(p))
    return AdminStore()


def _admins(store, *members: str) -> None:
    """Helper group 'Admins' (all permissions) with the named local accounts as members."""
    store.create_group("Admins", ALL_PERMISSIONS, members=[{"type": "local", "ref": m} for m in members])


# ── HIGH: validate a running session against the store ─────────────
def test_get_active_returns_enabled_account(store):
    store.create("alice", "password1")
    _admins(store, "alice")
    acc = store.get_active("alice")
    assert acc and acc["is_admin"] is True


def test_get_active_none_for_disabled(store):
    store.create("alice", "password1")
    store.create("boss", "password1")
    _admins(store, "boss")
    store.update("alice", enabled=False)  # alice is not a manager, so she can be disabled
    assert store.get_active("alice") is None


def test_get_active_none_for_missing(store):
    assert store.get_active("ghost") is None


def test_get_active_case_insensitive(store):
    store.create("Alice", "password1")
    assert store.get_active("alice") is not None


def test_validated_principal_uses_store_permissions(store, monkeypatch):
    # The token carries no permissions, so they come fresh from the group membership.
    store.create("carol", "password1")
    store.create("boss", "password1")
    _admins(store, "carol", "boss")  # both are managers
    store.create_group("Logs", {"logs"}, members=[{"type": "local", "ref": "carol"}])
    monkeypatch.setattr(deps, "get_admin_store", lambda: store)
    token = create_session_token("carol", "Carol")
    store.remove_member("Admins", "local", "carol")  # demoted (boss stays a manager)
    result = deps._validated_principal(token)
    assert result is not None
    principal, _ = result
    assert principal.permissions == frozenset({"logs"})
    assert principal.is_admin is False
    assert principal.has("logs") and not principal.has("accounts")


def test_validated_principal_rejects_deleted(store, monkeypatch):
    store.create("dave", "password1")
    store.create("boss", "password1")
    _admins(store, "dave", "boss")
    monkeypatch.setattr(deps, "get_admin_store", lambda: store)
    token = create_session_token("dave", "Dave")
    store.delete("dave")  # "boss" stays a manager, so this is allowed
    assert deps._validated_principal(token) is None


def test_validated_principal_rejects_disabled(store, monkeypatch):
    store.create("erin", "password1")
    store.create("boss", "password1")
    _admins(store, "boss")
    store.create_group("Viewer", VIEWER_PERMISSIONS, members=[{"type": "local", "ref": "erin"}])
    monkeypatch.setattr(deps, "get_admin_store", lambda: store)
    token = create_session_token("erin", "Erin")
    store.update("erin", enabled=False)
    assert deps._validated_principal(token) is None


def test_validated_principal_rejects_garbage(store, monkeypatch):
    monkeypatch.setattr(deps, "get_admin_store", lambda: store)
    assert deps._validated_principal("not-a-jwt") is None
    assert deps._validated_principal(None) is None


# ── HIGH: granting must not exceed your own permissions ────────────
def _granter(perms) -> Principal:
    return Principal("bob", "Bob", frozenset(perms))


def test_grantable_allows_subset():
    # Passing on only your own permissions is allowed (no HTTPException).
    _ensure_grantable(_granter({PERM_ACCOUNTS, PERM_LOGS}), frozenset({PERM_LOGS}))
    _ensure_grantable(_granter({PERM_ACCOUNTS}), frozenset())  # no permissions at all is fine


def test_grantable_full_admin_grants_anything():
    _ensure_grantable(_granter(ALL_PERMISSIONS), ALL_PERMISSIONS)  # no error


def test_grantable_blocks_escalation():
    # An account with ONLY 'accounts' must not hand itself 'update' or 'ldap'.
    with pytest.raises(HTTPException) as exc:
        _ensure_grantable(_granter({PERM_ACCOUNTS}), frozenset({PERM_ACCOUNTS, PERM_UPDATE, PERM_LDAP}))
    assert exc.value.status_code == 403


def test_grantable_blocks_single_excess_permission():
    with pytest.raises(HTTPException) as exc:
        _ensure_grantable(_granter({PERM_ACCOUNTS, PERM_LOGS}), frozenset({PERM_ACCOUNTS, PERM_UPDATE}))
    assert exc.value.status_code == 403


# ── Login brake (brute force) ──────────────────────────────────────
def test_throttle_generous_then_locks(monkeypatch):
    monkeypatch.setattr(settings, "login_max_failures", 3)
    monkeypatch.setattr(settings, "login_window_minutes", 5)
    t = LoginThrottle()
    k = t.key("10.0.0.1", "alice")
    for _ in range(3):
        assert t.retry_after(k) == 0
        t.record_failure(k)
    assert t.retry_after(k) > 0


def test_throttle_reset_on_success(monkeypatch):
    monkeypatch.setattr(settings, "login_max_failures", 3)
    t = LoginThrottle()
    k = t.key("10.0.0.1", "alice")
    for _ in range(3):
        t.record_failure(k)
    assert t.retry_after(k) > 0
    t.reset(k)
    assert t.retry_after(k) == 0


def test_throttle_key_normalizes_user_and_separates_ip():
    t = LoginThrottle()
    assert t.key("10.0.0.1", "Alice") == t.key("10.0.0.1", "alice")
    assert t.key("10.0.0.1", "a") != t.key("10.0.0.2", "a")


# ── Ingest source allowlist ────────────────────────────────────────
def test_ingest_allowlist_empty_allows_all(monkeypatch):
    monkeypatch.setattr(settings, "ingest_allowed_ips", "")
    assert tcp_server._peer_allowed(("10.9.9.9", 5140)) is True


def test_ingest_allowlist_single_ips(monkeypatch):
    monkeypatch.setattr(settings, "ingest_allowed_ips", "10.0.0.10, 10.0.0.11")
    assert tcp_server._peer_allowed(("10.0.0.10", 5140)) is True
    assert tcp_server._peer_allowed(("10.0.0.11", 6000)) is True
    assert tcp_server._peer_allowed(("10.0.0.99", 5140)) is False


def test_ingest_allowlist_cidr(monkeypatch):
    monkeypatch.setattr(settings, "ingest_allowed_ips", "10.1.0.0/24")
    assert tcp_server._peer_allowed(("10.1.0.55", 5140)) is True
    assert tcp_server._peer_allowed(("10.2.0.55", 5140)) is False


def test_ingest_allowlist_rejects_bad_peer(monkeypatch):
    monkeypatch.setattr(settings, "ingest_allowed_ips", "10.0.0.10")
    assert tcp_server._peer_allowed(None) is False
    assert tcp_server._peer_allowed(("not-an-ip", 5140)) is False


# ── Wildcard limit (ReDoS protection) ──────────────────────────────
def test_wildcard_three_stars_ok():
    specs = parser.compile_specs([FilterSpec(field=FilterField.USER, value="a*b*c*d")])
    assert len(specs) == 1


def test_wildcard_four_stars_rejected():
    specs = parser.compile_specs([FilterSpec(field=FilterField.USER, value="a*b*c*d*e")])
    assert specs == []


def test_wildcard_question_marks_not_limited():
    specs = parser.compile_specs([FilterSpec(field=FilterField.USER, value="a?b?c?d?e?f")])
    assert len(specs) == 1


# ── The login brake over HTTP, and what the audit log sees ─────────
# The unit tests above drive ``LoginThrottle`` directly. These go through the real
# endpoint, because two things only go wrong there: which address the key is built
# from, and whether a blocked attempt is recorded at all.
@pytest.fixture
def http(tmp_path, monkeypatch):
    from backend import audit
    from backend.auth import store as store_module, throttle as throttle_mod
    from backend.auth.store import AdminStore
    from fastapi.testclient import TestClient

    monkeypatch.setattr(settings, "admin_store_path", str(tmp_path / "admins.json"))
    monkeypatch.setattr(audit, "_DIR", tmp_path / "audit")
    monkeypatch.setattr(settings, "audit_enabled", True)
    monkeypatch.setattr(settings, "login_max_failures", 2)
    monkeypatch.setattr(settings, "login_window_minutes", 5)
    monkeypatch.setattr(store_module, "_store", AdminStore())
    monkeypatch.setattr(throttle_mod, "_throttle", throttle_mod.LoginThrottle())
    get_admin_store = store_module.get_admin_store
    get_admin_store().create("alice", "password1")

    from backend.main import app

    return TestClient(app)


def _bad_login(client, **kwargs):
    return client.post("/api/auth/login", json={"username": "alice", "password": "wrong"}, **kwargs)


def test_login_brake_bites_over_http(http):
    assert _bad_login(http).status_code == 401
    assert _bad_login(http).status_code == 401
    assert _bad_login(http).status_code == 429


def test_login_brake_survives_a_rotating_forwarded_for(http):
    """``X-Forwarded-For`` is attacker controlled unless a trusted proxy sets it.

    Keying the brake on it means a new value per attempt is a new key, and the
    counter never reaches the limit. The brake has to hold on the peer address.
    """
    codes = [
        _bad_login(http, headers={"X-Forwarded-For": f"203.0.113.{i}"}).status_code
        for i in range(6)
    ]
    assert 429 in codes, f"the brake never bit: {codes}"


def test_blocked_login_is_audited(http):
    from backend import audit

    _bad_login(http)
    _bad_login(http)
    assert _bad_login(http).status_code == 429
    events = [e["event"] for e in audit.query(limit=10)]
    assert events.count(audit.LOGIN_FAIL) == 3, f"the blocked attempt is missing: {events}"


def test_audit_entry_records_the_peer_not_the_header(http):
    from backend import audit

    _bad_login(http, headers={"X-Forwarded-For": "203.0.113.9"})
    assert [e["ip"] for e in audit.query(limit=10)] == ["testclient"]


# ── CORS ───────────────────────────────────────────────────────────
def test_cors_wildcard_does_not_hand_out_credentials(monkeypatch):
    """``*`` plus ``allow_credentials`` is not "open to everyone", it is worse.

    Starlette answers a cookie-carrying request by echoing the requesting origin back
    with ``Access-Control-Allow-Credentials: true``, so any page on the internet could
    read this API with the visitor's session. An operator who types ``*`` into the
    settings form must not get that.
    """
    from fastapi.testclient import TestClient

    from backend.main import create_app

    monkeypatch.setattr(settings, "cors_origins", "*")
    client = TestClient(create_app())
    resp = client.get("/api/health", headers={"Origin": "https://evil.example", "Cookie": "x=1"})
    assert resp.headers.get("access-control-allow-origin") != "https://evil.example"
    assert resp.headers.get("access-control-allow-credentials") != "true"


def test_cors_keeps_credentials_for_a_listed_origin(monkeypatch):
    from fastapi.testclient import TestClient

    from backend.main import create_app

    monkeypatch.setattr(settings, "cors_origins", "https://console.example")
    client = TestClient(create_app())
    resp = client.get("/api/health", headers={"Origin": "https://console.example", "Cookie": "x=1"})
    assert resp.headers.get("access-control-allow-origin") == "https://console.example"
    assert resp.headers.get("access-control-allow-credentials") == "true"


# ── What the overview hands out ────────────────────────────────────
# One permission opens the endpoint, but two blocks inside the answer belong to other
# permissions. A caller must not read them just because the overview is open to them.
@pytest.fixture
def overview_client(tmp_path, monkeypatch):
    from backend.auth import store as store_module
    from backend.auth.models import PERM_OVERVIEW, PERM_SETTINGS
    from backend.auth.store import AdminStore
    from fastapi.testclient import TestClient

    monkeypatch.setattr(settings, "admin_store_path", str(tmp_path / "admins.json"))
    monkeypatch.setattr(settings, "audit_enabled", False)
    monkeypatch.setattr(store_module, "_store", AdminStore())
    store = store_module.get_admin_store()
    for name, perms in (
        ("plain", {PERM_OVERVIEW}),
        ("counter", {PERM_OVERVIEW, PERM_ACCOUNTS}),
        ("tuner", {PERM_OVERVIEW, PERM_SETTINGS}),
        ("nobody", {PERM_LOGS}),
    ):
        store.create(name, "password1")
        store.create_group(f"G-{name}", perms, members=[{"type": "local", "ref": name}])

    from backend.main import app

    def status(username: str):
        client = TestClient(app)
        assert client.post(
            "/api/auth/login", json={"username": username, "password": "password1"}
        ).status_code == 200
        return client.get("/api/admin/status")

    return status


def test_status_needs_the_overview_permission(overview_client):
    assert overview_client("nobody").status_code == 403


def test_status_without_extra_permissions_has_neither_block(overview_client):
    body = overview_client("plain").json()
    assert "accounts" not in body and "security" not in body


def test_status_adds_account_counts_only_with_accounts(overview_client):
    assert "accounts" in overview_client("counter").json()
    assert "accounts" not in overview_client("tuner").json()


def test_status_adds_security_flags_only_with_settings(overview_client):
    assert "security" in overview_client("tuner").json()
    assert "security" not in overview_client("counter").json()


# ── Secrets must not come back out ─────────────────────────────────
# The bind password and the client secret go in over HTTP and are stored encrypted.
# They must not reappear anywhere: not in the answer that confirms the save, not in a
# later read, not in a validation error, and not in the error log the settings area
# can read.
_BIND_PW = "ldap-bind-pw-7f3a"
_CLIENT_SECRET = "oidc-client-secret-91bd"


@pytest.fixture
def identity_admin(tmp_path, monkeypatch):
    from backend import ldap_config, oidc_config
    from backend.auth import store as store_module
    from backend.auth.models import PERM_LDAP, PERM_SETTINGS
    from backend.auth.store import AdminStore
    from fastapi.testclient import TestClient

    monkeypatch.setattr(settings, "admin_store_path", str(tmp_path / "admins.json"))
    monkeypatch.setattr(settings, "audit_enabled", False)
    monkeypatch.setattr(ldap_config, "_PATH", tmp_path / "ldap_config.json")
    monkeypatch.setattr(oidc_config, "_PATH", tmp_path / "oidc_config.json")
    monkeypatch.setattr(store_module, "_store", AdminStore())
    store = store_module.get_admin_store()
    store.create("ida", "password1")
    store.create_group("Identity", {PERM_LDAP, PERM_SETTINGS},
                       members=[{"type": "local", "ref": "ida"}])

    from backend.main import app

    client = TestClient(app)
    assert client.post("/api/auth/login", json={"username": "ida", "password": "password1"}).status_code == 200
    return client


def test_bind_password_never_comes_back(identity_admin):
    saved = identity_admin.put(
        "/api/admin/ldap",
        json={"ldap_server": "dc.example.com", "ldap_domain": "example.com",
              "ldap_base_dn": "DC=example,DC=com", "ldap_bind_user": "svc@example.com",
              "ldap_bind_password": _BIND_PW},
    )
    assert saved.status_code == 200
    assert _BIND_PW not in saved.text
    assert saved.json()["ldap_bind_password_set"] is True
    assert _BIND_PW not in identity_admin.get("/api/admin/ldap").text


def test_client_secret_never_comes_back(identity_admin):
    saved = identity_admin.put(
        "/api/admin/oidc",
        json={"oidc_issuer": "https://idp.example/v2.0", "oidc_client_id": "cid",
              "oidc_client_secret": _CLIENT_SECRET},
    )
    assert saved.status_code == 200
    assert _CLIENT_SECRET not in saved.text
    assert saved.json()["oidc_client_secret_set"] is True
    assert _CLIENT_SECRET not in identity_admin.get("/api/admin/oidc").text


def test_a_rejected_ldap_body_does_not_echo_the_password(identity_admin):
    rejected = identity_admin.put(
        "/api/admin/ldap",
        json={"ldap_port": "not-a-number", "ldap_bind_password": _BIND_PW},
    )
    assert rejected.status_code >= 400
    assert _BIND_PW not in rejected.text


def test_a_rejected_oidc_body_does_not_echo_the_secret(identity_admin):
    rejected = identity_admin.put(
        "/api/admin/oidc",
        json={"oidc_enabled": "maybe", "oidc_client_secret": _CLIENT_SECRET},
    )
    assert rejected.status_code >= 400
    assert _CLIENT_SECRET not in rejected.text


def test_secrets_stay_out_of_the_error_log(identity_admin):
    identity_admin.put("/api/admin/ldap", json={"ldap_bind_password": _BIND_PW})
    identity_admin.put("/api/admin/oidc", json={"oidc_client_secret": _CLIENT_SECRET})
    logs = identity_admin.get("/api/admin/logs?limit=300&level=debug")
    assert logs.status_code == 200
    assert _BIND_PW not in logs.text and _CLIENT_SECRET not in logs.text


def test_connection_test_does_not_report_the_password(identity_admin, monkeypatch):
    """The LDAP test reports why it failed, and that text goes straight to the UI."""
    monkeypatch.setattr(settings, "ldap_server", "198.51.100.254")
    monkeypatch.setattr(settings, "ldap_domain", "example.com")
    monkeypatch.setattr(settings, "ldap_base_dn", "DC=example,DC=com")
    monkeypatch.setattr(settings, "ldap_bind_user", "svc@example.com")
    monkeypatch.setattr(settings, "ldap_bind_password", _BIND_PW)
    monkeypatch.setattr(settings, "ldap_connect_timeout_seconds", 1)

    import ldap3
    from ldap3.core.exceptions import LDAPBindError

    def boom(*a, **k):
        raise LDAPBindError("automatic bind not successful - invalidCredentials")

    monkeypatch.setattr(ldap3, "Connection", boom)
    resp = identity_admin.post("/api/admin/ldap/test")
    assert resp.status_code == 200 and resp.json()["ok"] is False
    assert _BIND_PW not in resp.text
