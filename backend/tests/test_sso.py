"""SSO / OIDC: feature flag, endpoint protection, PKCE and flow cookie, group lookup, and
the mocked happy path (no real IdP).

Aligned with the admin UI model: the SSO callback carries NO groups or permissions in the
token. Instead it maps the AD groups reloaded live onto permissions through the account
store group-to-permission mapping, and mirrors the user just in time as an AD account
(like the AD password login). Without a matching group there is no access
(``sso_error=noperms``)."""
from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from backend.auth import store as store_module
from backend.auth.store import AdminStore, get_admin_store
from backend.config import settings


def _configure(monkeypatch) -> None:
    """Configure OIDC completely (for this test only)."""
    monkeypatch.setattr(settings, "oidc_enabled", True)
    monkeypatch.setattr(settings, "oidc_issuer", "https://login.microsoftonline.com/tid/v2.0")
    monkeypatch.setattr(settings, "oidc_client_id", "client-123")
    monkeypatch.setattr(settings, "oidc_client_secret", "top-secret")


_FAKE_DISCOVERY = {
    "authorization_endpoint": "https://idp.example/authorize",
    "token_endpoint": "https://idp.example/token",
    "jwks_uri": "https://idp.example/jwks",
    "issuer": "https://login.microsoftonline.com/tid/v2.0",
}


@pytest.fixture
def client(tmp_path, monkeypatch):
    """TestClient with an isolated account store. NO lifespan context (no ingest, no seed)."""
    monkeypatch.setattr(settings, "admin_store_path", str(tmp_path / "admins.json"))
    monkeypatch.setattr(settings, "audit_enabled", False)  # no audit files during the test
    monkeypatch.setattr(store_module, "_store", AdminStore())

    from backend.main import app

    return TestClient(app)


# ── Feature flag and protection ────────────────────────────────────
def test_health_exposes_sso_flag_off_by_default(client):
    assert client.get("/api/health").json()["sso_enabled"] is False


def test_sso_endpoints_404_when_disabled(client):
    assert client.get("/api/auth/sso/login", follow_redirects=False).status_code == 404
    assert (
        client.get("/api/auth/sso/callback?code=x&state=y", follow_redirects=False).status_code == 404
    )


def test_health_sso_flag_on_when_configured(client, monkeypatch):
    _configure(monkeypatch)
    assert client.get("/api/health").json()["sso_enabled"] is True


# ── PKCE and the signed flow cookie ────────────────────────────────
def test_pkce_and_flow_cookie_roundtrip():
    from backend.api import sso_routes

    verifier, challenge = sso_routes._pkce_pair()
    assert verifier and challenge
    assert "=" not in challenge  # base64url without padding

    token = sso_routes._sign_flow({"state": "s1", "nonce": "n1", "cv": verifier, "ru": "http://x/cb"})
    data = sso_routes._read_flow(token)
    assert data is not None
    assert data["state"] == "s1" and data["nonce"] == "n1" and data["cv"] == verifier
    # A tampered or empty cookie gives None, without crashing.
    assert sso_routes._read_flow("not-a-jwt") is None
    assert sso_routes._read_flow("") is None


# ── Login redirect ─────────────────────────────────────────────────
def test_sso_login_redirects_to_idp(client, monkeypatch):
    from backend.api import sso_routes

    _configure(monkeypatch)
    monkeypatch.setattr(sso_routes, "_discovery", lambda: _FAKE_DISCOVERY)

    r = client.get("/api/auth/sso/login", follow_redirects=False)
    assert r.status_code == 303
    loc = r.headers["location"]
    assert loc.startswith("https://idp.example/authorize?")
    q = parse_qs(urlparse(loc).query)
    assert q["client_id"] == ["client-123"]
    assert q["response_type"] == ["code"]
    assert q["code_challenge_method"] == ["S256"]
    assert q["code_challenge"] and q["state"] and q["nonce"]
    # The flow cookie hangs off the configured session cookie name.
    assert f"{settings.session_cookie_name}_sso_flow=" in r.headers.get("set-cookie", "")


def test_sso_login_discovery_failure_redirects_with_error(client, monkeypatch):
    from backend.api import sso_routes

    _configure(monkeypatch)

    def _boom():
        raise RuntimeError("issuer unreachable")

    monkeypatch.setattr(sso_routes, "_discovery", _boom)
    r = client.get("/api/auth/sso/login", follow_redirects=False)
    assert r.status_code == 303
    assert "/?sso_error=discovery" in r.headers["location"]


# ── Callback ───────────────────────────────────────────────────────
def test_sso_callback_state_mismatch(client, monkeypatch):
    _configure(monkeypatch)
    # No flow cookie, so the state cannot match.
    r = client.get("/api/auth/sso/callback?code=abc&state=nope", follow_redirects=False)
    assert r.status_code == 303
    assert "/?sso_error=state" in r.headers["location"]


def _prime_login(client, monkeypatch) -> str:
    """Call /login so a valid flow cookie lands in the jar, and return the state."""
    from backend.api import sso_routes

    monkeypatch.setattr(sso_routes, "_discovery", lambda: _FAKE_DISCOVERY)
    r1 = client.get("/api/auth/sso/login", follow_redirects=False)
    return parse_qs(urlparse(r1.headers["location"]).query)["state"][0]


def test_sso_callback_happy_path_provisions_and_sets_session(client, monkeypatch):
    from backend.api import sso_routes

    _configure(monkeypatch)
    # A group with the AD group "ZS-Admins" as a member, so its permissions apply to the user.
    get_admin_store().create_group(
        "ZS-Admins", {"logs", "overview"}, members=[{"type": "ad_group", "ref": "ZS-Admins"}]
    )
    state = _prime_login(client, monkeypatch)

    monkeypatch.setattr(sso_routes, "_exchange_code", lambda *a, **k: {"id_token": "dummy"})
    monkeypatch.setattr(
        sso_routes,
        "_validate_id_token",
        lambda *a, **k: {"preferred_username": "max@corp.com", "name": "Max Example"},
    )
    monkeypatch.setattr(
        sso_routes, "lookup_groups", lambda upn: (frozenset({"ZS-Admins"}), "Max Example", "max@corp.com")
    )

    r = client.get(f"/api/auth/sso/callback?code=abc&state={state}", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/"
    assert f"{settings.session_cookie_name}=" in r.headers.get("set-cookie", "")

    # The session is valid: /me knows the AD user (normalized to sAMAccountName) and permissions.
    me = client.get("/api/auth/me")
    assert me.status_code == 200
    body = me.json()
    assert body["username"] == "max"
    assert body["display_name"] == "Max Example"
    assert body["source"] == "ad"
    assert set(body["permissions"]) == {"logs", "overview"}

    # And: NO account was created, only an identity entry (UUID) for the account list.
    store = get_admin_store()
    assert store.list() == []
    ident = store.list_ad_identities()
    assert len(ident) == 1 and ident[0]["username"] == "max" and len(ident[0]["id"]) == 36


def test_sso_callback_no_matching_group_is_denied(client, monkeypatch):
    from backend.api import sso_routes

    _configure(monkeypatch)
    # NO matching group in the store, so no permissions, so access is denied.
    state = _prime_login(client, monkeypatch)
    monkeypatch.setattr(sso_routes, "_exchange_code", lambda *a, **k: {"id_token": "dummy"})
    monkeypatch.setattr(
        sso_routes, "_validate_id_token", lambda *a, **k: {"preferred_username": "max@corp.com"}
    )
    monkeypatch.setattr(
        sso_routes, "lookup_groups", lambda upn: (frozenset({"Unmapped"}), "Max", "max@corp.com")
    )

    r = client.get(f"/api/auth/sso/callback?code=abc&state={state}", follow_redirects=False)
    assert r.status_code == 303
    assert "/?sso_error=noperms" in r.headers["location"]
    # NO account was created.
    assert get_admin_store().get_active("max") is None


def test_sso_callback_local_collision_is_denied(client, monkeypatch):
    from backend.api import sso_routes

    _configure(monkeypatch)
    # A local (break-glass) account of the same name exists, so SSO must not go through.
    store = get_admin_store()
    store.create("max", "password1")
    store.create_group("ZS-Admins", {"logs", "overview"}, members=[{"type": "ad_group", "ref": "ZS-Admins"}])
    state = _prime_login(client, monkeypatch)
    monkeypatch.setattr(sso_routes, "_exchange_code", lambda *a, **k: {"id_token": "dummy"})
    monkeypatch.setattr(
        sso_routes, "_validate_id_token", lambda *a, **k: {"preferred_username": "max@corp.com"}
    )
    monkeypatch.setattr(
        sso_routes, "lookup_groups", lambda upn: (frozenset({"ZS-Admins"}), "Max", "max@corp.com")
    )

    r = client.get(f"/api/auth/sso/callback?code=abc&state={state}", follow_redirects=False)
    assert r.status_code == 303
    assert "/?sso_error=collision" in r.headers["location"]
    # The local account stays local (untouched).
    assert store.get_active("max")["source"] == "local"


def test_sso_callback_no_identity_redirects_with_error(client, monkeypatch):
    from backend.api import sso_routes

    _configure(monkeypatch)
    state = _prime_login(client, monkeypatch)
    monkeypatch.setattr(sso_routes, "_exchange_code", lambda *a, **k: {"id_token": "dummy"})
    # An ID token with no usable identity (no UPN, no e-mail).
    monkeypatch.setattr(sso_routes, "_validate_id_token", lambda *a, **k: {"sub": "abc"})

    r = client.get(f"/api/auth/sso/callback?code=abc&state={state}", follow_redirects=False)
    assert r.status_code == 303
    assert "/?sso_error=identity" in r.headers["location"]


# ── Group lookup (service account, ldap3 mocked) ───────────────────
def test_lookup_groups_via_service_account(monkeypatch):
    from backend.auth import ldap_client

    monkeypatch.setattr(settings, "ldap_bind_user", "svc@corp.local")
    monkeypatch.setattr(settings, "ldap_bind_password", "x")
    monkeypatch.setattr(settings, "ldap_base_dn", "DC=corp,DC=local")
    monkeypatch.setattr(settings, "ldap_domain", "corp.local")
    monkeypatch.setattr(settings, "ldap_group_attr", "memberOf")

    class _Attr:
        def __init__(self, values):
            self.values = values
            self.value = values[0] if values else None

    class _Entry:
        def __init__(self):
            self._d = {
                "memberOf": _Attr(["CN=Net-Admins,OU=a", "CN=ZS-Users,OU=b"]),
                "displayName": _Attr(["Max Example"]),
                "mail": _Attr(["max@corp.com"]),
            }

        def __contains__(self, k):
            return k in self._d

        def __getitem__(self, k):
            return self._d[k]

    class _Conn:
        entries = [_Entry()]

        def search(self, **kw):
            return True

        def unbind(self):
            return True

    monkeypatch.setattr(ldap_client, "build_ldap_server", lambda ldap3: object())
    import ldap3

    monkeypatch.setattr(ldap3, "Connection", lambda *a, **k: _Conn())

    groups, display, email = ldap_client.lookup_groups("max@corp.com")
    assert groups == frozenset({"Net-Admins", "ZS-Users"})
    assert display == "Max Example"
    assert email == "max@corp.com"


def test_lookup_groups_without_service_account_is_empty(monkeypatch):
    from backend.auth import ldap_client

    monkeypatch.setattr(settings, "ldap_bind_user", "")
    monkeypatch.setattr(settings, "ldap_base_dn", "")
    groups, display, email = ldap_client.lookup_groups("max@corp.com")
    assert groups == frozenset() and display == "" and email == ""
