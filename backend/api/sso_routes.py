"""SSO / OpenID Connect (Entra ID): an additional login path next to password/AD login.

The flow (authorization code flow + PKCE):
  1. ``GET /api/auth/sso/login``    redirects to the IdP (Entra); state, nonce and the
                                       PKCE verifier live in a short-lived, signed flow
                                       cookie.
  2. ``GET /api/auth/sso/callback`` exchanges the code for tokens, checks the ID token
                                       strictly (signature via JWKS, iss/aud/exp/nonce),
                                       reads the identity, loads the GROUPS live from the
                                       AD/Global Catalog and, exactly as for the AD
                                       password login, maps them to permissions through
                                       the group-to-permissions mapping (account store),
                                       mirrors the user just in time as an account
                                       (source "ad") and sets the same session cookie.

Deliberately WITHOUT authlib: httpx (discovery/token) plus PyJWT/PyJWKClient (RS256
validation). ``httpx`` is imported lazily and ONLY here, so the app still runs without
that package as long as SSO is not enabled. The routes are synchronous (``def``), so
FastAPI runs them in the threadpool and the blocking HTTP, crypto and LDAP calls do not
hold up the event loop. As with the AD login, nothing extra about the user is stored: the
groups apply at runtime only, and the store holds just the account plus its effective
permissions.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import time
import urllib.parse

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import RedirectResponse

from backend import audit
from backend.auth.ldap_client import lookup_groups
from backend.auth.store import get_admin_store
from backend.auth.tokens import create_session_token
from backend.config import settings
from backend.logging_config import get_logger

router = APIRouter(prefix="/api/auth/sso", tags=["auth"])
log = get_logger("api.sso")

# Short-lived cookie that carries state, nonce and the PKCE verifier across the redirect.
# Signed with the JWT secret, so no server state is needed (which fits the stateless
# session architecture). The name is derived from the configured session cookie so that
# both cookies of one instance share the same prefix; otherwise two names would have to
# be maintained separately.
_FLOW_TTL_SECONDS = 600
_FLOW_PATH = "/api/auth/sso"
# Where to return to after a successful login (the SPA root).
_POST_LOGIN_PATH = "/"


def _flow_cookie() -> str:
    return f"{settings.session_cookie_name}_sso_flow"


# Cache the discovery document (authorization_endpoint/token_endpoint/jwks_uri) per issuer.
_DISCOVERY_TTL_SECONDS = 3600
_discovery_cache: dict[str, dict] = {}
# Reuse one PyJWKClient per jwks_uri (it keeps an internal key cache).
_jwks_clients: dict = {}


def _require_configured() -> None:
    if not settings.oidc_configured:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SSO is not enabled.")


def _discovery() -> dict:
    """Load the issuer's OIDC discovery document (cached)."""
    import httpx

    issuer = settings.oidc_issuer.strip().rstrip("/")
    cached = _discovery_cache.get(issuer)
    now = time.time()
    if cached and now - cached["at"] < _DISCOVERY_TTL_SECONDS:
        return cached["doc"]
    url = f"{issuer}/.well-known/openid-configuration"
    with httpx.Client(timeout=10.0) as client:
        resp = client.get(url)
        resp.raise_for_status()
        doc = resp.json()
    _discovery_cache[issuer] = {"doc": doc, "at": now}
    return doc


def _redirect_uri(request: Request) -> str:
    """Redirect URI: either set explicitly (recommended behind a reverse proxy) or derived."""
    configured = settings.oidc_redirect_url.strip()
    if configured:
        return configured
    base = str(request.base_url).rstrip("/")
    return f"{base}/api/auth/sso/callback"


def _pkce_pair() -> tuple[str, str]:
    """(code_verifier, code_challenge) for PKCE (S256)."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _sign_flow(data: dict) -> str:
    import jwt

    payload = {**data, "exp": int(time.time()) + _FLOW_TTL_SECONDS}
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def _read_flow(token: str) -> dict | None:
    import jwt

    if not token:
        return None
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None


def _exchange_code(doc: dict, code: str, verifier: str, redirect_uri: str) -> dict:
    """Exchange the authorization code for tokens (token endpoint)."""
    import httpx

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": settings.oidc_client_id,
        "client_secret": settings.oidc_client_secret,
        "code_verifier": verifier,
    }
    with httpx.Client(timeout=10.0) as client:
        resp = client.post(doc["token_endpoint"], data=data)
        resp.raise_for_status()
        return resp.json()


def _validate_id_token(doc: dict, id_token: str, nonce: str) -> dict:
    """Check the ID token strictly: signature (JWKS), issuer, audience, expiry, nonce."""
    import jwt
    from jwt import PyJWKClient

    jwks_uri = doc["jwks_uri"]
    client = _jwks_clients.get(jwks_uri)
    if client is None:
        client = PyJWKClient(jwks_uri)
        _jwks_clients[jwks_uri] = client
    signing_key = client.get_signing_key_from_jwt(id_token).key
    claims = jwt.decode(
        id_token,
        signing_key,
        algorithms=["RS256"],
        audience=settings.oidc_client_id,
        issuer=doc.get("issuer") or settings.oidc_issuer.strip().rstrip("/"),
    )
    if nonce and claims.get("nonce") != nonce:
        raise ValueError("nonce mismatch")
    return claims


def _fail(reason: str) -> RedirectResponse:
    """Back to the login page with a machine-readable error reason (the UI shows a notice)."""
    return RedirectResponse(url=f"/?sso_error={reason}", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/login")
def sso_login(request: Request):
    """Starts the OIDC flow: redirect to the IdP (Entra) with state, nonce and PKCE."""
    _require_configured()
    try:
        doc = _discovery()
    except Exception as exc:  # noqa: BLE001 report discovery errors cleanly to the UI
        log.warning("sso.discovery_failed", error=str(exc))
        return _fail("discovery")

    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    verifier, challenge = _pkce_pair()
    redirect_uri = _redirect_uri(request)

    params = {
        "client_id": settings.oidc_client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": settings.oidc_scopes.strip() or "openid profile email",
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "response_mode": "query",
    }
    auth_url = doc["authorization_endpoint"] + "?" + urllib.parse.urlencode(params)
    resp = RedirectResponse(url=auth_url, status_code=status.HTTP_303_SEE_OTHER)
    resp.set_cookie(
        _flow_cookie(),
        _sign_flow({"state": state, "nonce": nonce, "cv": verifier, "ru": redirect_uri}),
        max_age=_FLOW_TTL_SECONDS,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite=settings.session_cookie_samesite,
        path=_FLOW_PATH,
    )
    return resp


@router.get("/callback")
def sso_callback(request: Request):
    """OIDC return channel: fetch tokens, verify the ID token, set the session as on login."""
    _require_configured()
    ip = audit.client_ip(request.headers, request.client.host if request.client else "")

    if request.query_params.get("error"):
        log.info(
            "sso.idp_error",
            error=request.query_params.get("error"),
            desc=request.query_params.get("error_description"),
        )
        return _fail("idp")

    code = request.query_params.get("code")
    state = request.query_params.get("state")
    flow = _read_flow(request.cookies.get(_flow_cookie(), ""))
    if not code or not state or not flow or state != flow.get("state"):
        log.warning("sso.state_mismatch")
        return _fail("state")

    try:
        doc = _discovery()
        tokens = _exchange_code(doc, code, flow["cv"], flow["ru"])
        id_token = tokens.get("id_token")
        if not id_token:
            raise ValueError("no id_token in token response")
        claims = _validate_id_token(doc, id_token, flow.get("nonce", ""))
    except Exception as exc:  # noqa: BLE001 any error leads back cleanly to the UI
        log.warning("sso.callback_failed", error=str(exc))
        return _fail("exchange")

    # Identity from the claims (UPN/email). Normalized to sAMAccountName for matching,
    # exactly as for the AD password login.
    upn = str(
        claims.get("preferred_username") or claims.get("upn") or claims.get("email") or ""
    ).strip()
    if not upn:
        log.warning("sso.no_identity", claim_keys=sorted(claims.keys()))
        return _fail("identity")
    username = upn.split("@")[0].split("\\")[-1]
    claim_name = str(claims.get("name") or username)

    # Load the groups LIVE from the AD/Global Catalog (service account, nothing is
    # stored) and map them to permissions as for the password login.
    groups, ad_display, _ad_mail = lookup_groups(upn)
    display_name = ad_display or claim_name

    store = get_admin_store()
    perms = store.effective_for_ad(username, groups)
    if not perms:
        log.info("sso.no_permissions", username=username, group_count=len(groups))
        audit.record(audit.LOGIN_FAIL, user=username, ip=ip, detail="sso:no_permissions")
        return _fail("noperms")

    # No account, and the same rules as for the AD password login: on a name collision
    # with a local (break-glass) account the SSO login is rejected; otherwise only the
    # identity is recorded.
    if store.account_exists(username):
        log.warning("sso.local_collision", username=username)
        audit.record(audit.LOGIN_FAIL, user=username, ip=ip, detail="sso:local_collision")
        return _fail("collision")
    identity = store.record_ad_login(username, display_name)

    token = create_session_token(identity["username"], identity["display_name"], "ad", perms)
    resp = RedirectResponse(url=_POST_LOGIN_PATH, status_code=status.HTTP_303_SEE_OTHER)
    resp.set_cookie(
        key=settings.session_cookie_name,
        value=token,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite=settings.session_cookie_samesite,
        max_age=settings.session_ttl_minutes * 60,
        path="/",
    )
    resp.delete_cookie(_flow_cookie(), path=_FLOW_PATH)
    log.info("sso.login_ok", username=identity["username"], group_count=len(groups), perms=len(perms))
    audit.record(audit.LOGIN_OK, user=identity["username"], ip=ip, detail=f"perms={len(perms)} via=sso")
    return resp
