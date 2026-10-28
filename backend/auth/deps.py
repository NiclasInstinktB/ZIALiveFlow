"""FastAPI dependencies: the current user, taken from the session cookie.

No anonymous access: without a valid session the answer is 401. Active sessions slide
along (sliding session) so that a user who is working does not get logged out mid-task.
The WebSocket uses the same cookie path (see ``principal_from_cookie``).

Three levels:
  * ``get_current_user``           → any valid session. Used for prefs.
  * ``require_permission(p)``      → only with permission ``p`` (e.g. "settings", "accounts").
  * ``require_any_permission(*p)`` → with AT LEAST one of the permissions. Used for the
    live flow, which both ``logs`` (clear text) and ``logs_obf`` (anonymized) open.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import HTTPException, Request, Response, status

from backend.auth.models import Principal
from backend.auth.store import get_admin_store
from backend.auth.tokens import create_session_token, decode_session_token
from backend.config import settings


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=settings.session_cookie_name,
        value=token,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite=settings.session_cookie_samesite,
        max_age=settings.session_ttl_minutes * 60,
        path="/",
    )


def _slide_session(payload: dict, principal: Principal, response: Response) -> None:
    """Renews the cookie once the token has passed half of its lifetime.

    The new token is issued with the principal's **current** data (name, permissions), not
    with the old token contents, so a permission change travels into the fresh token. For
    AD sessions the permissions computed at login are kept (there is no account in the store).
    """
    try:
        iat = int(payload.get("iat", 0))
        exp = int(payload.get("exp", 0))
    except (TypeError, ValueError):
        return
    lifetime = exp - iat
    if lifetime <= 0:
        return
    now = int(datetime.now(timezone.utc).timestamp())
    if (now - iat) * 2 < lifetime:
        return  # still in the first half → no refresh needed
    fresh = create_session_token(
        principal.username, principal.display_name, principal.source, principal.permissions
    )
    set_session_cookie(response, fresh)


def _validated_principal(token: str | None) -> tuple[Principal, dict] | None:
    """Decode the token and check the session.

    * **Local** session: checked against the account store. Valid only if the account
      still exists **and** is active. Permissions and display name come from the store, so
      deactivating, deleting or changing permissions hits a running session immediately.
    * **AD session**: AD users have no account (permissions come through groups, computed
      at login), so identity and permissions sit signed inside the token. Without
      permissions in the token the session is invalid. A name that meanwhile belongs to a
      local account is rejected (an AD token must never slip into a local account).

    ``None`` means there is no valid session.
    """
    if not token:
        return None
    payload = decode_session_token(token)
    if not payload:
        return None
    username = str(payload.get("sub", ""))
    store = get_admin_store()

    if str(payload.get("src", "local")) == "ad":
        perms = frozenset(str(p) for p in (payload.get("perm") or []))
        if not username or not perms or store.account_exists(username):
            return None
        principal = Principal(
            username=username,
            display_name=str(payload.get("name") or username),
            permissions=perms,
            source="ad",
        )
        return principal, payload

    account = store.get_active(username)
    if account is None:
        return None  # account deleted or deactivated → session invalid
    principal = Principal(
        username=account["username"],
        display_name=account["display_name"],
        permissions=frozenset(account.get("permissions", [])),
        source=account.get("source", "local"),
    )
    return principal, payload


def principal_from_cookie(token: str | None) -> Principal | None:
    """Validates a session cookie value (also used for the WebSocket handshake)."""
    validated = _validated_principal(token)
    return validated[0] if validated else None


def get_current_user(request: Request, response: Response) -> Principal:
    """Any valid session (admin or viewer)."""
    token = request.cookies.get(settings.session_cookie_name)
    validated = _validated_principal(token)
    if validated is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not signed in, or the session is invalid.",
        )
    principal, payload = validated
    _slide_session(payload, principal, response)
    return principal


def require_permission(permission: str):
    """Dependency factory: requires exactly ONE permission (``auth.models.PERMISSIONS``).

    Usage: ``_: Principal = Depends(require_permission("settings"))``.
    """

    def _dep(request: Request, response: Response) -> Principal:
        principal = get_current_user(request, response)
        if not principal.has(permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Missing permission for this area.",
            )
        return principal

    return _dep


def require_any_permission(*permissions: str):
    """Dependency factory: requires AT LEAST ONE of the listed permissions.

    For areas with several access levels, e.g. the live flow, which both ``logs`` (clear
    text) and ``logs_obf`` (anonymized) open. Which level applies is then decided by
    ``Principal.logs_obfuscated``.
    """
    wanted = frozenset(permissions)

    def _dep(request: Request, response: Response) -> Principal:
        principal = get_current_user(request, response)
        if not wanted & principal.permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Missing permission for this area.",
            )
        return principal

    return _dep
