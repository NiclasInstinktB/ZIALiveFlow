"""Auth and account management endpoints (local + AD accounts, granular permissions)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from backend import audit
from backend import __version__ as APP_VERSION
from backend.auth.deps import get_current_user, principal_from_cookie, require_permission, set_session_cookie
from backend.auth.ldap_client import authenticate as ldap_authenticate, search_directory
from backend.auth.models import (
    PERM_ACCOUNTS,
    PERMISSION_LABELS,
    PERMISSIONS,
    Principal,
    normalize_member_type,
    normalize_permissions,
    normalize_source,
)
from backend.auth.store import get_admin_store
from backend.auth.throttle import get_throttle
from backend.auth.tokens import create_session_token
from backend.config import settings
from backend.logging_config import get_logger

router = APIRouter(prefix="/api", tags=["auth"])
log = get_logger("api.auth")


# ── Schemas ────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class MeResponse(BaseModel):
    username: str
    display_name: str
    is_admin: bool
    # "local" (local account) | "ad" (via AD/LDAP); controls the password change, among
    # other things.
    source: str
    # The user's effective permissions plus the catalog (key + label) for the UI checkboxes.
    permissions: list[str]
    permission_catalog: list[dict]
    idle_timeout_minutes: int
    session_ttl_minutes: int
    retention_minutes: int
    version: str
    # Per-deployment defaults for the UI (admin backend, settings).
    # Display name of the application (header, browser title).
    app_name: str
    # Default language for visitors who have not chosen one.
    default_language: str
    # Source code link (AGPL section 13), visible in the UI.
    source_url: str
    # Appended to a user filter that contains no "@".
    user_domain_suffix: str


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8)


# Accounts no longer carry permissions of their own: permissions come only via groups.
class CreateAccountRequest(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=8)
    display_name: str = ""


class UpdateAccountRequest(BaseModel):
    password: str | None = Field(default=None, min_length=8)
    display_name: str | None = None
    enabled: bool | None = None


class CreateGroupRequest(BaseModel):
    name: str = Field(..., min_length=1)
    permissions: list[str] = Field(default_factory=list)
    # Full access as a flag rather than a list: it picks up future permissions automatically.
    all_permissions: bool = False


class UpdateGroupRequest(BaseModel):
    # All fields optional: only what is sent gets changed (``name`` renames the group).
    name: str | None = Field(default=None, min_length=1)
    permissions: list[str] | None = None
    all_permissions: bool | None = None


class MemberRequest(BaseModel):
    # Member type: "local" | "ad_user" | "ad_group"; ref is the username or the CN.
    type: str = Field(..., min_length=1)
    ref: str = Field(..., min_length=1)


def _catalog() -> list[dict]:
    return [{"key": p, "label": PERMISSION_LABELS[p]} for p in PERMISSIONS]


def _ensure_grantable(granter: Principal, granted: frozenset[str]) -> None:
    """An account manager may only grant permissions they hold themselves.

    This prevents permission escalation: without the check, an account holding ONLY the
    'accounts' permission could assign itself (or a new account) any permission it liked,
    including 'update' and 'ldap', defeating the granular separation of duties. A full
    admin (who holds every permission) is not restricted by this.
    """
    excess = granted - granter.permissions
    if excess:
        labels = ", ".join(PERMISSION_LABELS.get(p, p) for p in sorted(excess))
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"You can only grant permissions that you hold yourself. Not allowed: {labels}.",
        )


def _ensure_may_grant_all(granter: Principal) -> None:
    """Only someone who holds every permission may grant full access.

    Otherwise the flag would be the most convenient permission escalation there is: an
    account with nothing but ``accounts`` could build itself a group with "all
    permissions".
    """
    if not granter.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Full access can only be granted by someone who holds every permission.",
        )


def _me(principal: Principal) -> MeResponse:
    return MeResponse(
        username=principal.username,
        display_name=principal.display_name,
        is_admin=principal.is_admin,
        source=principal.source,
        permissions=sorted(principal.permissions),
        permission_catalog=_catalog(),
        idle_timeout_minutes=settings.session_idle_minutes,
        session_ttl_minutes=settings.session_ttl_minutes,
        retention_minutes=settings.retention_minutes,
        version=APP_VERSION,
        app_name=settings.app_name.strip(),
        default_language=settings.default_language.strip().lower(),
        source_url=settings.source_url.strip(),
        user_domain_suffix=settings.user_domain_suffix.strip(),
    )


# ── Login / session ────────────────────────────────────────────────
@router.post("/auth/login", response_model=MeResponse)
async def login(body: LoginRequest, request: Request, response: Response) -> MeResponse:
    ip = audit.client_ip(request.headers, request.client.host if request.client else "")

    # Brute-force brake: block briefly after too many failed attempts (IP + user).
    throttle = get_throttle()
    tkey = throttle.key(ip, body.username)
    wait = throttle.retry_after(tkey)
    if wait > 0:
        log.warning("api.auth.login_throttled", username=body.username, ip=ip, retry_after=wait)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Please wait a moment and try again.",
            headers={"Retry-After": str(wait)},
        )

    store = get_admin_store()

    # 1) Local accounts first: they always work (break glass, even if AD is down).
    account = store.verify_login(body.username, body.password)
    principal: Principal | None = None
    via = "local"
    if account:
        principal = Principal(
            username=account["username"],
            display_name=account["display_name"],
            permissions=frozenset(account["permissions"]),
            source=normalize_source(account.get("source")),
        )

    # 2) AD/LDAP login, if configured and there was no local match. AD users get NO
    #    account: their permissions are computed here from the AD groups and travel
    #    signed inside the session (see auth/tokens.py).
    if not principal and settings.ldap_configured:
        lres = ldap_authenticate(body.username, body.password)
        if lres.ok:
            # Name collision with a local account: an AD login must NEVER pass as a
            # local account (that would inherit its permissions and bypass break glass).
            if store.account_exists(lres.username):
                throttle.record_failure(tkey)
                log.warning("api.auth.ldap_local_collision", username=lres.username)
                audit.record(audit.LOGIN_FAIL, user=lres.username, ip=ip, detail="ldap:local_collision")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Sign-in not possible: this username is reserved for a local account.",
                )
            perms = store.effective_for_ad(lres.username, lres.groups)
            if not perms:
                throttle.record_failure(tkey)
                log.info("api.auth.ldap_no_permissions", username=lres.username)
                audit.record(audit.LOGIN_FAIL, user=lres.username, ip=ip, detail="ldap:no_permissions")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="No access: you are not assigned to any authorized group, either directly or through your AD groups.",
                )
            identity = store.record_ad_login(lres.username, lres.display_name)
            principal = Principal(
                username=identity["username"],
                display_name=identity["display_name"],
                permissions=perms,
                source="ad",
            )
            via = "ad"

    if not principal:
        throttle.record_failure(tkey)
        log.info("api.auth.login_failed", username=body.username)
        audit.record(audit.LOGIN_FAIL, user=body.username, ip=ip)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sign-in failed.")

    throttle.reset(tkey)  # success clears the counter right away ("off once logged in")
    token = create_session_token(
        principal.username, principal.display_name, principal.source, principal.permissions
    )
    set_session_cookie(response, token)
    if principal.source != "ad":
        store.touch_login(principal.username)
    log.info("api.auth.login_ok", username=principal.username, via=via, perms=len(principal.permissions))
    audit.record(audit.LOGIN_OK, user=principal.username, ip=ip, detail=f"perms={len(principal.permissions)} via={via}")
    return _me(principal)


@router.post("/auth/logout")
async def logout(request: Request, response: Response) -> dict:
    principal = principal_from_cookie(request.cookies.get(settings.session_cookie_name))
    if principal:
        ip = audit.client_ip(request.headers, request.client.host if request.client else "")
        audit.record(audit.LOGOUT, user=principal.username, ip=ip)
    response.delete_cookie(settings.session_cookie_name, path="/")
    return {"status": "ok"}


@router.get("/auth/me", response_model=MeResponse)
async def me(principal: Principal = Depends(get_current_user)) -> MeResponse:
    return _me(principal)


@router.post("/auth/change-password")
async def change_password(
    body: ChangePasswordRequest, principal: Principal = Depends(get_current_user)
) -> dict:
    # AD accounts have no local password; it is changed in Active Directory.
    if principal.is_ad:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="AD accounts change their password in Active Directory, not here.",
        )
    store = get_admin_store()
    if not store.verify_login(principal.username, body.current_password):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="The current password is incorrect.")
    store.update(principal.username, password=body.new_password)
    log.info("api.auth.password_changed", username=principal.username)
    return {"status": "ok"}


# ── Account management (only with the "accounts" permission) ───────
@router.get("/admins")
async def list_accounts(_: Principal = Depends(require_permission(PERM_ACCOUNTS))) -> list[dict]:
    return get_admin_store().list()


@router.post("/admins")
async def create_account(
    body: CreateAccountRequest, _: Principal = Depends(require_permission(PERM_ACCOUNTS))
) -> dict:
    # A local account with no permissions of its own: it gets them via group membership.
    try:
        return get_admin_store().create(body.username, body.password, body.display_name)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.put("/admins/{username}")
async def update_account(
    username: str, body: UpdateAccountRequest, _: Principal = Depends(require_permission(PERM_ACCOUNTS))
) -> dict:
    try:
        return get_admin_store().update(
            username,
            password=body.password,
            display_name=body.display_name,
            enabled=body.enabled,
        )
    except KeyError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.delete("/admins/{username}")
async def delete_account(username: str, principal: Principal = Depends(require_permission(PERM_ACCOUNTS))) -> dict:
    if username.lower() == principal.username.lower():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You cannot delete your own account.")
    try:
        get_admin_store().delete(username)
        return {"status": "ok"}
    except KeyError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


# ── AD identities (informational, NOT accounts) ────────────────────
# AD users are never created as accounts: they are authorized once through a group, and
# at login the AD groups decide. All that is listed here is who has already signed in
# (UUID, display name, last sign-in). Entries can be deleted; they come back at the
# next login.
@router.get("/admins/identities")
async def list_identities(_: Principal = Depends(require_permission(PERM_ACCOUNTS))) -> list[dict]:
    return get_admin_store().list_ad_identities()


@router.delete("/admins/identities/{username}")
async def forget_identity(username: str, _: Principal = Depends(require_permission(PERM_ACCOUNTS))) -> dict:
    try:
        get_admin_store().forget_ad_identity(username)
        return {"status": "ok"}
    except KeyError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Entry not found.")


# ── Groups (permissions + members; "accounts" permission) ──────────
# A group carries permissions and a member list (local accounts, AD users, AD groups).
# The escalation brake (``_ensure_grantable``) means you may only give a group
# permissions you hold yourself, and may only add members to a group whose permissions
# you hold yourself (otherwise you could promote yourself or others through the
# membership).
def _group_or_404(name: str) -> dict:
    for g in get_admin_store().list_groups():
        if g["name"].lower() == name.lower():
            return g
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found.")


@router.get("/admins/groups")
async def list_groups(_: Principal = Depends(require_permission(PERM_ACCOUNTS))) -> list[dict]:
    return get_admin_store().list_groups()


@router.post("/admins/groups")
async def create_group(
    body: CreateGroupRequest, principal: Principal = Depends(require_permission(PERM_ACCOUNTS))
) -> dict:
    perms = normalize_permissions(body.permissions)
    _ensure_grantable(principal, perms)
    if body.all_permissions:
        _ensure_may_grant_all(principal)
    try:
        return get_admin_store().create_group(body.name, perms, all_permissions=body.all_permissions)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.put("/admins/groups/{name}")
async def update_group(
    name: str, body: UpdateGroupRequest, principal: Principal = Depends(require_permission(PERM_ACCOUNTS))
) -> dict:
    store = get_admin_store()
    out = _group_or_404(name)
    try:
        if body.all_permissions:
            _ensure_may_grant_all(principal)
        if body.permissions is not None or body.all_permissions is not None:
            perms = None
            if body.permissions is not None:
                perms = normalize_permissions(body.permissions)
                _ensure_grantable(principal, perms)
            # ``permissions=None`` leaves the stored list as it is. That matters when
            # the flag is switched off: otherwise the resolved full list would be frozen
            # in and the group would stay a full admin in practice.
            out = store.set_group_permissions(name, perms, all_permissions=body.all_permissions)
        if body.name is not None:
            # Renaming changes no permissions, only who may manage the group (PERM_ACCOUNTS).
            out = store.rename_group(name, body.name)
        return out
    except KeyError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found.")
    except ValueError as e:  # LastAdminError / name conflict
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.delete("/admins/groups/{name}")
async def delete_group(name: str, _: Principal = Depends(require_permission(PERM_ACCOUNTS))) -> dict:
    try:
        get_admin_store().delete_group(name)
        return {"status": "ok"}
    except KeyError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found.")
    except ValueError as e:  # LastAdminError
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/admins/groups/{name}/members")
async def add_group_member(
    name: str, body: MemberRequest, principal: Principal = Depends(require_permission(PERM_ACCOUNTS))
) -> dict:
    if not normalize_member_type(body.type):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid member type.")
    group = _group_or_404(name)
    # Adding a member grants that person this group's permissions, so the escalation
    # brake applies.
    _ensure_grantable(principal, normalize_permissions(group["permissions"]))
    try:
        return get_admin_store().add_member(name, body.type, body.ref)
    except KeyError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found.")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.delete("/admins/groups/{name}/members")
async def remove_group_member(
    name: str, type: str, ref: str, _: Principal = Depends(require_permission(PERM_ACCOUNTS))
) -> dict:
    try:
        return get_admin_store().remove_member(name, type, ref)
    except KeyError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found.")
    except ValueError as e:  # LastAdminError
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/admins/directory")
async def directory_search(
    q: str, kind: str = "user", limit: int = 200, _: Principal = Depends(require_permission(PERM_ACCOUNTS))
) -> dict:
    """AD/Global Catalog search for the member picker (users or groups). ``q`` may
    contain wildcards (``*Connect*``); without ``*`` it is matched as a substring.

    Response: ``{status, detail, entries}``, where ``status`` says unambiguously why
    nothing came back (``no_service_account``/``bind_failed``/``search_failed``/``ok``
    with 0 hits)."""
    return search_directory(q, kind, limit)
