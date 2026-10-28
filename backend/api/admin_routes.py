"""Admin backend: status/diagnostics plus settings that can be changed at runtime.

Every endpoint requires exactly ONE permission (``require_permission``): the overview
needs ``overview``, settings need ``settings``, AD/LDAP needs ``ldap``, audit needs
``audit``, update needs ``update``. Anyone without the respective permission gets 403.
"""
from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from backend import __version__ as APP_VERSION
from backend.auth.deps import require_permission
from backend.auth.models import (
    PERM_ACCOUNTS,
    PERM_AUDIT,
    PERM_LDAP,
    PERM_OVERVIEW,
    PERM_SETTINGS,
    PERM_UPDATE,
    Principal,
)
from backend.auth.store import get_admin_store
from backend.config import settings
from backend.ingest import tcp_server
from backend.ingest.hub import get_hub
from backend.logging_config import get_logger
from backend.runtime import STARTED_AT
from backend import audit, ldap_config, log_buffer, oidc_config, settings_store, updater

router = APIRouter(prefix="/api/admin", tags=["admin"])
log = get_logger("api.admin")


# The settings body is deliberately an open mapping rather than a field-per-setting
# model. settings_store.SPECS is the single definition of what exists and what is valid;
# a parallel pydantic model would be a second list to keep in step, and the two would
# drift. Unknown keys are ignored, known ones are validated in the store.
SettingsUpdate = dict[str, Any]


@router.get("/status")
async def status_overview(principal: Principal = Depends(require_permission(PERM_OVERVIEW))) -> dict:
    """Live status for the overview (permission 'overview'). Account counts only with
    permission 'accounts', security flags only with permission 'settings'."""
    hub = get_hub()
    listening = tcp_server.listening()
    now = time.time()
    data = {
        "version": APP_VERSION,
        "app_env": settings.app_env,
        "is_production": settings.is_production,
        "started_at": STARTED_AT,
        "uptime_seconds": int(now - STARTED_AT),
        "now": now,
        "ingest": {
            "enabled": settings.ingest_enabled,
            "bind_host": settings.ingest_bind_host,
            "web_port": settings.ingest_web_port,
            "fw_port": settings.ingest_fw_port,
            "dns_port": settings.ingest_dns_port,
            "web_listening": listening.get("web", False),
            "fw_listening": listening.get("fw", False),
            "dns_listening": listening.get("dns", False),
        },
        "throughput": hub.global_stats(),
        "feeds": hub.feed_health(),
        "retention_minutes": settings.retention_minutes,
        "buffer_max_records": settings.buffer_max_records,
        "session": {
            "idle_minutes": settings.session_idle_minutes,
            "ttl_minutes": settings.session_ttl_minutes,
            "cookie_secure": settings.session_cookie_secure,
            "cookie_samesite": settings.session_cookie_samesite,
        },
    }
    if principal.has(PERM_ACCOUNTS):
        data["accounts"] = get_admin_store().counts()
    if principal.has(PERM_SETTINGS):
        data["security"] = {"jwt_secret_is_default": settings.jwt_secret_is_default}
    return data


def _settings_envelope(editable: dict, restart_pending: list[str] | None = None) -> dict:
    """Shared response for GET and PUT: values plus the metadata the UI renders from.

    ``catalogue`` carries kind, tier, bounds, choices and hint per setting, so the admin
    form is generated from the backend definition instead of a second hand-kept list in
    the frontend that drifts out of step.
    """
    return {
        "editable": editable,
        "catalogue": settings_store.catalogue(),
        "restart_required": sorted(settings_store.RESTART_REQUIRED),
        # Union of "outstanding since this process started" and whatever this very
        # request just changed, so a reload keeps showing it.
        "restart_pending": sorted(set(settings_store.restart_pending()) | set(restart_pending or [])),
        "read_only": settings_store.read_only_view(),
    }


@router.get("/settings")
async def get_settings(_: Principal = Depends(require_permission(PERM_SETTINGS))) -> dict:
    return _settings_envelope(settings_store.current())


@router.put("/settings")
async def put_settings(body: SettingsUpdate, _: Principal = Depends(require_permission(PERM_SETTINGS))) -> dict:
    # body is a plain dict, not a pydantic model, so there is no model_dump() here.
    changes = {k: v for k, v in body.items() if v is not None}
    try:
        applied, pending = settings_store.update(changes)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    return _settings_envelope(applied, pending)


# ── AD/LDAP configuration (editable in the admin backend, .env = fallback) ──
class LdapUpdate(BaseModel):
    ldap_server: str | None = None
    ldap_port: int | None = None
    ldap_use_ssl: bool | None = None
    ldap_domain: str | None = None
    ldap_base_dn: str | None = None
    ldap_bind_user: str | None = None
    # Omit the password = unchanged, "" = clear it, anything else = set it (encrypted).
    ldap_bind_password: str | None = None
    ldap_group_attr: str | None = None
    ldap_connect_timeout_seconds: int | None = None
    # The AD group to permissions mapping is NO LONGER maintained here but in the
    # "Accounts" tab (account store), so that AD groups are managed like local accounts.


@router.get("/ldap")
async def get_ldap(_: Principal = Depends(require_permission(PERM_LDAP))) -> dict:
    """Current LDAP config (without the bind password, only ``ldap_bind_password_set``)."""
    return ldap_config.current_public()


@router.put("/ldap")
async def put_ldap(body: LdapUpdate, principal: Principal = Depends(require_permission(PERM_LDAP))) -> dict:
    # exclude_unset: change only the fields actually sent (omit the password = keep it).
    changes = body.model_dump(exclude_unset=True)
    try:
        result = ldap_config.update(changes)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    log.info("api.admin.ldap_updated", by=principal.username, configured=result["configured"])
    return result


@router.post("/ldap/test")
async def test_ldap(_: Principal = Depends(require_permission(PERM_LDAP))) -> dict:
    """Best-effort connection test against the currently stored LDAP config."""
    return ldap_config.test_connection()


# ── SSO / OpenID Connect (editable in the admin backend, .env = fallback) ──
# Part of the identity/login configuration, so it uses the same permission as AD/LDAP
# (``ldap``).
class OidcUpdate(BaseModel):
    oidc_enabled: bool | None = None
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    # Omit the secret = unchanged, "" = clear it, anything else = set it (encrypted).
    oidc_client_secret: str | None = None
    oidc_redirect_url: str | None = None
    oidc_scopes: str | None = None


@router.get("/oidc")
async def get_oidc(_: Principal = Depends(require_permission(PERM_LDAP))) -> dict:
    """Current OIDC config (without the client secret, only ``oidc_client_secret_set``)."""
    return oidc_config.current_public()


@router.put("/oidc")
async def put_oidc(body: OidcUpdate, principal: Principal = Depends(require_permission(PERM_LDAP))) -> dict:
    # exclude_unset: change only the fields actually sent (omit the secret = keep it).
    changes = body.model_dump(exclude_unset=True)
    try:
        result = oidc_config.update(changes)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    log.info("api.admin.oidc_updated", by=principal.username, configured=result["configured"])
    return result


@router.post("/oidc/test")
async def test_oidc(_: Principal = Depends(require_permission(PERM_LDAP))) -> dict:
    """Best-effort test: load the OIDC discovery document of the currently stored issuer."""
    return oidc_config.test_connection()


# ── Audit log (logins + searches, up to 30 days) ───────────────────
@router.get("/audit")
async def audit_log(
    _: Principal = Depends(require_permission(PERM_AUDIT)),
    limit: int = 500,
    event: str | None = None,
    user: str | None = None,
    days: int | None = None,
) -> dict:
    """Most recent audit entries (optionally filtered by event, user or period)."""
    audit.prune()  # clean up expired daily files while we are here
    return {
        "entries": audit.query(limit=max(1, min(2000, limit)), event=event, user=user, since_days=days),
        "stats": audit.stats(),
    }


# ── Error log (in-memory ring buffer) ──────────────────────────────
# Until now the reason for a failure only appeared in the service journal, invisible to
# anyone without server access. But the line that names the reason belongs exactly where
# the failure shows up.
@router.get("/logs")
async def recent_logs(
    _: Principal = Depends(require_permission(PERM_SETTINGS)),
    limit: int = 50,
    level: str = "warning",
) -> dict:
    """The most recent warnings and errors of the running process."""
    return {
        "entries": log_buffer.recent(limit=limit, level=level),
        "counts": log_buffer.counts(),
        "level": level,
    }


@router.delete("/logs")
async def clear_logs(principal: Principal = Depends(require_permission(PERM_SETTINGS))) -> dict:
    """Empty the buffer, handy for getting a clean slate before a test."""
    removed = log_buffer.clear()
    log.info("admin.logs_cleared", by=principal.username, removed=removed)
    return {"removed": removed}


# ── Self-update (Git) ──────────────────────────────────────────────
@router.get("/update")
async def update_status(_: Principal = Depends(require_permission(PERM_UPDATE))) -> dict:
    """Current git state (local, fast)."""
    return updater.status()


@router.post("/update/check")
async def update_check(_: Principal = Depends(require_permission(PERM_UPDATE))) -> dict:
    """Check for updates (git fetch + how many commits behind)."""
    return updater.check()


@router.post("/update/run")
async def update_run(principal: Principal = Depends(require_permission(PERM_UPDATE))) -> dict:
    """Kick off the update (triggers the systemd .path unit). The service restarts afterwards."""
    log.warning("api.admin.update_requested", by=principal.username)
    result = updater.trigger_update()
    if not result.get("triggered"):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=result.get("error", "The update could not be started."),
        )
    return result
