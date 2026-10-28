"""Runtime LDAP configuration: editable in the admin backend, persistent across restarts.

Holds the AD/LDAP **connection** only (servers including global catalog and failover,
domain, base DN, service account). The **AD group to permission mapping** no longer lives
here but in the account store (``auth/store.py``): AD groups are maintained in the
"Accounts" tab, just like local accounts. Legacy configurations are migrated once at
startup (:func:`take_legacy_group_permissions`), and default permissions are dropped
without replacement in the process.

The bind password is stored **Fernet encrypted** (``crypto``) and never returned in clear
text. ``.env`` remains the **bootstrap and fallback** for the connection fields.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from backend import crypto
from backend.auth.models import normalize_permissions
from backend.config import PROJECT_ROOT, settings
from backend.logging_config import get_logger

log = get_logger("ldap.config")

_PATH: Path = PROJECT_ROOT / "backend" / "data" / "ldap_config.json"

# Connection fields (not secret), applied one to one onto ``settings.<name>``.
_STR_FIELDS = (
    "ldap_server",
    "ldap_domain",
    "ldap_base_dn",
    "ldap_bind_user",
    "ldap_group_attr",
)
_BOOL_FIELDS = ("ldap_use_ssl",)
_INT_FIELDS: dict[str, tuple[int, int]] = {
    "ldap_port": (0, 65535),
    "ldap_connect_timeout_seconds": (1, 60),
}
_SECRET_FIELD = "ldap_bind_password"
_SECRET_STORE_KEY = "ldap_bind_password_enc"


def _clamp_int(name: str, value) -> int:
    lo, hi = _INT_FIELDS[name]
    return max(lo, min(hi, int(value)))


def _read_raw() -> dict:
    if not _PATH.exists():
        return {}
    try:
        return json.loads(_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        log.warning("ldap.config.read_failed", path=str(_PATH))
        return {}


def _save(store: dict) -> None:
    _PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = _PATH.with_suffix(_PATH.suffix + ".tmp")
    tmp.write_text(json.dumps(store, indent=2), encoding="utf-8")
    os.replace(tmp, _PATH)


def _clean_group_permissions(raw) -> list[dict]:
    """Clean a ``[{group, permissions[]}]`` list: drop empty groups, filter permissions."""
    out: list[dict] = []
    for entry in raw or []:
        if not isinstance(entry, dict):
            continue
        group = str(entry.get("group", "")).strip()
        if not group:
            continue
        out.append({"group": group, "permissions": sorted(normalize_permissions(entry.get("permissions")))})
    return out


def load_and_apply() -> None:
    """Apply the persisted connection config onto ``settings`` at startup, if there is one.

    The group mapping is NOT put onto ``settings``: it is read straight from the store
    when it is needed (at login). ``.env`` is the fallback for the connection.
    """
    data = _read_raw()
    if not data:
        return
    applied = 0
    for name in _STR_FIELDS:
        if isinstance(data.get(name), str):
            setattr(settings, name, data[name])
            applied += 1
    for name in _BOOL_FIELDS:
        if name in data:
            setattr(settings, name, bool(data[name]))
            applied += 1
    for name in _INT_FIELDS:
        if name in data:
            try:
                setattr(settings, name, _clamp_int(name, data[name]))
                applied += 1
            except (TypeError, ValueError):
                continue
    enc = data.get(_SECRET_STORE_KEY)
    if enc:
        settings.ldap_bind_password = crypto.decrypt(enc)
        applied += 1
    if applied:
        log.info("ldap.config.loaded", fields=applied, configured=settings.ldap_configured)


def current_public() -> dict:
    """The current LDAP config for the UI, WITHOUT the password (only ``ldap_bind_password_set``)."""
    return {
        "ldap_server": settings.ldap_server,
        "ldap_port": settings.ldap_port,
        "ldap_use_ssl": settings.ldap_use_ssl,
        "ldap_domain": settings.ldap_domain,
        "ldap_base_dn": settings.ldap_base_dn,
        "ldap_bind_user": settings.ldap_bind_user,
        "ldap_bind_password_set": bool(settings.ldap_bind_password),
        "ldap_group_attr": settings.ldap_group_attr,
        "ldap_connect_timeout_seconds": settings.ldap_connect_timeout_seconds,
        "configured": settings.ldap_configured,
    }


def update(changes: dict) -> dict:
    """Validate the LDAP fields and group mapping, apply them to ``settings``, persist.

    Password semantics (``ldap_bind_password``): key NOT present means unchanged; an empty
    string clears it; a non-empty string sets a new one (stored encrypted).
    """
    store = _read_raw()

    for name in _STR_FIELDS:
        if changes.get(name) is not None:
            val = str(changes[name]).strip()
            setattr(settings, name, val)
            store[name] = val

    for name in _BOOL_FIELDS:
        if changes.get(name) is not None:
            setattr(settings, name, bool(changes[name]))
            store[name] = bool(changes[name])

    for name in _INT_FIELDS:
        if changes.get(name) is not None:
            try:
                v = _clamp_int(name, changes[name])
            except (TypeError, ValueError):
                raise ValueError(f"Invalid value for {name}.")
            setattr(settings, name, v)
            store[name] = v

    if _SECRET_FIELD in changes and changes[_SECRET_FIELD] is not None:
        pw = str(changes[_SECRET_FIELD])
        if pw == "":
            settings.ldap_bind_password = ""
            store.pop(_SECRET_STORE_KEY, None)
        else:
            settings.ldap_bind_password = pw
            store[_SECRET_STORE_KEY] = crypto.encrypt(pw)

    _save(store)
    log.info("ldap.config.updated", configured=settings.ldap_configured)
    return current_public()


def take_legacy_group_permissions() -> list[dict]:
    """One-off migration: take the old AD-group-to-permission mapping out of the LDAP
    config and return it. The AD groups move into the account store (``auth/store.py``).
    ``default_permissions`` is dropped **without replacement** in the process (permissions
    are now only ever granted per group or per user). After the call both keys are gone
    from the file, so a second call returns an empty list."""
    data = _read_raw()
    groups = data.pop("group_permissions", None)
    had_default = data.pop("default_permissions", None) is not None
    if groups is None and not had_default:
        return []
    _save(data)
    cleaned = _clean_group_permissions(groups)
    log.info("ldap.config.groups_extracted", count=len(cleaned), dropped_default=had_default)
    return cleaned


def test_connection() -> dict:
    """Best-effort test of the config currently applied: is the server reachable, and (if
    a service account is set) does a bind work. Returns ``{ok, detail}``."""
    if not settings.ldap_configured:
        return {"ok": False, "detail": "LDAP is incomplete: set server, domain and base DN."}
    try:
        import ldap3
        from ldap3.core.exceptions import LDAPException
    except ImportError:  # pragma: no cover
        return {"ok": False, "detail": "ldap3 is not installed."}

    from backend.auth.ldap_client import build_ldap_server

    try:
        server = build_ldap_server(ldap3)
        if settings.ldap_bind_user:
            conn = ldap3.Connection(
                server,
                user=settings.ldap_bind_user,
                password=settings.ldap_bind_password,
                authentication=ldap3.SIMPLE,
                auto_bind=True,
            )
            conn.unbind()
            return {"ok": True, "detail": "Connection and service account bind succeeded."}
        conn = ldap3.Connection(server, auto_bind=False)
        conn.open()  # TCP/TLS reachability only
        conn.unbind()
        return {"ok": True, "detail": "Server reachable (no service account set, so the bind was not tested)."}
    except LDAPException as exc:
        return {"ok": False, "detail": f"Failed: {exc}"}
    except Exception as exc:  # noqa: BLE001 - no raw stack trace in the UI
        return {"ok": False, "detail": f"Failed: {exc}"}
