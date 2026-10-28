"""Runtime OIDC/SSO configuration: editable in the admin backend, persistent across restarts.

The counterpart to ``ldap_config``: holds the OIDC connection (enabled flag, issuer,
client ID, redirect URI, scopes). The **client secret** is stored Fernet encrypted
(``crypto``) and never returned in clear text (the API only reports
``oidc_client_secret_set: bool``). ``.env`` remains the **bootstrap and fallback**; the
values stored in the backend win and are applied onto ``settings`` at startup.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from backend import crypto
from backend.config import PROJECT_ROOT, settings
from backend.logging_config import get_logger

log = get_logger("oidc.config")

_PATH: Path = PROJECT_ROOT / "backend" / "data" / "oidc_config.json"

# Non-secret fields, applied one to one onto ``settings.<name>``.
_STR_FIELDS = ("oidc_issuer", "oidc_client_id", "oidc_redirect_url", "oidc_scopes")
_BOOL_FIELDS = ("oidc_enabled",)
_SECRET_FIELD = "oidc_client_secret"
_SECRET_STORE_KEY = "oidc_client_secret_enc"


def _read_raw() -> dict:
    if not _PATH.exists():
        return {}
    try:
        return json.loads(_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        log.warning("oidc.config.read_failed", path=str(_PATH))
        return {}


def _save(store: dict) -> None:
    _PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = _PATH.with_suffix(_PATH.suffix + ".tmp")
    tmp.write_text(json.dumps(store, indent=2), encoding="utf-8")
    os.replace(tmp, _PATH)


def load_and_apply() -> None:
    """Apply the persisted OIDC config onto ``settings`` at startup, if there is one.

    ``.env`` is the fallback: with no file present, everything stays as the environment
    set it.
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
    enc = data.get(_SECRET_STORE_KEY)
    if enc:
        settings.oidc_client_secret = crypto.decrypt(enc)
        applied += 1
    if applied:
        log.info("oidc.config.loaded", fields=applied, configured=settings.oidc_configured)


def current_public() -> dict:
    """The current OIDC config for the UI, WITHOUT the client secret (only ``..._set``)."""
    return {
        "oidc_enabled": settings.oidc_enabled,
        "oidc_issuer": settings.oidc_issuer,
        "oidc_client_id": settings.oidc_client_id,
        "oidc_client_secret_set": bool(settings.oidc_client_secret),
        "oidc_redirect_url": settings.oidc_redirect_url,
        "oidc_scopes": settings.oidc_scopes,
        "configured": settings.oidc_configured,
    }


def update(changes: dict) -> dict:
    """Validate the OIDC fields, apply them to ``settings``, persist them.

    Secret semantics (``oidc_client_secret``): key NOT present means unchanged; an empty
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

    if _SECRET_FIELD in changes and changes[_SECRET_FIELD] is not None:
        secret = str(changes[_SECRET_FIELD])
        if secret == "":
            settings.oidc_client_secret = ""
            store.pop(_SECRET_STORE_KEY, None)
        else:
            settings.oidc_client_secret = secret
            store[_SECRET_STORE_KEY] = crypto.encrypt(secret)

    _save(store)
    log.info("oidc.config.updated", configured=settings.oidc_configured)
    return current_public()


def test_connection() -> dict:
    """Best-effort test: load the issuer OIDC discovery document and check that the three
    core endpoints (authorization/token/jwks) are present. Returns ``{ok, detail}``."""
    issuer = settings.oidc_issuer.strip().rstrip("/")
    if not issuer:
        return {"ok": False, "detail": "Issuer URL is missing."}
    try:
        import httpx
    except ImportError:  # pragma: no cover - httpx is only needed for SSO
        return {"ok": False, "detail": "httpx is not installed (required for SSO)."}

    url = f"{issuer}/.well-known/openid-configuration"
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(url)
            resp.raise_for_status()
            doc = resp.json()
    except Exception as exc:  # noqa: BLE001 - no raw stack trace in the UI
        return {"ok": False, "detail": f"Discovery failed: {exc}"}

    missing = [k for k in ("authorization_endpoint", "token_endpoint", "jwks_uri") if not doc.get(k)]
    if missing:
        return {"ok": False, "detail": f"Discovery incomplete (missing: {', '.join(missing)})."}
    return {"ok": True, "detail": "Discovery succeeded, endpoints found."}
