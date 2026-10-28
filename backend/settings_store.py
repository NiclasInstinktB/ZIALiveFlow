"""Runtime settings: editable in the admin backend, persisted across restarts.

Every setting that matters for operating the app lives here, so an operator never has
to edit a file on the server to change how the instance behaves. Secrets are the one
exception: JWT signing key, encryption key, bootstrap password, directory bind password
and the OIDC client secret stay in the environment and are never writable through HTTP.

Settings fall into two tiers:

``live``
    Read fresh on every use, so a change takes effect at once. Retention is consulted
    when the buffer evicts, session lifetimes when a token is minted, the login throttle
    on every attempt.

``restart``
    Bound at process start: listening sockets, CORS, cookie attributes, log format. The
    value is stored and reported immediately, but the running process keeps using the old
    one until it is restarted. The API marks these so the UI can say so plainly.

Startup order matters for the restart tier. ``load_and_apply()`` has to run before the
server binds anything, otherwise an operator could set a port in the admin UI and watch
it be ignored forever. ``serve.py`` calls it first for exactly that reason, and
``backend/main.py`` calls it again inside the lifespan so that running under a bare
``uvicorn backend.main:app`` still picks up everything except the bind address.
"""
from __future__ import annotations

import ipaddress
import json
import os
import zoneinfo
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from backend.config import PROJECT_ROOT, Settings, settings
from backend.logging_config import get_logger

log = get_logger("settings.store")

_PATH: Path = PROJECT_ROOT / "backend" / "data" / "runtime_settings.json"


class SettingError(ValueError):
    """Rejected value. The message is shown to the operator, so keep it actionable."""


@dataclass(frozen=True)
class Spec:
    """One editable setting: how to validate it and when it takes effect."""

    kind: str  # "int" | "text" | "bool" | "choice"
    tier: str  # "live" | "restart"
    lo: int | None = None
    hi: int | None = None
    max_length: int | None = None
    choices: tuple[str, ...] | None = None
    # Extra validation beyond the kind, for example a parseable timezone.
    check: Callable[[str], str] | None = None
    # Shown in the admin UI as the field hint.
    hint: str = ""


# ── Validators ─────────────────────────────────────────────────────


def _check_timezone(value: str) -> str:
    """Reject an unknown IANA zone here rather than silently serving shifted times.

    The web feed sends local time without an offset, so a wrong zone does not raise an
    error anywhere, it just moves every web timestamp by a few hours. That is the kind of
    bug people chase for days, so it is worth refusing the bad value at the point of entry.
    """
    try:
        zoneinfo.ZoneInfo(value)
    except Exception:
        raise SettingError(
            f"Unknown time zone '{value}'. Use an IANA name such as 'UTC' or 'Europe/Berlin'."
        )
    return value


def _check_ip_allowlist(value: str) -> str:
    """Comma separated IPs and CIDRs. Empty means no restriction."""
    cleaned = []
    for token in value.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            cleaned.append(str(ipaddress.ip_network(token, strict=False)))
        except ValueError:
            raise SettingError(f"'{token}' is not a valid IP address or CIDR range.")
    return ", ".join(cleaned)


def _check_origins(value: str) -> str:
    """Comma separated CORS origins. Each needs a scheme or the browser ignores it."""
    cleaned = []
    for token in value.split(","):
        token = token.strip().rstrip("/")
        if not token:
            continue
        if token != "*" and "://" not in token:
            raise SettingError(f"Origin '{token}' needs a scheme, for example https://{token}.")
        cleaned.append(token)
    return ", ".join(cleaned)


def _check_app_name(value: str) -> str:
    """An empty name would leave the header and browser tab blank."""
    return value or str(Settings.model_fields["app_name"].default)


def _check_domain_suffix(value: str) -> str:
    """Empty means append nothing. Otherwise the '@' is required.

    Without it the UI would build 'first.lastexample.com' and quietly match nothing.
    """
    if not value:
        return ""
    return value if value.startswith("@") else f"@{value}"


def _check_source_url(value: str) -> str:
    """AGPL section 13 expects network users to be able to reach the source."""
    if not value:
        return ""
    if not value.startswith(("http://", "https://")):
        raise SettingError("The source URL must start with http:// or https://.")
    return value.rstrip("/")


def _check_host(value: str) -> str:
    if not value:
        raise SettingError("The bind address must not be empty. Use 127.0.0.1 or 0.0.0.0.")
    return value


# ── The catalogue ──────────────────────────────────────────────────
# Keep the bounds in step with the Field() constraints in config.Settings.

SPECS: dict[str, Spec] = {
    # Branding and UI defaults.
    "app_name": Spec("text", "live", max_length=60, check=_check_app_name,
                     hint="Shown in the header and the browser tab."),
    "default_language": Spec("choice", "live", choices=("en", "de", "fr", "es", "it", "pt", "nl", "ja", "zh"),
                             hint="Used for visitors who have not picked a language."),
    "user_domain_suffix": Spec("text", "live", max_length=120, check=_check_domain_suffix,
                               hint="Appended to a user filter that has no '@'. Empty appends nothing."),
    "source_url": Spec("text", "live", max_length=200, check=_check_source_url,
                       hint="Link to the source code, shown in the footer."),
    # Buffer and retention.
    "retention_minutes": Spec("int", "live", lo=1, hi=60,
                              hint="How long matches stay in memory."),
    "buffer_max_records": Spec("int", "live", lo=1_000, hi=5_000_000,
                               hint="Hard ceiling on buffered records."),
    # Sessions.
    "session_ttl_minutes": Spec("int", "live", lo=5, hi=10_080,
                                hint="Maximum lifetime of a sign-in."),
    "session_idle_minutes": Spec("int", "live", lo=1, hi=1440,
                                 hint="Automatic sign-out after inactivity."),
    # Login throttle.
    "login_max_failures": Spec("int", "live", lo=1, hi=1000,
                               hint="Failed attempts per IP and user before a short block."),
    "login_window_minutes": Spec("int", "live", lo=1, hi=1440,
                                 hint="Window the failed attempts are counted in."),
    # Audit log.
    "audit_enabled": Spec("bool", "live", hint="Record sign-ins and searches as metadata."),
    "audit_retention_days": Spec("int", "live", lo=1, hi=365,
                                 hint="Daily audit files older than this are deleted."),
    # Ingest allowlist is consulted per connection, so it applies at once.
    "ingest_allowed_ips": Spec("text", "live", max_length=2000, check=_check_ip_allowlist,
                               hint="Only these IPs or CIDRs may deliver feeds. Empty allows all."),
    # Display threshold only, read fresh for every stats message, so it applies at once.
    "feed_stale_after_seconds": Spec("int", "live", lo=10, hi=86_400,
                                     hint="After this long without a line the live view marks the feed as silent."),
    # Self update.
    "update_branch": Spec("text", "live", max_length=100,
                          hint="Branch the updater pulls from."),
    # ── Restart tier ───────────────────────────────────────────────
    "app_host": Spec("text", "restart", max_length=100, check=_check_host,
                     hint="Address the web UI binds to."),
    "app_port": Spec("int", "restart", lo=1, hi=65535,
                     hint="Port the web UI binds to."),
    "ingest_enabled": Spec("bool", "restart", hint="Start the feed listeners at all."),
    "ingest_bind_host": Spec("text", "restart", max_length=100, check=_check_host,
                             hint="Address the feed listeners bind to."),
    # lo=0 on the feed ports: 0 means "do not start this listener", which is how a
    # deployment without, say, a DNS feed is configured.
    "ingest_web_port": Spec("int", "restart", lo=0, hi=65535,
                            hint="TCP port for the web log feed. 0 turns the feed off."),
    "ingest_fw_port": Spec("int", "restart", lo=0, hi=65535,
                           hint="TCP port for the firewall log feed. 0 turns the feed off."),
    "ingest_dns_port": Spec("int", "restart", lo=0, hi=65535,
                            hint="TCP port for the DNS log feed. 0 turns the feed off."),
    "ingest_idle_timeout_seconds": Spec("int", "restart", lo=0, hi=86_400,
                                        hint="Drop a feed connection that has delivered nothing for this long. 0 is off."),
    # TCP keepalive is the other half of dead connection detection: the idle timeout
    # acts from this side, keepalive asks the kernel to prod the other one.
    "ingest_tcp_keepalive": Spec("bool", "restart",
                                 hint="Let the kernel probe idle feed connections."),
    "ingest_keepalive_idle_seconds": Spec("int", "restart", lo=5, hi=7200,
                                          hint="Quiet period before the first keepalive probe."),
    "ingest_keepalive_interval_seconds": Spec("int", "restart", lo=1, hi=600,
                                              hint="Gap between keepalive probes."),
    "ingest_keepalive_count": Spec("int", "restart", lo=1, hi=20,
                                   hint="Unanswered probes before the connection counts as dead."),
    "feed_timezone": Spec("text", "restart", max_length=60, check=_check_timezone,
                          hint="Must match the time zone configured for the NSS feeds."),
    "session_cookie_name": Spec("text", "restart", max_length=60,
                                hint="Changing this signs everyone out."),
    "session_cookie_secure": Spec("bool", "restart",
                                  hint="Send the cookie over HTTPS only. Required behind TLS."),
    "session_cookie_samesite": Spec("choice", "restart", choices=("lax", "strict", "none"),
                                    hint="Cross-site behaviour of the session cookie."),
    "cors_origins": Spec("text", "restart", max_length=1000, check=_check_origins,
                         hint="Browser origins allowed to call the API."),
    "log_level": Spec("choice", "restart", choices=("debug", "info", "warning", "error"),
                      hint="Verbosity of the process log."),
    "log_format": Spec("choice", "restart", choices=("console", "json"),
                       hint="Human readable or structured JSON."),
}

# Kept as a name so existing imports and the API response shape stay valid.
RESTART_REQUIRED: frozenset[str] = frozenset(n for n, s in SPECS.items() if s.tier == "restart")


# ── Coercion ───────────────────────────────────────────────────────


def _coerce(name: str, raw: Any) -> Any:
    spec = SPECS[name]
    if spec.kind == "int":
        try:
            value = int(raw)
        except (TypeError, ValueError):
            raise SettingError(f"{name} must be a whole number.")
        # Clamp rather than reject: the UI already enforces the range, and clamping keeps
        # a stored file from an older version with different bounds loadable.
        return max(spec.lo, min(spec.hi, value))
    if spec.kind == "bool":
        if isinstance(raw, bool):
            return raw
        return str(raw).strip().lower() in ("1", "true", "yes", "on")
    text = " ".join(str(raw).split())
    if spec.max_length:
        text = text[: spec.max_length]
    if spec.kind == "choice":
        text = text.lower()
        if text not in spec.choices:
            raise SettingError(f"{name}: allowed values are {', '.join(spec.choices)}.")
        return text
    if spec.check:
        return spec.check(text)
    return text


def current() -> dict[str, Any]:
    return {name: getattr(settings, name) for name in SPECS}


def catalogue() -> dict[str, dict]:
    """Field metadata for the admin UI: kind, tier, bounds, choices, hint."""
    out: dict[str, dict] = {}
    for name, spec in SPECS.items():
        entry: dict[str, Any] = {"kind": spec.kind, "tier": spec.tier, "hint": spec.hint}
        if spec.kind == "int":
            entry["min"], entry["max"] = spec.lo, spec.hi
        if spec.max_length:
            entry["max_length"] = spec.max_length
        if spec.choices:
            entry["choices"] = list(spec.choices)
        out[name] = entry
    return out


def read_only_view() -> dict:
    """Settings that are deliberately not writable over HTTP, for display only."""
    return {
        "app_env": settings.app_env,
        "is_production": settings.is_production,
        "jwt_secret_is_default": settings.jwt_secret_is_default,
        "env_file": ENV_FILE_LABEL,
    }


ENV_FILE_LABEL = os.getenv("APP_ENV_FILE", str(PROJECT_ROOT / ".env")) or "(none)"


# ── Persistence ────────────────────────────────────────────────────


def _stored() -> dict[str, Any]:
    """The override file as a dict. Missing, unreadable or not an object gives {}.

    A corrupt file must not stop the app from starting, so this never raises.
    """
    if not _PATH.exists():
        return {}
    try:
        data = json.loads(_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        log.warning("settings.load_failed", path=str(_PATH))
        return {}
    return data if isinstance(data, dict) else {}


def _save(applied: dict[str, Any]) -> None:
    """Merge the changed keys into the file, leaving everything else alone.

    This file holds ONLY what an operator actually changed in the admin backend. Writing
    the full settings set instead would bake every value from the env file into it on the
    first save, after which editing the env file would silently stop having any effect.
    """
    merged = {**_stored(), **applied}
    _PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = _PATH.with_suffix(_PATH.suffix + ".tmp")
    tmp.write_text(json.dumps(merged, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, _PATH)


def load_and_apply() -> None:
    """Apply the stored overrides onto ``settings``.

    Must run before anything binds a socket, see the module docstring. A value that no
    longer validates is skipped rather than fatal, so a stale file cannot stop the app
    from starting.
    """
    data = _stored()
    if not data:
        return
    applied = {}
    for name in SPECS:
        if name not in data:
            continue
        try:
            setattr(settings, name, _coerce(name, data[name]))
            applied[name] = getattr(settings, name)
        except (SettingError, TypeError, ValueError):
            log.warning("settings.skipped_invalid", setting=name)
    if applied:
        log.info("settings.loaded", count=len(applied))


def update(changes: dict) -> tuple[dict[str, Any], list[str]]:
    """Validate everything first, then apply and persist. All or nothing.

    Coercion happens for the whole batch before a single value is written. Validating and
    assigning in one pass would leave the earlier values of a batch applied in memory when
    a later one is rejected, while the caller gets an error and nothing is persisted, so
    memory and file would disagree.
    """
    coerced: dict[str, Any] = {}
    for name, value in changes.items():
        if name not in SPECS or value is None:
            continue
        coerced[name] = _coerce(name, value)  # raises SettingError, nothing applied yet

    # Only values that actually differ reach the file, so it stays a record of what an
    # operator deliberately changed.
    applied = {n: v for n, v in coerced.items() if getattr(settings, n) != v}
    pending: list[str] = []
    if applied:
        for name, value in applied.items():
            setattr(settings, name, value)
        _save(applied)
        pending = sorted(n for n in applied if SPECS[n].tier == "restart")
        log.info("settings.updated", changed=sorted(applied), restart_pending=pending)
    return current(), pending
