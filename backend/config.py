"""Central configuration: every setting comes from environment variables / .env.

Secrets are read exclusively from the environment (pydantic-settings), never from the
code. The app is protected by **local admin accounts** (``backend/auth/store.py``) and,
optionally, additionally by **AD/LDAP** (``backend/auth/ldap_client.py``, login against
the central directory service). Local accounts always stay valid as a break-glass path.
"""
from __future__ import annotations

import contextlib
import ipaddress
import os
from contextvars import ContextVar
from pathlib import Path
from typing import Iterator

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Project root (one level above backend/)
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Which env file gets read is itself configurable: ``APP_ENV_FILE`` can point at a
# different file (several instances on one host) or be empty to read none at all. The
# tests need the latter: otherwise the developer's ``.env`` decides the test outcome,
# and ``git clone && pytest`` is not reproducible.
_ENV_FILE_RAW = os.getenv("APP_ENV_FILE")
if _ENV_FILE_RAW is None:
    ENV_FILE: str | None = str(PROJECT_ROOT / ".env")
else:
    ENV_FILE = _ENV_FILE_RAW.strip() or None

# Placeholder secret; must be replaced in production (enforced by a startup check).
DEFAULT_JWT_SECRET = "change-me-in-prod-please-set-a-long-random-secret"

# ── Draft overlay ───────────────────────────────────────────────────
# This exists so that "Test connection" can check the values currently TYPED INTO the
# form instead of only being useful after saving. A ContextVar rather than a global
# mutation: asyncio gives every task its own copy of the context, so only the testing
# call sees the draft values, while concurrent requests keep working against the saved
# state undisturbed.
_OVERLAY: ContextVar[dict] = ContextVar("settings_overlay", default={})


@contextlib.contextmanager
def overlay(values: dict) -> Iterator[None]:
    """Overlay values for this call only: nothing is persisted."""
    if not values:
        yield
        return
    token = _OVERLAY.set({**_OVERLAY.get(), **values})
    try:
        yield
    finally:
        _OVERLAY.reset(token)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    def __getattribute__(self, name: str):
        # Only real settings are overlaid; everything internal (``_`` prefix, pydantic
        # machinery) passes through unchanged. Derived properties such as
        # ``ldap_configured`` read their fields through exactly this path, so they pick
        # up the draft automatically.
        if not name.startswith("_"):
            current = _OVERLAY.get()
            if current and name in current:
                return current[name]
        return super().__getattribute__(name)

    # ── Environment ────────────────────────────────────────────────
    # "dev" | "prod": controls the hardening checks (secret required, cookie-secure warning).
    app_env: str = "dev"

    # ── Session / JWT (local admin accounts) ───────────────────────
    jwt_secret: str = DEFAULT_JWT_SECRET
    jwt_algorithm: str = "HS256"
    # Fernet key (base64, 32 bytes) for encrypting stored secrets (the LDAP bind
    # password). Empty: derived deterministically from JWT_SECRET (see crypto.py).
    app_encryption_key: str = ""
    session_ttl_minutes: int = Field(default=480, ge=5, le=10080)
    # Automatic logout on inactivity (frontend idle timer).
    session_idle_minutes: int = Field(default=30, ge=1, le=1440)
    session_cookie_name: str = "zlf_session"
    # Send the cookie over HTTPS only (True in production).
    session_cookie_secure: bool = False
    session_cookie_samesite: str = "lax"

    # ── Login throttle (brute force) ───────────────────────────────
    # Deliberately *generous*: a short, rolling block (HTTP 429) kicks in only after many
    # failed attempts per (IP + user) inside the window. A successful login clears the
    # counter immediately. The state is kept purely in memory.
    login_max_failures: int = Field(default=20, ge=1, le=1000)
    login_window_minutes: int = Field(default=5, ge=1, le=1440)

    # ── Local admin accounts ───────────────────────────────────────
    # Where the accounts are stored (PBKDF2 hashes, no cleartext).
    admin_store_path: str = "backend/data/admins.json"
    # First-admin bootstrap. If both are set and the store is empty, the account is
    # created at startup. Otherwise a random password is generated and written to the
    # log ONCE.
    admin_initial_user: str = "admin"
    admin_initial_password: str = ""

    # ── Superadmin (break glass) ───────────────────────────────────
    # Accounts that ALWAYS hold every permission: independent of groups, and not
    # revocable through the UI. That is precisely why this lives here and not in the
    # admin backend: permissions otherwise come only through groups, and whoever does
    # not hold a permission may not hand it to anyone either (the escalation brake),
    # not even to themselves. Without this path you can lock yourself out of your own
    # application: deleting the last group that carries the "accounts" permission is
    # enough.
    #
    # Comma-separated list of usernames; applies to local AND AD accounts (the name is
    # the sAMAccountName). Example: "admin, first.last"
    superadmin_users: str = ""
    # Optional addition: members of this AD group (CN) are superadmins.
    superadmin_ad_group: str = ""

    # ── AD / LDAP (shared login, optional) ─────────────────────────
    # An additional AD login IN PARALLEL with the local accounts. Active as soon as
    # LDAP_SERVER + LDAP_DOMAIN + LDAP_BASE_DN are set. If LDAP is not configured,
    # nothing changes (local accounts only). AD-authenticated users are mirrored into
    # the account store just in time (source "ad", no local password); their role comes
    # from the AD groups (see below).
    # One OR several AD servers (comma- or whitespace-separated, up to 4): the first is
    # primary, the rest are failover targets (ldap3 ServerPool, strategy FIRST). Each
    # entry may use its own scheme: ldap://, ldaps://, gc:// or gcs:// (Global Catalog,
    # forest-wide group search, ports 3268/3269).
    ldap_server: str = ""                                # e.g. "gc://dc01.example.com, gc://dc02.example.com"
    ldap_port: int = Field(default=0, ge=0, le=65535)    # 0 = auto per scheme (389/636, GC 3268/3269)
    ldap_use_ssl: bool = True                            # LDAPS (recommended)
    ldap_domain: str = ""                                # UPN domain (user@DOMAIN), e.g. "example.com"
    ldap_base_dn: str = ""                               # search base, e.g. "DC=example,DC=com"
    # Optional service account for the group search (otherwise the user binds themselves).
    ldap_bind_user: str = ""                             # UPN or DN of the service account
    ldap_bind_password: str = ""
    ldap_group_attr: str = "memberOf"
    ldap_connect_timeout_seconds: int = Field(default=5, ge=1, le=60)
    # The AD group to permissions mapping is NOT set here but interactively in the admin
    # backend (tab "Accounts", AD groups), persisted in the account store
    # backend/data/admins.json.

    # ── SSO / OpenID Connect (Entra ID, optional) ──────────────────
    # An ADDITIONAL login path via OIDC (authorization code + PKCE) against an IdP
    # (for example Microsoft Entra ID): purely additive, OFF by default. All existing
    # login paths (local, AD password) stay untouched. The IDENTITY comes from the ID
    # token; the GROUPS are loaded live from the AD/Global Catalog (service account
    # LDAP_BIND_USER), exactly as for the AD password login, and mapped to permissions
    # through the group-to-permissions mapping (account store). Nothing extra is stored;
    # AD users are mirrored just in time as an account (source "ad") as before. Active
    # only once OIDC_ENABLED=true AND issuer/client ID/secret are set.
    oidc_enabled: bool = False
    # Issuer URL = discovery base. Entra: https://login.microsoftonline.com/<tenant-id>/v2.0
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    # Redirect URI (must be registered in the Entra app registration). Empty: derived
    # from the request (origin + /api/auth/sso/callback). Better set explicitly behind a
    # reverse proxy, which may otherwise report the wrong scheme or host.
    oidc_redirect_url: str = ""
    # Requested scopes. openid is mandatory; profile/email provide name and UPN.
    oidc_scopes: str = "openid profile email"

    # ── NSS ingest (TCP) ───────────────────────────────────────────
    # Bind address and ports of the feed listeners (web/firewall/DNS). Port 0 = feed off.
    ingest_bind_host: str = "0.0.0.0"
    ingest_web_port: int = Field(default=5140, ge=0, le=65535)
    ingest_fw_port: int = Field(default=5141, ge=0, le=65535)
    ingest_dns_port: int = Field(default=5142, ge=0, le=65535)
    # Start ingest at all? (Can be turned off for pure UI or dev sessions.)
    ingest_enabled: bool = True
    # Application-side source allowlist: ONLY these IPs/networks may deliver feeds
    # (comma-separated, single IPs OR CIDR, e.g. "10.0.0.10, 10.0.0.11, 10.1.0.0/24").
    # Empty = everything allowed (then the firewall is the only protection). Defense in
    # depth on top of the firewall rule.
    ingest_allowed_ips: str = ""
    # ── Dead connection detection on the feed connections ──────────
    # A TCP connection can die quietly: a firewall or NAT idle timeout, or a blocked
    # kernel (a full audit backlog, say), leaves a half open connection behind. Both
    # sides consider it healthy, nothing simply flows any more, and ``reader.read()``
    # then waits forever, with no EOF and no error.
    #
    # Two independent safety nets against that:
    #  1. TCP keepalive lets the kernel prod the other side by itself.
    #  2. The idle timeout closes a silent connection from this side, after which the
    #     NSS server reconnects. One reconnect beats hours of being blind.
    ingest_tcp_keepalive: bool = True
    # Quiet period before the first keepalive probe (seconds).
    ingest_keepalive_idle_seconds: int = Field(default=60, ge=5, le=7200)
    # Spacing of the probes and how many of them before the connection counts as dead.
    ingest_keepalive_interval_seconds: int = Field(default=10, ge=1, le=600)
    ingest_keepalive_count: int = Field(default=3, ge=1, le=20)
    # If NO line arrives for this long, the connection counts as dead and is closed.
    # 0 = off. Set it generously: the value has to sit above the longest normal feed
    # pause, otherwise a healthy but quiet connection gets dropped.
    ingest_idle_timeout_seconds: int = Field(default=600, ge=0, le=86400)
    # When the live view marks the feed as silent. Display only, and much shorter than
    # the idle timeout: the indicator should warn long before anything is disconnected.
    feed_stale_after_seconds: int = Field(default=120, ge=10, le=86400)
    # Time zone of the NSS feeds (IANA name). It MUST match the Time Zone set in the
    # Zscaler console (NSS Feed, Time Zone). The web feed delivers %s{time} as local
    # time WITHOUT a zone, so without this value the timestamp cannot be resolved. The
    # firewall and DNS feeds deliver %d{epochtime} (absolute) and are unaffected.
    feed_timezone: str = "Europe/Berlin"

    # ── UI defaults (per deployment) ───────────────────────────────
    # Display name of the application: header, browser title, login page. Freely
    # choosable and editable in the admin backend; this is only the initial value.
    app_name: str = "ZIA Live-Flow"
    # Source code link, visible in the UI. Section 13 of the AGPL requires that users
    # who operate the application over a network can get at the source code.
    source_url: str = "https://github.com/NiclasInstinktB/ZIALiveFlow"
    # Default UI language for visitors who have not chosen one (en, de, fr, es, it, pt, nl, ja, zh).
    # The browser, or a pick in the language switcher, takes precedence.
    default_language: str = "en"
    # Appended in the live view to a user filter that contains no "@"
    # ("first.last" becomes "first.last@example.com"). Empty = append nothing.
    user_domain_suffix: str = "@example.com"

    # ── Ring buffer / retention ────────────────────────────────────
    # How long matches are kept in RAM (minutes). Only matches are retained.
    retention_minutes: int = Field(default=30, ge=1, le=60)
    # Hard cap on retained records (memory safety net).
    buffer_max_records: int = Field(default=200_000, ge=1_000, le=5_000_000)

    # ── Self-update (admin backend) ────────────────────────────────
    # Branch the updater pulls from (git fetch + reset --hard origin/<branch>).
    update_branch: str = "main"

    # ── Audit log ──────────────────────────────────────────────────
    # Records logins and searches (filters): metadata, NOT the log payloads.
    # Persisted as one JSONL file per day; files older than the retention are deleted.
    audit_enabled: bool = True
    audit_retention_days: int = Field(default=30, ge=1, le=365)

    # ── App / logging ──────────────────────────────────────────────
    log_level: str = "INFO"
    log_format: str = "console"  # "json" | "console"
    cors_origins: str = "http://localhost:5173"
    app_host: str = "127.0.0.1"
    app_port: int = 8000

    # ── Derived values ─────────────────────────────────────────────
    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def admin_store_file(self) -> Path:
        p = Path(self.admin_store_path)
        return p if p.is_absolute() else PROJECT_ROOT / p

    @property
    def ingest_allowed_networks(self) -> list[ipaddress._BaseNetwork]:
        """``ingest_allowed_ips`` as a list of IP networks. Single IPs become /32 or
        /128. Invalid tokens are skipped silently. Empty = no restriction (all sources
        allowed)."""
        nets: list[ipaddress._BaseNetwork] = []
        for tok in self.ingest_allowed_ips.split(","):
            tok = tok.strip()
            if not tok:
                continue
            try:
                nets.append(ipaddress.ip_network(tok, strict=False))
            except ValueError:
                continue
        return nets

    @property
    def superadmin_user_list(self) -> list[str]:
        """Superadmin usernames, lowercased (the comparison is case-insensitive)."""
        return [u.strip().lower() for u in self.superadmin_users.split(",") if u.strip()]

    @property
    def is_production(self) -> bool:
        return self.app_env.strip().lower() in ("prod", "production")

    @property
    def jwt_secret_is_default(self) -> bool:
        return self.jwt_secret == DEFAULT_JWT_SECRET

    # ── AD/LDAP derivations ────────────────────────────────────────
    @property
    def ldap_configured(self) -> bool:
        """Is the AD login active? Only once server, domain and base DN are set."""
        return bool(self.ldap_server.strip() and self.ldap_domain.strip() and self.ldap_base_dn.strip())

    @property
    def oidc_configured(self) -> bool:
        """SSO usable: enabled AND fully configured (issuer + client + secret)."""
        return bool(
            self.oidc_enabled
            and self.oidc_issuer.strip()
            and self.oidc_client_id.strip()
            and self.oidc_client_secret.strip()
        )


settings = Settings()


# ═══════════════════════════════════════════════════════════════════
#  Feed field layout: the columns of the flat, tab-separated NSS lines.
#
#  The FIRST FIVE positions are identical for all feeds and make up
#  the cheap positional prefilter (no full parse):
#     0 = type tag ("web"/"fw"/"dns")
#     1 = SRC IP  (web: internal client IP %s{cip}, fw: %s{csip}, dns: %s{cip})
#     2 = DST IP  (web: server IP %s{sip},          fw: %s{cdip}, dns: %s{sip})
#     3 = user    (%s{login})
#     4 = location(%s{location})
#  The rest is type-specific. If the Feed Output Format changes in the
#  Zscaler console, this list MUST be kept IDENTICAL to it (see
#  README/PLAN for the exact feed strings).
#
#  Field names follow the official NSS tokens (help.zscaler.com):
#  Web Logs, Firewall Logs and DNS Logs Feed Output Format.
# ═══════════════════════════════════════════════════════════════════

# Shared positions used by the cheap prefilter.
COL_TYPE = 0
COL_SRC_IP = 1
COL_DST_IP = 2
COL_USER = 3
COL_LOCATION = 4

# ── Web logs ──  (for the token mapping see the feed string in the README)
#   src_ip=%s{cip}  dst_ip=%s{sip}  user=%s{login}  location=%s{location}
WEB_COLUMNS: tuple[str, ...] = (
    "type",                 # 0  "web"
    "src_ip",               # 1  %s{cip}      internal client IP (PREFILTER)
    "dst_ip",               # 2  %s{sip}      server IP          (PREFILTER)
    "user",                 # 3  %s{login}                       (PREFILTER)
    "location",             # 4  %s{location}                    (PREFILTER)
    "ts",                   # 5  %s{time}
    "dept",                 # 6  %s{dept}
    "action",               # 7  %s{action}
    "reason",               # 8  %s{reason}
    "proto",                # 9  %s{proto}
    "http_method",          # 10 %s{reqmethod}
    "http_status",          # 11 %s{respcode}
    "bytes_tx",             # 12 %d{reqsize}
    "bytes_rx",             # 13 %d{respsize}
    "target",               # 14 %s{url}
    "host",                 # 15 %s{host}
    "category",             # 16 %s{urlcat}
    "url_class",            # 17 %s{urlclass}
    "app_name",             # 18 %s{appname}   (cloud app)
    "app_class",            # 19 %s{appclass}
    "rule",                 # 20 %s{rulelabel}
    "rule_type",            # 21 %s{ruletype}
    "tls_version",          # 22 %s{clienttlsversion}
    "tls_cipher",           # 23 %s{clientsslcipher}
    "server_tls_version",   # 24 %s{srvtlsversion}
    "threat_name",          # 25 %s{threatname}
    "threat_category",      # 26 %s{malwarecat}
    "risk_score",           # 27 %d{riskscore}
    "client_public_ip",     # 28 %s{cintip}    NATed public IP
    "user_agent",           # 29 %s{ua}
    "device_name",          # 30 %s{devicehostname}
    "device_owner",         # 31 %s{deviceowner}
    "content_type",         # 32 %s{contenttype}
    # ── New (2026-07-22): SSL/policy/forwarding, tokens per the official Zscaler docs ──
    "ssl_inspected",        # 33 %s{ssldecrypted}        SSL/TLS Inspected (Yes/No)
    "ssl_policy",           # 34 %s{ssl_rulename}        SSL/TLS Policy Name
    "ssl_policy_reason",    # 35 %s{externalspr}         SSL/TLS Policy Reason
    "url_policy",           # 36 %s{urlfilterrulelabel}  URL Filtering Policy Name
    "fwd_rule",             # 37 %s{rdr_rulename}        Forwarding Rule (Forwarding Control)
    "gateway",              # 38 %s{fwd_gw_name}         Gateway Name
)

# ── Firewall logs ──
#   src_ip=%s{csip}  dst_ip=%s{cdip}  user=%s{login}  location=%s{location}
FW_COLUMNS: tuple[str, ...] = (
    "type",                 # 0  "fw"
    "src_ip",               # 1  %s{csip}     client source IP   (PREFILTER)
    "dst_ip",               # 2  %s{cdip}     client dest IP     (PREFILTER)
    "user",                 # 3  %s{login}                        (PREFILTER)
    "location",             # 4  %s{location}                     (PREFILTER)
    "ts",                   # 5  %d{epochtime}  (the console rejected %s{datetime})
    "dept",                 # 6  %s{dept}
    "action",               # 7  %s{action}
    "proto",                # 8  %s{ipproto}
    "src_port",             # 9  %d{csport}
    "dst_port",             # 10 %d{cdport}
    "server_ip",            # 11 %s{sdip}      server dest IP (after NAT)
    "server_port",          # 12 %d{sdport}
    "client_public_ip",     # 13 %s{tsip}      Zscaler egress/NAT IP
    "bytes_rx",             # 14 %ld{inbytes}
    "bytes_tx",             # 15 %ld{outbytes}
    "duration_ms",          # 16 %d{durationms}
    "nwservice",            # 17 %s{nwsvc}     network service
    "app_name",             # 18 %s{nwapp}     network application
    "category",             # 19 %s{ipcat}
    "rule",                 # 20 %s{rulelabel}
    "dest_country",         # 21 %s{destcountry}
    "tunnel_type",          # 22 %s{ttype}
    "dnat",                 # 23 %s{dnat}
    "num_sessions",         # 24 %d{numsessions}
    # ── New (2026-07-22): tokens per the official Zscaler docs ──
    "fwd_rule",             # 25 %s{rdr_rulename}       Forwarding Rule (Forwarding Control)
    "flow_type",            # 26 %s{flow_type}          Flow Type (Direct/VPN/ZIA/ZPA/...)
)

# ── DNS logs ──
#   src_ip=%s{cip}  dst_ip=%s{sip} (the DNS server that was asked)  user=%s{login}  location=%s{location}
#   A DNS line carries two decisions: the request (req*) and the response (res*) are
#   evaluated separately and can be blocked separately.
DNS_COLUMNS: tuple[str, ...] = (
    "type",                 # 0  "dns"
    "src_ip",               # 1  %s{cip}      client IP          (PREFILTER)
    "dst_ip",               # 2  %s{sip}      DNS server IP      (PREFILTER)
    "user",                 # 3  %s{login}                       (PREFILTER)
    "location",             # 4  %s{location}                    (PREFILTER)
    "ts",                   # 5  %d{epochtime}
    "dept",                 # 6  %s{dept}
    "dns_query",            # 7  %s{req}          the name that was looked up
    "dns_req_type",         # 8  %s{reqtype}      A/AAAA/CNAME/...
    "dns_req_action",       # 9  %s{reqaction}    decision on the request
    "dns_req_rule",         # 10 %s{reqrulelabel}
    "dns_response",         # 11 %s{res}          answer (IP or name)
    "dns_res_type",         # 12 %s{restype}
    "dns_res_action",       # 13 %s{resaction}    decision on the response
    "dns_res_rule",         # 14 %s{resrulelabel}
    "dns_error",            # 15 %s{error}        e.g. NXDOMAIN/SERVFAIL
    "category",             # 16 %s{domcat}       domain category
    "dns_res_ip_cat",       # 17 %s{respipcat}    category of the answer IP
    "app_name",             # 18 %s{dnsapp}
    "app_class",            # 19 %s{dnsappcat}
    "dst_port",             # 20 %d{sport}        server port
    "proto",                # 21 %s{protocol}     UDP/TCP/DoH
    "duration_ms",          # 22 %d{durationms}
    "device_name",          # 23 %s{devicehostname}
    "device_owner",         # 24 %s{deviceowner}
)

# Type tag (column 0) to column layout. The one place where a feed is "known".
FEED_COLUMNS: dict[str, tuple[str, ...]] = {"web": WEB_COLUMNS, "fw": FW_COLUMNS, "dns": DNS_COLUMNS}
