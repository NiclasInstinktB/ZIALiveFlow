"""AD/LDAP login: bind with the user credentials plus a group lookup.

An optional login path running IN PARALLEL with the local accounts (``auth/store.py``).
If LDAP is configured (``LDAP_SERVER``/``LDAP_DOMAIN``/``LDAP_BASE_DN``), users can sign
in with their AD account. Authentication is a **SIMPLE bind** with the UPN
``user@domain``; afterwards the group memberships (``memberOf``) are read. Mapping those
onto **permissions** happens in the account store
(``auth.store.AdminStore.effective_for_ad``, the union of the groups the person belongs
to directly or through one of their AD groups). Here we only authenticate and read the
groups.

Deliberately lean (no dev mock, no break-glass branch): the break glass here is the
**local accounts**, which stay valid at all times, including while AD is down. ``ldap3``
is imported ONLY inside the functions, so the app still runs without the package as long
as no AD is configured.

``LDAP_SERVER`` may carry SEVERAL servers (comma or whitespace separated, primary plus
failover) and its own scheme per entry: ``ldap://``, ``ldaps://`` as well as ``gc://`` /
``gcs://`` for the **global catalog** (forest-wide group search, ports 3268/3269).
See :func:`build_ldap_server`.

"""
from __future__ import annotations

from dataclasses import dataclass, field

from backend.config import settings
from backend.logging_config import get_logger

log = get_logger("auth.ldap")

# Default ports per scheme. The global catalog (forest-wide group search) does NOT run
# on 389/636 but on 3268 (clear text / StartTLS) and 3269 (LDAPS).
LDAP_PORT = 389
LDAPS_PORT = 636
GC_PORT = 3268
GCS_PORT = 3269

# Maximum number of AD servers (primary plus failover). Further entries are ignored.
LDAP_MAX_SERVERS = 4


@dataclass
class LdapResult:
    """Result of one AD login attempt."""

    ok: bool
    username: str = ""
    display_name: str = ""
    groups: frozenset[str] = field(default_factory=frozenset)
    error: str = ""


def _cn_from_dn(dn: str) -> str:
    """``CN=Net-Admins,OU=...`` becomes ``Net-Admins``. Otherwise the DN is unchanged."""
    for part in dn.split(","):
        part = part.strip()
        if part.upper().startswith("CN="):
            return part[3:]
    return dn


def _split_server_specs(raw: str) -> list[str]:
    """Server list from ``LDAP_SERVER``, separated by comma, semicolon or whitespace.

    The first entry is the primary one (required), any further ones are failover targets.
    """
    import re

    return [p for p in re.split(r"[\s,;]+", (raw or "").strip()) if p]


def _build_one_server(ldap3, spec: str):
    """Builds ONE ``ldap3.Server`` from a server string (scheme/host/port).

    Supports ``ldap://``, ``ldaps://`` as well as ``gc://`` / ``gcs://`` (global catalog).
    ldap3 itself only knows ``ldap(s)://``; an unknown prefix such as ``gc://`` would be
    read as a host with a port and abort with *"port must be an integer"*. That is why we
    resolve scheme, host and port ourselves here and always pass an integer port.
    """
    raw = spec.strip()
    is_gc = False

    # An explicitly given scheme decides SSL completely; only a bare hostname inherits
    # the LDAPS checkbox (``ldap_use_ssl``) from the settings. Otherwise "ldap://host"
    # plus a ticked LDAPS box would try TLS on port 389.
    low = raw.lower()
    if low.startswith("gcs://"):
        raw, is_gc, use_ssl = raw[6:], True, True
    elif low.startswith("gc://"):
        raw, is_gc, use_ssl = raw[5:], True, False
    elif low.startswith("ldaps://"):
        raw, use_ssl = raw[8:], True
    elif low.startswith("ldap://"):
        raw, use_ssl = raw[7:], False
    else:
        use_ssl = bool(settings.ldap_use_ssl)

    # Split an optional ":port" off the host (leave bracketed IPv6 [..] alone).
    host = raw.rstrip("/")
    host_port = 0
    if not host.startswith("[") and host.count(":") == 1:
        maybe_host, _, maybe_port = host.partition(":")
        if maybe_port.isdigit():
            host, host_port = maybe_host, int(maybe_port)

    # Port priority: host suffix > explicitly set LDAP_PORT > scheme default.
    # The str() guard covers ldap_port arriving as a string (otherwise a string port
    # would reach ldap3 and produce "Source port must be an integer").
    try:
        configured = int(str(settings.ldap_port).strip() or 0)
    except (TypeError, ValueError):
        configured = 0
    port = host_port or configured
    if not port:
        if is_gc:
            port = GCS_PORT if use_ssl else GC_PORT
        else:
            port = LDAPS_PORT if use_ssl else LDAP_PORT

    return ldap3.Server(
        host,
        port=int(port),
        use_ssl=use_ssl,
        get_info=ldap3.NONE,
        connect_timeout=settings.ldap_connect_timeout_seconds,
    )


def build_ldap_server(ldap3):
    """Builds the connection target for ldap3 out of ``LDAP_SERVER``.

    The field may contain SEVERAL servers (comma or whitespace separated), up to
    ``LDAP_MAX_SERVERS``. The first is the primary one, the rest are failover targets.
    One server gives an ``ldap3.Server``, several give an ``ldap3.ServerPool`` (strategy
    FIRST: always use the primary, and only switch down the list once it fails). Each
    entry may carry its own scheme and port (see :func:`_build_one_server`).
    """
    specs = _split_server_specs(settings.ldap_server) or [""]
    if len(specs) > LDAP_MAX_SERVERS:
        log.warning(
            "auth.ldap.too_many_servers",
            given=len(specs), used=LDAP_MAX_SERVERS, ignored=specs[LDAP_MAX_SERVERS:],
        )
        specs = specs[:LDAP_MAX_SERVERS]

    servers = [_build_one_server(ldap3, s) for s in specs]
    if len(servers) == 1:
        return servers[0]

    # FIRST = primary first, on failure move down the list to the next reachable one.
    # active=1: ONE bounded check pass (active=True would loop forever if every server
    # is down), then a clean LDAPServerPoolExhaustedError.
    # exhaust=False: a server that is briefly unreachable stays in the pool.
    return ldap3.ServerPool(servers, ldap3.FIRST, active=1, exhaust=False)


def _search_principal(search_conn, identity: str) -> tuple[frozenset[str], str, str]:
    """Looks up ONE user in AD / the global catalog and reads groups, display name, mail.

    ``identity`` may be a sAMAccountName, a UPN (user@domain) or a mail address; all three
    are searched. That matters for SSO, where the IdP may hand over a different UPN suffix
    than the on-prem account carries. ``search_conn`` must already be bound: for password
    login that is the user or service bind, for the SSO group lookup the service account.
    Returns ``(group CNs, display_name, email)``.
    """
    sam = identity.split("@")[0].split("\\")[-1]
    upn = identity if "@" in identity else f"{sam}@{settings.ldap_domain}"
    # RFC 4515 escaping at the point of interpolation. The name is a VALUE to search
    # for, never part of the filter's structure: a bracket or a wildcard in it would
    # otherwise rewrite the query, and the groups of whatever account the rewritten
    # query returns are the ones that end up deciding the session's permissions. Only
    # the filter copies are escaped; ``sam`` is still used as the display-name fallback.
    f_upn, f_sam, f_identity = _ldap_escape(upn), _ldap_escape(sam), _ldap_escape(identity)
    search_conn.search(
        search_base=settings.ldap_base_dn,
        search_filter=(
            f"(&(objectClass=user)(|(userPrincipalName={f_upn})"
            f"(sAMAccountName={f_sam})(mail={f_identity})))"
        ),
        attributes=[settings.ldap_group_attr, "displayName", "cn", "mail", "userPrincipalName"],
    )
    groups: set[str] = set()
    display_name = sam
    email = ""
    if search_conn.entries:
        entry = search_conn.entries[0]
        raw_groups = entry[settings.ldap_group_attr].values if settings.ldap_group_attr in entry else []
        groups = {_cn_from_dn(str(g)) for g in raw_groups}
        if "displayName" in entry and entry["displayName"].value:
            display_name = str(entry["displayName"].value)
        elif "cn" in entry and entry["cn"].value:
            display_name = str(entry["cn"].value)
        if "mail" in entry and entry["mail"].value:
            email = str(entry["mail"].value)
        elif "userPrincipalName" in entry and entry["userPrincipalName"].value:
            email = str(entry["userPrincipalName"].value)
    return frozenset(groups), display_name, email


def lookup_groups(identity: str) -> tuple[frozenset[str], str, str]:
    """Loads AD / global catalog groups (plus display name and mail) for an identity,
    bound as the service account (``LDAP_BIND_USER``), WITHOUT the user password.

    This is for the SSO path: after a successful OIDC sign-in the groups are reloaded LIVE
    here and matched to permissions through the group-to-permission mapping (account
    store). Nothing about the user is stored. Returns ``(frozenset(), "", "")`` if no
    service account or base DN is set, or if AD cannot be reached. The SSO login then
    fails for lack of permissions, which is intended: no silent access.
    """
    identity = (identity or "").strip()
    if not identity:
        return frozenset(), "", ""
    if not (settings.ldap_bind_user and settings.ldap_base_dn):
        log.warning(
            "auth.lookup_groups.no_service_account",
            hint="The SSO group lookup needs LDAP_BIND_USER and LDAP_BASE_DN (service account).",
        )
        return frozenset(), "", ""

    try:
        import ldap3
        from ldap3.core.exceptions import LDAPException
    except ImportError:  # pragma: no cover - only relevant if LDAP is configured but the package is absent
        log.error("auth.lookup_groups.package_missing", hint="pip install ldap3 (in requirements.txt)")
        return frozenset(), "", ""

    server = build_ldap_server(ldap3)
    try:
        conn = ldap3.Connection(
            server,
            user=settings.ldap_bind_user,
            password=settings.ldap_bind_password,
            authentication=ldap3.SIMPLE,
            auto_bind=True,
        )
    except LDAPException as exc:
        log.warning("auth.lookup_groups.bind_failed", error=str(exc))
        return frozenset(), "", ""
    try:
        groups, display_name, email = _search_principal(conn, identity)
        log.info("auth.lookup_groups.ok", identity=identity, group_count=len(groups))
        return groups, display_name, email
    except LDAPException as exc:
        log.warning("auth.lookup_groups.search_failed", identity=identity, error=str(exc))
        return frozenset(), "", ""
    finally:
        try:
            conn.unbind()
        except Exception:  # pragma: no cover - best effort cleanup
            pass


def _ldap_escape(value: str) -> str:
    """RFC 4515 escaping for filter values (prevents filter injection)."""
    out = []
    for ch in value:
        if ch in "\\*()":
            out.append("\\%02x" % ord(ch))
        elif ch == "\0":
            out.append("\\00")
        else:
            out.append(ch)
    return "".join(out)


def _ldap_pattern(value: str) -> str:
    """User input becomes a filter value in which ``*`` acts as a wildcard.

    Everything except ``*`` is RFC 4515 escaped (no filter injection), and runs of ``*``
    are collapsed. Without a wildcard of its own the term is searched as a **substring**
    (``Connect`` becomes ``*Connect*``) so that hits in the middle of a word show up too;
    ``*Connect`` then deliberately matches only at the end.
    """
    import re

    pattern = "".join("*" if ch == "*" else _ldap_escape(ch) for ch in value)
    pattern = re.sub(r"\*+", "*", pattern)
    return pattern if "*" in pattern else f"*{pattern}*"


# Minimum input length WITHOUT wildcards: "*" on its own would pull the entire AD.
DIRECTORY_MIN_QUERY = 2
# Upper bound on hits per search (the UI shows them in a searchable list).
DIRECTORY_MAX_LIMIT = 500


def _dir_result(status: str, entries=(), detail: str = "") -> dict:
    """Uniform response of the directory search, carrying an **unambiguous** reason.

    ``status`` is one of ``ok``, ``too_short``, ``no_service_account``,
    ``package_missing``, ``bind_failed``, ``search_failed``. The UI shows the message that
    belongs to exactly that case instead of guessing between "no hits" and "not
    configured".
    """
    return {"status": status, "detail": detail, "entries": list(entries)}


def search_directory(query: str, kind: str, limit: int = 200) -> dict:
    """Searches AD / the global catalog for **users** or **groups**, bound as the service
    account (``LDAP_BIND_USER``). Used by the member picker in account management.

    ``query`` may contain wildcards (``*``): ``*Connect*`` finds everything with "Connect"
    in the name. Without a ``*`` the term is searched as a substring automatically (see
    :func:`_ldap_pattern`).

    Returns ``{status, detail, entries}`` (see :func:`_dir_result`). ``entries`` is the
    duplicate-free list ``{type, ref, display}`` sorted by display name, where ``ref`` is
    the sAMAccountName (user) or the CN (group)."""
    query = (query or "").strip()
    kind = "group" if str(kind).lower().startswith("group") else "user"
    limit = max(1, min(int(limit or 0) or 200, DIRECTORY_MAX_LIMIT))
    if len(query.replace("*", "").strip()) < DIRECTORY_MIN_QUERY:
        return _dir_result("too_short", detail=f"Enter at least {DIRECTORY_MIN_QUERY} characters (not counting *).")
    if not (settings.ldap_bind_user and settings.ldap_base_dn):
        log.warning("auth.search_directory.no_service_account")
        return _dir_result(
            "no_service_account",
            detail="No LDAP service account (bind user plus base DN) has been configured.",
        )

    try:
        import ldap3
        from ldap3.core.exceptions import LDAPException
    except ImportError:  # pragma: no cover
        log.error("auth.search_directory.package_missing")
        return _dir_result("package_missing", detail="The Python package 'ldap3' is missing on the server.")

    q = _ldap_pattern(query)
    if kind == "group":
        flt = f"(&(objectClass=group)(|(cn={q})(displayName={q})))"
        attrs = ["cn", "displayName"]
    else:
        flt = f"(&(objectClass=user)(objectCategory=person)(|(sAMAccountName={q})(displayName={q})(userPrincipalName={q})))"
        attrs = ["sAMAccountName", "displayName", "userPrincipalName"]

    server = build_ldap_server(ldap3)
    try:
        conn = ldap3.Connection(
            server, user=settings.ldap_bind_user, password=settings.ldap_bind_password,
            authentication=ldap3.SIMPLE, auto_bind=True,
        )
    except LDAPException as exc:
        log.warning("auth.search_directory.bind_failed", error=str(exc))
        return _dir_result("bind_failed", detail=str(exc))
    try:
        conn.search(search_base=settings.ldap_base_dn, search_filter=flt, attributes=attrs, size_limit=limit)
        out: list[dict] = []
        seen: set[str] = set()
        for entry in conn.entries:
            if kind == "group":
                ref = str(entry["cn"].value) if "cn" in entry and entry["cn"].value else ""
            else:
                ref = str(entry["sAMAccountName"].value) if "sAMAccountName" in entry and entry["sAMAccountName"].value else ""
            if not ref or ref.lower() in seen:  # show duplicates (several domains in the GC) only once
                continue
            seen.add(ref.lower())
            display = ref
            if "displayName" in entry and entry["displayName"].value:
                display = str(entry["displayName"].value)
            out.append({"type": "ad_group" if kind == "group" else "ad_user", "ref": ref, "display": display})
        out.sort(key=lambda e: (e["display"].lower(), e["ref"].lower()))
        log.info("auth.search_directory.ok", kind=kind, query=query, filter=flt, hits=len(out))
        return _dir_result("ok", out)
    except LDAPException as exc:
        log.warning("auth.search_directory.search_failed", error=str(exc))
        return _dir_result("search_failed", detail=str(exc))
    finally:
        try:
            conn.unbind()
        except Exception:  # pragma: no cover
            pass


def authenticate(username: str, password: str) -> LdapResult:
    """Bind against AD with the user credentials, then read the groups.

    ``ok=True`` only on a successful bind. If just the following group search fails (the
    bind was fine), the user counts as authenticated with an empty group set, and
    ``store.effective_for_ad`` then decides about access: no matching group means no
    permissions, which means the sign-in is rejected.
    """
    username = (username or "").strip()
    if not username or not password:
        return LdapResult(ok=False, error="Username or password missing.")
    if not settings.ldap_configured:
        return LdapResult(ok=False, error="AD is not configured.")

    # Keep the import local: without a configured AD the app stays usable without ldap3.
    try:
        import ldap3
        from ldap3.core.exceptions import LDAPException
    except ImportError:  # pragma: no cover - only relevant if LDAP is configured but the package is absent
        log.error("auth.ldap.package_missing", hint="pip install ldap3 (in requirements.txt)")
        return LdapResult(ok=False, error="LDAP support is not installed.")

    # Build the UPN (user@domain) unless it is already given as a UPN or DOMAIN\\user.
    upn = username if ("@" in username or "\\" in username) else f"{username}@{settings.ldap_domain}"
    # One OR several servers (failover) plus scheme and port resolution, global catalog included.
    server = build_ldap_server(ldap3)

    try:
        conn = ldap3.Connection(
            server, user=upn, password=password, authentication=ldap3.SIMPLE, auto_bind=True
        )
    except LDAPException as exc:
        log.info("auth.ldap.bind_failed", username=username, error=str(exc))
        return LdapResult(ok=False, error="Sign-in against AD failed.")

    try:
        # Search connection: the service account if one is configured, otherwise the user.
        search_conn = conn
        if settings.ldap_bind_user:
            try:
                search_conn = ldap3.Connection(
                    server,
                    user=settings.ldap_bind_user,
                    password=settings.ldap_bind_password,
                    authentication=ldap3.SIMPLE,
                    auto_bind=True,
                )
            except LDAPException as exc:
                log.warning("auth.ldap.service_bind_failed", error=str(exc))
                search_conn = conn

        sam = username.split("@")[0].split("\\")[-1]
        # Shared lookup (groups, display name, mail), the same logic as the SSO lookup.
        groups, display_name, _email = _search_principal(search_conn, username)
        log.info("auth.ldap.ok", username=sam, group_count=len(groups))
        return LdapResult(ok=True, username=sam, display_name=display_name, groups=groups)
    except LDAPException as exc:
        # The bind worked, so the user is authenticated; only the groups are missing.
        log.warning("auth.ldap.search_failed", username=username, error=str(exc))
        return LdapResult(ok=True, username=username.split("@")[0], display_name=username, groups=frozenset())
    finally:
        try:
            conn.unbind()
        except Exception:  # pragma: no cover - best effort cleanup
            pass
