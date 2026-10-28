"""Line parser plus positional prefilter plus verdict derivation.

The prefilter (:func:`wants`) decides **without a full parse**, from the first columns
(type/src/dst/user), whether a line is of any interest at all. Only on a match is the
line normalized into a :class:`FlowRecord`.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import re

from backend.config import COL_DST_IP, COL_LOCATION, COL_SRC_IP, COL_USER, FEED_COLUMNS
from backend.ingest.models import (
    SEVERITY,
    FilterField,
    FilterGroup,
    FilterOp,
    FilterSpec,
    FlowRecord,
    Verdict,
)
from backend.ingest.timestamps import to_epoch
from backend.logging_config import get_logger

log = get_logger("ingest.parser")

# One precompiled filter: (field, matcher). The matcher is either an exact string (a fast
# == comparison), an IP network (CIDR membership) or a compiled regex (wildcard * / ?).
CompiledFilter = tuple[str, object]
# One precompiled group: (op, filters). ``op`` is "and" or "or".
CompiledGroup = tuple[str, list[CompiledFilter]]

_IP_FIELDS = {FilterField.SRC_IP.value, FilterField.DST_IP.value}
_Network = (ipaddress.IPv4Network, ipaddress.IPv6Network)

# Largest filter network allowed: /23 (= 512 IPv4 addresses). Wider networks such as /8
# would produce enormous result sets and topple the server under load, so such filters
# are discarded here (a safeguard that does not rely on the frontend check).
_MIN_IPV4_PREFIX = 23
_MIN_IPV6_PREFIX = 64

# ReDoS protection: at most 3 '*' per filter value. More wildcards translate into many
# consecutive ``.*`` (fnmatch.translate) and can trigger catastrophic backtracking in the
# shared ingest loop. Such filters are discarded.
_MAX_WILDCARDS = 3


def compile_specs(specs: list[FilterSpec]) -> list[CompiledFilter]:
    """Precompile the filters ONCE when they are set, so the hot loop stays cheap.

    - IP fields containing ``/`` → CIDR network (e.g. ``10.20.30.0/24`` or ``/23``),
      matched by subnet membership.
    - Values containing ``*`` or ``?`` → glob regex.
    - Everything else → exact string.
    User/location are case insensitive, IPs are exact.
    """
    out: list[CompiledFilter] = []
    for spec in specs:
        s = spec.normalized()
        value = s.value
        field = s.field.value
        if field in _IP_FIELDS and "/" in value:
            try:
                net = ipaddress.ip_network(value, strict=False)
            except ValueError:
                net = None
            if net is not None:
                min_prefix = _MIN_IPV4_PREFIX if net.version == 4 else _MIN_IPV6_PREFIX
                if net.prefixlen < min_prefix:
                    # Network too wide (e.g. /8): discard it rather than overload the server.
                    log.warning("filter.cidr_too_broad", field=field, value=value, prefix=net.prefixlen)
                    continue
                out.append((field, net))
                continue
            # not a valid CIDR → falls through to the string/wildcard handling below
        if "*" in value or "?" in value:
            if value.count("*") > _MAX_WILDCARDS:
                # Too many wildcards: discard (ReDoS protection) rather than risk the loop.
                log.warning("filter.too_many_wildcards", field=field, value=value, stars=value.count("*"))
                continue
            flags = re.IGNORECASE if field in (FilterField.USER.value, FilterField.LOCATION.value) else 0
            out.append((field, re.compile(fnmatch.translate(value), flags)))
        else:
            out.append((field, value))
    return out


def compile_groups(groups: list[FilterGroup]) -> list[CompiledGroup]:
    """Precompile the groups; empty groups drop out.

    This matters for AND groups: if ``compile_specs`` discards one condition (CIDR too
    wide, too many wildcards), the group would match **more broadly** than was asked for.
    So in that case the whole AND group is dropped: better no match at all than silently
    too many.
    """
    out: list[CompiledGroup] = []
    for group in groups:
        g = group.normalized()
        if not g.items:
            continue
        compiled = compile_specs(g.items)
        if not compiled:
            continue
        if g.op is FilterOp.AND and len(compiled) < len(g.items):
            log.warning("filter.and_group_incomplete", kept=len(compiled), wanted=len(g.items))
            continue
        out.append((g.op.value, compiled))
    return out

_BLOCK_ACTIONS = {"block", "blocked", "drop", "dropped", "deny", "denied", "reset"}
_SSL_PROTOS = {"ssl", "https", "http_proxy_ssl", "tls"}
# DNS "errors" that are none: on a successful lookup the field is empty, "None" or
# "NOERROR", depending on the console.
_DNS_NO_ERROR = {"", "none", "noerror", "no_error", "0", "na", "n/a"}


def _int(s: str) -> int:
    try:
        return int(s)
    except (ValueError, TypeError):
        return 0


def _opt_int(s: str) -> int | None:
    try:
        return int(s)
    except (ValueError, TypeError):
        return None


def _hit(field: str, matcher: object, src: str, dst: str, user: str, loc: str) -> bool:
    """A single precompiled filter checked against the positional values of one line."""
    if field == "src_ip":
        val = src
    elif field == "dst_ip":
        val = dst
    elif field == "user":
        val = user
    else:  # location
        val = loc
    if isinstance(matcher, str):
        return val == matcher
    if isinstance(matcher, _Network):  # CIDR: subnet membership
        try:
            return ipaddress.ip_address(val) in matcher
        except ValueError:
            return False  # the field is not a valid IP → no match
    # compiled glob regex (fnmatch.translate anchors at the end)
    return bool(matcher.match(val))


def wants(
    fields: list[str],
    groups: list[CompiledGroup],
    join: str = "and",
    feeds: frozenset[str] | None = None,
) -> bool:
    """Positional match against the precompiled groups.

    Two levels: inside a group its own operator joins the conditions, between the groups
    it is ``join``. That makes ``(source A OR source B) AND destination C`` just as
    expressible as ``source A OR (source B AND destination C)``, without anyone having to
    guess a bracket precedence rule.

    ``feeds`` narrows this to certain type tags (``None`` = all). The check comes first:
    DNS is by far the loudest feed, and whoever turns it off should not pay for a filter
    comparison on it either.

    With no active filters nothing is of interest, so everything is dropped (deliberately
    lean).
    """
    if not groups:
        return False
    if feeds is not None and (not fields or fields[0].strip().lower() not in feeds):
        return False
    n = len(fields)
    src = fields[COL_SRC_IP] if n > COL_SRC_IP else ""
    dst = fields[COL_DST_IP] if n > COL_DST_IP else ""
    user = fields[COL_USER].lower() if n > COL_USER else ""
    loc = fields[COL_LOCATION].lower() if n > COL_LOCATION else ""
    join_or = join == "or"
    for op, compiled in groups:
        if op == "and":
            group_hit = all(_hit(f, m, src, dst, user, loc) for f, m in compiled)
        else:
            group_hit = any(_hit(f, m, src, dst, user, loc) for f, m in compiled)
        if join_or:
            if group_hit:
                return True
        elif not group_hit:
            return False
    return not join_or


def _is_block(action: str) -> bool:
    act = action.strip().lower()
    return any(b in act for b in _BLOCK_ACTIONS)


def _dns_decision(row: dict[str, str]) -> tuple[str, str]:
    """Action and rule of a DNS line: request and response are decided separately.

    What counts is the stage that blocked. Otherwise a lookup blocked on the response
    would be shown with the (permitting) request rule. Without a block the response
    wins, because it is the later decision.
    """
    req_action, res_action = row.get("dns_req_action", ""), row.get("dns_res_action", "")
    req_rule, res_rule = row.get("dns_req_rule", ""), row.get("dns_res_rule", "")
    if _is_block(req_action):
        return req_action, req_rule
    if _is_block(res_action):
        return res_action, res_rule
    return res_action or req_action, res_rule or req_rule


def _compute_verdict(logtype: str, action: str, proto: str, tls_version: str,
                     http_status: str, bytes_rx: int, dns_error: str = "",
                     dns_response: str = "") -> str:
    if _is_block(action):
        return Verdict.BLOCKED.value

    if logtype == "dns":
        # DNS has no byte counters: "return traffic" here means did an answer come back?
        if dns_error.strip().lower() not in _DNS_NO_ERROR:
            return Verdict.DNS_ERROR.value
        return Verdict.ALLOWED.value if dns_response.strip() else Verdict.NO_RESPONSE.value

    if logtype == "web":
        if proto.strip().lower() in _SSL_PROTOS and not tls_version.strip():
            return Verdict.SSL_FAILED.value
        code = _int(http_status[:3]) if http_status[:1].isdigit() else 0
        if 400 <= code <= 599:
            return Verdict.HTTP_ERROR.value

    if bytes_rx == 0:
        return Verdict.NO_RESPONSE.value
    return Verdict.ALLOWED.value


def parse(fields: list[str], seq: int, received_at: float) -> FlowRecord | None:
    """Builds a normalized record from a tab-separated line (already split)."""
    if not fields:
        return None
    logtype = fields[0].strip().lower()
    columns = FEED_COLUMNS.get(logtype)
    if columns is None:
        return None

    # Map positionally onto column names (missing columns stay empty).
    row: dict[str, str] = {}
    for i, name in enumerate(columns):
        row[name] = fields[i] if i < len(fields) else ""

    ts_raw = row.get("ts", "")
    bytes_rx = _int(row.get("bytes_rx", ""))
    if logtype == "dns":
        action, rule = _dns_decision(row)
        # The error code goes into "reason", so the status column shows NXDOMAIN and
        # friends without needing a column of its own.
        error = row.get("dns_error", "")
        reason = "" if error.strip().lower() in _DNS_NO_ERROR else error
    else:
        action, rule, reason = row.get("action", ""), row.get("rule", ""), row.get("reason", "")
    verdict = _compute_verdict(
        logtype,
        action,
        row.get("proto", ""),
        row.get("tls_version", ""),
        row.get("http_status", ""),
        bytes_rx,
        row.get("dns_error", ""),
        row.get("dns_response", ""),
    )

    return FlowRecord(
        id=seq,
        received_at=received_at,
        logtype=logtype,
        ts=ts_raw,
        ts_epoch=to_epoch(ts_raw),
        user=row.get("user", ""),
        location=row.get("location", ""),
        dept=row.get("dept", ""),
        src_ip=row.get("src_ip", ""),
        src_port=_opt_int(row.get("src_port", "")),
        dst_ip=row.get("dst_ip", ""),
        dst_port=_opt_int(row.get("dst_port", "")),
        server_ip=row.get("server_ip", ""),
        server_port=_opt_int(row.get("server_port", "")),
        client_public_ip=row.get("client_public_ip", ""),
        proto=row.get("proto", ""),
        action=action,
        target=row.get("target", "") or row.get("dns_query", "") or row.get("app_name", ""),
        host=row.get("host", "") or row.get("dns_query", ""),
        reason=reason,
        rule=rule,
        rule_type=row.get("rule_type", ""),
        bytes_tx=_int(row.get("bytes_tx", "")),
        bytes_rx=bytes_rx,
        http_method=row.get("http_method", ""),
        http_status=row.get("http_status", ""),
        category=row.get("category", ""),
        url_class=row.get("url_class", ""),
        app_name=row.get("app_name", ""),
        app_class=row.get("app_class", ""),
        nwservice=row.get("nwservice", ""),
        tls_version=row.get("tls_version", ""),
        tls_cipher=row.get("tls_cipher", ""),
        server_tls_version=row.get("server_tls_version", ""),
        threat_name=row.get("threat_name", ""),
        threat_category=row.get("threat_category", ""),
        risk_score=_opt_int(row.get("risk_score", "")),
        user_agent=row.get("user_agent", ""),
        device_name=row.get("device_name", ""),
        device_owner=row.get("device_owner", ""),
        content_type=row.get("content_type", ""),
        dest_country=row.get("dest_country", ""),
        tunnel_type=row.get("tunnel_type", ""),
        dnat=row.get("dnat", ""),
        num_sessions=_opt_int(row.get("num_sessions", "")),
        duration_ms=_opt_int(row.get("duration_ms", "")),
        ssl_inspected=row.get("ssl_inspected", ""),
        ssl_policy=row.get("ssl_policy", ""),
        ssl_policy_reason=row.get("ssl_policy_reason", ""),
        url_policy=row.get("url_policy", ""),
        fwd_rule=row.get("fwd_rule", ""),
        gateway=row.get("gateway", ""),
        flow_type=row.get("flow_type", ""),
        dns_req_type=row.get("dns_req_type", ""),
        dns_req_action=row.get("dns_req_action", ""),
        dns_req_rule=row.get("dns_req_rule", ""),
        dns_response=row.get("dns_response", ""),
        dns_res_type=row.get("dns_res_type", ""),
        dns_res_action=row.get("dns_res_action", ""),
        dns_res_rule=row.get("dns_res_rule", ""),
        dns_error=row.get("dns_error", ""),
        dns_res_ip_cat=row.get("dns_res_ip_cat", ""),
        verdict=verdict,
        severity=SEVERITY.get(Verdict(verdict), "info"),
    )
