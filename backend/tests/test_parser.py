"""Parser, filter and verdict tests."""
from __future__ import annotations

from backend.ingest import parser
from backend.ingest.models import FilterField, FilterGroup, FilterOp, FilterSpec, Verdict


def _web(src, dst, user, action="Allowed", proto="HTTPS", status="200",
         resp="24000", tls="TLSv1.3", reason="", location="HQ"):
    # 33 fields; the order matches WEB_COLUMNS.
    return ["web", src, dst, user, location, "Mon Jul 21 10:00:00 2026", "IT", action, reason,
            proto, "GET", status, "800", resp, "https://host/path", "host", "Cat", "Class",
            "App", "AppClass", "Rule", "RuleType", tls, "TLS_AES", tls, "", "", "0",
            "203.0.113.9", "UA", "Dev", user, "text/html"]


def _fw(src, dst, user, action="Allow", inb="48000", outb="3000", location="HQ"):
    # 25 fields; the order matches FW_COLUMNS.
    return ["fw", src, dst, user, location, "Mon Jul 21 10:00:00 2026", "IT", action, "TCP",
            "51000", "443", dst, "443", "198.51.100.90", inb, outb, "1200", "HTTPS", "GitHub",
            "Cat", "Allow-Rule", "Germany", "IPSEC", "No", "1"]


def _c(*specs):
    """One OR group built from the specs, the shape ``wants`` expects."""
    return parser.compile_groups([FilterGroup(op=FilterOp.OR, items=list(specs))])


def _and(*specs):
    return parser.compile_groups([FilterGroup(op=FilterOp.AND, items=list(specs))])


def _src(v):
    return FilterSpec(field=FilterField.SRC_IP, value=v)


def _dst(v):
    return FilterSpec(field=FilterField.DST_IP, value=v)


def test_wants_positional_match():
    specs = _c(FilterSpec(field=FilterField.SRC_IP, value="10.20.30.40"))
    assert parser.wants(_web("10.20.30.40", "1.1.1.1", "a@b"), specs)
    assert not parser.wants(_web("10.20.30.99", "1.1.1.1", "a@b"), specs)


def test_wants_user_case_insensitive():
    specs = _c(FilterSpec(field=FilterField.USER, value="Alice@Corp.Example"))
    assert parser.wants(_web("10.0.0.1", "1.1.1.1", "alice@corp.example"), specs)


def test_wants_dst_ip():
    specs = _c(FilterSpec(field=FilterField.DST_IP, value="198.51.100.4"))
    assert parser.wants(_fw("10.0.0.1", "198.51.100.4", "a@b"), specs)


def test_wants_location():
    specs = _c(FilterSpec(field=FilterField.LOCATION, value="Berlin-HQ"))
    assert parser.wants(_web("10.0.0.1", "1.1.1.1", "a@b", location="Berlin-HQ"), specs)
    assert not parser.wants(_web("10.0.0.1", "1.1.1.1", "a@b", location="Site-A-Plant"), specs)


def test_wants_location_case_insensitive():
    specs = _c(FilterSpec(field=FilterField.LOCATION, value="berlin-hq"))
    assert parser.wants(_fw("10.0.0.1", "1.1.1.1", "a@b", location="Berlin-HQ"), specs)


def test_wants_location_wildcard():
    specs = _c(FilterSpec(field=FilterField.LOCATION, value="*-Plant"))
    assert parser.wants(_web("10.0.0.1", "1.1.1.1", "a@b", location="Site-A-Plant"), specs)
    assert not parser.wants(_web("10.0.0.1", "1.1.1.1", "a@b", location="Berlin-HQ"), specs)


def test_cidr_24():
    specs = _c(FilterSpec(field=FilterField.SRC_IP, value="10.20.30.0/24"))
    assert parser.wants(_web("10.20.30.1", "1.1.1.1", "a@b"), specs)
    assert parser.wants(_web("10.20.30.254", "1.1.1.1", "a@b"), specs)
    assert not parser.wants(_web("10.20.31.1", "1.1.1.1", "a@b"), specs)


def test_cidr_23():
    # a /23 covers .30.x AND .31.x
    specs = _c(FilterSpec(field=FilterField.SRC_IP, value="10.20.30.0/23"))
    assert parser.wants(_web("10.20.30.5", "1.1.1.1", "a@b"), specs)
    assert parser.wants(_web("10.20.31.200", "1.1.1.1", "a@b"), specs)
    assert not parser.wants(_web("10.20.32.1", "1.1.1.1", "a@b"), specs)


def test_cidr_dst_ip():
    specs = _c(FilterSpec(field=FilterField.DST_IP, value="198.51.100.0/24"))
    assert parser.wants(_fw("10.0.0.1", "198.51.100.4", "a@b"), specs)
    assert not parser.wants(_fw("10.0.0.1", "198.51.101.4", "a@b"), specs)


def test_cidr_host_notation():
    # /32 means an exact IP; a non-matching IP falls through
    specs = _c(FilterSpec(field=FilterField.SRC_IP, value="10.20.30.40/32"))
    assert parser.wants(_web("10.20.30.40", "1.1.1.1", "a@b"), specs)
    assert not parser.wants(_web("10.20.30.41", "1.1.1.1", "a@b"), specs)


def test_cidr_too_broad_rejected():
    # /23 and /24 are allowed (one compiled filter each in the group).
    assert len(_c(_src("10.20.30.0/23"))[0][1]) == 1
    assert len(_c(_dst("10.20.30.0/24"))[0][1]) == 1
    # /8 and /22 are too wide, so they are discarded (server protection) and never match.
    assert _c(_src("10.0.0.0/8")) == []
    assert _c(_src("10.20.28.0/22")) == []
    dropped = _c(_src("10.0.0.0/8"))
    assert not parser.wants(_web("10.1.2.3", "1.1.1.1", "a@b"), dropped)


def test_no_filter_drops_everything():
    assert not parser.wants(_web("10.0.0.1", "1.1.1.1", "a@b"), [])


def test_wildcard_src_ip():
    specs = _c(FilterSpec(field=FilterField.SRC_IP, value="10.20.30.*"))
    assert parser.wants(_web("10.20.30.40", "1.1.1.1", "a@b"), specs)
    assert parser.wants(_web("10.20.30.255", "1.1.1.1", "a@b"), specs)
    assert not parser.wants(_web("10.20.31.40", "1.1.1.1", "a@b"), specs)


def test_wildcard_user_suffix():
    specs = _c(FilterSpec(field=FilterField.USER, value="*@corp.example"))
    assert parser.wants(_web("10.0.0.1", "1.1.1.1", "Alice@Corp.Example"), specs)
    assert not parser.wants(_web("10.0.0.1", "1.1.1.1", "bob@other.example"), specs)


def test_wildcard_no_partial_overmatch():
    # 10.20.30.4* may match 10.20.30.4x but not 10.20.31.40 (anchored at the end).
    specs = _c(FilterSpec(field=FilterField.DST_IP, value="10.20.30.4?"))
    assert parser.wants(_fw("1.1.1.1", "10.20.30.41", "a@b"), specs)
    assert not parser.wants(_fw("1.1.1.1", "10.20.30.410", "a@b"), specs)


# ── AND/OR: joining the groups ────────────────────────────────────
def test_group_or_matches_either():
    g = _c(_src("10.0.0.1"), _src("10.0.0.2"))
    assert parser.wants(_web("10.0.0.1", "1.1.1.1", "a@b"), g)
    assert parser.wants(_web("10.0.0.2", "1.1.1.1", "a@b"), g)
    assert not parser.wants(_web("10.0.0.3", "1.1.1.1", "a@b"), g)


def test_group_and_requires_both():
    g = _and(_src("10.0.0.1"), _dst("1.1.1.1"))
    assert parser.wants(_web("10.0.0.1", "1.1.1.1", "a@b"), g)
    assert not parser.wants(_web("10.0.0.1", "8.8.8.8", "a@b"), g)
    assert not parser.wants(_web("10.0.0.9", "1.1.1.1", "a@b"), g)


def test_join_and_across_groups():
    # (source A OR source B) AND destination C, the case that used to be impossible.
    groups = parser.compile_groups([
        FilterGroup(op=FilterOp.OR, items=[_src("10.0.0.1"), _src("10.0.0.2")]),
        FilterGroup(op=FilterOp.OR, items=[_dst("1.1.1.1")]),
    ])
    assert parser.wants(_web("10.0.0.1", "1.1.1.1", "a@b"), groups, "and")
    assert parser.wants(_web("10.0.0.2", "1.1.1.1", "a@b"), groups, "and")
    assert not parser.wants(_web("10.0.0.1", "8.8.8.8", "a@b"), groups, "and")
    assert not parser.wants(_web("10.0.0.9", "1.1.1.1", "a@b"), groups, "and")
    # With OR in between we are back to the old, broad behaviour.
    assert parser.wants(_web("10.0.0.1", "8.8.8.8", "a@b"), groups, "or")


def test_join_or_with_and_group():
    # source A OR (source B AND destination C)
    groups = parser.compile_groups([
        FilterGroup(op=FilterOp.OR, items=[_src("10.0.0.1")]),
        FilterGroup(op=FilterOp.AND, items=[_src("10.0.0.2"), _dst("1.1.1.1")]),
    ])
    assert parser.wants(_web("10.0.0.1", "8.8.8.8", "a@b"), groups, "or")
    assert parser.wants(_web("10.0.0.2", "1.1.1.1", "a@b"), groups, "or")
    assert not parser.wants(_web("10.0.0.2", "8.8.8.8", "a@b"), groups, "or")


def test_and_group_dropped_when_condition_rejected():
    # If an AND condition falls victim to the server protection, the group would match
    # more broadly than asked for, so the whole group is discarded.
    groups = parser.compile_groups([
        FilterGroup(op=FilterOp.AND, items=[_src("10.0.0.0/8"), _dst("1.1.1.1")]),
    ])
    assert groups == []
    assert not parser.wants(_web("10.0.0.1", "1.1.1.1", "a@b"), groups, "and")


def test_empty_groups_drop_everything():
    assert not parser.wants(_web("10.0.0.1", "1.1.1.1", "a@b"), [], "and")
    assert not parser.wants(_web("10.0.0.1", "1.1.1.1", "a@b"), [], "or")


def test_verdict_blocked():
    rec = parser.parse(_web("10.0.0.1", "1.1.1.1", "a@b", action="Blocked", status="0", resp="0"), 1, 0.0)
    assert rec.verdict == Verdict.BLOCKED.value
    assert rec.severity == "bad"


def test_verdict_ssl_failed():
    rec = parser.parse(_web("10.0.0.1", "1.1.1.1", "a@b", proto="SSL", tls="", status="0", resp="0"), 1, 0.0)
    assert rec.verdict == Verdict.SSL_FAILED.value


def test_verdict_no_response_web():
    rec = parser.parse(_web("10.0.0.1", "1.1.1.1", "a@b", status="0", resp="0", tls="TLSv1.2"), 1, 0.0)
    assert rec.verdict == Verdict.NO_RESPONSE.value


def test_verdict_http_error():
    rec = parser.parse(_web("10.0.0.1", "1.1.1.1", "a@b", status="503", resp="500"), 1, 0.0)
    assert rec.verdict == Verdict.HTTP_ERROR.value


def test_verdict_allowed_web():
    rec = parser.parse(_web("10.0.0.1", "1.1.1.1", "a@b"), 1, 0.0)
    assert rec.verdict == Verdict.ALLOWED.value
    assert rec.severity == "good"


def test_fw_no_response():
    rec = parser.parse(_fw("10.0.0.1", "1.1.1.1", "a@b", inb="0", outb="1200"), 1, 0.0)
    assert rec.verdict == Verdict.NO_RESPONSE.value
    assert rec.bytes_rx == 0
    assert rec.bytes_tx == 1200


def test_fw_ports_parsed():
    rec = parser.parse(_fw("10.0.0.1", "1.1.1.1", "a@b"), 1, 0.0)
    assert rec.src_port == 51000
    assert rec.dst_port == 443
    assert rec.logtype == "fw"


def test_web_rich_fields():
    rec = parser.parse(_web("10.0.0.1", "1.1.1.1", "a@b", location="Berlin-HQ"), 1, 0.0)
    assert rec.location == "Berlin-HQ"
    assert rec.dept == "IT"
    assert rec.host == "host"
    assert rec.app_name == "App"
    assert rec.user_agent == "UA"
    assert rec.device_name == "Dev"
    assert rec.client_public_ip == "203.0.113.9"
    assert rec.target == "https://host/path"


def test_fw_rich_fields():
    rec = parser.parse(_fw("10.0.0.1", "1.1.1.1", "a@b"), 1, 0.0)
    assert rec.target == "GitHub"          # firewall: target = nwApp
    assert rec.app_name == "GitHub"
    assert rec.dest_country == "Germany"
    assert rec.tunnel_type == "IPSEC"
    assert rec.server_ip == "1.1.1.1"
    assert rec.client_public_ip == "198.51.100.90"


def test_unknown_type_ignored():
    assert parser.parse(["smtp", "x", "y", "z"], 1, 0.0) is None


def _dns(src, user="a@b", req_action="Allow", res_action="Allow", response="203.0.113.50",
         error="NOERROR", query="portal.example.com"):
    # 25 fields; the order matches DNS_COLUMNS.
    return ["dns", src, "192.0.2.53", user, "HQ", "1784628000000", "IT",
            query, "A", req_action, "Req-Rule", response, "A", res_action, "Res-Rule", error,
            "Professional Services", "Business", "GitHub", "Business",
            "53", "UDP", "12", "Dev", user]


def test_dns_fields_and_target():
    rec = parser.parse(_dns("10.0.0.1"), 1, 0.0)
    assert rec.logtype == "dns"
    assert rec.target == "portal.example.com"
    assert rec.host == "portal.example.com"   # host= hits web and DNS lines alike
    assert rec.dns_response == "203.0.113.50"
    assert rec.dns_req_type == "A"
    assert rec.dst_ip == "192.0.2.53" and rec.dst_port == 53
    assert rec.category == "Professional Services"
    assert rec.ts_epoch == 1784628000.0
    assert rec.verdict == Verdict.ALLOWED.value
    assert rec.reason == ""                   # NOERROR is not a reason


def test_dns_request_block_uses_request_rule():
    rec = parser.parse(_dns("10.0.0.1", req_action="Block", response="", error=""), 1, 0.0)
    assert rec.verdict == Verdict.BLOCKED.value
    assert rec.action == "Block" and rec.rule == "Req-Rule"


def test_dns_response_block_uses_response_rule():
    rec = parser.parse(_dns("10.0.0.1", res_action="Block"), 1, 0.0)
    assert rec.verdict == Verdict.BLOCKED.value
    assert rec.rule == "Res-Rule"


def test_dns_error_and_no_answer():
    nx = parser.parse(_dns("10.0.0.1", response="", error="NXDOMAIN"), 1, 0.0)
    assert nx.verdict == Verdict.DNS_ERROR.value
    assert nx.severity == "warn"
    assert nx.reason == "NXDOMAIN"
    silent = parser.parse(_dns("10.0.0.1", response="", error=""), 1, 0.0)
    assert silent.verdict == Verdict.NO_RESPONSE.value


def test_dns_prefilter_positions():
    assert parser.wants(_dns("10.0.0.1"), _c(_src("10.0.0.1")))
    assert parser.wants(_dns("10.0.0.1"), _c(_dst("192.0.2.53")))


def test_feed_restriction():
    groups = _c(_src("10.0.0.1"))
    assert parser.wants(_dns("10.0.0.1"), groups, feeds=None)
    assert not parser.wants(_dns("10.0.0.1"), groups, feeds=frozenset({"web", "fw"}))
    assert parser.wants(_web("10.0.0.1", "1.1.1.1", "a@b"), groups, feeds=frozenset({"web", "fw"}))
