"""Hub: per-user view isolation plus field diagnostics."""
from __future__ import annotations

from backend.ingest.hub import Hub
from backend.ingest.models import FilterField, FilterGroup, FilterOp, FilterSpec


def _web(src, user, location="HQ"):
    # 39 fields; the order matches WEB_COLUMNS.
    return [
        "web", src, "1.1.1.1", user, location, "Mon Jul 21 10:00:00 2026", "IT", "Allowed", "",
        "HTTPS", "GET", "200", "800", "24000", "https://host/path", "host", "Cat", "Class",
        "App", "AppClass", "Rule", "RuleType", "TLSv1.3", "TLS_AES", "TLSv1.3", "", "", "0",
        "203.0.113.9", "UA", "Dev", user, "text/html",
        "Yes", "SSL-Pol", "", "URL-Pol", "Fwd-Rule", "GW-DE",
    ]


def test_view_isolation():
    hub = Hub()
    a = hub.register()
    a.set_filters([FilterSpec(field=FilterField.USER, value="alice@corp.example")])
    b = hub.register()
    b.set_filters([FilterSpec(field=FilterField.SRC_IP, value="10.0.0.9")])

    hub.handle_fields(_web("10.0.0.1", "alice@corp.example"))  # A only
    hub.handle_fields(_web("10.0.0.9", "bob@corp.example"))    # B only
    hub.handle_fields(_web("10.0.0.5", "carol@corp.example"))  # nobody

    assert a.stats()["matched"] == 1
    assert b.stats()["matched"] == 1
    sa, sb = a.snapshot(), b.snapshot()
    assert len(sa) == 1 and sa[0]["user"] == "alice@corp.example"
    assert len(sb) == 1 and sb[0]["src_ip"] == "10.0.0.9"


def test_view_filter_groups_and_across_fields():
    """The case that used to be impossible: source AND destination at the same time."""
    hub = Hub()
    v = hub.register()
    v.set_filters(
        [
            FilterGroup(op=FilterOp.OR, items=[
                FilterSpec(field=FilterField.SRC_IP, value="10.0.0.1"),
                FilterSpec(field=FilterField.SRC_IP, value="10.0.0.2"),
            ]),
            FilterGroup(op=FilterOp.OR, items=[
                FilterSpec(field=FilterField.LOCATION, value="Site-1"),
            ]),
        ],
        FilterOp.AND,
    )
    hub.handle_fields(_web("10.0.0.1", "a@b", location="Site-1"))  # both groups
    hub.handle_fields(_web("10.0.0.2", "a@b", location="Site-1"))  # both groups
    hub.handle_fields(_web("10.0.0.1", "a@b", location="HQ"))      # location does not match
    hub.handle_fields(_web("10.0.0.9", "a@b", location="Site-1"))  # source does not match
    assert v.stats()["matched"] == 2
    assert v.stats()["join"] == "and"


def test_view_flat_filter_list_stays_or():
    """Legacy behaviour: a flat spec list stays ONE OR group."""
    hub = Hub()
    v = hub.register()
    v.set_filters([
        FilterSpec(field=FilterField.SRC_IP, value="10.0.0.1"),
        FilterSpec(field=FilterField.SRC_IP, value="10.0.0.2"),
    ])
    hub.handle_fields(_web("10.0.0.1", "a@b"))
    hub.handle_fields(_web("10.0.0.2", "a@b"))
    hub.handle_fields(_web("10.0.0.3", "a@b"))
    assert v.stats()["matched"] == 2
    assert v.stats()["groups"] == [{"op": "or", "items": [
        {"field": "src_ip", "value": "10.0.0.1"},
        {"field": "src_ip", "value": "10.0.0.2"},
    ]}]


def test_view_without_filter_gets_nothing():
    hub = Hub()
    v = hub.register()  # no filter set
    hub.handle_fields(_web("10.0.0.1", "a@b"))
    assert v.stats()["matched"] == 0


def test_unregister_stops_delivery():
    hub = Hub()
    v = hub.register()
    v.set_filters([FilterSpec(field=FilterField.USER, value="a@b")])
    hub.unregister(v)
    hub.handle_fields(_web("10.0.0.1", "a@b"))
    assert v.stats()["matched"] == 0


def test_feed_diagnostics():
    hub = Hub()
    hub.handle_fields(_web("10.0.0.1", "a@b"))
    hub.handle_fields(_web("10.0.0.2", "c@d"))
    health = {h["feed"]: h for h in hub.feed_health()}
    assert health["web"]["lines"] == 2
    assert health["web"]["last_field_count"] == 39
    assert health["web"]["expected_cols"] == 39
    assert health["web"]["short_lines"] == 0
    assert hub.global_stats()["total_lines"] == 2


def test_short_line_detected():
    hub = Hub()
    hub.handle_fields(["web", "10.0.0.1", "1.1.1.1"])  # far too short
    health = {h["feed"]: h for h in hub.feed_health()}
    assert health["web"]["short_lines"] == 1


def test_recent_samples_collected_without_filter():
    hub = Hub()  # NO views or filters, but the sample must still be filled
    for i in range(64):
        hub.handle_fields(_web(f"10.0.0.{i % 250}", "u@x"))
    samples = hub.recent_samples()
    assert len(samples) >= 1  # sampled (every 16th line), so several hits
    assert samples[-1]["logtype"] == "web"
    assert samples[-1]["rule"] == "Rule"  # the field value is ready for suggestions


def _dns(src, user="u@x"):
    # 25 fields; the order matches DNS_COLUMNS.
    return [
        "dns", src, "192.0.2.53", user, "HQ", "1784628000000", "IT",
        "portal.example.com", "A", "Allow", "Req-Rule", "203.0.113.50", "A", "Allow", "Res-Rule", "NOERROR",
        "Cat", "Business", "App", "AppCat", "53", "UDP", "12", "Dev", user,
    ]


def test_dns_feed_diagnostics():
    hub = Hub()
    hub.handle_fields(_dns("10.0.0.1"))
    health = {h["feed"]: h for h in hub.feed_health()}
    assert health["dns"]["lines"] == 1
    assert health["dns"]["expected_cols"] == 25
    assert health["dns"]["short_lines"] == 0
    assert hub.global_stats()["other_lines"] == 0


def test_view_feed_selection():
    """Turning DNS off means no DNS lines, even when the filter matches."""
    hub = Hub()
    spec = [FilterSpec(field=FilterField.SRC_IP, value="10.0.0.1")]
    everything = hub.register()
    everything.set_filters(spec)
    no_dns = hub.register()
    no_dns.set_filters(spec, feeds=frozenset({"web", "fw"}))
    only_dns = hub.register()
    only_dns.set_filters(spec, feeds=frozenset({"dns"}))

    hub.handle_fields(_web("10.0.0.1", "u@x"))
    hub.handle_fields(_dns("10.0.0.1"))

    assert everything.stats()["matched"] == 2
    assert [r["logtype"] for r in no_dns.snapshot()] == ["web"]
    assert [r["logtype"] for r in only_dns.snapshot()] == ["dns"]
    assert no_dns.stats()["feeds"] == ["fw", "web"]
    assert everything.stats()["feeds"] == ["dns", "fw", "web"]


# ── A rejected group must not widen an AND join ───────────────────
def _src(v):
    return FilterSpec(field=FilterField.SRC_IP, value=v)


def _dst(v):
    return FilterSpec(field=FilterField.DST_IP, value=v)


def test_and_join_dropped_when_a_group_is_rejected():
    """``compile_groups`` already protects an AND group whose condition is discarded;
    the same has to hold for an AND join BETWEEN groups.

    What arrives: the operator asks for "source in 10.20.30.0/24 AND destination in
    10.0.0.0/8". The /8 is rejected by the server protection, so only the source group
    survives. Joined with AND, that leaves "source in 10.20.30.0/24" against ANY
    destination, which is far more than was asked for, and it is exactly the flood the
    CIDR guard exists to prevent.
    """
    hub = Hub()
    v = hub.register()
    v.set_filters(
        [
            FilterGroup(op=FilterOp.OR, items=[_src("10.20.30.0/24")]),
            FilterGroup(op=FilterOp.OR, items=[_dst("10.0.0.0/8")]),
        ],
        FilterOp.AND,
    )
    # Destination 203.0.113.9 is not in 10.0.0.0/8, so this line was never asked for.
    hub.handle_fields(_web("10.20.30.5", "a@b"))
    assert v.stats()["matched"] == 0
    assert v.snapshot() == []


def test_and_join_survives_when_every_group_compiles():
    """The guard must not break the normal case."""
    hub = Hub()
    v = hub.register()
    v.set_filters(
        [
            FilterGroup(op=FilterOp.OR, items=[_src("10.0.0.1")]),
            FilterGroup(op=FilterOp.OR, items=[_dst("1.1.1.1")]),
        ],
        FilterOp.AND,
    )
    hub.handle_fields(_web("10.0.0.1", "a@b"))
    assert v.stats()["matched"] == 1


def test_or_join_keeps_the_groups_that_compiled():
    """With OR between the groups a dropped group makes the filter NARROWER, which is the
    safe direction, so the rest stays active."""
    hub = Hub()
    v = hub.register()
    v.set_filters(
        [
            FilterGroup(op=FilterOp.OR, items=[_src("10.0.0.1")]),
            FilterGroup(op=FilterOp.OR, items=[_dst("10.0.0.0/8")]),  # rejected
        ],
        FilterOp.OR,
    )
    hub.handle_fields(_web("10.0.0.1", "a@b"))
    assert v.stats()["matched"] == 1


# ── Feed selection: the three edge cases ──────────────────────────
def _only(feeds):
    hub = Hub()
    v = hub.register()
    v.set_filters([FilterSpec(field=FilterField.SRC_IP, value="10.0.0.1")], feeds=feeds)
    hub.handle_fields(_web("10.0.0.1", "u@x"))
    hub.handle_fields(_dns("10.0.0.1"))
    return v


def test_no_feed_key_means_every_feed():
    """An older client does not send the key at all, and must keep seeing everything."""
    v = _only(None)
    assert v.stats()["matched"] == 2
    assert v.stats()["feeds"] == ["dns", "fw", "web"]


def test_selecting_every_feed_is_the_same_as_selecting_none():
    v = _only(frozenset({"web", "fw", "dns"}))
    assert v.stats()["matched"] == 2
    assert v.stats()["feeds"] == ["dns", "fw", "web"]


def test_an_empty_selection_delivers_nothing():
    """Asking for no feed has to mean no feed, not silently all of them."""
    v = _only(frozenset())
    assert v.stats()["matched"] == 0
    assert v.stats()["feeds"] == []


def test_an_unknown_feed_name_delivers_nothing():
    """Fail closed: a name the server does not know must not open the whole firehose."""
    v = _only(frozenset({"smtp"}))
    assert v.stats()["matched"] == 0


def test_an_unknown_name_alongside_a_known_one_keeps_the_known_one():
    v = _only(frozenset({"smtp", "dns"}))
    assert [r["logtype"] for r in v.snapshot()] == ["dns"]


def test_setting_filters_again_without_feeds_restores_every_feed():
    """Documented protocol: the feeds key absent means all feeds."""
    hub = Hub()
    v = hub.register()
    spec = [FilterSpec(field=FilterField.SRC_IP, value="10.0.0.1")]
    v.set_filters(spec, feeds=frozenset({"web"}))
    assert v.stats()["feeds"] == ["web"]
    v.set_filters(spec)
    assert v.stats()["feeds"] == ["dns", "fw", "web"]
    hub.handle_fields(_dns("10.0.0.1"))
    assert v.stats()["matched"] == 1
