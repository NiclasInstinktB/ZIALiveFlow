"""The two shipped tools: the feed simulator and the throughput benchmark.

Both are documented in the README as the way to try the app without a real NSS server and
to check the ingest path still carries the load. Nothing else imports them, so nothing
else notices when they stop working: that is exactly why they need tests.
"""
from __future__ import annotations

import time

import pytest

from backend.config import DNS_COLUMNS, FW_COLUMNS, WEB_COLUMNS
from backend.ingest import hub as hub_module
from backend.ingest import parser
from backend.ingest.hub import Hub
from backend.ingest.models import FilterField, FilterGroup, FilterOp, FilterSpec
from backend.ingest.timestamps import to_epoch
from backend.tools import benchmark, feed_sim


# ── feed_sim ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "maker, columns, tag",
    [
        (feed_sim.web_line, WEB_COLUMNS, "web"),
        (feed_sim.fw_line, FW_COLUMNS, "fw"),
        (feed_sim.dns_line, DNS_COLUMNS, "dns"),
    ],
)
@pytest.mark.parametrize("match", [True, False])
def test_simulated_lines_match_the_column_schema(maker, columns, tag, match):
    """A simulator one column out of step teaches people the wrong field layout."""
    for _ in range(50):
        fields = maker(match).split(feed_sim.TAB)
        assert len(fields) == len(columns)
        assert fields[0] == tag
        record = parser.parse(fields, 1, 0.0)
        assert record is not None and record.logtype == tag


def test_the_advertised_filters_really_match():
    """The simulator prints three filters to try. They have to work, or the first thing
    anyone does with this app shows an empty table."""
    groups = parser.compile_groups([
        FilterGroup(op=FilterOp.OR, items=[
            FilterSpec(field=FilterField.SRC_IP, value=feed_sim.MATCH_SRC),
        ]),
    ])
    user_groups = parser.compile_groups([
        FilterGroup(op=FilterOp.OR, items=[
            FilterSpec(field=FilterField.USER, value=feed_sim.MATCH_USER),
        ]),
    ])
    loc_groups = parser.compile_groups([
        FilterGroup(op=FilterOp.OR, items=[
            FilterSpec(field=FilterField.LOCATION, value=feed_sim.MATCH_LOCATION),
        ]),
    ])
    for maker in (feed_sim.web_line, feed_sim.fw_line, feed_sim.dns_line):
        fields = maker(True).split(feed_sim.TAB)
        assert parser.wants(fields, groups)
        assert parser.wants(fields, user_groups)
        assert parser.wants(fields, loc_groups)
        # And a non-matching line must not slip through.
        assert not parser.wants(maker(False).split(feed_sim.TAB), groups)


def test_simulated_timestamps_are_readable():
    """Web sends asctime in the feed zone, firewall and DNS send epoch milliseconds."""
    now = time.time()
    web_ts = feed_sim.web_line(True).split(feed_sim.TAB)[5]
    fw_ts = feed_sim.fw_line(True).split(feed_sim.TAB)[5]
    assert to_epoch(web_ts) is not None
    assert abs(to_epoch(fw_ts) - now) < 60


# ── benchmark ──────────────────────────────────────────────────────


def test_benchmark_runs_against_the_current_hub_api(monkeypatch, capsys):
    """Filters moved to per-connection views, so the hub itself has neither
    ``set_filters`` nor ``stats``.

    What happens: ``python -m backend.tools.benchmark`` dies on the first line of the
    first run with ``AttributeError: 'Hub' object has no attribute 'set_filters'``, so
    the one tool that says whether the ingest path still carries 1M/min cannot be run at
    all.
    """
    monkeypatch.setattr(hub_module, "_hub", Hub())
    monkeypatch.setattr(benchmark, "N", 200)

    benchmark._run("probe", benchmark._prepare(1.0))

    out = capsys.readouterr().out
    assert "probe" in out and "buffered:" in out
    # Every matching line was buffered: half the lines are web, half firewall, and the
    # filter matches all of them.
    assert "buffered: 200" in out


def test_benchmark_counts_only_matches(monkeypatch, capsys):
    monkeypatch.setattr(hub_module, "_hub", Hub())
    monkeypatch.setattr(benchmark, "N", 200)
    benchmark._run("none", benchmark._prepare(0.0))
    assert "buffered: 0" in capsys.readouterr().out


def test_benchmark_leaves_no_view_behind(monkeypatch, capsys):
    """Each run has to clean up, or the next one delivers into the previous view too and
    measures something other than it claims."""
    hub = Hub()
    monkeypatch.setattr(hub_module, "_hub", hub)
    monkeypatch.setattr(benchmark, "N", 100)
    benchmark._run("first", benchmark._prepare(1.0))
    benchmark._run("second", benchmark._prepare(1.0))
    capsys.readouterr()
    assert hub.global_stats()["active_views"] == 0
