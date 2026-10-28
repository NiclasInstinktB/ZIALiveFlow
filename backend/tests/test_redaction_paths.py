"""The anonymized view as a guarantee, not as a display option.

``test_obfuscation.py`` covers the permission logic and the HTTP and WebSocket surface.
What is pinned here is the layer underneath, where a leak would be invisible from the
outside:

* the record dict is **shared** by every view the line matched, so masking for one
  session must not reach the others, and masking for one session must not be skipped
  because another already handled it,
* the hub keeps the parsed records themselves (ring buffer and sample buffer), so masking
  a copy must never reach back into them,
* no field of the normalized schema other than the four masked ones may carry a personal
  value through, however the feed lays its columns out.
"""
from __future__ import annotations

from backend.ingest import parser
from backend.ingest.hub import Hub
from backend.ingest.models import FilterField, FilterSpec, FlowRecord
from backend.ingest.redact import MASK, REDACTED_FIELDS, redact, redact_all

# Values that appear nowhere else, so finding one in a masked record means it leaked.
PERSON = {
    "user": "unique.person@example.com",
    "dept": "Unique-Department",
    "device_name": "UNIQUE-DEVICE-NAME",
    "device_owner": "Unique Person Fullname",
}


def _web() -> list[str]:
    """39 fields, the order matching WEB_COLUMNS."""
    return [
        "web", "10.0.0.1", "1.1.1.1", PERSON["user"], "Site-1",
        "Mon Jul 21 10:00:00 2026", PERSON["dept"], "Allowed", "", "HTTPS", "GET", "200",
        "800", "24000", "https://host/path", "host", "Cat", "Class", "App", "AppClass",
        "Rule", "RuleType", "TLSv1.3", "TLS_AES", "TLSv1.3", "", "", "0", "203.0.113.9",
        "UA", PERSON["device_name"], PERSON["device_owner"], "text/html",
        "Yes", "SSL-Pol", "", "URL-Pol", "Fwd-Rule", "GW-DE",
    ]


def _dns() -> list[str]:
    """25 fields, the order matching DNS_COLUMNS. DNS carries the device columns too."""
    return [
        "dns", "10.0.0.1", "192.0.2.53", PERSON["user"], "Site-1", "1784628000000",
        PERSON["dept"], "portal.example.com", "A", "Allow", "Req-Rule", "203.0.113.50",
        "A", "Allow", "Res-Rule", "NOERROR", "Cat", "Business", "App", "AppCat",
        "53", "UDP", "12", PERSON["device_name"], PERSON["device_owner"],
    ]


def _fw() -> list[str]:
    """27 fields, the order matching FW_COLUMNS. The firewall feed has no device columns."""
    return [
        "fw", "10.0.0.1", "198.51.100.4", PERSON["user"], "Site-1", "1784628000000",
        PERSON["dept"], "Allow", "TCP", "51000", "443", "198.51.100.4", "443",
        "198.51.100.90", "48000", "3000", "1200", "HTTPS", "GitHub", "Cat", "Rule",
        "Germany", "IPSEC", "No", "1", "Fwd-Rule", "Direct",
    ]


def _leaks(masked: dict) -> list[str]:
    """Every key of the masked record still carrying a personal value."""
    secrets = set(PERSON.values())
    return sorted(k for k, v in masked.items() if isinstance(v, str) and v in secrets)


# ── No field of the schema gets a personal value through ───────────


def test_no_field_leaks_on_a_web_line():
    masked = redact(parser.parse(_web(), 1, 0.0).as_dict())
    assert _leaks(masked) == []
    assert all(masked[f] == MASK for f in REDACTED_FIELDS)


def test_no_field_leaks_on_a_dns_line():
    masked = redact(parser.parse(_dns(), 1, 0.0).as_dict())
    assert _leaks(masked) == []
    assert masked["device_name"] == MASK and masked["device_owner"] == MASK


def test_no_field_leaks_on_a_firewall_line():
    masked = redact(parser.parse(_fw(), 1, 0.0).as_dict())
    assert _leaks(masked) == []
    assert masked["user"] == MASK and masked["dept"] == MASK


def test_every_masked_field_exists_in_the_schema():
    """A field renamed in FlowRecord but not here would silently stop being masked."""
    schema = FlowRecord(id=1, received_at=0.0, logtype="web", ts="").as_dict()
    assert set(REDACTED_FIELDS) <= set(schema)


# ── The shared record dict ─────────────────────────────────────────


def test_masking_for_one_view_leaves_the_other_views_untouched():
    """The hub builds ONE payload dict and hands it to every matching view. If masking
    were in place, an anonymized session would black out the clear-text sessions too."""
    hub = Hub()
    plain, anonymized = hub.register(), hub.register()
    spec = [FilterSpec(field=FilterField.SRC_IP, value="10.0.0.1")]
    plain.set_filters(spec)
    anonymized.set_filters(spec)
    hub.handle_fields(_web())

    shared = plain.queue.get_nowait()
    assert anonymized.queue.get_nowait() is shared  # precondition: the same object

    masked = redact(shared)
    assert masked["user"] == MASK
    assert shared["user"] == PERSON["user"]          # the clear-text session is intact
    assert plain.snapshot()[0]["user"] == PERSON["user"]


def test_masking_does_not_reach_the_buffered_record():
    """``snapshot()`` builds the dicts fresh, so a masked copy must not write back into
    the ring buffer and anonymize the record for everyone who reads it later."""
    hub = Hub()
    view = hub.register()
    view.set_filters([FilterSpec(field=FilterField.SRC_IP, value="10.0.0.1")])
    hub.handle_fields(_web())

    redact_all(view.snapshot())
    assert view.snapshot()[0]["user"] == PERSON["user"]
    assert view.snapshot()[0]["device_owner"] == PERSON["device_owner"]


def test_masking_does_not_reach_the_sample_buffer():
    """The sampled example records feed the chip editor and the field suggestions. An
    anonymized reader gets a masked copy; the next clear-text reader must not."""
    hub = Hub()
    for _ in range(16):  # the sample buffer takes every sixteenth line
        hub.handle_fields(_web())
    assert redact_all(hub.recent_samples())[-1]["user"] == MASK
    assert hub.recent_samples()[-1]["user"] == PERSON["user"]


def test_masking_twice_changes_nothing():
    """Both the snapshot and the live record pass through ``redact``; a second pass over
    an already masked record must not turn ``***`` into anything else."""
    once = redact(parser.parse(_web(), 1, 0.0).as_dict())
    twice = redact(once)
    assert twice == once


def test_an_empty_personal_field_is_not_turned_into_a_mask():
    """``***`` where the feed sent nothing would claim a value that never existed."""
    line = _web()
    line[6] = ""    # dept
    line[31] = ""   # device_owner
    masked = redact(parser.parse(line, 1, 0.0).as_dict())
    assert masked["dept"] == "" and masked["device_owner"] == ""
    assert masked["user"] == MASK
