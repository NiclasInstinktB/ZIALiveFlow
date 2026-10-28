"""Anonymized log view: masking of personally identifiable fields.

Belongs to the ``logs_obf`` permission (:mod:`backend.auth.models`). Anyone allowed to see
the live flow only in anonymized form gets the personal fields as ``***``.

**Server side, not in the frontend.** The masking happens right before sending, so the
clear text never leaves the process. That way it also covers everything the client derives
from the records: query search, chip counters, CSV export and the detail view all operate
on ``***`` only.

Deliberately a **full blackout** (no partial masking, no pseudonym): a remainder such as
``n***@example.com`` would often still be traceable given typical naming schemes. Anyone
who needs to follow a single person filters by source IP instead; the user field is blocked
as a filter (see ``api/stream_routes.py``).

Empty fields stay empty: the UI keeps showing a placeholder dash there rather than a
masking token, which would wrongly suggest that a value exists.
"""
from __future__ import annotations

MASK = "***"

# Fields from ``FlowRecord.as_dict()`` that identify a person:
#   user         → the user's e-mail or login name (the main field)
#   dept         → department; combined with location this narrows down to a few people fast
#   device_name  → device name, often something like "NB-LASTNAME"
#   device_owner → device owner, effectively the person's real name
REDACTED_FIELDS: tuple[str, ...] = ("user", "dept", "device_name", "device_owner")


def redact(payload: dict) -> dict:
    """Shallow copy of the record dict with the personal fields masked.

    A copy rather than in-place: the hub hands the same payload dict to ALL matching views
    (``hub.handle_fields``), so masking in place would destroy the clear-text view of the
    other users along with it.
    """
    out = dict(payload)
    for field in REDACTED_FIELDS:
        if out.get(field):
            out[field] = MASK
    return out


def redact_all(payloads: list[dict]) -> list[dict]:
    """``redact()`` applied over a list (snapshot or sample records)."""
    return [redact(p) for p in payloads]
