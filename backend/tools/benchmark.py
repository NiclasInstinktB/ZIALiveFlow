"""Throughput benchmark of the ingest path (one core, no network).

Measures decode plus split('\\t') plus the positional prefilter (plus a full parse on
matches), which is exactly what happens per line in the TCP handler. Target: 1M/min,
about 16,667/s.

    python -m backend.tools.benchmark
"""
from __future__ import annotations

import time

from backend.ingest.hub import get_hub
from backend.ingest.models import FilterField, FilterSpec
from backend.tools.feed_sim import fw_line, web_line

N = 1_000_000
TARGET_PER_SEC = 1_000_000 / 60


def _prepare(ratio: float) -> list[bytes]:
    # Prepare the raw byte lines (not part of the measurement).
    import random

    out: list[bytes] = []
    for i in range(N):
        m = random.random() < ratio
        s = web_line(m) if (i % 2 == 0) else fw_line(m)
        out.append((s + "\n").encode("utf-8"))
    return out


def _run(name: str, lines: list[bytes]) -> None:
    hub = get_hub()
    hub.set_filters([FilterSpec(field=FilterField.SRC_IP, value="10.20.30.40")])
    handle = hub.handle_fields
    t0 = time.perf_counter()
    for raw in lines:
        fields = raw.decode("utf-8", "replace").rstrip("\r").split("\t")
        handle(fields)
    dt = time.perf_counter() - t0
    rate = N / dt
    print(
        f"{name:<28} {N:>9,} lines in {dt:6.2f}s  ->  {rate:>10,.0f}/s  "
        f"({rate * 60 / 1_000_000:5.2f} M/min)  |  {rate / TARGET_PER_SEC:4.1f}x target  "
        f"|  buffered: {hub.stats()['buffered']:,}"
    )


def main() -> None:
    print(f"Target: 1M/min = {TARGET_PER_SEC:,.0f}/s on ONE core\n")
    print("Realistic firehose (the filter matches roughly one in a thousand):")
    _run("  reject-only (0% matches)", _prepare(0.0))
    _run("  0.1% matches", _prepare(0.001))
    print("\nWorst case (everything is parsed and buffered):")
    _run("  100% matches", _prepare(1.0))


if __name__ == "__main__":
    main()
