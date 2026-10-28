"""Process-wide runtime values (e.g. the start time used by the uptime display)."""
from __future__ import annotations

import time

STARTED_AT: float = time.time()
