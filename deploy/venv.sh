#!/usr/bin/env bash
# Python venv on the newest installed Python, plus the backend dependencies.
# Called by setup.sh and update.sh, runs as the app user. Can also be run by hand:
#   sudo -u zscaler-admin bash /opt/zscaler-admin-ui/deploy/venv.sh
# PYTHON=/path/to/python3.x forces a specific interpreter.
set -euo pipefail
cd "$(dirname "$0")/.."            # -> /opt/zscaler-admin-ui

# anything older gets flagged by vulnerability scans, so warn loudly below this
WANT_MINOR=15

minor() { "$1" -c 'import sys; print(sys.version_info[1] if sys.version_info[0] == 3 else -1)' 2>/dev/null; }

# newest python3.x on PATH. python3 alone is often the ancient distro one, so look at all of them
pick() {
  if [ -n "${PYTHON:-}" ]; then command -v "$PYTHON"; return; fi
  local best="" best_m=-1 b m
  for b in python3 $(compgen -c python3. | grep -E '^python3\.[0-9]+$' | sort -u); do
    command -v "$b" >/dev/null 2>&1 || continue
    m="$(minor "$b")" || continue
    if [ -n "$m" ] && [ "$m" -gt "$best_m" ]; then best="$(command -v "$b")"; best_m="$m"; fi
  done
  echo "$best"
}

PY="$(pick || true)"
[ -n "$PY" ] || { echo "ERROR: no python3 found. Set PYTHON=/path/to/python3 and run again."; exit 1; }
NEW="$(minor "$PY")"
echo "  Python: $PY ($("$PY" --version 2>&1))"

# pyyaml (pulled in by uvicorn[standard]) has no wheel for a brand new Python and the
# servers have no compiler. pure python is fine, nothing here parses yaml on a hot path
export PYYAML_FORCE_LIBYAML=0

deps() { "$1/bin/python" -m pip install -q --upgrade pip && "$1/bin/python" -m pip install -q -r backend/requirements.txt; }

HAVE=-1
if [ -x .venv/bin/python ]; then HAVE="$(minor .venv/bin/python || echo -1)"; fi

if [ "$NEW" -lt "$WANT_MINOR" ] && [ "$HAVE" -lt "$WANT_MINOR" ]; then
  echo "  WARN: newest Python on this host is 3.$NEW. Install Python 3.$WANT_MINOR, the next update moves the venv over by itself."
fi

# same python, or the venv is somehow newer than what we found (never downgrade)
if [ "$HAVE" -ge "$NEW" ]; then
  deps .venv
  exit 0
fi

[ "$HAVE" -ge 0 ] && echo "  venv runs Python 3.$HAVE, rebuilding it on 3.$NEW"
# build next to the old one and only swap when everything installed. if the build
# breaks halfway the service keeps running on the old venv instead of on nothing
rm -rf .venv.new
if "$PY" -m venv .venv.new && deps .venv.new; then
  rm -rf .venv.old
  if [ -d .venv ]; then mv .venv .venv.old; fi
  mv .venv.new .venv
  # the scripts in bin/ have the build path baked in, point them at the real one
  find .venv/bin -maxdepth 1 -type f -exec grep -lI "$PWD/.venv.new" {} + 2>/dev/null \
    | xargs -r sed -i "s|$PWD/.venv.new|$PWD/.venv|g"
  rm -rf .venv.old
  echo "  venv now on $(.venv/bin/python --version 2>&1)"
else
  echo "  WARN: rebuilding the venv failed, keeping the old one"
  rm -rf .venv.new
  [ -d .venv ] || exit 1
  deps .venv
fi
