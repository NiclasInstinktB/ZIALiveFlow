#!/usr/bin/env bash
# Thin wrapper around manage.py for Linux and macOS. Windows users run:
#   .venv\Scripts\python manage.py <command>
set -euo pipefail
cd "$(dirname "$0")"
PY=".venv/bin/python"
[ -x "$PY" ] || PY="python3"
exec "$PY" manage.py "$@"
