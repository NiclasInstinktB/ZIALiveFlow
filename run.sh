#!/usr/bin/env bash
# Thin wrapper around serve.py for Linux and macOS. Windows users run:
#   .venv\Scripts\python serve.py
set -euo pipefail
cd "$(dirname "$0")"
PY=".venv/bin/python"
[ -x "$PY" ] || { echo "No virtual environment found. Run: python3 install.py" >&2; exit 1; }
exec "$PY" serve.py "$@"
