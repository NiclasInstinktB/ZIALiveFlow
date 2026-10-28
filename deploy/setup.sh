#!/usr/bin/env bash
# Zscaler Admin UI: first-time install and build (runs as the app user, in the repo directory).
#   sudo -u zscaler-admin PYTHON=python3.12 bash /opt/zscaler-admin-ui/deploy/setup.sh
set -euo pipefail
cd "$(dirname "$0")/.."            # -> /opt/zscaler-admin-ui
PY="${PYTHON:-python3}"

echo "== venv =="
[ -d .venv ] || "$PY" -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r backend/requirements.txt

echo "== .env =="
[ -f .env ] || { cp .env.example .env; echo "  Created .env from .env.example. Set JWT_SECRET!"; }

echo "== frontend build =="
( cd frontend && npm ci && npm run build )

mkdir -p backend/data logs
echo "Setup complete. Next: deploy/install-suse.sh (as root)."
