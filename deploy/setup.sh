#!/usr/bin/env bash
# Zscaler Admin UI: first-time install and build (runs as the app user, in the repo directory).
#   sudo -u zscaler-admin bash /opt/zscaler-admin-ui/deploy/setup.sh
# Python: the newest python3.x on PATH, see deploy/venv.sh. PYTHON=... overrides it.
set -euo pipefail
cd "$(dirname "$0")/.."            # -> /opt/zscaler-admin-ui

echo "== venv =="
bash deploy/venv.sh

echo "== .env =="
[ -f .env ] || { cp .env.example .env; echo "  Created .env from .env.example. Set JWT_SECRET!"; }

echo "== frontend build =="
( cd frontend && npm ci && npm run build )

mkdir -p backend/data logs
echo "Setup complete. Next: deploy/install-suse.sh (as root)."
