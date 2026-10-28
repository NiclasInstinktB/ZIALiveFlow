#!/usr/bin/env bash
# Zscaler Admin UI: self-update.
# Pulls the latest version from git, rebuilds, and restarts the service.
# Runs as the app user (zscaler-admin), either manually or triggered by the systemd
# .path unit, which watches logs/update.trigger (written by the admin backend).
set -euo pipefail
cd "$(dirname "$0")/.."            # -> /opt/zscaler-admin-ui
BRANCH="${UPDATE_BRANCH:-main}"
SERVICE="${UPDATE_SERVICE:-zscaler-admin-ui}"

mkdir -p logs
exec >>"logs/update.log" 2>&1
echo "===== $(date -Is) update start (branch=$BRANCH) ====="

# Remove the trigger right away so the .path unit does not fire again.
rm -f logs/update.trigger

# Fetch the latest version (hard reset onto origin/<branch>).
git fetch --prune origin
git reset --hard "origin/${BRANCH}"

# Backend dependencies.
.venv/bin/pip install --upgrade pip >/dev/null
.venv/bin/pip install -r backend/requirements.txt

# Build the frontend.
( cd frontend && npm ci && npm run build )

# Restart the service (the narrow sudoers rule allows exactly this one command).
sudo /usr/bin/systemctl restart "${SERVICE}"
echo "===== $(date -Is) update done -> $(git rev-parse --short HEAD) ====="
