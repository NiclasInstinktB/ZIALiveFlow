#!/usr/bin/env bash
# Zscaler Admin UI: installation on SUSE (SLES/openSUSE), run as ROOT.
#
# Precondition: the repo is already cloned to /opt/zscaler-admin-ui
#   (e.g. git clone https://git.example.com/your-org/Zscaler-Admin-UI.git /opt/zscaler-admin-ui)
#
# Afterwards: put the certificate into /etc/ssl/zscaler-admin-ui/, check .env (JWT_SECRET!),
# and open the firewall for the NSS feed IPs. See docs/DEPLOY.md for details.
set -euo pipefail

APP=zscaler-admin-ui
SVCUSER=zscaler-admin
DIR=/opt/$APP

[ "$(id -u)" -eq 0 ] || { echo "Please run as root."; exit 1; }
[ -d "$DIR/.git" ] || { echo "No repo at $DIR. Clone it there first."; exit 1; }

# NOTHING is installed via zypper. python3 (3.11+), node, npm, git and nginx
# are expected to be present already; this script only uses what is there.
echo "== Selecting an existing Python =="
PYBIN="${PYTHON:-}"
if [ -z "$PYBIN" ]; then
  for b in python3.12 python3.11 python3; do
    command -v "$b" >/dev/null 2>&1 && { PYBIN="$b"; break; }
  done
fi
[ -n "$PYBIN" ] && command -v "$PYBIN" >/dev/null 2>&1 || {
  echo "ERROR: no python3 on PATH. (Set PYTHON=/path/to/python3 and run again.)"; exit 1;
}
echo "  Python: $PYBIN ($("$PYBIN" --version 2>&1))"

echo "== Checking for required tools (warning only, nothing is installed) =="
for t in git nginx node npm; do
  command -v "$t" >/dev/null 2>&1 || echo "  WARN: '$t' not on PATH. Check this; other apps may rely on it."
done

echo "== Service group and user =="
# On SUSE, 'useradd' does NOT create a group of the same name automatically, so create it here.
getent group "$SVCUSER" >/dev/null || groupadd -r "$SVCUSER"
# -M: do not create a home directory (home IS the already cloned repo directory).
id "$SVCUSER" &>/dev/null || useradd -r -M -d "$DIR" -g "$SVCUSER" "$SVCUSER"
# Make sure the primary group is set (in case the user was created earlier without one).
usermod -g "$SVCUSER" "$SVCUSER" 2>/dev/null || true

echo "== Directories and permissions =="
mkdir -p "$DIR/backend/data" "$DIR/logs" "/etc/ssl/$APP"
chown -R "$SVCUSER:$SVCUSER" "$DIR"
chmod 750 "/etc/ssl/$APP"
# Mark the git repo as trusted system-wide (avoids the "dubious ownership" error).
git config --system --add safe.directory "$DIR" 2>/dev/null || true

echo "== Build (venv + frontend) as $SVCUSER =="
sudo -u "$SVCUSER" PYTHON="$PYBIN" bash "$DIR/deploy/setup.sh"

echo "== systemd units =="
install -m644 "$DIR/deploy/$APP.service"         "/etc/systemd/system/$APP.service"
install -m644 "$DIR/deploy/$APP-update.service"  "/etc/systemd/system/$APP-update.service"
install -m644 "$DIR/deploy/$APP-update.path"     "/etc/systemd/system/$APP-update.path"

echo "== sudoers (restart only) =="
install -m440 "$DIR/deploy/$APP.sudoers" "/etc/sudoers.d/$APP"
visudo -cf "/etc/sudoers.d/$APP"

echo "== nginx vHost =="
install -m644 "$DIR/deploy/nginx-$APP.conf" "/etc/nginx/vhosts.d/$APP.conf"

echo "== Firewall =="
firewall-cmd --permanent --add-service=http  >/dev/null || true
firewall-cmd --permanent --add-service=https >/dev/null || true
# Allow the NSS ingest ports ONLY from the NSS servers. Enter your IP(s) here:
#   for ip in 192.0.2.10 192.0.2.11; do
#     firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=$ip port port=5140 protocol=tcp accept"
#     firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=$ip port port=5141 protocol=tcp accept"
#   done
firewall-cmd --reload >/dev/null || true

echo "== Enabling services =="
systemctl daemon-reload
systemctl enable --now "$APP.service" "$APP-update.path"

if nginx -t; then
  systemctl reload nginx
else
  echo "!! nginx config is invalid (is the certificate in place?). After fixing: systemctl reload nginx"
fi

echo
echo "DONE. Checklist:"
echo "  1) Certificate: /etc/ssl/$APP/fullchain.pem + privkey.pem (root:root, key chmod 600)"
echo "  2) $DIR/.env: set JWT_SECRET, SESSION_COOKIE_SECURE=true, check INGEST_BIND_HOST"
echo "  3) Open the firewall for the NSS feed IPs (see above)"
echo "  4) DNS: zscaler-admin.example.com -> this host"
echo "  5) Restart: systemctl restart $APP && systemctl status $APP"
