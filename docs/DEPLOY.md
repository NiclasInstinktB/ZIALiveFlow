# Deployment (Linux, behind nginx)

This guide covers one specific deployment: the app running as a systemd service
on `127.0.0.1:8001`, with nginx terminating TLS and proxying to it. The NSS
ingest ports (5140/5141/5142) are bound by the app itself, not by nginx. It is a
Linux-only setup because it relies on systemd and nginx. For plain local or
cross-platform startup, see the README.

Tested on SUSE (SLES/openSUSE). On other distributions everything works the
same way except for the package and firewall steps.

## Requirements

`python3` (3.11+), `node`, `npm`, `git`, `nginx`. The installer deliberately
does not install anything: it uses what is already on the system.

## 1. Clone and install

```bash
sudo git clone https://github.com/NiclasInstinktB/ZIALiveFlow.git /opt/zscaler-admin-ui
sudo bash /opt/zscaler-admin-ui/deploy/install-suse.sh
```

The installer creates the service user and group, builds the venv and the
frontend, and installs the systemd units, the nginx vHost, and a narrow sudoers
rule that permits nothing but restarting this one service.

## 2. Configure

Create `.env` from the template and set at least the following:

```bash
cd /opt/zscaler-admin-ui
sudo -u zscaler-admin cp .env.example .env
sudo -u zscaler-admin vi .env
```

| Variable | Value |
|---|---|
| `JWT_SECRET` | `python3 -c "import secrets; print(secrets.token_urlsafe(48))"` |
| `SESSION_COOKIE_SECURE` | `true` (when behind TLS) |
| `INGEST_BIND_HOST` | the interface the NSS servers can reach |
| `INGEST_ALLOWED_IPS` | the IP addresses of the NSS servers |
| `FEED_TIMEZONE` | the time zone of the feeds, see [NSS-FEEDS.md](NSS-FEEDS.md) |

## 3. Certificate

Put `fullchain.pem` and `privkey.pem` into `/etc/ssl/zscaler-admin-ui/`
(owned by `root:root`, key `chmod 600`), then set `server_name` in
`deploy/nginx-zscaler-admin-ui.conf` to your own hostname.

## 4. Firewall

Allow the ingest ports **only** from the NSS servers:

```bash
for ip in <NSS-IP-1> <NSS-IP-2>; do
  firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=$ip port port=5140 protocol=tcp accept"
  firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=$ip port port=5141 protocol=tcp accept"
  # Only needed if you run the DNS feed. Leave it out, or set INGEST_DNS_PORT=0, if not.
  firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=$ip port port=5142 protocol=tcp accept"
done
firewall-cmd --reload
```

## 5. Start and verify

```bash
sudo systemctl restart zscaler-admin-ui
sudo systemctl status  zscaler-admin-ui
curl -sk https://<hostname>/api/health
```

On the **first start** the app creates an admin account. If
`ADMIN_INITIAL_PASSWORD` is not set, a random password is written to the log
**once**:

```bash
sudo journalctl -u zscaler-admin-ui | grep bootstrap
```

Log in with it and change the password.

To check whether both feeds arrive complete, open **Admin -> Overview -> Field
diagnostics**, which compares the expected and the actual field count per feed.

## Troubleshooting

```bash
sudo journalctl -u zscaler-admin-ui -f     # service log
ss -ltnp | grep -E ':8001|:5140|:5141|:5142'  # are the ports listening?
sudo tcpdump -nAi any 'tcp port 5140' -c 5 # is feed data arriving?
nginx -t                                    # vHost syntax
```
