"""Feed simulator: sends synthetic web, firewall and DNS lines to the TCP listeners.

For testing without a real NSS server. It produces lines in the exact feed format (tab
separated, column 0 = type) matching ``WEB_COLUMNS`` / ``FW_COLUMNS`` / ``DNS_COLUMNS``
and sprinkles in
matches for a known client IP, user and location, so you can set a filter in the UI and
see flows right away.

    python -m backend.tools.feed_sim --host 127.0.0.1 --count 200 --rate 20

Filters to try in the UI:
    source IP = 10.20.30.40, user = alice@corp.example, location = Site-HQ
"""
from __future__ import annotations

import argparse
import random
import socket
import time

from backend.config import DNS_COLUMNS, FW_COLUMNS, WEB_COLUMNS, settings

TAB = "\t"

# Recurring match values (positions 1/3/4 = src_ip / user / location).
MATCH_SRC = "10.20.30.40"
MATCH_USER = "alice@corp.example"
MATCH_LOCATION = "Site-HQ"
NOISE_SRCS = ["10.99.0.5", "10.88.7.7", "172.16.4.9", "10.20.30.41"]
NOISE_LOCS = ["Site-A-Plant", "Site-B-Plant", "Remote-VPN", "Site-C-HQ"]
HOSTS = ["portal.example.com", "api.github.com", "updates.microsoft.com", "cdn.jsdelivr.net"]
DEPTS = ["IT", "Engineering", "Sales", "HR"]
CLOUD_APPS = ["GitHub", "Microsoft 365", "Salesforce", "Dropbox"]
DEVICES = ["NB-4711", "WKS-0815", "MAC-2201"]
COUNTRIES = ["United States", "Germany", "Ireland", "Netherlands"]
# Forwarding and URL policy rules. SIPA (ZPA) runs through a forwarding rule, and that
# is what makes the flow recognizable in the firewall log without a separate ZPA feed.
WEB_RULES = ["URL-Filter-Default", "Allow-Business-Apps", "Block-Adult-Content", "SIPA-ZPA-Forward"]
FW_RULES = ["SIPA-ZPA-Forward", "Allow-Internet-Direct", "Default-Forwarding", "Block-Malware-C2"]


def _web_ts() -> str:
    """Web feed = ``%s{time}`` → asctime in the feed zone (local time here)."""
    return time.strftime("%a %b %d %H:%M:%S %Y")


def _fw_ts() -> str:
    """Firewall feed = ``%d{epochtime}`` → epoch milliseconds (zone independent)."""
    return str(int(time.time() * 1000))


def web_line(match: bool) -> str:
    src = MATCH_SRC if match else random.choice(NOISE_SRCS)
    user = MATCH_USER if match else "bob@corp.example"
    loc = MATCH_LOCATION if match else random.choice(NOISE_LOCS)
    host = random.choice(HOSTS)
    app = random.choice(CLOUD_APPS)
    scenario = random.random()
    threat_name = threat_cat = ""
    risk = "0"
    if scenario < 0.15:          # blocked
        action, respcode, respsize, tlsver, reason = "Blocked", "0", "0", "", "URL Category Block"
        proto = "HTTPS"
    elif scenario < 0.3:         # SSL never gets established
        action, respcode, respsize, tlsver, reason = "Allowed", "0", "0", "", "SSL handshake failed"
        proto = "SSL"
    elif scenario < 0.45:        # no return traffic
        action, respcode, respsize, tlsver, reason = "Allowed", "0", "0", "TLSv1.2", ""
        proto = "HTTPS"
    elif scenario < 0.6:         # HTTP error
        action, respcode, respsize, tlsver, reason = "Allowed", "503", "512", "TLSv1.2", ""
        proto = "HTTPS"
    elif scenario < 0.68:        # malware detected
        action, respcode, respsize, tlsver, reason = "Blocked", "0", "0", "TLSv1.3", "Malware detected"
        proto = "HTTPS"
        threat_name, threat_cat, risk = "EICAR-Test", "Virus", "95"
    else:                        # fine
        action, respcode, respsize, tlsver, reason = "Allowed", "200", "24051", "TLSv1.3", ""
        proto = "HTTPS"
    rule = "Block-Adult-Content" if action == "Blocked" else random.choice(WEB_RULES)
    fields = [
        "web", src, "203.0.113.20", user, loc, _web_ts(), random.choice(DEPTS), action, reason, proto,
        "GET", respcode, "812", respsize, f"https://{host}/path", host, "Professional Services",
        "Business Use", app, "Business", rule, "URL Filtering", tlsver, "TLS_AES_256_GCM",
        tlsver, threat_name, threat_cat, risk, "203.0.113.9",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", random.choice(DEVICES), user, "text/html",
        # added later: ssl_inspected, ssl_policy, ssl_policy_reason, url_policy, fwd_rule, gateway
        "Yes" if tlsver else "No", "Default SSL Inspection",
        "" if action != "Blocked" else "SSL Category Bypass", "URL-Filter-Default",
        random.choice(WEB_RULES), "GW-EU-01",
    ]
    return TAB.join(fields)


def fw_line(match: bool) -> str:
    src = MATCH_SRC if match else random.choice(NOISE_SRCS)
    user = MATCH_USER if match else "bob@corp.example"
    loc = MATCH_LOCATION if match else random.choice(NOISE_LOCS)
    scenario = random.random()
    if scenario < 0.2:           # drop
        action, inbytes, outbytes, rule = "Drop", "0", "60", "Block-Malware-C2"
    elif scenario < 0.4:         # no return traffic
        action, inbytes, outbytes, rule = "Allow", "0", "1240", random.choice(FW_RULES)
    else:                        # fine; matches more often go through SIPA forwarding
        action, inbytes, outbytes = "Allow", "48210", "3120"
        rule = "SIPA-ZPA-Forward" if match and random.random() < 0.6 else random.choice(FW_RULES)
    fields = [
        "fw", src, "198.51.100.4", user, loc, _fw_ts(), random.choice(DEPTS), action, "TCP",
        str(random.randint(30000, 60000)), "443", "198.51.100.4", "443", "198.51.100.90",
        inbytes, outbytes, str(random.randint(1, 8000)), "HTTPS", "GitHub", "Online Tools",
        rule, random.choice(COUNTRIES), "IPSEC", "No", "1",
        # added later: fwd_rule, flow_type
        random.choice(FW_RULES), random.choice(["Direct", "Tunnel", "ZPA"]),
    ]
    return TAB.join(fields)


def dns_line(match: bool) -> str:
    src = MATCH_SRC if match else random.choice(NOISE_SRCS)
    user = MATCH_USER if match else "bob@corp.example"
    loc = MATCH_LOCATION if match else random.choice(NOISE_LOCS)
    host = random.choice(HOSTS)
    req_action, res_action, req_rule, res_rule = "Allow", "Allow", "Default DNS", "Default DNS"
    response, error = "203.0.113.50", "NOERROR"
    scenario = random.random()
    if scenario < 0.15:          # request blocked (domain category)
        host, req_action, req_rule, response, error = "bad.example.net", "Block", "Block-Malicious-DNS", "", ""
    elif scenario < 0.25:        # response blocked (the answer IP looks risky)
        res_action, res_rule = "Block", "Block-Risky-Resolved-IP"
    elif scenario < 0.4:         # the name does not exist
        host, response, error = "typo.example.cmo", "", "NXDOMAIN"
    fields = [
        "dns", src, "192.0.2.53", user, loc, _fw_ts(), random.choice(DEPTS),
        host, "A", req_action, req_rule, response, "A" if response else "", res_action, res_rule, error,
        "Professional Services", "Business" if response else "", random.choice(CLOUD_APPS), "Business",
        "53", random.choice(["UDP", "TCP"]), str(random.randint(1, 120)), random.choice(DEVICES), user,
    ]
    return TAB.join(fields)


def main() -> None:
    ap = argparse.ArgumentParser(description="NSS feed simulator")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--web-port", type=int, default=settings.ingest_web_port)
    ap.add_argument("--fw-port", type=int, default=settings.ingest_fw_port)
    ap.add_argument("--dns-port", type=int, default=settings.ingest_dns_port, help="0 sends no DNS lines")
    ap.add_argument("--count", type=int, default=200, help="lines per feed")
    ap.add_argument("--rate", type=float, default=20.0, help="lines per second per feed")
    ap.add_argument("--match-ratio", type=float, default=0.4, help="share of matching lines")
    args = ap.parse_args()

    # Self-check: the field count must match the config schema, or columns shift.
    assert len(web_line(True).split(TAB)) == len(WEB_COLUMNS), "web_line != WEB_COLUMNS"
    assert len(fw_line(True).split(TAB)) == len(FW_COLUMNS), "fw_line != FW_COLUMNS"
    assert len(dns_line(True).split(TAB)) == len(DNS_COLUMNS), "dns_line != DNS_COLUMNS"

    web = socket.create_connection((args.host, args.web_port))
    fw = socket.create_connection((args.host, args.fw_port))
    dns = socket.create_connection((args.host, args.dns_port)) if args.dns_port > 0 else None
    print(f"connected: web={args.host}:{args.web_port} fw={args.host}:{args.fw_port}"
          + (f" dns={args.host}:{args.dns_port}" if dns else ""))
    print(f"matching filters:  source IP={MATCH_SRC}  |  user={MATCH_USER}  |  location={MATCH_LOCATION}")
    delay = 1.0 / args.rate if args.rate > 0 else 0
    try:
        for _ in range(args.count):
            m = random.random() < args.match_ratio
            web.sendall((web_line(m) + "\n").encode("utf-8"))
            fw.sendall((fw_line(m) + "\n").encode("utf-8"))
            if dns:
                dns.sendall((dns_line(m) + "\n").encode("utf-8"))
            if delay:
                time.sleep(delay)
        print(f"done: sent {args.count} lines per feed")
    finally:
        web.close()
        fw.close()
        if dns:
            dns.close()


if __name__ == "__main__":
    main()
