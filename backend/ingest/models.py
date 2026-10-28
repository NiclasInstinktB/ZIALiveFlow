"""Unified flow schema plus filter model.

A ``FlowRecord`` is the normalized view across web, firewall and DNS logs. Only matches ever
become a record: the rest of the firehose is discarded positionally beforehand (see
``parser.wants``).
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from pydantic import BaseModel


class Verdict(str, Enum):
    ALLOWED = "allowed"          # allowed, return traffic seen
    BLOCKED = "blocked"          # drop/block
    NO_RESPONSE = "no_response"  # allowed, but no return traffic
    SSL_FAILED = "ssl_failed"    # HTTPS/SSL, but no TLS established
    HTTP_ERROR = "http_error"    # HTTP 4xx/5xx
    DNS_ERROR = "dns_error"      # DNS answer carrying an error code (NXDOMAIN, SERVFAIL, ...)
    UNKNOWN = "unknown"


# Verdict → severity (drives the color in the UI).
SEVERITY: dict[str, str] = {
    Verdict.ALLOWED: "good",
    Verdict.BLOCKED: "bad",
    Verdict.NO_RESPONSE: "warn",
    Verdict.SSL_FAILED: "warn",
    Verdict.HTTP_ERROR: "warn",
    Verdict.DNS_ERROR: "warn",
    Verdict.UNKNOWN: "info",
}


@dataclass(slots=True)
class FlowRecord:
    """One normalized flow. Deliberately a ``slots`` dataclass instead of a pydantic
    model: much less RAM per record, so the ring buffer stays small. The fields cover
    web, firewall AND DNS logs (those that do not apply stay empty)."""

    id: int
    received_at: float          # receive time (epoch s), the basis for the TTL
    logtype: str                # "web" | "fw" | "dns"
    ts: str                     # timestamp from the log itself (raw value, for diagnostics)
    # ``ts`` resolved to epoch seconds (see ingest/timestamps.py). None = not interpretable.
    # The UI shows this value only; it deliberately no longer interprets time strings
    # (the feed zone lives in the backend).
    ts_epoch: float | None = None
    user: str = ""
    location: str = ""          # gateway location / sub-location
    dept: str = ""              # the user's department
    src_ip: str = ""            # web: internal client IP, fw: client source IP
    src_port: int | None = None
    dst_ip: str = ""
    dst_port: int | None = None
    server_ip: str = ""         # fw: the real server behind NAT
    server_port: int | None = None
    client_public_ip: str = ""  # NATed public IP (web: cintip, fw: tsip)
    proto: str = ""
    action: str = ""
    target: str = ""            # web: URL, fw: nwApp, dns: the name that was looked up
    host: str = ""              # web: host from the HTTP request, dns: the name looked up
    reason: str = ""
    rule: str = ""              # the rule / policy that was applied
    rule_type: str = ""         # web: policy type
    bytes_tx: int = 0
    bytes_rx: int = 0
    http_method: str = ""
    http_status: str = ""
    category: str = ""          # web: URL category, fw: IP category
    url_class: str = ""         # web: URL class
    app_name: str = ""          # web: cloud app, fw: nwApp
    app_class: str = ""         # web: cloud app class
    nwservice: str = ""         # fw: network service
    tls_version: str = ""       # client TLS
    tls_cipher: str = ""
    server_tls_version: str = ""
    threat_name: str = ""
    threat_category: str = ""
    risk_score: int | None = None
    user_agent: str = ""
    device_name: str = ""
    device_owner: str = ""
    content_type: str = ""
    dest_country: str = ""      # fw
    tunnel_type: str = ""       # fw: GRE/IPSEC/...
    dnat: str = ""              # fw
    num_sessions: int | None = None  # fw (aggregated sessions)
    duration_ms: int | None = None
    # ── SSL / policy / forwarding (web + fw) ──
    ssl_inspected: str = ""     # web: SSL/TLS inspection performed (Yes/No)
    ssl_policy: str = ""        # web: SSL/TLS policy name
    ssl_policy_reason: str = "" # web: SSL/TLS policy reason
    url_policy: str = ""        # web: URL filtering policy name
    fwd_rule: str = ""          # forwarding rule (web + fw)
    gateway: str = ""           # web: gateway name
    flow_type: str = ""         # fw: flow type
    # ── DNS: request and response are decided separately ──
    dns_req_type: str = ""      # A/AAAA/CNAME/...
    dns_req_action: str = ""
    dns_req_rule: str = ""
    dns_response: str = ""      # resolved IP or name
    dns_res_type: str = ""
    dns_res_action: str = ""
    dns_res_rule: str = ""
    dns_error: str = ""         # NXDOMAIN/SERVFAIL/...
    dns_res_ip_cat: str = ""    # category of the answer IP
    verdict: str = Verdict.UNKNOWN.value
    severity: str = "info"

    def as_dict(self) -> dict:
        """Flat dict view for the WebSocket / JSON output."""
        return {
            "id": self.id, "received_at": self.received_at, "logtype": self.logtype,
            "ts": self.ts, "ts_epoch": self.ts_epoch, "user": self.user,
            "location": self.location, "dept": self.dept,
            "src_ip": self.src_ip, "src_port": self.src_port, "dst_ip": self.dst_ip,
            "dst_port": self.dst_port, "server_ip": self.server_ip, "server_port": self.server_port,
            "client_public_ip": self.client_public_ip, "proto": self.proto, "action": self.action,
            "target": self.target, "host": self.host, "reason": self.reason, "rule": self.rule,
            "rule_type": self.rule_type, "bytes_tx": self.bytes_tx, "bytes_rx": self.bytes_rx,
            "http_method": self.http_method, "http_status": self.http_status, "category": self.category,
            "url_class": self.url_class, "app_name": self.app_name, "app_class": self.app_class,
            "nwservice": self.nwservice, "tls_version": self.tls_version, "tls_cipher": self.tls_cipher,
            "server_tls_version": self.server_tls_version, "threat_name": self.threat_name,
            "threat_category": self.threat_category, "risk_score": self.risk_score,
            "user_agent": self.user_agent, "device_name": self.device_name,
            "device_owner": self.device_owner, "content_type": self.content_type,
            "dest_country": self.dest_country, "tunnel_type": self.tunnel_type, "dnat": self.dnat,
            "num_sessions": self.num_sessions, "duration_ms": self.duration_ms,
            "ssl_inspected": self.ssl_inspected, "ssl_policy": self.ssl_policy,
            "ssl_policy_reason": self.ssl_policy_reason, "url_policy": self.url_policy,
            "fwd_rule": self.fwd_rule, "gateway": self.gateway, "flow_type": self.flow_type,
            "dns_req_type": self.dns_req_type, "dns_req_action": self.dns_req_action,
            "dns_req_rule": self.dns_req_rule, "dns_response": self.dns_response,
            "dns_res_type": self.dns_res_type, "dns_res_action": self.dns_res_action,
            "dns_res_rule": self.dns_res_rule, "dns_error": self.dns_error,
            "dns_res_ip_cat": self.dns_res_ip_cat,
            "verdict": self.verdict, "severity": self.severity,
        }


class FilterField(str, Enum):
    SRC_IP = "src_ip"
    DST_IP = "dst_ip"
    USER = "user"
    LOCATION = "location"


# Filter fields that are compared case insensitively (user/location).
_CI_FIELDS = {FilterField.USER, FilterField.LOCATION}


class FilterSpec(BaseModel):
    field: FilterField
    value: str

    def normalized(self) -> "FilterSpec":
        # User/location case insensitive, IPs untouched (exact string comparison).
        val = self.value.strip()
        if self.field in _CI_FIELDS:
            val = val.lower()
        return FilterSpec(field=self.field, value=val)


class FilterOp(str, Enum):
    AND = "and"
    OR = "or"


class FilterGroup(BaseModel):
    """One filter group: several specs joined by ONE operator.

    Two levels are enough to express what you actually need when searching logs, and
    they stay unambiguous without any bracket syntax:

        (source A OR source B) AND (destination C)
        (source A) OR (source B AND destination C)

    The filter used to be ONE flat OR list. That made it impossible to search for
    "source X **and** destination Y", which is exactly the case this is about.
    """

    op: FilterOp = FilterOp.OR
    items: list[FilterSpec] = []

    def normalized(self) -> "FilterGroup":
        return FilterGroup(
            op=self.op,
            items=[s.normalized() for s in self.items if s.value.strip()],
        )
