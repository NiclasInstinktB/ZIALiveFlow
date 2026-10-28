// Mini query language for the flow search.
//
//   type=Web*           wildcard match (field "type" starts with "web")
//   status=404          substring match (case-insensitive)
//   user=*@corp.example wildcard
//   rule!=Default       per-field negation
//   Site-H*             free text WITH wildcard (across all fields)
//   -github             free-text exclusion
//   github 443          several terms = AND
//
// ONE field catalogue (QUERY_FIELDS). New backend fields are queryable
// **automatically**: unknown record keys are picked up by fieldNames() and
// resolveField() below, so the search "grows" without extra maintenance.
//
// Field names are canonical ENGLISH so that a stored chip or preset keeps
// working regardless of the UI language. German names remain as aliases, so
// queries written before the English switch still parse.
import type { FlowRecord } from "./types";

export interface QueryField {
  key: string; // field on the record
  label: string; // canonical English name (shown in autocomplete)
  aliases: string[];
}

export const QUERY_FIELDS: QueryField[] = [
  { key: "logtype", label: "type", aliases: ["type", "typ", "logtype"] },
  { key: "verdict", label: "verdict", aliases: ["verdict", "bewertung"] },
  { key: "user", label: "user", aliases: ["user", "benutzer"] },
  { key: "location", label: "location", aliases: ["location", "standort", "ort"] },
  { key: "dept", label: "department", aliases: ["department", "dept", "abteilung"] },
  { key: "src_ip", label: "source", aliases: ["source", "src", "src_ip", "quelle", "quellip"] },
  { key: "dst_ip", label: "destination", aliases: ["destination", "dst", "dst_ip", "ziel", "zielip"] },
  { key: "server_ip", label: "server", aliases: ["server", "server_ip"] },
  { key: "client_public_ip", label: "publicip", aliases: ["publicip", "client_public_ip", "natip"] },
  { key: "proto", label: "proto", aliases: ["proto", "protocol", "protokoll"] },
  { key: "action", label: "action", aliases: ["action", "aktion"] },
  { key: "target", label: "url", aliases: ["url", "target", "zielurl"] },
  { key: "host", label: "host", aliases: ["host", "hostname"] },
  { key: "app_name", label: "app", aliases: ["app", "app_name", "appname", "cloudapp"] },
  { key: "reason", label: "reason", aliases: ["reason", "grund"] },
  { key: "rule", label: "rule", aliases: ["rule", "regel"] },
  { key: "fwd_rule", label: "forwarding", aliases: ["forwarding", "fwd", "fwd_rule", "fwdregel", "forwardingregel"] },
  { key: "gateway", label: "gateway", aliases: ["gateway", "gw"] },
  { key: "flow_type", label: "flowtype", aliases: ["flowtype", "flow", "flow_type", "flowtyp"] },
  { key: "ssl_inspected", label: "sslinspected", aliases: ["sslinspected", "ssl_inspected", "inspected", "sslgeprueft"] },
  { key: "url_policy", label: "urlpolicy", aliases: ["urlpolicy", "url_policy", "urlfilter", "urlfilterregel"] },
  { key: "ssl_policy", label: "sslpolicy", aliases: ["sslpolicy", "ssl_policy"] },
  { key: "http_status", label: "status", aliases: ["status", "http", "http_status", "code"] },
  { key: "category", label: "category", aliases: ["category", "kategorie", "cat"] },
  { key: "url_class", label: "urlclass", aliases: ["urlclass", "url_class", "class", "urlklasse"] },
  { key: "threat_name", label: "threat", aliases: ["threat", "threat_name", "bedrohung", "malware"] },
  { key: "dest_country", label: "country", aliases: ["country", "land", "dest_country"] },
  { key: "tunnel_type", label: "tunnel", aliases: ["tunnel", "tunnel_type", "ttype"] },
  { key: "nwservice", label: "netservice", aliases: ["netservice", "nwservice", "nwsvc"] },
  { key: "device_name", label: "device", aliases: ["device", "device_name", "geraet"] },
  { key: "tls_version", label: "tls", aliases: ["tls", "tls_version"] },
  { key: "src_port", label: "srcport", aliases: ["srcport", "src_port", "quellport"] },
  { key: "dst_port", label: "dstport", aliases: ["dstport", "dst_port", "zielport"] },
  // DNS: the requested name lives in host/target, so "query" and "domain" below
  // are routed there instead of getting a field of their own.
  { key: "dns_req_type", label: "dnstype", aliases: ["dnstype", "dns_req_type", "qtype", "rrtype", "dnstyp"] },
  { key: "dns_response", label: "dnsresponse", aliases: ["dnsresponse", "dns_response", "resolved", "dnsantwort"] },
  { key: "dns_error", label: "dnserror", aliases: ["dnserror", "dns_error", "rcode", "dnsfehler"] },
];

const ALIAS_TO_KEY = new Map<string, string>();
for (const f of QUERY_FIELDS) for (const a of f.aliases) ALIAS_TO_KEY.set(a.toLowerCase(), f.key);
ALIAS_TO_KEY.set("label", "target"); // convenience alias
for (const a of ["query", "dnsquery", "domain", "domaene"]) ALIAS_TO_KEY.set(a, "host"); // the DNS name

// Record keys we do not offer as search fields (internal or not useful).
// ts_epoch is the resolved log time as a raw epoch value: good for display,
// worthless as a search term (the readable raw value sits in ts).
const HIDDEN_KEYS = new Set(["id", "received_at", "severity", "ts_epoch"]);

export function fieldValue(r: FlowRecord, key: string): string {
  const v = (r as unknown as Record<string, unknown>)[key];
  return v === null || v === undefined ? "" : String(v);
}

function resolveField(name: string): string {
  const n = name.toLowerCase();
  return ALIAS_TO_KEY.get(n) ?? n; // unknown: try it as a raw record key
}

/** Field names for autocomplete: the catalogue plus any new record keys. */
export function fieldNames(records: FlowRecord[]): string[] {
  const names = new Set<string>(QUERY_FIELDS.map((f) => f.label));
  const sample = records[0];
  if (sample) {
    for (const k of Object.keys(sample)) {
      if (!HIDDEN_KEYS.has(k) && !ALIAS_TO_KEY.has(k)) names.add(k);
    }
  }
  return [...names];
}

// ── Parsing ────────────────────────────────────────────────────────
type Term =
  | { kind: "field"; key: string; ne: boolean; match: (v: string) => boolean }
  | { kind: "text"; neg: boolean; needle: string; match: (haystack: string) => boolean };

const FIELD_RE = /^(-?)([\w.-]+)(!=|=|:)(.*)$/;

function tokenize(input: string): string[] {
  const out: string[] = [];
  let cur = "";
  let q = false;
  for (const ch of input) {
    if (ch === '"') {
      q = !q;
      continue;
    }
    if (!q && /\s/.test(ch)) {
      if (cur) {
        out.push(cur);
        cur = "";
      }
      continue;
    }
    cur += ch;
  }
  if (cur) out.push(cur);
  return out;
}

function wildcardRe(v: string): RegExp {
  const esc = v.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
  return new RegExp("^" + esc + "$", "i");
}

function valueMatcher(v: string): (s: string) => boolean {
  if (v.includes("*") || v.includes("?")) {
    const re = wildcardRe(v);
    return (s) => re.test(s);
  }
  const low = v.toLowerCase();
  if (!low) return () => true;
  return (s) => s.toLowerCase().includes(low); // no wildcard: lenient substring match
}

// Free text (a term without `field=`) runs against the haystack built from all
// fields. Without a wildcard this is a plain substring match. WITH `*` or `?`
// it becomes an unanchored regex, but **word-wise**: `*` stands for "any
// characters except whitespace". Otherwise `a*b` would match straight across
// field boundaries (the haystack is one line of values joined by spaces) and
// would hit practically everything.
// Previously the star was searched for literally here, so `Site-H*` never
// found anything.
function textMatcher(needle: string): (haystack: string) => boolean {
  if (!needle) return () => true;
  if (!needle.includes("*") && !needle.includes("?")) return (h) => h.includes(needle);
  const esc = needle
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, "[^\\s]*")
    .replace(/\?/g, "[^\\s]");
  const re = new RegExp(esc, "i");
  return (h) => re.test(h);
}

export function parseQuery(input: string): Term[] {
  const terms: Term[] = [];
  for (const tok of tokenize(input)) {
    const m = tok.match(FIELD_RE);
    if (m && m[2] && !m[1] /* a leading '-' means free-text exclusion, not a field */) {
      const key = resolveField(m[2]);
      const ne = m[3] === "!=";
      terms.push({ kind: "field", key, ne, match: valueMatcher(m[4]) });
    } else {
      const neg = tok.startsWith("-");
      const needle = (neg ? tok.slice(1) : tok).toLowerCase();
      terms.push({ kind: "text", neg, needle, match: textMatcher(needle) });
    }
  }
  return terms;
}

export function matchRecord(r: FlowRecord, terms: Term[], haystack: string): boolean {
  for (const t of terms) {
    if (t.kind === "field") {
      const hit = t.match(fieldValue(r, t.key));
      if (t.ne ? hit : !hit) return false;
    } else {
      if (!t.needle) continue;
      const hit = t.match(haystack);
      if (t.neg ? hit : !hit) return false;
    }
  }
  return true;
}

// ── Autocomplete ───────────────────────────────────────────────────
export interface Suggestion {
  label: string;
  replace: string; // replaces the current token
}

export function suggest(
  input: string,
  caret: number,
  records: FlowRecord[]
): { start: number; end: number; items: Suggestion[] } {
  const left = input.slice(0, caret);
  const start = Math.max(left.lastIndexOf(" "), left.lastIndexOf('"')) + 1;
  const token = left.slice(start);
  const end = caret;

  const m = token.match(FIELD_RE);
  if (m && m[2]) {
    // Value suggestions taken from the records currently on screen.
    const key = resolveField(m[2]);
    const prefix = m[4].toLowerCase();
    const seen = new Set<string>();
    for (const r of records) {
      const v = fieldValue(r, key);
      if (v && v.toLowerCase().includes(prefix)) seen.add(v);
      if (seen.size >= 12) break;
    }
    const items = [...seen].map((v) => ({ label: v, replace: `${m[1]}${m[2]}${m[3]}${v}` }));
    return { start, end, items };
  }

  // Field name suggestions.
  const p = token.replace(/^-/, "").toLowerCase();
  if (!p) return { start, end, items: [] };
  const items = fieldNames(records)
    .filter((n) => n.startsWith(p))
    .slice(0, 8)
    .map((n) => ({ label: n + "=", replace: n + "=" }));
  return { start, end, items };
}
