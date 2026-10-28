# NSS feed configuration (ready to copy)

Create three **TCP** feeds in the Zscaler console: **Administration -> Nanolog Streaming Service (NSS)
-> NSS Feeds -> Add NSS Feed**. Set Feed Output Type = **Custom**, use `\t` as the field separator
and `\n` at the end of the line. Do **not** change the field order: it maps 1:1 to
`WEB_COLUMNS`/`FW_COLUMNS`/`DNS_COLUMNS` in [../backend/config.py](../backend/config.py).

The feed target is the IP address of the server running this app: web logs go to port **5140**,
firewall logs to port **5141**, DNS logs to port **5142**. Set Time Zone to match `FEED_TIMEZONE`
in `.env` (see below).

---

## Web feed (port 5140, Log Type = Web Log), 39 fields

```
web\t%s{cip}\t%s{sip}\t%s{login}\t%s{location}\t%s{time}\t%s{dept}\t%s{action}\t%s{reason}\t%s{proto}\t%s{reqmethod}\t%s{respcode}\t%d{reqsize}\t%d{respsize}\t%s{url}\t%s{host}\t%s{urlcat}\t%s{urlclass}\t%s{appname}\t%s{appclass}\t%s{rulelabel}\t%s{ruletype}\t%s{clienttlsversion}\t%s{clientsslcipher}\t%s{srvtlsversion}\t%s{threatname}\t%s{malwarecat}\t%d{riskscore}\t%s{cintip}\t%s{ua}\t%s{devicehostname}\t%s{deviceowner}\t%s{contenttype}\t%s{ssldecrypted}\t%s{ssl_rulename}\t%s{externalspr}\t%s{urlfilterrulelabel}\t%s{rdr_rulename}\t%s{fwd_gw_name}\n
```

## Firewall feed (port 5141, Log Type = Firewall Log), 27 fields

```
fw\t%s{csip}\t%s{cdip}\t%s{login}\t%s{location}\t%d{epochtime}\t%s{dept}\t%s{action}\t%s{ipproto}\t%d{csport}\t%d{cdport}\t%s{sdip}\t%d{sdport}\t%s{tsip}\t%ld{inbytes}\t%ld{outbytes}\t%d{durationms}\t%s{nwsvc}\t%s{nwapp}\t%s{ipcat}\t%s{rulelabel}\t%s{destcountry}\t%s{ttype}\t%s{dnat}\t%d{numsessions}\t%s{rdr_rulename}\t%s{flow_type}\n
```

## DNS feed (port 5142, Log Type = DNS Log), 25 fields

```
dns\t%s{cip}\t%s{sip}\t%s{login}\t%s{location}\t%d{epochtime}\t%s{dept}\t%s{req}\t%s{reqtype}\t%s{reqaction}\t%s{reqrulelabel}\t%s{res}\t%s{restype}\t%s{resaction}\t%s{resrulelabel}\t%s{error}\t%s{domcat}\t%s{respipcat}\t%s{dnsapp}\t%s{dnsappcat}\t%d{sport}\t%s{protocol}\t%d{durationms}\t%s{devicehostname}\t%s{deviceowner}\n
```

A DNS line carries **two decisions**: the request (`req*`) and the response (`res*`) are checked
separately against the DNS control rules. The live view shows under **action/rule** whichever stage
blocked, and the response otherwise; the detail view shows both stages on their own. Verdicts:
block gives *Blocked*, an error code (`NXDOMAIN`, `SERVFAIL`, ...) gives *DNS error*, no answer
gives *No return traffic*, anything else *Allowed*. The destination IP (`sip`) is the DNS server
that was asked, and the name that was looked up lands in **target / URL** and **host**, so a query
such as `host=*.example.com` matches web and DNS lines alike.

> **Check the DNS tokens against the field picker** before the feed goes live. Unlike the web and
> firewall tokens they are not yet confirmed against the console. If the console rejects a token,
> **keep the position** (use another token or a placeholder) and update `DNS_COLUMNS` plus
> `dns_line` in the feed simulator to match. `INGEST_DNS_PORT=0` turns the feed off completely.

---

## New in v0.8.0: tokens taken from the official Zscaler NSS documentation

These are the **last** fields of each feed. The token names are confirmed against the Zscaler
documentation (NSS Feed Output Format: Web/Firewall Logs). Fields that arrive empty are shown as a
placeholder in the UI.

| Field (display name) | Token | Feed |
|---|---|---|
| SSL/TLS Inspected | `%s{ssldecrypted}` | Web |
| SSL/TLS Policy Name | `%s{ssl_rulename}` | Web |
| SSL/TLS Policy Reason | `%s{externalspr}` | Web |
| URL Filtering Policy Name | `%s{urlfilterrulelabel}` | Web |
| Forwarding Rule (Forwarding Control) | `%s{rdr_rulename}` | Web + FW |
| Gateway Name | `%s{fwd_gw_name}` | Web |
| Flow Type (Direct/VPN/ZIA/ZPA/...) | `%s{flow_type}` | FW |

> **Already included, no feed change needed:** the firewall **Rule Name** is `rulelabel` (column
> "Rule"), **Network Service** is `nwsvc` (column "Net service"), and **Network Application** is
> `nwapp` (column "App"). Switch them on under **View -> Columns**.

## Time zone (important)

The feeds deliver the log time in **different formats**:

| Feed | Token | Format | Zone |
|---|---|---|---|
| Web | `%s{time}` | asctime, e.g. `Wed Jul 22 11:53:51 2026` | **local time of the feed's zone** (the string carries no zone information) |
| FW | `%d{epochtime}` | epoch milliseconds | absolute, independent of any zone |
| DNS | `%d{epochtime}` | epoch, seconds or milliseconds, both are recognised | absolute, independent of any zone |

The web string therefore has to be interpreted in the feed's own zone. That happens **in the
backend** during parsing ([../backend/ingest/timestamps.py](../backend/ingest/timestamps.py)); the
zone comes from `FEED_TIMEZONE` in `.env`. The frontend only ever receives the resolved `ts_epoch`
and no longer interprets time strings itself.

**If you change the Time Zone of a feed in the Zscaler console, change `FEED_TIMEZONE` with it**
and restart the service. Otherwise the web timestamps are off by the zone or DST offset (for
example two hours during summer time in a UTC+1 zone). Firewall timestamps are not affected, so
"only the web logs are shifted" is exactly this symptom. To check the current value, open
**Admin -> Settings -> Read-only -> Feed time zone**; an IANA name the server does not recognise is
flagged there as unknown and UTC is used instead.

> Server requirement: the IANA time zone database. It comes from the pip package `tzdata`
> (listed in `backend/requirements.txt`), independently of the system `tzdata`.

## 3 critical rules

1. **Do not change the field order.** The position is the column index in `config.py`.
2. **The first field is a literal** (`web`, `fw` or `dns`, without `%`): the type tag in column 0.
3. **Separator is `\t`, line ends with `\n`.** The parser splits on tabs and reads line by line.

## Prefilter positions (0 to 4, all feeds)
Type, source IP, destination IP, user, location.

## Verification

```bash
ss -ltnp | grep -E ':5140|:5141|:5142'
sudo tcpdump -nAi any 'tcp port 5140' -c 5
```
Then in the UI: **Admin -> Overview -> Field diagnostics**, which shows the expected 39/27/25
fields against what actually arrives, plus how often each column is populated.

## Feed selection in the live view

**WEB**, **FW** and **DNS** switch the feeds on and off per view. That takes effect **on the
server**, just like the filters: a deselected feed never reaches that view's buffer at all (DNS is
the loudest feed and would otherwise push web and firewall lines out quickly). The selection is
stored per account.

## When nothing arrives

A standing TCP connection can die quietly, and until it is noticed an empty table looks exactly
like "no matches". Two settings cover that: `INGEST_IDLE_TIMEOUT_SECONDS` (default 600) drops a
connection that has delivered nothing for that long, so the NSS server reconnects, and
`FEED_STALE_AFTER_SECONDS` (default 120) is the display threshold after which the live view marks
the feed as silent. Every stats message carries the feed state, so the indicator tells "nothing is
arriving" apart from "nothing matched".
