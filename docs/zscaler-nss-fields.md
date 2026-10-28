# Zscaler NSS: full field and token reference (web + firewall)

> Source: the **official Zscaler documentation** "NSS Feed Output Format: Web Logs / Firewall Logs"
> (help.zscaler.com). Those pages are rendered client-side in JavaScript, so they cannot be fetched
> as plain HTML; the content is kept here instead. This file is the reference used when adding a
> field: token, display name in Insights, short description. To add a field, look up the token here,
> append it to the end of `WEB_COLUMNS`/`FW_COLUMNS` (config.py), and make the matching change in
> `models.FlowRecord` plus `as_dict`, `parser.parse`, `feed_sim`, `types.ts`, the LiveView columns
> and detail pane, and the feed strings (README and docs/NSS-FEEDS.md).

Type prefixes: `%s{}` string, `%d{}` integer, `%ld{}` long, `%02d{}`/`%04d{}` zero-padded.
An `o` prefix means obfuscated (for example `%s{ocsip}`), an `e` prefix means hex-encoded, and a
`b64` prefix means Base64.

---

## FIREWALL logs

### Date/Time
| Token | Insights | Description |
|---|---|---|
| `%s{time}` | Logged Time | Date and time of the transaction (no time zone), e.g. `Mon Oct 16 22:55:48 2023` |
| `%s{tz}` | (none) | Time zone as configured on the feed, e.g. `GMT` |
| `%02d{ss}` `%02d{mm}` `%02d{hh}` `%02d{dd}` `%02d{mth}` `%04d{yyyy}` | (none) | Second, minute, hour, day, month, year (derived from Logged Time) |
| `%s{mon}` `%s{day}` | (none) | Month name / weekday |
| `%d{epochtime}` | (none) | Epoch time of the transaction |

### Client Information
| Token | Insights | Description |
|---|---|---|
| `%s{csip}` | Client Source IP | Client source IP (for aggregated records: the last session) |
| `%d{csport}` | Client Source Port | Client source port |
| `%s{cdip}` | Client Destination IP | Client destination IP |
| `%d{cdport}` | Client Destination Port | Client destination port |
| `%s{cdfqdn}` | Client Destination Name | Client destination FQDN (HTTP Host header) |
| `%s{tsip}` | Client Tunnel IP | Tunnel IP of the client (source side) |
| `%s{location}` | Location | Location the session started from |
| `%s{ttype}` | Traffic Forwarding | Forwarding method to the firewall, e.g. `L2 tunnel` |
| `%s{aggregate}` | Aggregated Session | Is the session aggregated? (Yes/No) |
| `%s{srcip_country}` | Source Country | Source country, derived from the client IP |

### Extranet
| Token | Insights | Description |
|---|---|---|
| `%s{extranet_name}` | Extranet Resource | Name of the extranet resource |

### IPS (Intrusion Prevention)
| Token | Insights | Description |
|---|---|---|
| `%s{threatcat}` | (none) | Threat category (IPS) |
| `%s{threatname}` | Threat Name | Threat name (IPS) |
| `%d{threat_score}` | Threat Score | 0 to 100 |
| `%s{threat_severity}` | Threat Severity | Critical/High/Medium/Low/None |
| `%s{ipsrulelabel}` | IPS Rule Name | IPS policy that was applied |
| `%d{ips_custom_signature}` | IPS Custom Signature | 1 = custom signature, 0 = not |

### Server Information
| Token | Insights | Description |
|---|---|---|
| `%d{sdport}` | Server Destination Port | Server destination port |
| `%s{sdip}` | Server Destination IP | Server destination IP |
| `%s{ssip}` | Server Source IP | Server source IP |
| `%d{ssport}` | Server Source Port | Server source port |
| `%s{ipcat}` | Server IP Category | URL category of the server IP |

### Session
| Token | Insights | Description |
|---|---|---|
| `%d{avgduration}` | (none) | Average session duration in ms (for aggregated records) |
| `%d{duration}` | (none) | Session or request duration in seconds |
| `%d{durationms}` | Session Duration | Session or request duration in milliseconds |
| `%d{numsessions}` | (none) | Number of aggregated sessions |
| `%s{stateful}` | (none) | Stateful? (Yes/No) |

### Transaction Action
| Token | Insights | Description |
|---|---|---|
| `%s{rulelabel}` | **Rule Name** | Name of the rule that was applied (firewall filtering) |
| `%s{action}` | Action | Allowed/Blocked |
| `%s{dnat}` | (none) | Was a DNAT policy applied? |
| `%s{dnatrulelabel}` | DNAT Rule Name | Name of the DNAT policy |

### Transaction Info
| Token | Insights | Description |
|---|---|---|
| `%d{recordid}` | (none) | Record ID (NSS-specific) |
| `%s{pcapid}` | Capture | PCAP path |
| `%ld{inbytes}` | Inbound Bytes | Bytes from server to client |
| `%ld{outbytes}` | Outbound Bytes | Bytes from client to server |
| `%s{nwapp}` | **Network Application** | Network application, e.g. SSH |
| `%s{nwsvc}` | **Network Service** | Network service, e.g. HTTP |
| `%s{ipproto}` | Network Protocol | IP protocol (TCP) |
| `%s{destcountry}` | Dest Country | Country code of the destination IP |
| `%s{eedone}` | (none) | Is the feed escaping hex-encoded? (NSS-specific) |

### User / Device
| Token | Insights | Description |
|---|---|---|
| `%s{login}` | User | Login (email address) |
| `%s{dept}` | Department | Department |
| `%s{devicehostname}` | Device Hostname | Device hostname |
| `%s{devicemodel}` | Device Model | Model |
| `%s{devicename}` | Device Name | Device name |
| `%s{deviceostype}` `%s{deviceosversion}` | OS Type / OS Version | Operating system |
| `%s{deviceowner}` | Device Owner | Owner |
| `%s{deviceappversion}` | (none) | App version |
| `%s{external_deviceid}` | External Device ID | MDM identifier |
| `%s{ztunnelversion}` | (none) | Z-Tunnel version |
| `%d{bypassed_session}` | Bypassed Session | 1/0 |
| `%s{bypass_etime}` | (none) | Time of the bypass |
| `%s{flow_type}` | **Flow Type** | Direct/Loopback/VPN/VPN Tunnel/ZIA/ZPA |

### Data Center
| Token | Insights | Description |
|---|---|---|
| `%s{datacenter}` `%s{datacentercity}` `%s{datacentercountry}` | Data Center | Data center name, city, country |

### Forwarding Control
| Token | Insights | Description |
|---|---|---|
| `%s{rdr_rulename}` | **Forwarding Rule** | Name of the redirect or forwarding policy |
| `%s{fwd_type}` | Forwarding Method | Direct/Drop/Proxy Chaining/ZPA |
| `%s{fwd_gw_name}` | Gateway Name | Gateway taken from the forwarding rule |
| `%s{zpa_app_seg_name}` | Application Segment | ZPA application segment |

Obfuscated (FW): `ocsip, oipsrulelabel, oipcat, orulelabel, odnatrulelabel, odevicehostname,
odevicename, odeviceowner, ordr_rulename, ofwd_gw_name, ozpa_app_seg_name`.
Hex (FW): `ethreatname, elocation, edepartment, erulelabel, elogin, edevicehostname`.

---

## WEB logs

### Date/Time
Same as firewall: `%s{time}` (Logged Time), `%s{tz}`, `%02d{ss/mm/hh/dd/mth}`, `%04d{yyyy}`,
`%s{mon}`, `%s{day}`, `%d{epochtime}`.

### User Information
| Token | Insights | Description |
|---|---|---|
| `%s{login}` | User | Login (email address) |
| `%s{dept}` | Department | Department |
| `%s{company}` `%s{cloudname}` | (none) | Company / Zscaler cloud (NSS-specific) |

### Bandwidth Control
`%d{txn_delay_req}` and `%d{txn_delay_resp}` (latency in ms), `%d{throttlereqsize}`,
`%d{throttlerespsize}`, `%s{bwthrottle}`, `%s{bwclassname}` (Bandwidth Class),
`%s{bwrulename}` (Bandwidth Rule).

### Cloud Application
| Token | Insights | Description |
|---|---|---|
| `%s{appname}` | Cloud Application | Cloud application name |
| `%s{appclass}` | Cloud Application Class | Category |
| `%s{app_risk_score}` | Risk Index | 1 to 5, or None |
| `%s{app_status}` | Application Status | Sanctioned/Unsanctioned/N/A |
| `%s{activity}` | Application Activity | Action, e.g. Download |
| `%s{prompt_req}` `%s{prompt_class}` | Prompt / Prompt Classification | Generative application prompt |
| `%s{inst_level1..3_type/id/name}` | App Instance Level 1..3 | Instance discovery |

### Data Center
`%s{datacenter}`, `%s{datacentercity}`, `%s{datacentercountry}`.

### DLP
`%s{dlpdict}` (DLP Dictionaries), `%s{dlpdicthitcount}`, `%s{dlpeng}` (DLP Engine),
`%d{dlpidentifier}`, `%d{exempt_dlpidentifier}`, `%s{dlpmd5}`, `%s{dlprulename}` (Allowed DLP Rule),
`%s{trig_dlprulename}`, `%s{other_dlprulenames}`, `%s{all_dlprulenames}`,
`%s{dlp_policy_action}` (DLP Policy Action), `%s{dlp_confirm_justification_msg}`.

### File Type Control
`%s{ft_rulename}` (Allowed File Type Rule), `%s{fileclass}`, `%s{filetype}` (Download File Type),
`%s{filename}`, `%s{filesubtype}`, `%s{upload_fileclass}`, `%s{upload_filetype}`,
`%s{upload_filename}`, `%s{upload_filesubtype}`, `%s{upload_doctypename}`,
`%s{upload_doc_sub_type}`, `%s{unscannabletype}` (Unscannable Type).

### Forwarding Control (web)
| Token | Insights | Description |
|---|---|---|
| `%s{rdr_rulename}` | **Forwarding Rule** | Name of the redirect or forwarding policy |
| `%s{fwd_type}` | Forwarding Method | Direct/Drop/Proxy Chaining/ZPA |
| `%s{fwd_gw_name}` | **Gateway Name** | Gateway taken from the forwarding rule |
| `%s{fwd_gw_ip}` | Gateway IP | Gateway IP |
| `%s{zpa_app_seg_name}` | Application Segment | ZPA application segment |

### HTTP Transaction
| Token | Insights | Description |
|---|---|---|
| `%d{reqdatasize}` `%d{reqhdrsize}` `%d{reqsize}` | Sent Bytes | Request sizes |
| `%d{respdatasize}` `%d{resphdrsize}` `%d{respsize}` | Received Bytes | Response sizes |
| `%d{totalsize}` | Total Bytes | Total |
| `%s{reqmethod}` | Request Method | GET/CONNECT/... |
| `%s{reqversion}` `%s{respversion}` | Request/Response HTTP Version | |
| `%s{respcode}` | Response Code | HTTP status code (403 on a block) |
| `%s{referer}` `%s{refererhost}` | Referrer URL | |
| `%s{uaclass}` `%s{ua}` `%s{ua_token}` | User Agent | User agent class, string, token |
| `%s{host}` | (none) | Destination hostname |
| `%s{url}` | URL | Destination URL (without the protocol) |
| `%s{df_hostname}` `%s{df_hosthead}` | Domain Fronted SNI / Host Header | Present on an SNI mismatch |
| `%s{contenttype}` | Content Type | |

### Mobile Application
`%s{mobappname}` (Mobile Application), `%s{mobappcat}`, `%s{mobdevtype}`.

### Network
| Token | Insights | Description |
|---|---|---|
| `%s{cip}` | Client IP | User IP (the internal one, where visible) |
| `%s{cintip}` | (none) | Client internet IP (NATed public address) |
| `%s{cpubip}` | Client External IP | Public IP of the client |
| `%d{clt_sport}` | Client Source Port | Needs to be enabled by Zscaler Support |
| `%s{srcip_country}` `%s{dstip_country}` | Source/Destination IP Country | |
| `%s{is_src_cntry_risky}` `%s{is_dst_cntry_risky}` | (none) | Is the country considered risky? |
| `%s{sip}` | Server IP | Destination server IP (0.0.0.0 when blocked) |
| `%d{srv_dport}` | Server Destination Port | Needs to be enabled by Zscaler Support |
| `%s{proto}` | Protocol | HTTP/FTP/... |
| `%s{alpnprotocol}` | ALPN Protocol | |
| `%s{trafficredirectmethod}` | Traffic Forwarding | GRE/IPSEC/PAC/... |
| `%s{location}` | Location | Gateway location or sub-location |
| `%s{userlocationname}` | User Location | Zero Trust Browser |

### Policy
| Token | Insights | Description |
|---|---|---|
| `%s{ruletype}` | Blocked Policy Type | Only set on a block |
| `%s{rulelabel}` | **Blocked Policy Name** | Only set on a block, e.g. URL_Filtering_1 |
| `%s{action}` | Policy Action | Allowed/Blocked |
| `%s{reason}` | (none) | Action and policy reason (on a block) |
| `%s{urlfilterrulelabel}` | **URL Filtering Policy Name** | URL filtering rule that was applied |
| `%s{apprulelabel}` | Cloud Application Policy Name | Application rule |

### Sandbox
`%s{bamd5}` (MD5), `%s{sha256}` (SHA-256).

### SSL/TLS
| Token | Insights | Description |
|---|---|---|
| `%s{ssldecrypted}` | **SSL/TLS Inspected** | Yes/No |
| `%s{ssl_rulename}` | **SSL/TLS Policy Name** | Name of the SSL/TLS inspection rule |
| `%s{externalspr}` | **SSL/TLS Policy Reason** | Blocked/Inspected/N/A, or "Not inspected because ..." |
| `%s{keyprotectiontype}` | Intermediate CA Protection Type | HSM/Software/N/A |
| `%s{ja4_str}` | JA4 Fingerprint | Needs to be enabled by Zscaler Support |

### Client Connection (TLS)
`%s{clientsslcipher}` (Client Connection Cipher), `%s{clienttlsversion}` (Client Connection TLS
Version), `%s{clientsslsessreuse}`, `%s{cltsslfailreason}` (Client SSL/TLS Handshake Failure
Reason), `%d{cltsslfailcount}`, various `%d{client_tls_keyex_*}` and `%d{client_tls_sig_*}` fields
(post-quantum offers), `%s{client_tls_keyex_alg}`, `%s{client_tls_sig_alg}`.

### Server Connection (TLS)
`%s{srvsslcipher}`, `%s{srvtlsversion}` (Server Connection TLS Version), `%s{serversslsessreuse}`,
`%s{srvocspresult}`, `%s{srvcertchainvalpass}`, `%s{srvwildcardcert}`, `%s{srvcertvalidationtype}`,
`%s{srvcertvalidityperiod}`, `%s{is_ssluntrustedca}`, `%s{is_sslselfsigned}`,
`%s{is_sslexpiredca}`, `%s{server_tls_keyex_alg}`, `%s{server_tls_sig_alg}`.

### Threat Protection
| Token | Insights | Description |
|---|---|---|
| `%d{riskscore}` | Suspicious Content | Page risk index, 0 to 100 |
| `%s{threatseverity}` | Threat Severity | Critical/High/Medium/Low/None |
| `%s{threatname}` | Threat Name | e.g. EICAR |
| `%s{malwarecat}` | Threat Category | Adware/Trojan/Sandbox and so on |
| `%s{malwareclass}` | Threat Super Category | |
| `%s{ai_ml_detect_src}` | AI/ML Detection Source | |

### URL Categorization
| Token | Insights | Description |
|---|---|---|
| `%s{urlclass}` | URL Class | |
| `%s{urlsupercat}` | URL Super Category | |
| `%s{urlcat}` | URL Category | Includes the advanced threat category |
| `%s{urlcatmethod}` | URL Categorization Method | DB-A/DB-B/AI-ML/User-Defined/None |

### Device (web)
Same as the firewall device fields, plus: `%s{devicetype}` (Device Type), `%s{external_devid}`
(External Device ID), `%d{bypassed_traffic}` (Bypassed Transaction), `%s{bypassed_etime}`,
`%s{flow_type}` (Flow Type), `%s{ztunnelversion}`.

### Miscellaneous
`%d{recordid}`, `%s{pcapid}` (Capture), `%s{productversion}`, `%s{nsssvcip}`, `%s{eedone}`.

### Encoded variants (web)
- **Obfuscated:** `ologin, obwclassname, odlpdict, odlpeng, odlprulename, ordr_rulename, ofwd_gw_name,
  ozpa_app_seg_name, ocip, ocpubip, ourlfilterrulelabel, oapprulelabel, ourlcat, odevicehostname,
  odevicename, odeviceowner`.
- **Base64 (`b64...`):** ua, filename, upload_filename, threatname, mobappname, host, url, referer,
  login, location, dept, urlcat, rulelabel, urlfilterrulelabel, apprulelabel, dlprulename,
  rdr_rulename, fwd_gw_name, zpa_app_seg_name, userlocationname.
- **Hex (`e...`):** ua, filename, upload_filename, mobappname, host, url, referer, refererpath,
  urlpath, refererhost, login, location, department, rulelabel, urlfilterrulelabel, apprulelabel,
  userlocationname, devicename, devicehostname, prompt_req.

---

## Tokens currently used by the tool (as of v0.9.0)

**Web (39):** `web, cip, sip, login, location, time, dept, action, reason, proto, reqmethod,
respcode, reqsize, respsize, url, host, urlcat, urlclass, appname, appclass, rulelabel,
ruletype, clienttlsversion, clientsslcipher, srvtlsversion, threatname, malwarecat, riskscore,
cintip, ua, devicehostname, deviceowner, contenttype, ssldecrypted, ssl_rulename, externalspr,
urlfilterrulelabel, rdr_rulename, fwd_gw_name`

**Firewall (27):** `fw, csip, cdip, login, location, epochtime, dept, action, ipproto, csport,
cdport, sdip, sdport, tsip, inbytes, outbytes, durationms, nwsvc, nwapp, ipcat, rulelabel,
destcountry, ttype, dnat, numsessions, rdr_rulename, flow_type`

**DNS (25, tokens still to be checked against the field picker):** `dns, cip, sip, login,
location, epochtime, dept, req, reqtype, reqaction, reqrulelabel, res, restype, resaction,
resrulelabel, error, domcat, respipcat, dnsapp, dnsappcat, sport, protocol, durationms,
devicehostname, deviceowner`

**Prefilter positions (0 to 4):** type, source IP, destination IP, user, location.
