# Replicant FortiGate (FortiOS) CEF and Syslog Reference

Reference for generating SAFE, SYNTHETIC FortiGate firewall telemetry over syslog for detection
engineering. Every log line produced from this reference is fabricated text. No real traffic is
observed, captured, or replayed. All addresses use RFC1918 internal ranges and IANA
documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) for externals so output is
unambiguously synthetic. Target: a LogRhythm SIEM (or any syslog collector) accepting a
Fortinet FortiGate CEF syslog source.

Verification labels: `[Unverified]` marks a specific claim not directly confirmed in a primary
source during research. `[Constructed]` marks a sample line assembled from documented field and
format rules rather than copied verbatim from a source.

---

## 1. CEF FORMAT SPEC

### 1.1 Header format

CEF is a text format carried over syslog. One CEF record is a syslog prefix, then a header of
seven pipe-delimited fields, then a space-delimited extension:

```
<syslog prefix> CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
```

Fortinet and ArcSight name the fifth field differently but it is the same field:

| Position | CEF spec name (ArcSight) | Common name | Notes |
|---|---|---|---|
| 1 | CEF:Version | CEF format version | Integer. `CEF:0` (spec 0.1) or `CEF:1` (spec 1.x). Mandatory, no space after the colon. |
| 2 | Device Vendor | deviceVendor | String, max 63. Vendor + Product pair must be unique. |
| 3 | Device Product | deviceProduct | String, max 63. |
| 4 | Device Version | deviceVersion | String, max 31. |
| 5 | Device Event Class ID | Signature ID / deviceEventClassId | String/int, max 1023. Unique per event type. Same role as an IDS signature ID. |
| 6 | Name | name | String, max 512. Human-readable event description. Should not duplicate data already in extension fields. |
| 7 | Severity | agentSeverity | 0 to 10, or the strings Unknown/Low/Medium/High/Very-High. |
| 8 | Extension | extension | Space-separated `key=value` pairs. Optional. |

Severity band interpretation (ArcSight agentSeverity): `0-3 = Low`, `4-6 = Medium`,
`7-8 = High`, `9-10 = Very-High`.

Canonical example from the CEF standard:

```
Sep 19 08:26:10 host CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232
```

### 1.2 Escaping rules

Escaping differs between the header and the extension. This split is the most common cause of
parser failures, so Replicant must apply it per-section.

Header (fields 2 through 7):
- Pipe `|` inside a header field value must be escaped as `\|`. The pipe delimiters themselves are not escaped.
- Backslash `\` must be escaped as `\\`.
- Equals `=` needs NO escaping in the header.
- Do not encode spaces. Spaces in header fields are literal and valid.

Extension (field 8, the key=value section):
- Equals `=` inside a value must be escaped as `\=`.
- Backslash `\` must be escaped as `\\`.
- Pipe `|` inside a value does NOT need escaping.
- Newline / carriage return inside a value is encoded as `\n` or `\r`. Multi-line values are allowed only in the extension, never in the header.
- The whole message must be UTF-8. Values containing spaces are legal (for example `filePath=/user/name/my file.txt`); a single space separates one value from the next key.

Escaping examples from the ArcSight standard:

```
CEF:0|security|threatmanager|1.0|100|detected a \| in message|10|src=10.0.0.1 act=blocked a | dst=1.1.1.1
CEF:0|security|threatmanager|1.0|100|detected a \\ in packet|10|src=10.0.0.1 act=blocked a \\ dst=1.1.1.1
CEF:0|security|threatmanager|1.0|100|detected a = in message|10|src=10.0.0.1 act=blocked a \= dst=1.1.1.1
```

### 1.3 Common / standard extension dictionary keys

Keys below are the ArcSight Extension Dictionary short names (the "CEF key name"). Use the short
name on the wire; the full name will be rejected by consumers. These are the keys most relevant
to network firewall telemetry.

The key and full-name columns are the format definition and are necessarily identical to the
specification: `src` means `sourceAddress` and cannot be written any other way. The Meaning column
is written for this project and is deliberately not the specification's wording. If you edit these
rows, keep it that way, and see `docs/prior-art-and-licensing.md` section 3.3 for why.

| CEF key | Full name | Type | Meaning |
|---|---|---|---|
| src | sourceAddress | IPv4/IPv6 | Source IP of the event. |
| dst | destinationAddress | IPv4/IPv6 | Destination IP of the event. |
| spt | sourcePort | Integer 0-65535 | Source port. |
| dpt | destinationPort | Integer 0-65535 | Destination port. |
| proto | transportProtocol | String | Layer-4 protocol (TCP, UDP, ICMP), or numeric in some senders. |
| app | applicationProtocol | String | Application-layer protocol (HTTP, HTTPS, DNS). |
| act | deviceAction | String | Action taken by the device (accept, deny, blocked, reset). |
| shost | sourceHostName | String | Source host name. |
| dhost | destinationHostName | String | Destination host name / queried FQDN. |
| suser | sourceUserName | String | Source user identity. |
| duser | destinationUserName | String | Destination / authenticating user identity. |
| in | bytesIn | Integer/Long | Bytes received (inbound). |
| out | bytesOut | Integer/Long | Bytes sent (outbound). |
| cnt | baseEventCount | Integer | Count when a single record aggregates multiple observations. |
| cn1, cn2, cn3 | deviceCustomNumber1..3 | Number | Custom numeric field. Requires a matching cn1Label etc. |
| cn1Label | deviceCustomNumber1Label | String | Label describing cn1. |
| cs1..cs6 | deviceCustomString1..6 | String | Custom string field. Requires a matching csXLabel. |
| cs1Label | deviceCustomString1Label | String | Label describing cs1. |
| deviceExternalId | deviceExternalId | String | Vendor device identifier (FortiGate serial number). |
| externalId | externalId | String | Event ID from the source device (FortiGate uses this for session ID). |
| rt | deviceReceiptTime | Timestamp | Event receipt time (epoch millis or a CEF date string). |
| start | startTime | Timestamp | Activity start time. |
| end | endTime | Timestamp | Activity end time. |
| dvc | deviceAddress | IPv4/IPv6 | Address of the reporting device. |
| dvchost | deviceHostName | String | Host name of the reporting device. |
| request | requestUrl | String | Requested URL. |
| dntdom | destinationNtDomain | String | Destination NT domain. |
| deviceInboundInterface | deviceInboundInterface | String | Ingress interface name. |
| deviceOutboundInterface | deviceOutboundInterface | String | Egress interface name. |

Notes: `bytesIn` and `bytesOut` accept Long values from CEF 1.0 onward. All IP fields accept
IPv6 from CEF 1.0 onward.

### 1.4 Syslog envelope wrapping a CEF payload

CEF uses syslog as transport. The prefix is prepended by the sending stack and is not part of
the CEF header.

RFC 3164 (BSD syslog), the format FortiGate emits with CEF:
```
<PRI>Mmm dd HH:MM:SS HOSTNAME CEF:0|Fortinet|Fortigate|...
```
- `<PRI>` = facility * 8 + severity. FortiGate syslog facility is configurable (`set facility`, default local7 = 23). Example: local7.notice = 23*8 + 5 = `<189>`.
- Timestamp `Mmm dd HH:MM:SS` has no year and no timezone.
- `HOSTNAME` is the FortiGate host name.

RFC 5424 (modern syslog), used if the collector expects it:
```
<PRI>1 2026-07-16T10:32:04.000Z HOSTNAME - - - - CEF:0|Fortinet|Fortigate|...
```
- Version digit `1`, ISO 8601 timestamp with timezone, structured-data placeholders.

To write CEF to a file without syslog, discard the `<PRI>Mmm dd HH:MM:SS HOSTNAME` prefix and
begin the line at `CEF:0|`.

LogRhythm ingest note: the LogRhythm "Syslog - Fortinet FortiGate v5.6 CEF" (and later) log
source type expects the CEF payload after a standard syslog prefix. LogRhythm reports the
`FTNTFGT`-prefixed keys are expected and normal for this source.

---

## 2. FORTIGATE CEF SPECIFICS

### 2.1 Identity fields and how FortiOS emits CEF

- Device Vendor = `Fortinet`.
- Device Product = `Fortigate`. Fortinet's own CEF examples emit `Fortigate` (lower-case g). Some SIEM source definitions label the product "FortiGate"; the string on the wire is `Fortigate`. Replicant should emit `Fortigate` to match real FortiOS output.
- Device Version = the FortiOS build string, for example `v7.4.3` or `v6.0.3`.

Enable CEF on the FortiGate (per LogRhythm and Fortinet):
```
config log syslogd setting
    set status enable
    set server <SIEM_IP>
    set format cef
end
```
FortiOS `format` accepts `default`, `csv`, `cef`, and `rfc5424`. Only `cef` produces the format
in this document. Multiple syslog outputs exist (`syslogd`, `syslogd2`, `syslogd3`,
`syslogd4`); each has its own `format`.

### 2.2 FortiOS-to-CEF header and field mapping rules

FortiOS builds the CEF header and extension from a native `key="value"` log line using these
rules (Fortinet "FortiOS to CEF log field mapping guidelines"):

- Header Name (field 6) = `type:subtype` followed by ` eventtype`, ` action`, ` status` when those native fields are present. Example: `traffic:forward close`, `utm:ips signature reset`, `event:system login failed`.
- Extension `cat` = the native `type:subtype` pair. Example `cat=traffic:forward`.
- Signature ID (field 5) = the last 5 digits of the native `logid`. Example `logid=0419016384` gives Signature ID `16384`.
- Severity (field 7) = the reversed FortiOS priority level (see 2.4).
- Native fields that map to a standard CEF key are renamed to that key. Native fields with no CEF equivalent are emitted with a `FTNTFGT` prefix, for example `FTNTFGTsubtype`, `FTNTFGTeventtime`, `FTNTFGTpoluuid`.
- Double quotes around native values are removed for CEF. Forward slashes, equals signs, and backslashes in values are escaped.

Confirmed native-to-CEF key mappings (from Fortinet CEF example lines):

| FortiGate native field | CEF key | Notes |
|---|---|---|
| srcip | src | |
| dstip | dst | |
| srcport | spt | |
| dstport | dpt | |
| proto | proto | IP protocol number: 6 = TCP, 17 = UDP, 1 = ICMP. |
| action | act | |
| srcintf | deviceInboundInterface | |
| dstintf | deviceOutboundInterface | |
| user | duser | Authenticating user maps to duser in DNS/event examples. |
| sentbyte | out | Bytes sent by the session originator (outbound). |
| rcvdbyte | in | Bytes received. |
| sessionid | externalId | |
| devid (serial) | deviceExternalId | FortiGate serial number. |
| logid | FTNTFGTlogid | Full logid retained in extension. |
| subtype | FTNTFGTsubtype | |
| level | FTNTFGTlevel | |
| vd | FTNTFGTvd | Virtual domain. |
| eventtime | FTNTFGTeventtime | Epoch. |
| policyid | FTNTFGTpolicyid | |
| poluuid | FTNTFGTpoluuid | |
| service | FTNTFGTservice | HTTP, HTTPS, DNS, etc. `[Unverified]` whether some builds map service to app. |
| srcintfrole / dstintfrole | FTNTFGTsrcintfrole / FTNTFGTdstintfrole | |

`[Unverified]`: a small number of byte-count and service mappings vary by FortiOS build. Some
builds emit `FTNTFGTsentbyte` / `FTNTFGTrcvdbyte` instead of `out` / `in`. Replicant should make
the byte-field key configurable and default to `out` / `in`, which is the mapping shown in
Fortinet and SIEM parsing documentation.

### 2.3 Main log types, subtypes, native fields, and Signature IDs

FortiOS logs carry `type` and `subtype`. The pairs below are the ones that matter for network
detection.

Traffic (type `traffic`, subtype `forward`, also `local`, `multicast`, `sniffer`):
- Accept and deny are the same subtype `forward`; the `action` field separates them (accept, deny, close, start, timeout, client-rst, server-rst).
- Native fields: srcip, srcport, dstip, dstport, proto, action, policyid, poluuid, sessionid, service, app, appcat, duration, sentbyte, rcvdbyte, sentpkt, rcvdpkt, srcintf, dstintf, srcintfrole, dstintfrole, srccountry, dstcountry, trandisp, transip, transport, dstcountry, level, vd, eventtime.
- Signature ID `00013` (logid `0000000013`, forward traffic). Header Name examples `traffic:forward accept`, `traffic:forward deny`, `traffic:forward close`.

UTM IPS / IDS (type `utm`, subtype `ips`, eventtype `signature` or `anomaly`):
- Native fields: severity, srcip, dstip, srcintf, dstintf, sessionid, action (detected, reset, drop, block, clear_session, pass), proto, service, policyid, attack (signature name), attackid (numeric), srcport, dstport, hostname, url, direction (incoming/outgoing), profile, ref, user, incidentserialno, msg, crscore, craction, crlevel.
- Signature ID `16384` for signature hits (logid `0419016384`). Rate-anomaly / DoS events use different logids, for example the `LOGID_ATTCK_ANOMALY_*` family (18432 TCP/UDP, 18433 ICMP, 18434 others). Header Name example `utm:ips signature reset`.

DNS (type `dns`, subtypes `dns-query` and `dns-response`; older builds log DNS under type `utm` subtype `dns`):
- Native fields: srcip, srcport, dstip, dstport, proto, profile, xid, qname (queried FQDN), qtype (A, AAAA, TXT, NULL, CNAME, PTR, MX, SRV), qtypeval (numeric type), qclass, action (pass, redirect, block), cat/catdesc (FortiGuard category), msg, user, eventtime.
- Signature ID `54802` for dns-response (logid `1501054802`). dns-query uses an adjacent logid in the same family `[Unverified: exact last-5 for query]`. Header Name example `dns:dns-response pass`. In CEF, qname appears as `FTNTFGTqname` and qtype as `FTNTFGTqtype`.

Event VPN (type `event`, subtype `vpn`) SSL-VPN and IPsec:
- Native fields: action (ssl-login-fail, ssl-new-con, tunnel-up, tunnel-down, tunnel-stats), logdesc, user, remip (remote source IP), tunneltype (ssl-web, ssl-tunnel, ipsec), tunnelid, group, dst_host, reason, msg, level, eventtime. For IPsec phase logs: action (negotiate, install_sa), cookies, xauthuser, peer_notif.
- SSL-VPN login failure Signature ID `39426` (LOG_ID_EVENT_SSL_VPN_USER_SSL_LOGIN_FAIL, logdesc "SSL VPN login fail"). SSL-VPN login success / tunnel-up logids are in the same `event:vpn` family `[Unverified: exact last-5 for the success/tunnel-up records]`. `remip` maps to `src` in CEF `[Unverified]`; `user` maps to `duser`.

Event user / admin auth (type `event`, subtype `user` for user auth, subtype `system` for admin logins):
- Native fields: action (login, logout, auth-logon, auth-logon-failed), logdesc, user, ui (ssh, https, jsconsole, telnet), method, srcip, dstip, status (success, failed), reason, msg, level, eventtime, profile.
- Confirmed Signature IDs from Fortinet CEF examples: `43008` Header Name `event:user authentication success` (severity 3); `32002` Header Name `event:system login failed` (severity 7, admin login to the device GUI/CLI).

UTM application control (type `utm`, subtype `app-ctrl`):
- Native fields: srcip, dstip, srcport, dstport, proto, action (pass, block, reset), app (application name), appcat (category), apprisk, appid, hostname, url, user, policyid, msg, eventtime.
- Signature IDs in the `LOGID_APP_CTRL_*` family, for example `28704` app-ctrl IPS pass, `28705` app-ctrl IPS block, `28706` app-ctrl IPS reset. Header Name example `utm:app-ctrl signature block` `[Unverified: exact Name suffix]`.

### 2.4 Severity mapping (reversed FortiOS priority level)

FortiOS assigns a `level` to each log. CEF severity (field 7) is the reversed level per Fortinet's
"CEF priority levels" page. FortiOS numeric priority runs 0 (emergency, most severe) to 7 (debug),
and CEF severity is the inverse so that higher is more severe.

| FortiOS level | FortiOS numeric | CEF severity |
|---|---|---|
| emergency | 0 | 8 |
| alert | 1 | 7 |
| critical | 2 | 6 |
| error | 3 | 5 |
| warning | 4 | 4 |
| notification (notice) | 5 | 3 |
| information | 6 | 2 |
| debug | 7 | 1 |

Anchors confirmed against Fortinet's own CEF example lines: `level=alert` produces severity `7`
(IPS signature reset, admin `system login failed`); `level=notice` produces severity `3`
(traffic close, DNS response pass, user authentication success); Fortinet documents 8 as the
highest CEF value, which corresponds to emergency. Rows between these anchors follow the linear
inverse `CEF severity = 8 - FortiOS numeric` and are consistent with all confirmed examples.

---

## 3. SAMPLE CEF LOG LINES

All lines below are `[Constructed]` from the field and format rules in Sections 1 and 2. They use
RFC1918 internal IPs and IANA documentation externals, a synthetic serial
`deviceExternalId=FGVMSYNTH0000001`, host `FGT-LAB-01`, FortiOS `v7.4.3`, and RFC 3164 syslog
prefixes with `<189>` (local7.notice) or `<188>` (local7.warning). Field order and the
`FTNTFGT` prefixing mirror the confirmed Fortinet CEF examples. Replace timestamps, IPs, ports,
byte counts, users, and session IDs at generation time.

Traffic forward accept:
```
<189>Jul 16 10:32:04 FGT-LAB-01 CEF:0|Fortinet|Fortigate|v7.4.3|00013|traffic:forward accept|3|deviceExternalId=FGVMSYNTH0000001 FTNTFGTlogid=0000000013 cat=traffic:forward FTNTFGTsubtype=forward FTNTFGTlevel=notice FTNTFGTvd=root FTNTFGTeventtime=1752661924 src=10.20.30.40 spt=51544 deviceInboundInterface=port2 dst=203.0.113.25 dpt=443 deviceOutboundInterface=port1 proto=6 act=accept FTNTFGTpolicyid=7 FTNTFGTservice=HTTPS app=HTTPS FTNTFGTtrandisp=snat externalId=48213 FTNTFGTduration=122 out=8421 in=61325 FTNTFGTsentpkt=64 FTNTFGTrcvdpkt=58
```

Traffic forward deny:
```
<188>Jul 16 10:32:07 FGT-LAB-01 CEF:0|Fortinet|Fortigate|v7.4.3|00013|traffic:forward deny|4|deviceExternalId=FGVMSYNTH0000001 FTNTFGTlogid=0000000013 cat=traffic:forward FTNTFGTsubtype=forward FTNTFGTlevel=warning FTNTFGTvd=root FTNTFGTeventtime=1752661927 src=10.20.30.55 spt=44992 deviceInboundInterface=port2 dst=198.51.100.77 dpt=3389 deviceOutboundInterface=port1 proto=6 act=deny FTNTFGTpolicyid=0 FTNTFGTservice=RDP FTNTFGTpolicytype=policy externalId=48260 out=0 in=0 FTNTFGTsentpkt=1 FTNTFGTrcvdpkt=0
```

IPS / IDS signature event:
```
<188>Jul 16 10:33:15 FGT-LAB-01 CEF:0|Fortinet|Fortigate|v7.4.3|16384|utm:ips signature reset|7|deviceExternalId=FGVMSYNTH0000001 FTNTFGTlogid=0419016384 cat=utm:ips FTNTFGTsubtype=ips FTNTFGTeventtype=signature FTNTFGTlevel=alert FTNTFGTvd=root FTNTFGTeventtime=1752661995 FTNTFGTseverity=high src=198.51.100.30 spt=443 dst=10.20.30.40 dpt=49180 proto=6 act=reset FTNTFGTservice=HTTPS FTNTFGTpolicyid=7 FTNTFGTattack=Apache.Struts.OGNL.Remote.Code.Execution FTNTFGTattackid=40449 FTNTFGThostname=10.20.30.40 request=/struts2/index.action FTNTFGTdirection=incoming FTNTFGTprofile=default externalId=901 cnt=1 FTNTFGTmsg=applications3A Apache.Struts.OGNL.Remote.Code.Execution
```

DNS query:
```
<189>Jul 16 10:34:01 FGT-LAB-01 CEF:0|Fortinet|Fortigate|v7.4.3|54803|dns:dns-query pass|3|deviceExternalId=FGVMSYNTH0000001 FTNTFGTlogid=1501054803 cat=dns:dns-query FTNTFGTsubtype=dns-query FTNTFGTlevel=notice FTNTFGTvd=root FTNTFGTeventtime=1752662041 FTNTFGTpolicyid=7 externalId=13355 src=10.20.30.40 spt=54621 deviceInboundInterface=port2 dst=10.20.0.53 dpt=53 proto=17 FTNTFGTprofile=default FTNTFGTxid=42311 FTNTFGTqname=updates.example.net FTNTFGTqtype=A FTNTFGTqtypeval=1 FTNTFGTqclass=IN act=pass
```

DNS response (NXDOMAIN). The response carries the resolution outcome, which the
query record does not. A DGA's signal is *failed* resolution, so this record type
is what makes REP-016 expressible at all:
```
<189>Jul 16 10:34:02 FGT-LAB-01 CEF:0|Fortinet|Fortigate|v7.4.3|54802|dns:dns-response pass|3|deviceExternalId=FGVMSYNTH0000001 FTNTFGTlogid=1501054802 cat=dns:dns-response FTNTFGTsubtype=dns-response FTNTFGTlevel=notice FTNTFGTvd=root FTNTFGTeventtime=1752662042 FTNTFGTpolicyid=7 externalId=13356 src=10.20.30.40 spt=54621 deviceInboundInterface=port2 dst=10.20.0.53 dpt=53 proto=17 FTNTFGTprofile=default FTNTFGTxid=42312 FTNTFGTqname=qv7x2p9k4m.invalid FTNTFGTqtype=A FTNTFGTqtypeval=1 FTNTFGTqclass=IN FTNTFGTrcode=NXDOMAIN act=pass
```
Signature ID `54802` is confirmed (section 2.4). `[Unverified]` the extension key
names `FTNTFGTrcode` and `FTNTFGTipaddr` against a live FortiOS build; both follow
the section 1.3 rule that non-standard fields take the `FTNTFGT` prefix.
`FTNTFGTipaddr` is emitted only when the name resolved, so its absence is itself
the NXDOMAIN signal.

SSL-VPN login success:
```
<189>Jul 16 10:35:22 FGT-LAB-01 CEF:0|Fortinet|Fortigate|v7.4.3|39947|event:vpn ssl-login|3|deviceExternalId=FGVMSYNTH0000001 FTNTFGTlogid=0101039947 cat=event:vpn FTNTFGTsubtype=vpn FTNTFGTlevel=notice FTNTFGTvd=root FTNTFGTeventtime=1752662122 FTNTFGTlogdesc=SSL VPN tunnel up FTNTFGTaction=tunnel-up duser=jsmith src=203.0.113.60 FTNTFGTremip=203.0.113.60 FTNTFGTtunneltype=ssl-tunnel FTNTFGTtunnelid=1846277 FTNTFGTgroup=vpn-users FTNTFGTreason=login-success FTNTFGTmsg=SSL tunnel established
```
`[Unverified]` Signature ID `39947` for the SSL-VPN success/tunnel-up record; the failure logid 39426 is confirmed, the adjacent success logid was not confirmed during research. Treat the last-5 value as configurable.

SSL-VPN login failure:
```
<188>Jul 16 10:35:40 FGT-LAB-01 CEF:0|Fortinet|Fortigate|v7.4.3|39426|event:vpn ssl-login-fail|7|deviceExternalId=FGVMSYNTH0000001 FTNTFGTlogid=0101039426 cat=event:vpn FTNTFGTsubtype=vpn FTNTFGTlevel=alert FTNTFGTvd=root FTNTFGTeventtime=1752662140 FTNTFGTlogdesc=SSL VPN login fail FTNTFGTaction=ssl-login-fail duser=jsmith src=198.51.100.200 FTNTFGTremip=198.51.100.200 FTNTFGTtunneltype=ssl-web FTNTFGTreason=sslvpn_login_permission_denied FTNTFGTmsg=SSL user failed to logged in
```

Admin / user auth failure:
```
<188>Jul 16 10:36:05 FGT-LAB-01 CEF:0|Fortinet|Fortigate|v7.4.3|32002|event:system login failed|7|deviceExternalId=FGVMSYNTH0000001 FTNTFGTlogid=0100032002 cat=event:system FTNTFGTsubtype=system FTNTFGTlevel=alert FTNTFGTvd=root FTNTFGTeventtime=1752662165 FTNTFGTlogdesc=Admin login failed FTNTFGTaction=login FTNTFGTstatus=failed duser=admin src=10.20.30.9 FTNTFGTui=https(10.20.30.9) FTNTFGTmethod=https FTNTFGTreason=name_invalid FTNTFGTmsg=Administrator admin login failed from https(10.20.30.9) because of invalid user name
```

---

## 4. TECHNIQUE TO FIELD MAPPING

For each behavior: the FortiGate log type/subtype to emit, the CEF fields Replicant must vary to
make the behavior detectable, and realistic value ranges/distributions for synthetic generation.
Native field names are given with their CEF key in parentheses. Ranges are generation guidance,
not thresholds.

| ATT&CK | Behavior | FortiGate log type:subtype | CEF fields that must vary (native -> CEF) | Realistic ranges / distributions |
|---|---|---|---|---|
| T1071 / T1571 | Periodic C2 callback | traffic:forward (act=accept); optionally utm:app-ctrl | Hold constant: src (src), dst (dst), dstport (dpt), proto (proto). Vary tightly: eventtime/rt, sentbyte (out), rcvdbyte (in), sessionid (externalId) | Interval 30-300 s fixed base with +/- 5-20% jitter. out 150-2000 B, low variance (std/mean < 0.25). in 100-1500 B. proto 6 or 17. dpt commonly 443, 8080, 8443, 53. One src to exactly one dst:dpt over many hours. sentpkt 1-10. Detection signal: near-constant interval and byte size to a single destination. |
| T1046 | Vertical port scan | traffic:forward (mostly act=deny); utm:ips anomaly for rate | Hold constant: src (src), dst (dst). Vary: dstport (dpt) across a wide set, action (act) | One src to one dst, 100-2000 unique dpt values in 60 s. dpt sequential or randomized over 1-65535. act mostly deny, some accept on open ports. out/in near 0. proto 6. Inter-event gap 1-50 ms. |
| T1046 | Horizontal sweep | traffic:forward (act=deny/accept) | Hold constant: src (src), dstport (dpt). Vary: dstip (dst) across a subnet | One src to 50-4000 unique dst in one /16 or /24, single dpt (445, 22, 3389, 23, 80). act mostly deny. out/in near 0. proto 6. Even inter-event spacing 1-100 ms. |
| T1071.004 / T1048.003 | DNS tunneling | dns:dns-query (and dns-response); older utm:dns | Vary: qname (FTNTFGTqname), qtype (FTNTFGTqtype). Hold: src (src), dst DNS resolver (dst), dpt=53 | qname label length 30-63 chars, high Shannon entropy (> 3.5 bits/char), base32/hex look. Subdomain cardinality > 100 unique labels under one registered parent domain per hour. qtype weighted to TXT, NULL, CNAME, A. Query rate 20-200 per minute from one src. dpt 53, proto 17 (or 6 for large TXT). |
| T1041 / T1048 | Outbound exfil volume | traffic:forward (act=accept/close) | Vary large: sentbyte (out). Hold: src (src), dst (dst), dstport (dpt) | out 10 MB to 5 GB to a single external dst, aggregated or per long session (duration 60-3600 s). out/in ratio > 20:1. dpt 443, 22, 21, 8080. Few dst (1-3). Off-hours weighting. Contrast with a normal baseline of out 1-500 KB. |
| T1018 / T1046 | Destination fan-out | traffic:forward | Vary: dstip (dst) unique count in a window. Hold: src (src) | One src to > 50 unique dst in 5 min (baseline typically < 10). dpt may be fixed (discovery) or varied. Mixed act. Small out/in. proto 6/17. |
| T1110 | Brute force (one user, many attempts) | event:vpn (ssl-login-fail) or event:user/system (status=failed) | Hold: duser (duser), src (src). Repeat: action/status, increment cnt | One duser, 20-500 failures in 1-10 min from one src. Inter-attempt 0.5-5 s. Occasional success at the end for credential-stuffing variants. act/status = fail. |
| T1110 | Password spray (many users, few attempts) | event:vpn (ssl-login-fail) or event:user (status=failed) | Vary: duser (duser) across a set. Hold: src (src) | 50-5000 unique duser, 1-3 attempts each, from one or few src. Spread over 10-60 min to evade lockout. Low per-user rate, high aggregate rate. |
| T1078 / T1133 | VPN geovelocity (impossible travel) | event:vpn (ssl-login / tunnel-up success) | Hold: duser (duser). Vary: remip (src), source country (FTNTFGTsrccountry), rt | Same duser, 2+ successful logins from src in geographically distant blocks (for example 203.0.113.0/24 then 198.51.100.0/24 tagged different srccountry) within 5-60 min, implying travel speed > 900 km/h. tunneltype ssl-tunnel or ipsec. act success. |
| T1090 | Denied outbound burst | traffic:forward (act=deny) | Hold: src (src). Repeat: action=deny, count via cnt | One src, > 50-1000 deny events in 60 s. dst may be one (blocked proxy/C2) or many. dpt fixed or varied. out/in near 0. Sharp rate spike over a low baseline. |
| T1595 | Recon / IDS event-rate spike | utm:ips (signature, anomaly) | Vary or repeat: attackid (FTNTFGTattackid), attack name (FTNTFGTattack), src (src). Increment cnt | Burst of 20-1000 IPS hits in 1-5 min, one src to one or many dst. Either one repeated attackid (single-signature flood) or many distinct attackid (scanner fingerprint). severity high/critical -> CEF 6-7. |
| T1583 | Newly observed external destination per host | traffic:forward; dns:dns-query for new FQDN | Track novelty of the (src, dst) or (src, qname) pair against a baseline window | First-seen external dst or registered domain for a given src within a 7-30 day baseline. Emit low-frequency first-contact events (1-5 per new dst). dst in external ranges, dpt 443/80/53. Pair novelty is the signal, not any single field value. |

Generation guidance for realism across all techniques: keep a per-host baseline of normal
`traffic:forward accept` (out 1-500 KB, common dpt 443/80/53, business-hours weighting) so the
malicious patterns above stand out statistically rather than by absolute value. Use consistent
`deviceExternalId`, `FTNTFGTvd`, and interface names per simulated device. Increment
`externalId` (session ID) per flow. Keep `eventtime` epoch and the syslog timestamp consistent.

---

## Sources

CEF standard (ArcSight / Micro Focus / OpenText):
- What is CEF (header format, escaping, severity bands): https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.3/cef-implementation-standard/Content/CEF/Chapter%201%20What%20is%20CEF.htm
- ArcSight Extension Dictionary (extension keys): https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.3/cef-implementation-standard/Content/CEF/Chapter%202%20ArcSight%20Extension.htm
- CEF Implementation Standard (PDF): https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.4/pdfdoc/cef-implementation-standard/cef-implementation-standard.pdf

FortiGate / FortiOS CEF (Fortinet Document Library):
- FortiOS to CEF log field mapping guidelines: https://docs.fortinet.com/document/fortigate/7.6.6/fortios-log-message-reference/998820/fortios-to-cef-log-field-mapping-guidelines
- CEF support (overview): https://docs.fortinet.com/document/fortigate/7.6.6/fortios-log-message-reference/604144/cef-support
- CEF priority levels (severity mapping): https://docs.fortinet.com/document/fortigate/7.6.6/fortios-log-message-reference/671442/cef-priority-levels
- Examples of CEF support: https://docs.fortinet.com/document/fortigate/7.6.6/fortios-log-message-reference/127777/examples-of-cef-support
- Traffic log support for CEF: https://docs.fortinet.com/document/fortigate/7.4.3/fortios-log-message-reference/949981/traffic-log-support-for-cef
- Event log support for CEF: https://docs.fortinet.com/document/fortigate/7.4.3/fortios-log-message-reference/463430/event-log-support-for-cef
- IPS log support for CEF: https://docs.fortinet.com/document/fortigate/7.6.3/fortios-log-message-reference/311596/ips-log-support-for-cef
- DNS log support for CEF: https://docs.fortinet.com/document/fortigate/7.4.3/fortios-log-message-reference/216594/dns-log-support-for-cef
- SSL-VPN login fail log ID 39426: https://docs.fortinet.com/document/fortigate/7.0.5/fortios-log-message-reference/39426/39426-log-id-event-ssl-vpn-user-ssl-login-fail
- Log message fields (native field dictionary): https://docs.fortinet.com/document/fortigate/7.0.0/fortios-log-message-reference/357866/log-message-fields
- Sample logs by log type (native examples): https://docs.fortinet.com/document/fortigate/6.2.0/cookbook/986892/sample-logs-by-log-type
- log syslogd setting (CLI, set format cef): https://docs.fortinet.com/document/fortigate/6.2.1/cli-reference/352620/log-syslogd-setting
- FTNTFGT prefix technical tip: https://community.fortinet.com/fortigate-3/technical-tip-fortigate-adding-ftntfgt-prefix-while-sending-logs-to-syslog-server-213038

SIEM parsing / ingest references:
- LogRhythm Syslog Fortinet FortiGate v5.6 CEF (config and FTNTFGT note): https://docs.logrhythm.com/devices/docs/syslog-fortinet-fortigate-v5-6-cef
- Google Chronicle Fortinet Firewall parser (sentbyte/rcvdbyte to out/in): https://docs.cloud.google.com/chronicle/docs/ingestion/default-parsers/fortinet-firewall
- Huntress Syslog Fortinet FortiGate Firewall: https://support.huntress.io/hc/en-us/articles/33937884048147-Syslog-Fortinet-FortiGate-Firewall

MITRE ATT&CK technique IDs referenced in Section 4 are from the MITRE ATT&CK Enterprise matrix
(https://attack.mitre.org/).
