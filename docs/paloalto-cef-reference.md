# Replicant Palo Alto (PAN-OS) CEF Reference

Companion to `docs/fortigate-cef-reference.md`. The CEF format spec (header layout, escaping,
syslog wrapping) is vendor-neutral and defined in Sections 1 of that file; this document only
covers what differs for Palo Alto Networks PAN-OS. The seven constructed sample lines in Section 3
are the oracle for `PaloAltoProfile`: the golden test reproduces each CEF payload byte for byte.

> **[Unverified]** All PAN-OS field mappings, signature-id strings, custom-field (`cs*`/`cn*`)
> assignments, and severity numbers below are constructed from the documented PAN-OS CEF format and
> are internally consistent, but they were not confirmed against a live PAN-OS build during
> authoring. Confirm field order and names on a target PAN-OS version before customer-facing use,
> the same way the FortiGate `[Unverified]` signature IDs are flagged.

---

## 1. CEF format spec

Reuse `docs/fortigate-cef-reference.md` Section 1 verbatim: header is
`CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension`;
header values escape `\` and `|`; extension values escape `\` and `=`; UTF-8; the syslog prefix is
added by the transport and is not part of the header. The CEF serializer is shared, so escaping is
identical across vendors.

---

## 2. PAN-OS CEF specifics

### 2.1 Identity fields

| CEF header field | PAN-OS value |
|---|---|
| Device Vendor | `Palo Alto Networks` |
| Device Product | `PAN-OS` |
| Device Version | `11.1.2` (configurable) |
| Signature ID | the PAN-OS log **subtype** string (`end`, `deny`, `vulnerability`, `globalprotect`, `general`) |
| Name | the PAN-OS log **type** (`TRAFFIC`, `THREAT`, `GLOBALPROTECT`, `SYSTEM`) |

Device constants for the lab profile: serial `deviceExternalId=007051000054321`, hostname
`PA-LAB-01`, virtual system `vsys1`, source zone `trust`, destination zone `untrust`, ingress
interface `ethernet1/2`, egress interface `ethernet1/1`, source NAT address `198.51.100.10`.

### 2.2 Field mapping (neutral category -> PAN-OS CEF)

PAN-OS uses standard CEF keys where they exist and the ArcSight custom-field slots (`cs1..cs6`
with `cs*Label`, `cn1..cn3` with `cn*Label`) plus `PanOS*`-prefixed keys for everything else.
`proto` is emitted as the string `tcp`/`udp` (not the IP protocol number). `rt` carries the event
epoch. Bytes: `in` = bytes received, `out` = bytes sent.

| Replicant neutral category | PAN-OS Name | Signature ID | act |
|---|---|---|---|
| `traffic:forward` accept | TRAFFIC | `end` | `allow` |
| `traffic:forward` deny | TRAFFIC | `deny` | `deny` |
| `utm:ips` | THREAT | `vulnerability` | `reset-both` |
| `dns:dns-query` | TRAFFIC | `end` | `allow` (app `dns`, query in `PanOSDNSQuery`) |
| `event:vpn` success | GLOBALPROTECT | `globalprotect` | `allow` (`PanOSEventID=gateway-auth-succ`) |
| `event:vpn` fail | GLOBALPROTECT | `globalprotect` | `deny` (`PanOSEventID=gateway-auth-fail`) |
| `event:system` | SYSTEM | `general` | `login` (`PanOSEventID=auth-fail`) |

### 2.3 Severity mapping (PAN-OS log level -> CEF severity, not reversed)

| Level | CEF severity |
|---|---|
| emergency | 10 |
| critical | 9 |
| alert | 8 |
| error | 6 |
| warning | 5 |
| notice / notification | 3 |
| information | 2 |
| debug | 1 |

Unlike FortiOS (which reverses priority), PAN-OS severity increases with seriousness, so the same
`utm:ips` event that is CEF severity 7 for FortiGate is CEF severity 8 here.

---

## 3. Sample CEF log lines

All lines are `[Constructed]` from the rules above, using the same synthetic entities, ports,
session IDs, byte counts, and event epochs as the seven FortiGate golden lines so the two profiles
can be compared directly. RFC 3164 syslog prefixes use `<189>` (local7.notice), `<188>`
(local7.warning), or `<185>` (local7.alert) and host `PA-LAB-01`.

Traffic forward accept:
```
<189>Jul 16 10:32:04 PA-LAB-01 CEF:0|Palo Alto Networks|PAN-OS|11.1.2|end|TRAFFIC|3|rt=1752661924 deviceExternalId=007051000054321 src=10.20.30.40 dst=203.0.113.25 spt=51544 dpt=443 proto=tcp act=allow app=HTTPS cs1Label=Rule cs1=policy-7 cs3Label=Virtual System cs3=vsys1 cs4Label=Source Zone cs4=trust cs5Label=Destination Zone cs5=untrust deviceInboundInterface=ethernet1/2 deviceOutboundInterface=ethernet1/1 sourceTranslatedAddress=198.51.100.10 sourceTranslatedPort=51544 cn1Label=SessionID cn1=48213 cnt=1 in=61325 out=8421 PanOSPacketsReceived=58 PanOSPacketsSent=64 cs6Label=LogProfile cs6=default
```

Traffic forward deny:
```
<188>Jul 16 10:32:07 PA-LAB-01 CEF:0|Palo Alto Networks|PAN-OS|11.1.2|deny|TRAFFIC|5|rt=1752661927 deviceExternalId=007051000054321 src=10.20.30.55 dst=198.51.100.77 spt=44992 dpt=3389 proto=tcp act=deny app=RDP cs1Label=Rule cs1=policy-0 cs3Label=Virtual System cs3=vsys1 cs4Label=Source Zone cs4=trust cs5Label=Destination Zone cs5=untrust deviceInboundInterface=ethernet1/2 deviceOutboundInterface=ethernet1/1 cn1Label=SessionID cn1=48260 cnt=1 in=0 out=0 PanOSPacketsReceived=0 PanOSPacketsSent=1 cs6Label=LogProfile cs6=default
```

IPS / vulnerability threat:
```
<185>Jul 16 10:33:15 PA-LAB-01 CEF:0|Palo Alto Networks|PAN-OS|11.1.2|vulnerability|THREAT|8|rt=1752661995 deviceExternalId=007051000054321 src=198.51.100.30 dst=10.20.30.40 spt=443 dpt=49180 proto=tcp act=reset-both app=HTTPS cs1Label=Rule cs1=policy-7 cs3Label=Virtual System cs3=vsys1 cs4Label=Source Zone cs4=untrust cs5Label=Destination Zone cs5=trust cn1Label=SessionID cn1=901 request=/struts2/index.action PanOSThreatID=40449 PanOSThreatName=Apache.Struts.OGNL.Remote.Code.Execution cs2Label=Severity cs2=high cn2Label=Direction cn2=0 cnt=1 cs6Label=Profile cs6=default
```

DNS query (traffic, app dns):
```
<189>Jul 16 10:34:01 PA-LAB-01 CEF:0|Palo Alto Networks|PAN-OS|11.1.2|end|TRAFFIC|3|rt=1752662041 deviceExternalId=007051000054321 src=10.20.30.40 dst=10.20.0.53 spt=54621 dpt=53 proto=udp act=allow app=dns cs1Label=Rule cs1=policy-7 cs3Label=Virtual System cs3=vsys1 cs4Label=Source Zone cs4=trust cs5Label=Destination Zone cs5=untrust deviceInboundInterface=ethernet1/2 deviceOutboundInterface=ethernet1/1 cn1Label=SessionID cn1=13355 PanOSDNSQuery=updates.example.net PanOSDNSType=A cnt=1 cs6Label=LogProfile cs6=default
```

DNS response (NXDOMAIN). Carries the resolution outcome, which the query record
does not; this is what makes the DGA technique (REP-016) expressible:
```
<189>Jul 16 10:34:02 PA-LAB-01 CEF:0|Palo Alto Networks|PAN-OS|11.1.2|end|TRAFFIC|3|rt=1752662042 deviceExternalId=007051000054321 src=10.20.30.40 dst=10.20.0.53 spt=54621 dpt=53 proto=udp act=allow app=dns cs1Label=Rule cs1=policy-7 cs3Label=Virtual System cs3=vsys1 cs4Label=Source Zone cs4=trust cs5Label=Destination Zone cs5=untrust deviceInboundInterface=ethernet1/2 deviceOutboundInterface=ethernet1/1 cn1Label=SessionID cn1=13356 PanOSDNSQuery=qv7x2p9k4m.invalid PanOSDNSType=A PanOSDNSResponseCode=NXDOMAIN cnt=1 cs6Label=LogProfile cs6=default
```
`[Unverified]` the extension key names `PanOSDNSResponseCode` and
`PanOSDNSResolvedAddress`. `PanOSDNSResolvedAddress` is emitted only when the name
resolved, so its absence is itself the NXDOMAIN signal.

GlobalProtect login success:
```
<189>Jul 16 10:35:22 PA-LAB-01 CEF:0|Palo Alto Networks|PAN-OS|11.1.2|globalprotect|GLOBALPROTECT|3|rt=1752662122 deviceExternalId=007051000054321 duser=jsmith suser=jsmith src=203.0.113.60 act=allow PanOSEventID=gateway-auth-succ PanOSStage=login PanOSAuthMethod=ssl-tunnel cs3Label=Virtual System cs3=vsys1 cn1Label=TunnelID cn1=1846277 cs2Label=Group cs2=vpn-users reason=login-success msg=SSL tunnel established
```

GlobalProtect login failure:
```
<185>Jul 16 10:35:40 PA-LAB-01 CEF:0|Palo Alto Networks|PAN-OS|11.1.2|globalprotect|GLOBALPROTECT|8|rt=1752662140 deviceExternalId=007051000054321 duser=jsmith suser=jsmith src=198.51.100.200 act=deny PanOSEventID=gateway-auth-fail PanOSStage=login PanOSAuthMethod=ssl-web cs3Label=Virtual System cs3=vsys1 reason=sslvpn_login_permission_denied msg=SSL user failed to logged in
```

System admin auth failure:
```
<185>Jul 16 10:36:05 PA-LAB-01 CEF:0|Palo Alto Networks|PAN-OS|11.1.2|general|SYSTEM|8|rt=1752662165 deviceExternalId=007051000054321 duser=admin suser=admin src=10.20.30.9 act=login PanOSEventID=auth-fail PanOSModule=general PanOSStatus=failed cs1Label=Client cs1=https cs3Label=Virtual System cs3=vsys1 reason=name_invalid msg=Administrator admin login failed from https(10.20.30.9) because of invalid user name
```

---

## 4. Notes

- The same technique catalog and scenario engine drive this profile. Techniques emit vendor-neutral
  `(log_type, subtype)` categories; `PaloAltoProfile.render` maps each to the PAN-OS layout above.
  The FortiGate `signature_id` in the catalog is documentation only and is not read by either profile.
- `event:vpn` with `srccountry` present (REP-011 geovelocity) adds `cs4Label=Source Region cs4=<country>`
  after `PanOSAuthMethod`; the seven golden lines omit it, so it stays optional.
- Select the vendor at run time with `--vendor paloalto` (default `fortigate`). Same seed plus
  technique yields the same plan for either vendor; only the serialization differs.
