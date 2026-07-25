# Replicant Check Point (Log Exporter) CEF Reference

Companion to `docs/fortigate-cef-reference.md`. The CEF format spec (header layout, escaping,
syslog wrapping) is vendor-neutral and defined in Section 1 of that file; this document only
covers what differs for Check Point Log Exporter CEF output. The seven constructed sample lines in
Section 3 are the oracle for `CheckPointProfile`: the golden test reproduces each CEF payload byte
for byte.

> **[Unverified]** All Check Point CEF field mappings, blade/product strings, custom-field
> (`cs*`/`cn*`/`flex*`) assignments, action casings, and syslog prefixes below were constructed from
> published Check Point Log Exporter documentation and third-party samples, and are internally
> consistent, but they were **not** confirmed against a live Check Point / Log Exporter build during
> authoring. Confirm field names, order, and the `product`/blade values on a target gateway and
> exporter version before customer-facing use, the same way the FortiGate `[Unverified]` signature
> IDs are flagged.
>
> Grounding, per field, so a reader knows what is documented vs. inferred:
> - **Grounded** (Check Point's own `CefFieldsMapping.xml` R80.20 GA and/or live samples): the header
>   8-tuple and its dynamic sources; Device Vendor `Check Point`; Device Version literal `Check Point`;
>   Device Product driven by the raw `product` (blade) field; `proto` as the numeric IANA protocol;
>   `rt` as epoch **milliseconds**; text-string Severity (`Unknown`/`Low`/`Medium`/`High`/`Very-High`,
>   not reversed); the `cp_severity` mirror key; `destinationDnsDomain` for DNS; the per-blade reuse of
>   `cs1..cs6`/`cn1..cn3` with `cs*Label` naming.
> - **[Inference] / [Unverified]** (not confirmed against a primary source): the exact `act` casing for
>   `Prevent` / `Reject`; the `Mobile Access` product string for remote-access VPN auth; a dedicated
>   `auth_status` key; the audit keys `administrator` / `operation`; and the choice to key
>   `deviceDirection` off the destination zone.
>
> Sources: Check Point SK122323 (Log Exporter); CheckMates "Log Exporter CEF Field Mappings" (posts the
> R80.20 GA `$EXPORTERDIR/conf/CefFieldsMapping.xml` and `CefFormatDefinition.xml`); Sekoia Check Point
> integration page (live sample lines); Microsoft Sentinel CEF field mapping (the `Severity` string set).

---

## 1. CEF format spec

Reuse `docs/fortigate-cef-reference.md` Section 1 verbatim for the header grammar and escaping: header
is `CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension`;
header values escape `\` and `|`; extension values escape `\` and `=`; UTF-8; the syslog prefix is
added by the transport and is not part of the header. The CEF serializer is shared, so escaping is
identical across vendors.

Two Check Point specifics that ride on top of that shared grammar:

- **`rt` is epoch milliseconds**, not seconds (grounded: `rt=1708352128000` in live samples). The same
  event that FortiGate/PAN-OS render with a seconds epoch is `eventtime * 1000` here.
- **Severity is a text string**, not a 0-10 integer. The shared serializer already stringifies the
  header severity, so a string flows through unchanged.

---

## 2. Check Point CEF specifics

### 2.1 Identity fields

| CEF header field | Check Point value |
|---|---|
| Device Vendor | `Check Point` (constant) |
| Device Product | the raw `product` (blade) field: `VPN-1 & FireWall-1` (firewall/VPN traffic, DNS), `SmartDefense` (IPS/Threat Prevention), `Mobile Access` (remote-access VPN auth, [Inference]), `Check Point` (management/audit) |
| Device Version | literal string `Check Point` (grounded: Log Exporter sets field 4 to the words "Check Point", not a version number) |
| Signature ID | default `Log`; for Threat Prevention it is the `protection_type` (`IPS`) |
| Name | default `Log`; for a firewall/DNS connection it is the `service_id` (`https`, `rdp`, `domain-udp`); for Threat Prevention it is the `protection_name` |
| Severity | a string: `Unknown` (plain connection / successful auth), `Low`/`Medium`/`High`/`Very-High` (threat / failed auth). Not reversed |

Device constants for the lab profile: gateway `origin=192.0.2.1`, hostname `CP-LAB-GW-01`, policy layer
`layer_name=Network`, source zone `Internal`, destination zone `External`, source NAT address
`198.51.100.10`. Real logs additionally carry `originsicname`, `loguid`, `sequencenum`, `rule_uid`, and
`layer_uuid`; those are omitted here for a readable oracle.

### 2.2 Field mapping (neutral category -> Check Point CEF)

Check Point emits standard CEF keys where they exist (`src`, `dst`, `spt`, `dpt`, `proto`, `act`, `rt`,
`in`, `out`, `deviceDirection`, `request`, `destinationDnsDomain`, `sourceTranslatedAddress`) and reuses
the ArcSight custom-field slots (`cs1..cs6` with `cs*Label`, `cn1..cn3` with `cn*Label`) per blade, plus
the Check Point-specific keys `cp_severity`, `service_id`, `layer_name`, `product`, `origin`, `inzone`,
`outzone`, and (for VPN/audit) `auth_status`, `administrator`, `operation`. `proto` is the numeric IANA
protocol (`6`/`17`), and `act` is the capitalized action string.

| Replicant neutral category | Device Product | Signature ID | Name | act | Severity |
|---|---|---|---|---|---|
| `traffic:forward` accept | VPN-1 & FireWall-1 | `Log` | service (`https`) | `Accept` | `Unknown` |
| `traffic:forward` deny | VPN-1 & FireWall-1 | `Log` | service (`rdp`) | `Drop` | `Unknown` |
| `utm:ips` | SmartDefense | `IPS` | protection name | `Prevent` | from `ips_severity` |
| `dns:dns-query` | VPN-1 & FireWall-1 | `Log` | `domain-udp` | `Accept` | `Unknown` |
| `event:vpn` success | Mobile Access | `Log` | `Log` | `Accept` | `Unknown` |
| `event:vpn` fail | Mobile Access | `Log` | `Log` | `Reject` | from level |
| `event:system` | Check Point | `Log` | `Log` | `Reject` | from level |

`deviceDirection` is `0` when the destination is an internal (RFC1918) address and `1` otherwise
([Inference]: keyed off the destination zone). `cp_severity` mirrors the header Severity and is emitted
only for logs that carry a threat/event severity (IPS, failed auth), not for plain `Unknown` connections.

### 2.3 Severity mapping (Check Point log level -> CEF severity string, not reversed)

Plain connection logs (firewall accept/deny, DNS) and successful auth carry no threat severity and emit
the string `Unknown`. Threat Prevention maps `ips_severity` directly; event failures map the neutral
level:

| Source | CEF severity string |
|---|---|
| plain connection / successful auth | `Unknown` |
| `ips_severity` low | `Low` |
| `ips_severity` medium | `Medium` |
| `ips_severity` high | `High` |
| `ips_severity` critical | `Very-High` |
| level emergency / critical | `Very-High` |
| level alert / error | `High` |
| level warning | `Medium` |
| level notice / notification / information / debug | `Low` |

Unlike FortiOS (which reverses priority into a 0-10 integer) and PAN-OS (a non-reversed 0-10 integer),
Check Point emits a **string** and increases with seriousness. The same `utm:ips` event that is CEF
severity `7` for FortiGate and `8` for PAN-OS is the string `High` here.

---

## 3. Sample CEF log lines

All lines are `[Constructed]` from the rules above, using the same synthetic entities, ports, session
IDs, byte counts, and event epochs as the seven FortiGate and Palo Alto golden lines so the three
profiles can be compared directly. RFC 3164 syslog prefixes are illustrative (`<189>`/`<188>`/`<187>`)
and host `CP-LAB-GW-01`; the real prefix is added by the transport. Note `rt` is milliseconds.

Traffic forward accept:
```
<189>Jul 16 10:32:04 CP-LAB-GW-01 CEF:0|Check Point|VPN-1 & FireWall-1|Check Point|Log|https|Unknown|act=Accept deviceDirection=1 rt=1752661924000 src=10.20.30.40 dst=203.0.113.25 spt=51544 dpt=443 proto=6 app=HTTPS service_id=https sourceTranslatedAddress=198.51.100.10 sourceTranslatedPort=51544 cs2Label=Rule Name cs2=policy-7 cn1Label=Elapsed cn1=122 in=61325 out=8421 inzone=Internal outzone=External layer_name=Network product=VPN-1 & FireWall-1 origin=192.0.2.1
```

Traffic forward deny:
```
<188>Jul 16 10:32:07 CP-LAB-GW-01 CEF:0|Check Point|VPN-1 & FireWall-1|Check Point|Log|rdp|Unknown|act=Drop deviceDirection=1 rt=1752661927000 src=10.20.30.55 dst=198.51.100.77 spt=44992 dpt=3389 proto=6 app=RDP service_id=rdp cs2Label=Rule Name cs2=policy-0 in=0 out=0 inzone=Internal outzone=External layer_name=Network product=VPN-1 & FireWall-1 origin=192.0.2.1
```

IPS / Threat Prevention:
```
<187>Jul 16 10:33:15 CP-LAB-GW-01 CEF:0|Check Point|SmartDefense|Check Point|IPS|Apache.Struts.OGNL.Remote.Code.Execution|High|act=Prevent deviceDirection=0 rt=1752661995000 src=198.51.100.30 dst=10.20.30.40 spt=443 dpt=49180 proto=6 app=HTTPS service_id=https cp_severity=High cs1Label=Threat Prevention Rule Name cs1=policy-7 cs2Label=Protection ID cs2=40449 cs3Label=Protection Type cs3=IPS cs4Label=Protection Name cs4=Apache.Struts.OGNL.Remote.Code.Execution request=/struts2/index.action msg=applications3A Apache.Struts.OGNL.Remote.Code.Execution product=SmartDefense origin=192.0.2.1
```

DNS query (firewall connection, app dns):
```
<189>Jul 16 10:34:01 CP-LAB-GW-01 CEF:0|Check Point|VPN-1 & FireWall-1|Check Point|Log|domain-udp|Unknown|act=Accept deviceDirection=0 rt=1752662041000 src=10.20.30.40 dst=10.20.0.53 spt=54621 dpt=53 proto=17 app=dns service_id=domain-udp destinationDnsDomain=updates.example.net cs2Label=Rule Name cs2=policy-7 inzone=Internal outzone=Internal layer_name=Network product=VPN-1 & FireWall-1 origin=192.0.2.1
```

DNS response (NXDOMAIN). Carries the resolution outcome, which the query record
does not; this is what makes the DGA technique (REP-016) expressible:
```
<189>Jul 16 10:34:02 CP-LAB-GW-01 CEF:0|Check Point|VPN-1 & FireWall-1|Check Point|Log|domain-udp|Unknown|act=Accept deviceDirection=0 rt=1752662042000 src=10.20.30.40 dst=10.20.0.53 spt=54621 dpt=53 proto=17 app=dns service_id=domain-udp destinationDnsDomain=qv7x2p9k4m.invalid dns_rcode=NXDOMAIN cs2Label=Rule Name cs2=policy-7 inzone=Internal outzone=Internal layer_name=Network product=VPN-1 & FireWall-1 origin=192.0.2.1
```
`[Unverified]` the extension key names `dns_rcode` and `dns_resolved_addr`.
`dns_resolved_addr` is emitted only when the name resolved, so its absence is
itself the NXDOMAIN signal.

Note `origin=192.0.2.1`: this synthetic device address sits in the same
documentation range as the REP-021 inbound scanner pool, so the entity model
reserves the low addresses of that range (`EntityConfig.scanner_reserve`) to keep
a scan source from ever being the reporting gateway's own address.

Mobile Access / VPN login success:
```
<189>Jul 16 10:35:22 CP-LAB-GW-01 CEF:0|Check Point|Mobile Access|Check Point|Log|Log|Unknown|act=Accept rt=1752662122000 src=203.0.113.60 duser=jsmith suser=jsmith auth_status=Successful Login cs3Label=User Group cs3=vpn-users cs5Label=Auth Method cs5=ssl-tunnel cn1Label=Tunnel ID cn1=1846277 reason=login-success msg=SSL tunnel established product=Mobile Access origin=192.0.2.1
```

Mobile Access / VPN login failure:
```
<187>Jul 16 10:35:40 CP-LAB-GW-01 CEF:0|Check Point|Mobile Access|Check Point|Log|Log|High|act=Reject rt=1752662140000 src=198.51.100.200 duser=jsmith suser=jsmith auth_status=Failed Login cp_severity=High cs5Label=Auth Method cs5=ssl-web reason=sslvpn_login_permission_denied msg=SSL user failed to logged in product=Mobile Access origin=192.0.2.1
```

System admin auth failure:
```
<187>Jul 16 10:36:05 CP-LAB-GW-01 CEF:0|Check Point|Check Point|Check Point|Log|Log|High|act=Reject rt=1752662165000 src=10.20.30.9 duser=admin suser=admin auth_status=Failed Login cp_severity=High administrator=admin operation=Log In cs1Label=Client cs1=https reason=name_invalid msg=Administrator admin login failed from https(10.20.30.9) because of invalid user name product=Check Point origin=192.0.2.1
```

---

## 4. Notes

- The same technique catalog and scenario engine drive this profile. Techniques emit vendor-neutral
  `(log_type, subtype)` categories; `CheckPointProfile.render` maps each to the Check Point layout above.
  The FortiGate `signature_id` in the catalog is documentation only and is not read by any profile.
- `event:vpn` with `srccountry` present (REP-011 geovelocity) is not represented in the eight golden
  lines; if added, a Source Region custom field would follow `auth_status`, matching how the FortiGate
  and PAN-OS profiles gate the same optional GeoIP tag.
- Select the vendor at run time with `--vendor checkpoint` (default `fortigate`). Same seed plus
  technique yields the same plan for any vendor; only the serialization differs.
- Real Log Exporter output also carries `loguid`, `sequencenum`, `rule_uid`, `layer_uuid`,
  `originsicname`, and (for Threat Prevention) `flexNumber1=Confidence` / `flexNumber2=Performance
  Impact` / `Signature=<CVE list>`. Those are omitted here to keep the oracle readable; add them when
  validating against a live exporter.
