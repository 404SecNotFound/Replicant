# Technique catalog expansion research, round 2

Status: research proposal. Companion to `technique-catalog-expansion-research.md`
(round 1). Round 1 proposed REP-012 through REP-020. This round proposes REP-021
through REP-024.

Author: RZA. Date: 2026-07-25.

## 1. What is different about this round

Round 1 drew on the strongest anchors regardless of publication date, which
reached back to 2004 for scan detection and 2012 for DGA clustering. This round
was restricted deliberately:

- **Recency.** Priority on 2023 to 2026 work from top venues (NDSS, USENIX
  Security, IMC, RAID, ACSAC).
- **Telemetry fit.** Firewall logs first, IDS and IPS alerts second. Anything
  needing packet payloads, provenance graphs, or endpoint agents was rejected
  regardless of how good the results were.
- **Evidence bar.** A candidate needed a real production or campus deployment, or
  a large real-traffic dataset, with measured results. Papers reporting only
  cross-validated accuracy on a public benchmark did not qualify on their own.

That third filter did most of the work, and section 2 explains why it is not an
arbitrary standard.

## 2. The evidence bar, and why it is set here

Bilot et al., "Sometimes Simpler is Better: A Comprehensive Analysis of
State-of-the-Art Provenance-Based Intrusion Detection Systems" (USENIX Security
2025) reimplemented eight state-of-the-art provenance IDS in one framework and
identified nine shortcomings that block practical deployment. Their headline
finding is that despite recent papers reporting near-perfect detection, most of
the added complexity is unnecessary: a simple neural network matched state of the
art on five of seven DARPA datasets while being lighter and faster.

That result is directly relevant to Replicant, in two ways.

First, it is the reason this document prefers deployment evidence over benchmark
accuracy. A reported 0.99 F1 on a public capture is weak evidence that a
detection survives contact with a real network.

Second, and more concretely: it validates the catalog's existing
`benign_baseline` field as a correctness requirement rather than a nicety. If
Replicant emits only the malicious pattern, any detection scores perfectly and
the operator learns nothing. Every proposal below therefore specifies a benign
baseline that is genuinely hard to separate from the signal, not a token one.

**[Inference]** This is my reading of the paper's implication for a telemetry
generator. The paper is about evaluating detectors, not about generating test
traffic.

## 3. Candidate summary

All four are Tier A: they reuse render paths that already exist, consistent with
the decision to add only `dns:dns-response` as new plumbing.

| Proposed | Name | Log path | Anchor | Evidence |
|---|---|---|---|---|
| REP-021 | Inbound perimeter scan reception | `traffic:forward` (deny, inbound) | IMC 2024, "Have you SYN me?" | 10 years of telescope data, 750M scanning campaigns, 45B packets |
| REP-022 | Multi-stage IDS alert chain | `utm:ips` | Wilkens et al. KCSM; ALERTPRO 2023; AACT 2025 | 446,458 alerts condensed to 700 scenario graphs; 61% alert reduction at 1.36% false negative in a 6-month real SOC deployment |
| REP-023 | TLS 1.3 C2 with flow-only signal | `traffic:forward` | RAID 2024, TLS 1.2 to TLS 1.3 C2 detection | 10.1M flow dataset (4.3M TLS 1.2, 5.8M TLS 1.3), Tranco-based benign traffic |
| REP-024 | Internal host as proxy relay | `traffic:forward` | NDSS, residential proxy detection | 15 months of collection, ~900 GB, 120k gateway and 110k relayed connections |

Round 1's REP-014 (cryptomining) also gains a much stronger and more recent
anchor from this round, covered in section 5.

## 4. Detailed proposals

### REP-021 Inbound perimeter scan reception

**The gap this fills.** REP-002, REP-003 and REP-019 are all outbound or
east-west: an internal source probing targets. That is the minority of what a
real perimeter firewall logs. The dominant volume is inbound unsolicited
scanning from the internet, and the catalog cannot currently produce any of it.

This matters beyond realism. Inbound background scanning is the primary false
positive source for outbound scan rules that are written without a direction
predicate. An operator who tests a scan rule with REP-002 alone never finds out
that the rule also fires on internet background radiation. REP-021 is the
negative control that exposes it.

**Evidence.** "Have you SYN me? Characterizing Ten Years of Internet Scanning"
(IMC 2024) analyzed a large network telescope across 2015 to 2024, covering over
750 million scanning campaigns that sent more than 45 billion packets. The
dataset establishes what inbound scanning actually looks like at a perimeter over
time, including the split between low-rate persistent scanners and aggressive
short campaigns. Related 2024 honeypot work observed 26,159,934 TCP and UDP
packets from 465,251 unique source addresses across an eight-month window, which
gives an order-of-magnitude anchor for source cardinality.

```yaml
  - id: REP-021
    name: "Inbound perimeter scan reception"
    ndr_rule: "NDR-RECON-020"
    ndr_uc: "UC-020"
    attack:
      tactics: ["TA0043 Reconnaissance"]
      techniques: ["T1595.001", "T1595.002"]
    fortigate:
      log_type: "traffic"
      subtype: "forward"
      signature_id: "00013"
      action: "deny"
    cef_fields_held: ["dst"]              # the perimeter address block
    cef_fields_varied: ["src", "dpt", "rt", "externalId"]
    params:
      low:    { unique_src: 200,  duration_min: 60, campaigns: 2, ports: [22, 23, 445, 3389] }
      medium: { unique_src: 1200, duration_min: 60, campaigns: 5, ports: [22, 23, 80, 443, 445, 3389, 5900] }
      high:   { unique_src: 5000, duration_min: 30, campaigns: 9, ports: [22, 23, 80, 443, 445, 1433, 3306, 3389, 5900, 8080] }
    distributions:
      src: "many distinct external sources, heavy-tailed: a few aggressive sources contribute most packets, a long tail sends one or two probes each"
      pattern: "steady low-rate background plus short aggressive campaigns overlaid, matching the two populations the IMC study separates"
      direction: "inbound, so FTNTFGTdirection and the interface pair must be the reverse of the outbound techniques"
    benign_baseline: "this technique IS largely the baseline of a perimeter. Its value is as a false-positive source for outbound scan rules, so it should be runnable concurrently with REP-002"
    references: ["Have you SYN me? Characterizing Ten Years of Internet Scanning, IMC 2024"]
    safety_notes: "external source addresses are synthetic, drawn from the documentation ranges. No real scanner infrastructure is named"
```

Design note: the entity model currently builds outbound flows. Emitting inbound
requires the interface pair and direction to be reversed. **[Unverified]** whether
`_traffic_forward` and the entity pools handle an inbound orientation cleanly; I
have not traced it. This is the one implementation risk in this proposal.

### REP-022 Multi-stage IDS alert chain

**The gap this fills.** REP-009 emits an IPS event rate spike, either one
signature repeated or many distinct signatures. It has no ordering, so it
exercises threshold rules and nothing else. Correlation content is a different
class of detection entirely: it cares whether alert A is followed by alert B on
the same entity pair within a window, in a kill-chain-plausible order.

For anyone writing LogRhythm AIE correlation rules this is the most directly
useful entry in either research round, because a rate spike cannot test a
multi-stage rule at all.

**Evidence.** Wilkens et al., "Multi-Stage Attack Detection via Kill Chain State
Machines," synthesize attack graphs from kill chain state machines over IDS
alerts. They condense up to 446,458 singleton alerts into 700 APT scenario
graphs, a reduction of up to three orders of magnitude, and on CSE-CIC-IDS2018
with a real multi-stage attack spanning ten days they surfaced the attack among
686 generated scenario graphs, about 68.6 scenarios per day. Note this paper is
2021, outside the 3-year window; it is included because it is the clearest
statement of the alert-ordering signal, and the recent work below builds on the
same premise.

Two recent anchors support the operational case. ALERTPRO (Computers & Security,
2023) uses context-aware reinforcement learning to prioritize alerts specifically
for multi-step attack scenarios. AACT (Turcotte et al., 2025) reports a six-month
real-SOC deployment learning from analyst triage actions, achieving a 61 percent
reduction in alerts shown to analysts at a 1.36 percent false negative rate.
Between them they establish that alert ordering and alert volume reduction are
live production problems, not benchmark artifacts.

```yaml
  - id: REP-022
    name: "Multi-stage IDS alert chain (kill-chain ordered)"
    ndr_rule: "NDR-CORR-021"
    ndr_uc: "UC-021"
    attack:
      tactics: ["TA0043 Reconnaissance", "TA0001 Initial Access", "TA0011 Command and Control"]
      techniques: ["T1595", "T1190", "T1071"]
    fortigate:
      log_type: "utm"
      subtype: "ips"
      signature_id: "16384"
      action: "reset"          # varies per stage
    cef_fields_held: ["src", "dst"]        # the entity pair the chain is about
    cef_fields_varied: ["FTNTFGTattack", "FTNTFGTattackid", "rt", "act", "FTNTFGTseverity"]
    params:
      low:    { stages: 3, hits_per_stage: [2, 5],  stage_gap_s: [120, 600], noise_alerts: 20 }
      medium: { stages: 4, hits_per_stage: [3, 12], stage_gap_s: [60, 300],  noise_alerts: 120 }
      high:   { stages: 5, hits_per_stage: [5, 25], stage_gap_s: [30, 180],  noise_alerts: 500 }
    distributions:
      stage_order: "recon signature, then exploit attempt, then post-exploitation or C2 signature. Strictly ordered in time, never interleaved out of order"
      severity: "ascending across stages, so a severity-weighted correlation rule sees escalation"
      noise_alerts: "unrelated single alerts on other entity pairs, interleaved, so the chain must be picked out of alert noise rather than handed over clean"
    benign_baseline: "noise_alerts IS the baseline. A correlation rule that fires on any 3 alerts in a window will fire on the noise too"
    references: ["Wilkens et al., Multi-Stage Attack Detection via Kill Chain State Machines", "ALERTPRO, Computers & Security 2023", "AACT, Turcotte et al. 2025"]
    safety_notes: "attack names and signature ids are labels only, identical to REP-009. No exploit text, no payloads"
```

The `noise_alerts` parameter is the part that makes this honest. Emitting a clean
3-alert chain would make any correlation rule look good. The AACT result (61
percent of alerts closable) is a reminder that real SOC alert streams are
overwhelmingly noise, so the chain has to be found inside noise.

### REP-023 TLS 1.3 C2 with flow-only signal

**The gap this fills, and why it fits the render-path decision.** The scope
decision for this expansion was to add only `dns:dns-response` and no `utm:ssl`
path. That looked like it ruled out encrypted-C2 techniques. The RAID 2024 result
turns that constraint into the technique.

**Evidence.** "Extending C2 Traffic Detection Methodologies: From TLS 1.2 to TLS
1.3-enabled Malware" (RAID 2024) shows that TLS 1.3 encrypts most handshake
messages and conceals the record content type, which degrades C2 classifiers
built for TLS 1.2 because their features came from cleartext handshake metadata.
Their dataset is 10.1 million flows, 4.3 million TLS 1.2 and 5.8 million TLS 1.3,
with benign traffic collected by browsing the January 2024 Tranco list.

The consequence for a detection engineer: as TLS 1.3 becomes the norm, C2
detection has to fall back on flow-level features, which are session counts,
byte volumes and ratios, packet counts, durations, and inter-session timing.
Those are exactly the fields a firewall traffic log carries and Replicant already
varies. So the technique to generate is C2 whose only detectable signal is
flow-level, with no handshake artifact available at all.

This is a graded pair with REP-012 in the same way REP-012 is graded against
REP-001: it tests whether a customer's encrypted-C2 content still works when the
metadata it was tuned on disappears.

```yaml
  - id: REP-023
    name: "TLS 1.3 C2 with flow-only signal"
    ndr_rule: "NDR-C2-022"
    ndr_uc: "UC-022"
    attack:
      tactics: ["TA0011 Command and Control"]
      techniques: ["T1071.001", "T1573.002"]
    fortigate:
      log_type: "traffic"
      subtype: "forward"
      signature_id: "00013"
      action: "accept"
    cef_fields_held: ["src", "dst", "dpt", "proto"]     # dpt always 443
    cef_fields_varied: ["rt", "out", "in", "externalId", "FTNTFGTduration"]
    params:
      low:    { sessions: 40,  interval_s: 180, out_bytes: [900, 1400],  in_bytes: [400, 900] }
      medium: { sessions: 120, interval_s: 90,  out_bytes: [1100, 1600], in_bytes: [500, 1100] }
      high:   { sessions: 300, interval_s: 45,  out_bytes: [1200, 1800], in_bytes: [600, 1300] }
    distributions:
      dpt: "always 443, indistinguishable from browsing on port alone"
      byte_profile: "narrow distribution. The distinguishing feature versus browsing is LOW variance, not high volume. Browsing to 443 has wildly variable transfer sizes; this does not"
      duration: "short and consistent per session, unlike a browsing session that holds open"
      handshake: "deliberately no handshake-derived field is emitted. If a detection needs JA3 or cipher suite, this technique gives it nothing, which is the point"
    benign_baseline: "concurrent browsing to 443 to other destinations with high byte variance and varied durations, so port and destination count cannot separate them"
    references: ["Extending C2 Traffic Detection Methodologies: From TLS 1.2 to TLS 1.3-enabled Malware, RAID 2024"]
    safety_notes: "single synthetic external destination. No TLS is negotiated by Replicant for this technique; the transport TLS option is unrelated and separate"
```

Worth stating plainly in the entry to avoid confusion: Replicant's `--transport
tls` option encrypts the syslog channel to the collector. It has nothing to do
with this technique, which is about the contents of log records describing a
third party's TLS session. Anyone reading the entry quickly could conflate them.

### REP-024 Internal host as proxy relay

**The gap this fills.** Nothing in the catalog models a host that is being used
as infrastructure. Every current technique treats an internal host as either a
source of malicious activity or a target. A compromised host enrolled into a
proxy network is neither: it relays, so it shows paired inbound and outbound
sessions with correlated timing and volume.

That pairing is visible in firewall logs without any payload inspection, which is
what makes it a fit.

**Evidence.** Recent NDSS work on adversarially robust residential proxy
detection collected 696 two-hour packet captures over 15 months, April 2024 to
July 2025, totalling around 900 GB, comprising more than 120,000 gateway
connections, 110,000 relayed connections, and roughly 6 million background
connections. The gateway-versus-relayed distinction in that dataset is precisely
the inbound and outbound pairing this technique generates. The paper's framing as
adversarially robust and explicitly "beyond RTT" also signals that naive timing
correlation is evadable, which is a useful thing for an operator to be able to
test against.

```yaml
  - id: REP-024
    name: "Internal host as proxy relay node"
    ndr_rule: "NDR-C2-023"
    ndr_uc: "UC-023"
    attack:
      tactics: ["TA0011 Command and Control"]
      techniques: ["T1090", "T1090.001"]
    fortigate:
      log_type: "traffic"
      subtype: "forward"
      signature_id: "00013"
      action: "accept"
    cef_fields_held: ["src"]        # the relay host, appearing as both dst (inbound) and src (outbound)
    cef_fields_varied: ["dst", "dpt", "spt", "rt", "out", "in", "externalId"]
    params:
      low:    { relay_pairs: 30,  lag_ms: [20, 200],  duration_min: 60,  clients: 5 }
      medium: { relay_pairs: 150, lag_ms: [10, 500],  duration_min: 60,  clients: 25 }
      high:   { relay_pairs: 600, lag_ms: [5, 1500],  duration_min: 30,  clients: 80 }
    distributions:
      pairing: "for each relayed request, an inbound session to the relay host followed within lag_ms by an outbound session from that host, with correlated byte volumes"
      byte_correlation: "outbound out_bytes approximately equals inbound in_bytes, within a small margin, because the host is forwarding"
      lag: "jittered, and at the high preset wide enough to defeat naive fixed-window timing correlation, per the adversarial framing in the source paper"
    benign_baseline: "a legitimate internal proxy or reverse proxy shows the same pairing. Separating them needs the host's role, not the pattern, so the baseline includes a sanctioned proxy host doing the same thing"
    references: ["Beyond RTT: An Adversarially Robust Two-Tiered Approach for Residential Proxy Detection, NDSS"]
    safety_notes: "Replicant relays nothing. Both halves of each pair are fabricated records. The only socket opened is to the operator's collector"
```

The benign baseline here is the strongest argument for the entry. A sanctioned
proxy and a compromised relay produce nearly the same firewall pattern, so this
technique tests whether a detection incorporates asset role or just pattern
matching. That is a failure mode worth being able to demonstrate.

## 5. Round 1 revision: REP-014 gains a stronger anchor

Round 1 anchored the cryptomining technique on MineHunter (ACSAC 2021, precision
97.0 percent and recall 99.7 percent over 28 TB in one month). A newer and better
anchor exists and the catalog entry should cite it as primary.

MineShark, "Cryptomining Traffic Detection at Scale" (NDSS 2025), ran for ten
months on a 10 Gbps campus network. It detected connections toward 105 mining
pools ahead of commercial systems deployed alongside it, of which 17.6 percent
were encrypted, automatically filtered over 99.3 percent of false alarms, and
sustained 1.3 Mpps with a 0.2 percent loss rate.

Two changes to the REP-014 entry follow from it:

1. The `high` preset should use port 443, since 17.6 percent of what MineShark
   found was encrypted and a mining technique that only ever uses ports 3333 to
   14444 tests a port-list rule rather than a behavioral one. Round 1 already had
   443 in the high preset; the MineShark number is the justification to keep it.
2. The false alarm figure (over 99.3 percent filtered) is the argument for adding
   a benign long-session baseline to the entry. Long-lived low-rate sessions are
   common in normal traffic, which is why that filtering rate was needed.

## 6. Considered and rejected in this round

| Idea | Anchor | Why not |
|---|---|---|
| Mirai-style IoT credential scan and report-in | Six-year Mirai scan evolution study; V3G4 variant, 2023 | Substantially overlaps REP-013 (self-propagation) and REP-007 (credential attack). Better handled as a preset on REP-013 with telnet ports 23 and 2323 than as a separate entry. Adding it standalone would inflate the menu without exercising a new detection. |
| Provenance and host-graph techniques | Bilot et al., USENIX Security 2025 | Needs process and file provenance. Structurally impossible from firewall logs, and the paper's own conclusion is that these systems are not deployment-ready. |
| LLM-based alert triage reproduction | CORTEX 2025; AACT 2025 | These are detection and triage systems, not adversary behaviors. Replicant generates telemetry; it has nothing to emit here. The AACT alert-volume finding is used instead to justify REP-022's noise parameter. |
| Lateral movement graph techniques | LMDetect (2024); Euler (NDSS 2022) | The signal is graph-structural over authentication logs, which REP-018 from round 1 already generates as a login chain. These papers strengthen REP-018's citation list rather than adding an entry. |
| Full APT campaign replay | S-DAPT and similar stage-aware synthetic datasets | This is what the Phase 4 scenario composer already does by chaining techniques. Correct home for it is `data/scenario-catalog.yaml`, not a technique entry. |

That last row is worth noting as a design confirmation: the existence of recent
work on stage-aware synthetic APT datasets, and on high-fidelity lateral movement
dataset generation (LMDG, 2025), is independent support for the approach
Replicant already took in Phase 4.

## 7. Combined implementation plan

Thirteen new techniques across both rounds, taking the catalog from 11 to 24.

**Tier A, no new render path (12 techniques):**

| Batch | Techniques |
|---|---|
| 1 | REP-015 low-throughput DNS exfil, REP-013 self-propagating spread, REP-012 jittered and fleet callback |
| 2 | REP-014 cryptomining, REP-019 stealth scan, REP-018 login chain |
| 3 | REP-021 inbound perimeter scan, REP-022 multi-stage IDS alert chain, REP-023 TLS 1.3 flow-only C2, REP-024 proxy relay |
| 4 | REP-017 DoH bypass, REP-020 newly registered domain (both need the warm-up mechanism) |

**Tier B, needs `dns:dns-response` (1 technique):** REP-016 DGA NXDOMAIN cluster.

**Known risks, carried forward:**

1. Multi-log-type plans. REP-017 (traffic plus dns), REP-018 (event plus
   traffic), REP-024 (paired inbound and outbound). **[Unverified]** whether the
   current planner and `EventRecord` design supports one plan spanning two render
   paths. Must be answered before batch 3 or 4.
2. Inbound orientation for REP-021. **[Unverified]** whether the entity model and
   `_traffic_forward` handle a reversed interface pair.
3. Long durations. REP-015 (up to 72 hours) and REP-019 interact with `--anchor`
   and `align: next-off-hours`.
4. Menu size. At 24 entries the backlog item to group by MITRE tactic in the web
   UI stops being cosmetic.
5. Vendor parity across FortiGate, Palo Alto and Check Point for every entry.

## 8. Sources

- [Sometimes Simpler is Better: A Comprehensive Analysis of State-of-the-Art Provenance-Based Intrusion Detection Systems (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/bilot)
- [Have you SYN me? Characterizing Ten Years of Internet Scanning (IMC 2024)](https://dl.acm.org/doi/10.1145/3646547.3688409)
- [MineShark: Cryptomining Traffic Detection at Scale (NDSS 2025)](https://www.ndss-symposium.org/ndss-paper/mineshark-cryptomining-traffic-detection-at-scale/)
- [Extending C2 Traffic Detection Methodologies: From TLS 1.2 to TLS 1.3-enabled Malware (RAID 2024)](https://dl.acm.org/doi/10.1145/3678890.3678921)
- [Beyond RTT: An Adversarially Robust Two-Tiered Approach for Residential Proxy Detection (NDSS)](https://www.ndss-symposium.org/wp-content/uploads/2026-f2086-paper.pdf)
- [Multi-Stage Attack Detection via Kill Chain State Machines (Wilkens et al.)](https://arxiv.org/abs/2103.14628)
- [Combating alert fatigue with AlertPro: context-aware alert prioritization using reinforcement learning for multi-step attack detection (Computers & Security, 2023)](https://www.sciencedirect.com/science/article/abs/pii/S0167404823004935)
- [AI-Driven Security Alert Screening and Alert Fatigue Mitigation in Security Operations Centers: A Survey (covers AACT and ALERTPRO)](https://arxiv.org/html/2605.08316)
- [Lateral Movement Detection via Time-aware Subgraph Classification on Authentication Logs (LMDetect, 2024)](https://arxiv.org/abs/2411.10279)
- [The evolution of Mirai botnet scans over a six-year period](https://www.sciencedirect.com/science/article/pii/S2214212623002132)
- [LMDG: Advancing Lateral Movement Detection Through High-Fidelity Dataset Generation (2025)](https://arxiv.org/pdf/2508.02942)
