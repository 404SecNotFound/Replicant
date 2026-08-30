# Technique catalog expansion research, round 4

Status: **proposal.** Nothing here is implemented. Companion to
`technique-catalog-expansion-research.md` (round 1, REP-012..REP-020,
implemented in v0.2.0), `technique-catalog-expansion-research-round2.md`
(round 2, REP-021..REP-024, implemented in v0.2.0), and
`round3-expansion-triage.md` (round 3, a triage of an external proposal
spanning REP-025..REP-041, nothing implemented).

The REP-025..REP-041 range is **claimed**. Round 3 parked or adopted in
principle REP-029, REP-030, REP-031, REP-032, REP-035, REP-036 and REP-041,
adopted with changes REP-025, REP-026, REP-027, REP-028, REP-033 and REP-034,
and rejected REP-037, REP-038, REP-039 and REP-040. This round does not
re-propose, renumber or supersede any of those. Where a round-3 decision
changes the framing of a round-4 candidate (REP-034's events-per-second
honesty rule, REP-031's non-collision with REP-046) the candidate says so in
place.

Produced externally as part of the catalog review of 2026-08-30 and taken into the
repository on that date, on the same terms as round 3: what belongs here is the
proposal as a record, not a commitment to build it. Adopting any of it is a
separate decision about where the project's effort goes, and it is the project
owner's. See `tasks/catalog-review-2026-08-plan.md` for how the rest of that
review was triaged.

## 1. What is different about this round

Round 1 drew on the strongest anchors regardless of date. Round 2 restricted
itself to recent top-venue work with deployment evidence. Round 3 was not
authored here at all: it arrived as an external gap analysis and the document
in this repo is the triage of it. This round returns to self-authored
proposals, with the selection rule narrowed further than either earlier round:

- **Complementarity with round 3.** Every candidate was checked against the
  round-3 parked and adopted sets, not just the implemented 24. A candidate
  that a round-3 entry already covers is out, even though no round-3 entry
  exists in code yet.
- **No new render path, as a selection criterion.** Round 1 treated "needs a
  new render path" as Tier B and shipped exactly one such item (REP-016).
  This round admits only candidates that bind to the five existing render
  paths. That is stated per entry in section 6, and most entries need no new
  field at all.
- **Difficulty-ladder framing.** Several candidates are deliberate hard
  versions of existing entries, in the same way REP-012 grades REP-001 and
  REP-019 grades REP-002: REP-042 against REP-005, REP-043 against REP-022,
  REP-046 against REP-011, REP-049 against REP-023. A green result on the
  easy entry proves less than an operator assumes; the hard version is the
  honest control.

As in round 1: every mapping from "this log pattern" to "this detection
fires" below is **[Inference]**, engineering judgment from the cited work.
Measured results attributed to a source are quoted from the source and are
checkable at the links in section 8. Two claims could not be verified against
a primary source in this session and are marked **[Unverified]** in place,
with what would resolve them.

## 2. Where the current catalog is thin

Counting the 24 shipped entries by ATT&CK tactic (an entry appears under
every tactic it lists):

| Tactic | Entries | Count |
|---|---|---|
| TA0011 Command and Control | REP-001, 004, 008, 010, 012, 015, 016, 017, 020, 022, 023, 024 | 12 |
| TA0007 Discovery | REP-002, 003, 006, 013, 019 | 5 |
| TA0043 Reconnaissance | REP-009, 019, 021, 022 | 4 |
| TA0010 Exfiltration | REP-004, 005, 015 | 3 |
| TA0006 Credential Access | REP-007, 018 | 2 |
| TA0008 Lateral Movement | REP-013, 018 | 2 |
| TA0001 Initial Access | REP-011, 022 | 2 |
| TA0042 Resource Development | REP-008, 020 | 2 |
| TA0005 Defense Evasion | REP-017 | 1 |
| TA0040 Impact | REP-014 | 1 |
| Execution, Persistence, Privilege Escalation, Collection | none | 0 |

Three observations, stated plainly because they drive the ranking below.

1. **The C2 weighting is mostly correct.** Twelve of twenty-four entries
   under Command and Control looks lopsided until the vantage point is
   considered: a perimeter firewall's most information-rich view of a
   compromise is exactly the callback, and the catalog's C2 entries are not
   duplicates of each other (periodicity, jitter, fleet aggregation, DNS,
   DoH, DGA, newly observed destination, newly registered domain, TLS 1.3
   flow-only, proxy relay, denied egress, alert chain). This is a firewall
   telemetry generator; the weighting matches the instrument.
2. **The empty tactics are structurally absent, not neglected.** Execution,
   Persistence, Privilege Escalation and Collection happen on a host. A
   firewall cannot see them except through their network shadows, and those
   shadows are already represented (REP-022's chain implies execution;
   REP-044 below is precisely Persistence's network shadow). Adding entries
   filed under those tactics would be relabeling, not coverage.
3. **The actionable thin spots are Impact, Initial Access, and flow-layer
   Exfiltration.** Impact has one entry (REP-014). Initial Access has two,
   both keyed on VPN logins. Exfiltration has three, two of which are DNS
   and one a naive volume spike that any threshold rule catches. Round 4
   addresses these with REP-047 (Impact), REP-043 and REP-044 (Initial
   Access's downstream shadow), and REP-042 (exfiltration that no
   volume rule can see).

## 3. Candidate summary

All ten are Tier A under the old terminology: they bind to existing render
paths and need no new field in any vendor profile. Ranked in proposal order.

| Proposed | Name | Log path | Anchor | Why it is not already covered |
|---|---|---|---|---|
| REP-042 | Size-limited chunked exfiltration | `traffic:forward` | ATT&CK T1030; Microsoft Security blog 2025-10-20 | REP-005 is one spike against a baseline; this is many sub-threshold transfers only visible in long-window per-(src,dst) aggregation |
| REP-043 | Inbound-exploit to egress-callback dialog correlation | `utm:ips` + `traffic:forward` | BotHunter, USENIX Security 2007 | nothing in the catalog joins an IPS alert to subsequent traffic in causal order |
| REP-044 | Compromised server role reversal (web-shell egress) | `traffic:forward` | joint NSA/ASD guidance, April 2020; ATT&CK T1505.003 | REP-008 is uniform per-host novelty; this keys on role violation (a server that becomes a client) |
| REP-045 | Beacon retries to dead C2, then fallback failover | `traffic:forward` | BotHunter SCADE; Disclosure, ACSAC 2012; Karasaridis et al. HotBots 2007 **[Unverified]** | REP-010 is denies across many destinations; REP-001 is successful callbacks; the signal here is failure ratio and retry timing to one destination, then failover |
| REP-046 | VPN login from an unfamiliar source network | `event:vpn` | Microsoft Entra ID Protection detector classes | REP-011 needs velocity arithmetic to fire; a first-ever source network violates no velocity constraint |
| REP-047 | Outbound DDoS participation from a compromised host | `traffic:forward` | D-WARD, IEEE TDSC 2005 | Impact has only REP-014; per-destination two-way statistics are a shape no entry produces |
| REP-048 | Long-lived near-idle session (held-open implant socket) | `traffic:forward` | RITA (Active Countermeasures) feature set | complement of REP-014 (steady symmetric bytes) and REP-023 (many short sessions): one very long session, near-zero bytes |
| REP-049 | Non-periodic C2 identifiable only by connection shape | `traffic:forward` | JACKSTRAWS, USENIX Security 2011 | every C2 entry with a timing signal gives a periodicity detector something; this gives it nothing |
| REP-050 | Compromised host as outbound spam relay | `traffic:forward` | Botlab, NSDI 2009; BotMiner, USENIX Security 2008 | REP-006 fan-out varies dpt; SMTP fan-out holds dpt and produces one short session per destination |
| REP-051 | Non-periodic group-similarity C2 cluster | `traffic:forward` | BotMiner, USENIX Security 2008 | cross-host shape similarity with no periodicity; ranked last, see the caveat in its section |

## 4. Detailed proposals

### REP-042 Size-limited chunked exfiltration ("a thousand small uploads")

**Hard version of REP-005.** REP-005 emits a large out-byte spike against the
host's own baseline; every volume rule fires. T1030 (Data Transfer Size
Limits) exists precisely because exfiltration need not spike: fixed-size
chunks, each under a plausible per-transfer threshold, recurring for days.
The ATT&CK T1030 detection strategy notes uniform packet sizes at consistent
intervals as the observable. Microsoft's 2025-10-20 analysis of threat
activity targeting Azure Blob Storage attributes T1030 to chunked exfiltration
constrained to fixed-size transfers that stay under established thresholds.
One secondary source quantifies the pattern as roughly 2.1 GB over 8 days via
about 90 sub-threshold transfers (attributed to DeepTempo); that figure is
**[Unverified]** pending primary confirmation and is not load-bearing.

The signal lives only in long-window per-(src,dst) aggregation: many
recurring sessions from one host to one rare external destination, each `out`
just under the threshold, near-uniform in size, hours-to-days in span, large
in aggregate, with no single session tripping anything. A rule tuned on
REP-005 reports clean here.

```yaml
  - id: REP-042
    name: "Size-limited chunked exfiltration"
    ndr_rule: "NDR-EXFIL-024"
    ndr_uc: "UC-024"
    attack:
      tactics: ["TA0010 Exfiltration"]
      techniques: ["T1030", "T1048", "T1020"]
    fortigate:
      log_type: "traffic"
      subtype: "forward"
      signature_id: "00013"
      action: "accept"
    cef_fields_held: ["src", "dst", "dpt", "proto"]
    cef_fields_varied: ["rt", "out", "in", "externalId", "FTNTFGTduration"]
    params:
      low:    { transfers: 40,  chunk_kb: [380, 420],   threshold_kb: 512,  span_h: 24 }
      medium: { transfers: 90,  chunk_kb: [900, 980],   threshold_kb: 1024, span_h: 96 }
      high:   { transfers: 200, chunk_kb: [1900, 2000], threshold_kb: 2048, span_h: 192 }
    distributions:
      out_bytes: "near-uniform per session, always just under threshold_kb; the distinguishing feature is LOW variance, like REP-023"
      in_bytes: "small ack-shaped responses"
      timing: "recurring over hours-to-days, loosely regular with gaps; no business-hours weighting"
      aggregate: "total out across the run is large; no single session is"
    benign_baseline: "a benign fixed-size uploader (backup or API agent) to a SECOND destination is emitted alongside with a similar chunk profile, so uniform size alone cannot separate them"
    references: ["MITRE ATT&CK T1030 Data Transfer Size Limits", "Microsoft Security blog 2025-10-20, threat activity targeting Azure Blob Storage"]
    safety_notes: "single synthetic external destination from 203.0.113.0/24; spans are long by design and stated in the run summary"
```

The foil is load-bearing: backup and sync agents are the canonical benign
fixed-size uploader, so the detection must use destination rarity or role,
not chunk uniformity alone.

### REP-043 Inbound-exploit to egress-callback dialog correlation (BotHunter chain)

**Hard version of REP-022.** REP-022 orders alerts within one log type.
Nothing in the catalog joins *across* log types in causal order: an IDS
alert, then a successful inbound dialog to the alerted host, then a new
outbound dialog from that same host. That three-part correlation is exactly
the dialog model of BotHunter (Gu, Porras, Yegneswaran, Fong, Lee, USENIX
Security 2007), whose E1-to-E5 state machine runs over IDS alerts and
connection dialogs, substantially the same telemetry a FortiGate emits as
`utm:ips` and `traffic:forward`. BotHunter was evaluated against roughly
9,000 live infections over 90 days, which is the deployment evidence round 2
asked for.

This is the strongest cross-log-type test the catalog can offer an operator's
correlation content, because the join key (the internal host) changes role
between the second and third legs: destination inbound, source outbound.

```yaml
  - id: REP-043
    name: "Inbound-exploit to egress-callback dialog correlation"
    ndr_rule: "NDR-CORR-025"
    ndr_uc: "UC-025"
    attack:
      tactics: ["TA0001 Initial Access", "TA0011 Command and Control"]
      techniques: ["T1190", "T1071", "T1105"]
    fortigate:
      log_type: "utm"            # emits traffic:forward legs too
      subtype: "ips"
      signature_id: "16384"
      action: "reset"
    cef_fields_held: ["dst"]       # the internal host the chain is about
    cef_fields_varied: ["src", "FTNTFGTattack", "FTNTFGTattackid", "act", "rt", "out", "in", "externalId"]
    params:
      low:    { chains: 1, alert_hits: [2, 4], inbound_sessions: [1, 3], outbound_sessions: [2, 6],  window_min: 120, noise_alerts: 30 }
      medium: { chains: 2, alert_hits: [3, 8], inbound_sessions: [2, 5], outbound_sessions: [4, 12], window_min: 90,  noise_alerts: 150 }
      high:   { chains: 3, alert_hits: [4, 12], inbound_sessions: [3, 8], outbound_sessions: [6, 20], window_min: 60, noise_alerts: 400 }
    distributions:
      chain: "exploit alert(s) against the host, then an accepted inbound session to it, then NEW outbound sessions from it to a destination it has no history with; kill-chain order with temporal locality, not strict lockstep"
      noise: "unrelated alerts and routine egress interleaved through the window, same principle as REP-022's noise_alerts"
    benign_baseline: "vulnerability-scanner alerts against the same host with NO subsequent change in its outbound behavior, plus unrelated routine egress, interleaved; a rule that fires on any alert-then-traffic pair fires on the baseline too"
    references: ["BotHunter, Gu et al., USENIX Security 2007"]
    safety_notes: "attack names are labels only, identical to REP-009 and REP-022; no exploit text"
```

The foil matters: enterprise vulnerability scanners produce exactly the
inbound alert half with none of the compromise half, and a correlation rule
that cannot tell scanner noise from a real chain will page on every scan
window.

### REP-044 Compromised server role reversal (web-shell egress)

**The gap this fills.** Every traffic entry treats an internal host as one
kind of actor. A server planted with a web shell changes kind: a host with a
stable inbound-only history initiates outbound sessions to a destination it
has never contacted. The joint NSA/ASD guidance "Detect and Prevent Web
Shell Malware" (April 2020) directs defenders to monitor for anomalous
outbound connections from web servers precisely because servers do not
originate client traffic, and ATT&CK T1505.003 lists Network Connection
Creation among its data sources.

**Distinct from REP-008.** REP-008 tests per-host destination novelty
uniformly. This keys on a role and baseline violation, the server-versus-
client distinction, which is a different analytic and a different false
positive population (patch checks and license calls, not new browsing).

```yaml
  - id: REP-044
    name: "Compromised server role reversal (web-shell egress)"
    ndr_rule: "NDR-C2-026"
    ndr_uc: "UC-026"
    attack:
      tactics: ["TA0003 Persistence", "TA0011 Command and Control"]
      techniques: ["T1505.003", "T1071"]
    fortigate:
      log_type: "traffic"
      subtype: "forward"
      signature_id: "00013"
      action: "accept"
    cef_fields_held: ["src"]       # the server, inbound-only during warm-up
    cef_fields_varied: ["dst", "dpt", "rt", "out", "in", "externalId", "FTNTFGTduration"]
    params:
      low:    { warmup_h: 24, inbound_per_h: [20, 60], egress_sessions: 6,  phase: "download-then-interactive" }
      medium: { warmup_h: 48, inbound_per_h: [20, 60], egress_sessions: 20, phase: "download-then-interactive" }
      high:   { warmup_h: 72, inbound_per_h: [10, 40], egress_sessions: 60, phase: "download-then-interactive" }
    distributions:
      warmup: "inbound client sessions to the server only; the server originates nothing, establishing its role baseline"
      egress: "first a download-heavy pull (in >> out), then interactive small-packet sessions (small both ways, irregular gaps) to one novel external destination"
    benign_baseline: "legitimate post-update outbound from a server (patch check, license call) is emitted from OTHER servers in the same run, so any server-egress alert fires on the baseline too"
    references: ["NSA/ASD, Detect and Prevent Web Shell Malware, April 2020", "MITRE ATT&CK T1505.003"]
    safety_notes: "novel destination from the synthetic external pool; warm-up is stated in the run summary per catalog note 4"
```

This is the first catalog entry filed under TA0003 Persistence, and it is
honest about why: the persistence itself is invisible to a firewall, and what
is generated is its network shadow.

### REP-045 Beacon retries to dead C2, then fallback failover

**The gap this fills.** REP-001 is successful callbacks; REP-010 is denies
across many destinations. Neither models a callback channel that is *failing*:
repeated attempts to one destination at backoff intervals with zero response
bytes, then a failover to a second destination after N failures. That is
T1008 (Fallback Channels), unused in the catalog, and the failure ratio plus
retry timing to a single destination is a distinct signal from both neighbors.
BotHunter's SCADE component weights failed connections in its anomaly score;
Disclosure (Bilge et al., ACSAC 2012) detects C&C from large-scale NetFlow
including the failure patterns of unreachable servers. A third anchor
(Karasaridis et al., "Wide-scale Botnet Detection and Characterization,"
USENIX HotBots 2007) is cited in secondary references but was not confirmed
against a fetched primary source in this session: **[Unverified]**, and the
entry stands on the first two without it.

```yaml
  - id: REP-045
    name: "Beacon retries to dead C2, then fallback failover"
    ndr_rule: "NDR-C2-027"
    ndr_uc: "UC-027"
    attack:
      tactics: ["TA0011 Command and Control"]
      techniques: ["T1071", "T1008"]
    fortigate:
      log_type: "traffic"
      subtype: "forward"
      signature_id: "00013"
      action: "deny"            # or accept with in=0, selectable
    cef_fields_held: ["src"]
    cef_fields_varied: ["dst", "dpt", "rt", "act", "out", "in", "externalId"]
    params:
      low:    { retries_primary: 6,  backoff: "geometric", failover_after: 5,  retries_fallback: 3,  duration_min: 240 }
      medium: { retries_primary: 12, backoff: "geometric", failover_after: 10, retries_fallback: 8,  duration_min: 360 }
      high:   { retries_primary: 25, backoff: "geometric", failover_after: 20, retries_fallback: 15, duration_min: 480 }
    distributions:
      retry_timing: "backoff between attempts to the primary: growing intervals, not the fixed period of REP-001"
      failure: "primary attempts get zero response bytes (deny, or accept with in=0); the failure ratio to ONE destination is the signal"
      failover: "after failover_after failures, attempts shift to a second synthetic destination which begins answering"
    benign_baseline: "a monitoring agent retrying a dead internal service on a fixed port is emitted alongside; destination role (internal service vs rare external) is what separates them"
    references: ["BotHunter, Gu et al., USENIX Security 2007", "Disclosure, Bilge et al., ACSAC 2012"]
    safety_notes: "both destinations synthetic; no connection is attempted to anything but the collector"
```

### REP-046 VPN login from an unfamiliar source network

**Hard version of REP-011.** REP-011's geovelocity arithmetic requires two
logins too far apart for the time between them. A first-ever successful login
from a source network absent from the user's entire history violates no
velocity constraint, so REP-011 cannot fire by construction. Microsoft Entra
ID Protection documents the detector split explicitly: Impossible Travel is a
separate class from Atypical Travel, Unfamiliar Sign-in Properties and New
Country, and the unfamiliar-property classes exist because velocity misses
exactly this case. Detection requires a per-user source baseline, not a
distance computation.

This does not collide with the round-3 parked REP-031 (concurrent overlapping
VPN sessions): REP-031 is a tunnel-lifetime join, this is a per-user
source-history join.

```yaml
  - id: REP-046
    name: "VPN login from an unfamiliar source network"
    ndr_rule: "NDR-ATO-028"
    ndr_uc: "UC-028"
    attack:
      tactics: ["TA0001 Initial Access"]
      techniques: ["T1078", "T1133"]
    fortigate:
      log_type: "event"
      subtype: "vpn"
      signature_id: "39947"    # [Unverified] same caveat as REP-011
      action: "tunnel-up"
    cef_fields_held: ["duser"]
    cef_fields_varied: ["src", "FTNTFGTsrccountry", "rt"]
    params:
      low:    { users: 3, history_logins_each: [10, 30], novel_logins: 1, window_min: 1440 }
      medium: { users: 8, history_logins_each: [10, 30], novel_logins: 2, window_min: 720 }
      high:   { users: 15, history_logins_each: [5, 20],  novel_logins: 4, window_min: 360 }
    distributions:
      history: "each user logs in only from a small stable set of source networks, establishing the per-user baseline"
      novel: "the test login comes from a source network absent from that user's history; SAME country and plausible hour, so no velocity or geo rule fires"
    benign_baseline: "genuine travel and ISP changes for OTHER users in the same run produce novel-source logins too; per-user novelty alone cannot separate them"
    references: ["Microsoft Entra ID Protection risk detections (Impossible Travel vs Atypical Travel vs Unfamiliar Sign-in Properties vs New Country)"]
    safety_notes: "source IPs and countries are synthetic tags; usernames from the synthetic directory pool"
```

The foil is the hard part of this entry and the reason it is worth shipping:
novel-source logins are a normal product of travel and ISP churn, so the
detection must weight additional context rather than alerting on novelty
alone.

### REP-047 Outbound DDoS participation from a compromised internal host

**The gap this fills.** Impact has exactly one entry (REP-014). A compromised
host participating in a direct network flood looks, at its own egress
firewall, like one internal host opening many sessions to a single external
destination with a highly asymmetric send:receive ratio. That is D-WARD's
core observable (Mirkovic and Reiher, IEEE TDSC 2005): per-destination
two-way statistics built from out/in ratios and connection counts, maintained
at the source end, the same vantage a perimeter firewall has.

**Honesty note, following the round-3 REP-034 precedent.** Safety rule 4 caps
events per second, so a flood cannot be expressed as an event-rate spike
here. The signal is carried entirely in per-session byte asymmetry and
session counts toward one destination. The entry must say so on its face, or
it teaches the operator to expect a spike Replicant will never produce.

```yaml
  - id: REP-047
    name: "Outbound DDoS participation from a compromised host"
    ndr_rule: "NDR-IMPACT-029"
    ndr_uc: "UC-029"
    attack:
      tactics: ["TA0040 Impact"]
      techniques: ["T1498.001"]
    fortigate:
      log_type: "traffic"
      subtype: "forward"
      signature_id: "00013"
      action: "accept"
    cef_fields_held: ["src", "dst"]
    cef_fields_varied: ["dpt", "spt", "proto", "rt", "out", "in", "externalId"]
    params:
      low:    { sessions: 60,  out_in_ratio: [10, 30],  protos: ["tcp"],        window_min: 30 }
      medium: { sessions: 200, out_in_ratio: [20, 60],  protos: ["tcp", "udp"], window_min: 20 }
      high:   { sessions: 500, out_in_ratio: [40, 100], protos: ["tcp", "udp"], window_min: 15 }
    distributions:
      dst: "one external destination for the whole run; session counts against it dwarf the host's norm"
      asymmetry: "out >> in per session; responses near zero or absent, the D-WARD two-way ratio departing from normal"
      rate: "bounded by the events-per-second safety cap; the cap is stated in the run summary"
    benign_baseline: "a backup or mirror sync to one destination (high volume but sustained, few LONG sessions with two-way bytes) is emitted alongside; session count and ratio, not volume, must separate them"
    references: ["D-WARD, Mirkovic and Reiher, IEEE TDSC 2005"]
    safety_notes: "destination from the synthetic external pool; no traffic is generated, only log records"
```

### REP-048 Long-lived near-idle session (held-open implant socket)

**The gap this fills.** REP-014 is long sessions with steady symmetric bytes;
REP-023 is many short sessions. The complement of both is one session held
open for hours carrying almost nothing: an implant keeping a socket warm for
later tasking. That is a distinct point in the (duration, total bytes) joint
distribution and neither neighbor exercises it. The anchor is RITA (Active
Countermeasures), an open-source framework whose published feature set
includes Long Connection Detection and Strobe Detection computed from
connection logs, the same fields a firewall traffic record carries. RITA is
a detection tool rather than a measured study, which is why this entry is
ranked below the paper-anchored candidates; the feature-set claim itself is
verifiable at the repository link.

```yaml
  - id: REP-048
    name: "Long-lived near-idle session (held-open implant socket)"
    ndr_rule: "NDR-C2-030"
    ndr_uc: "UC-030"
    attack:
      tactics: ["TA0011 Command and Control"]
      techniques: ["T1095", "T1071"]
    fortigate:
      log_type: "traffic"
      subtype: "forward"
      signature_id: "00013"
      action: "accept"
    cef_fields_held: ["src", "dst", "dpt", "proto"]
    cef_fields_varied: ["rt", "out", "in", "FTNTFGTduration", "externalId"]
    params:
      low:    { sessions: 1, session_min: 240,  total_bytes: [200, 2000],  keepalive_s: 300 }
      medium: { sessions: 2, session_min: 480,  total_bytes: [500, 4000],  keepalive_s: 600 }
      high:   { sessions: 3, session_min: 720,  total_bytes: [1000, 8000], keepalive_s: 900 }
    distributions:
      duration: "single sessions lasting hours, handled by the duration_override_s path resolved in round 2"
      bytes: "near-zero total; only tiny keepalive-sized transfers at long intervals, nothing like REP-014's steady share traffic"
      dst: "rare external destination with no history from any host"
    benign_baseline: "SSH management, database pools and keepalive sessions from SANCTIONED hosts are emitted alongside; destination rarity and host role, not duration alone, must separate them"
    references: ["RITA, Active Countermeasures (Long Connection Detection, Strobe Detection)"]
    safety_notes: "synthetic external destination; long simulated durations stated in the run summary"
```

### REP-049 Non-periodic C2 identifiable only by connection shape

**Hard version of REP-023, and the endpoint of the catalog's C2 difficulty
ladder.** REP-001, REP-012 and REP-023 all leave a timing signal a
periodicity detector can work with. This candidate removes it: deliberately
aperiodic callback timing, a constant narrow byte shape, short consistent
durations. The periodicity graders written against REP-001/012/023 get
nothing, and detection must fall back to connection-graph and byte-shape
features, exactly the features JACKSTRAWS (Jacob, Hund, Kruegel, Holz,
USENIX Security 2011) uses to pick C2 connections out of bot traffic without
relying on timing regularity.

```yaml
  - id: REP-049
    name: "Non-periodic C2 identifiable only by connection shape"
    ndr_rule: "NDR-C2-031"
    ndr_uc: "UC-031"
    attack:
      tactics: ["TA0011 Command and Control"]
      techniques: ["T1071.001", "T1573.002"]
    fortigate:
      log_type: "traffic"
      subtype: "forward"
      signature_id: "00013"
      action: "accept"
    cef_fields_held: ["src", "dst", "dpt", "proto"]      # dpt always 443
    cef_fields_varied: ["rt", "out", "in", "externalId", "FTNTFGTduration"]
    params:
      low:    { sessions: 30,  gap_s: [90, 900],   out_bytes: [900, 1300],  in_bytes: [400, 800],  session_s: [2, 8] }
      medium: { sessions: 100, gap_s: [45, 600],   out_bytes: [1000, 1500], in_bytes: [500, 1000], session_s: [2, 8] }
      high:   { sessions: 250, gap_s: [20, 400],   out_bytes: [1100, 1700], in_bytes: [600, 1200], session_s: [2, 8] }
    distributions:
      timing: "deliberately aperiodic; inter-session gaps drawn wide and irregular so autocorrelation and FFT find no peak"
      byte_profile: "constant narrow shape, low variance; duration short and consistent. The shape is the only signal, which is the point"
    benign_baseline: "browsing to 443 with high byte variance, PLUS aperiodic benign software callbacks with a similar narrow shape; byte shape alone cannot separate them, forcing graph or destination features"
    references: ["JACKSTRAWS, Jacob et al., USENIX Security 2011"]
    safety_notes: "one synthetic external destination; no TLS is negotiated (same note as REP-023)"
```

The second half of the foil (aperiodic benign software with a similar shape)
is what keeps this honest: a detector that fires on narrow-byte aperiodic
sessions alone will fire on every quiet updater in the enterprise.

### REP-050 Compromised host as outbound spam relay

**The gap this fills.** REP-006 fan-out varies destination port and produces
a discovery signal. A spam relay is a service-specific fan-out: a
workstation-class host making many short sessions to many distinct external
destinations, all on SMTP ports, inside a window. Holding dpt constant at
25/587 with one short session per destination is a shape REP-006 does not
produce, and it exercises T1071.003 (Mail Protocols), an unused
sub-technique. Botlab (John, Moshchuk, Gribble, Krishnamurthy, NSDI 2009)
studied spamming botnets from live feeds and establishes what botnet spam
sending looks like at the network edge; BotMiner (USENIX Security 2008) is
the detection-framework anchor, since its spam-module analysis keys on
exactly this class of egress.

```yaml
  - id: REP-050
    name: "Compromised host as outbound spam relay"
    ndr_rule: "NDR-C2-032"
    ndr_uc: "UC-032"
    attack:
      tactics: ["TA0011 Command and Control"]
      techniques: ["T1071.003"]
    fortigate:
      log_type: "traffic"
      subtype: "forward"
      signature_id: "00013"
      action: "accept"
    cef_fields_held: ["src", "dpt"]          # dpt in {25, 587}
    cef_fields_varied: ["dst", "rt", "out", "in", "externalId"]
    params:
      low:    { unique_dst: 40,  window_min: 60, dpt: 25,  session_s: [2, 10] }
      medium: { unique_dst: 150, window_min: 60, dpt: 587, session_s: [2, 10] }
      high:   { unique_dst: 400, window_min: 30, dpt: 25,  session_s: [1, 8] }
    distributions:
      dst: "many distinct external destinations, one short session each, heavy-tailed across MX-like space"
      bytes: "small out, minimal in; consistent with short SMTP transactions"
      port: "held at 25 or 587 for the whole run; this is what separates it from REP-006"
    benign_baseline: "the real mail gateway emits the IDENTICAL pattern in the same run; only asset role separates them, the same lesson as REP-024's sanctioned proxy"
    references: ["Botlab, John et al., NSDI 2009", "BotMiner, Gu et al., USENIX Security 2008"]
    safety_notes: "all destinations synthetic; no mail is composed or sent, only log records"
```

### REP-051 Non-periodic group-similarity C2 cluster (BotMiner-style)

**Ranked last, with an explicit caveat.** Several internal hosts contact the
same rare destination in a window with statistically similar connection
shapes and no periodicity. Detection is cross-host similarity clustering,
BotMiner's C-plane/A-plane model (USENIX Security 2008). The caveat: this is
a sibling of REP-012's fleet mode, which also hides per-host signal and
exposes it only in aggregate. What remains distinct is the absence of
periodicity (REP-012's aggregate is periodic; this aggregate is merely
similar), and whether that difference survives contact with the repo's
"parameterise, do not add" rule is a judgment call. **If the overlap with
REP-012 is judged too close, drop this entry first.**

```yaml
  - id: REP-051
    name: "Non-periodic group-similarity C2 cluster"
    ndr_rule: "NDR-C2-033"
    ndr_uc: "UC-033"
    attack:
      tactics: ["TA0011 Command and Control"]
      techniques: ["T1071"]
    fortigate:
      log_type: "traffic"
      subtype: "forward"
      signature_id: "00013"
      action: "accept"
    cef_fields_held: ["dst", "dpt", "proto"]      # src deliberately NOT held
    cef_fields_varied: ["src", "rt", "out", "in", "externalId", "FTNTFGTduration"]
    params:
      low:    { hosts: 4,  sessions_each: [3, 8],  window_min: 240, shape: "narrow" }
      medium: { hosts: 10, sessions_each: [2, 6],  window_min: 360, shape: "narrow" }
      high:   { hosts: 20, sessions_each: [1, 4],  window_min: 480, shape: "narrow" }
    distributions:
      shape: "all hosts draw from the SAME narrow (out, in, duration) distribution; per-host sessions too few to characterize alone"
      timing: "no shared period and no per-host period; only cross-host shape similarity and shared destination"
    benign_baseline: "a fleet pulling updates from one sanctioned update server shows the identical pattern; destination role and software inventory, not the cluster, must separate them. This is the exact false positive BotMiner-style detectors must suppress"
    references: ["BotMiner, Gu et al., USENIX Security 2008"]
    safety_notes: "one synthetic external destination; nothing executes on any host"
```

## 5. Considered and rejected for round 4

Recording these so the same ground is not re-covered, same standard as round
1's section 5 and round 2's section 6.

| Idea | Comparable | Why not |
|---|---|---|
| Zeek or packet-layer companion output | Security Onion's Mordor, Splunk attack_range, flowsynth | A format gap, not a technique. Every candidate above is already expressible in the CEF render paths; a second serialization of the same events exercises no new detection. If a Zeek `conn.log` writer is ever wanted it is an emitter feature, belongs to all 24+ entries at once, and should be proposed as such, not smuggled in as a catalog entry. |
| Paired reference detection rules per use case | Splunk attack_range ships ESCU detections alongside its data | Replicant deliberately does not ship detection content: the catalog exists to *test* an operator's rules, and shipping reference answers both invites overfitting and doubles the maintenance surface. Worth recording as a possible non-catalog enhancement (a separate contrib pack), not a technique. |
| Whole-network benign background generator | GHOSTS, EvidenceForge-style agent frameworks | Per-technique foils already exist and are the honest version of background noise, because they are tuned to confuse the specific detection. A standalone background-radiation mode that is not keyed to any technique's failure modes is a different product with a different validation burden. Not rejected forever; rejected as a technique. |
| TLS fingerprint anomaly / encrypted traffic analysis | Anderson and McGrew, AISec 2016 | Deferred since round 1 and still blocked: needs a `utm:ssl` render path in three vendor profiles plus new golden lines. Nothing has changed the cost side since round 1's section 5. Revisit only if an SSL path is added for other reasons. |
| Reputation and threat-intel based detections | n/a | Structurally untestable with synthetic entities: the signal is a lookup against an external list, and a 203.0.113.x address is on no list (this is also why round 3 rejected domain fronting, REP-040). Recommendation: the README should document this blind class in one place so operators know reputation content is out of scope by design rather than by omission. |

## 6. Implementation notes

For each proposed entry: the FortiGate log type and subtype it binds to,
whether any new render path or field is needed, and which existing builder it
most resembles. **No candidate needs a new render path or a new field**; that
was a selection criterion, not an outcome to verify later.

| Proposed | FortiGate binding | New path or field | Nearest existing builder |
|---|---|---|---|
| REP-042 | `traffic:forward`, accept | none | REP-005 planner, plus a foil phase to a second destination |
| REP-043 | `utm:ips` + `traffic:forward` in one plan | none; one plan spanning two render paths was resolved in round 2 (`render()` dispatches per record) | REP-022 alert emission plus REP-024's paired-leg structure |
| REP-044 | `traffic:forward`, accept | none | REP-008 warm-up mechanism plus REP-021's interface direction handling |
| REP-045 | `traffic:forward`, deny or accept-zero-in | none | REP-010 deny emission plus REP-001's per-(src,dst) session loop, with backoff timing |
| REP-046 | `event:vpn`, tunnel-up | none; `39947` carries the same `[Unverified]` caveat as REP-011 and REP-018 | REP-011 planner plus a REP-008-style warm-up for per-user source history |
| REP-047 | `traffic:forward`, accept, mixed proto | none | REP-014's session-shape loop with REP-006's destination concentration inverted (one dst, many sessions) |
| REP-048 | `traffic:forward`, accept | none; long durations use the `duration_override_s` path resolved in round 2 | REP-014, with bytes driven toward zero |
| REP-049 | `traffic:forward`, accept, dpt 443 | none | REP-023, with interval generation replaced by aperiodic gap draws |
| REP-050 | `traffic:forward`, accept, dpt held | none | REP-003's held-port many-destination loop, flipped to accept and external destinations |
| REP-051 | `traffic:forward`, accept | none | REP-012 fleet mode, with phases decorrelated so no period exists |

Three practical notes:

1. **Warm-up entries.** REP-044 and REP-046 share the REP-008 property and
   must state the warm-up in the run summary per catalog note 4. Reuse that
   mechanism; do not add a second one.
2. **Long simulated spans.** REP-042 (up to 192 h), REP-044 (72 h warm-up)
   and REP-048 (720 min sessions) interact with `--anchor` and
   `align: next-off-hours`, the same risk round 1 flagged for REP-015.
   Validate against those flags before calling any of them done.
3. **Events-per-second honesty.** REP-047's entry text must carry the cap
   statement shown above. This is the round-3 REP-034 standard applied at
   authorship time rather than at triage time.

## 7. Suggested sequencing

If the set is not wanted at once:

1. **REP-042** chunked exfiltration. Highest detection value per unit of
   work; directly exposes the blind spot REP-005 leaves.
2. **REP-043** dialog correlation. The only cross-log-type causal join in
   the proposal set; reuses resolved machinery.
3. **REP-046** unfamiliar VPN source. Small, and the Entra detector
   documentation makes the detection contract unusually precise.
4. **REP-044** role reversal, **REP-047** DDoS participation, **REP-048**
   near-idle session.
5. **REP-045** dead-C2 failover, **REP-049** shape-only C2, **REP-050**
   spam relay.
6. **REP-051** only after the REP-012 overlap question is answered; drop it
   first if the answer is "parameterise."

## 8. Sources

- [MITRE ATT&CK: Data Transfer Size Limits (T1030)](https://attack.mitre.org/techniques/T1030/)
- [Inside the attack chain: threat activity targeting Azure Blob Storage (Microsoft Security Blog, 2025-10-20)](https://www.microsoft.com/en-us/security/blog/2025/10/20/inside-the-attack-chain-threat-activity-targeting-azure-blob-storage/)
- [BotHunter: Detecting Malware Infection Through IDS-Driven Dialog Correlation (USENIX Security 2007)](https://www.usenix.org/legacy/event/sec07/tech/full_papers/gu/gu.pdf)
- [Disclosure: Detecting Botnet Command and Control Servers through Large-Scale NetFlow Analysis (ACSAC 2012, dblp record)](https://dblp.org/rec/conf/acsac/BilgeBRKK12.html)
- [Detect and Prevent Web Shell Malware (joint NSA/ASD guidance, April 2020)](https://media.defense.gov/2020/Jun/09/2002313081/-1/-1/0/CSI-DETECT-AND-PREVENT-WEB-SHELL-MALWARE-20200422.PDF)
- [MITRE ATT&CK: Web Shell (T1505.003)](https://attack.mitre.org/techniques/T1505/003/)
- [MITRE ATT&CK: Fallback Channels (T1008)](https://attack.mitre.org/techniques/T1008/)
- [Microsoft Entra ID Protection risk detections](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks)
- [D-WARD: A Source-End Defense Against Flooding Denial-of-Service Attacks (IEEE TDSC 2005)](https://ieeexplore.ieee.org/document/1542059)
- [MITRE ATT&CK: Direct Network Flood (T1498.001)](https://attack.mitre.org/techniques/T1498/001/)
- [RITA: Real Intelligence Threat Analytics (Active Countermeasures)](https://github.com/activecm/rita)
- [JACKSTRAWS: Picking Command and Control Connections from Bot Traffic (USENIX Security 2011)](https://www.usenix.org/legacy/events/sec11/tech/full_papers/Jacob.pdf)
- [Studying Spamming Botnets Using Botlab (NSDI 2009)](https://www.usenix.org/legacy/event/nsdi09/tech/full_papers/john/john.pdf)
- [BotMiner: Clustering Analysis of Network Traffic for Protocol- and Structure-Independent Botnet Detection (USENIX Security 2008)](https://corescholar.libraries.wright.edu/cse/4/)
- [MITRE ATT&CK: Mail Protocols (T1071.003)](https://attack.mitre.org/techniques/T1071/003/)
- [MITRE ATT&CK: Non-Application Layer Protocol (T1095)](https://attack.mitre.org/techniques/T1095/)

Cited but **[Unverified]**, with no primary URL confirmed in this session:

- Karasaridis et al., "Wide-scale Botnet Detection and Characterization,"
  USENIX HotBots 2007. Known through secondary references only; confirm a
  primary URL before it appears in a catalog entry's `references` field.
- The "2.1 GB over 8 days via ~90 sub-threshold transfers" figure attributed
  to DeepTempo. Secondary source; REP-042 does not depend on it.
