# Technique catalog expansion research

Status: research proposal. Nothing here is implemented. No catalog entry, engine
builder, or test has been added as a result of this document.

Author: RZA. Date: 2026-07-25.

## 1. Purpose

The catalog currently holds eleven techniques (REP-001 through REP-011). This
document proposes nine additions, each anchored to a peer-reviewed detection
paper with published results, and scores each one for feasibility against what
the Replicant engine can actually emit today.

The selection rule used throughout: a candidate earns a place only if it is
(a) grounded in published research with concrete measured results, (b)
expressible as a pattern in firewall or DNS log fields, and (c) materially
distinct from an existing entry. Candidates that fail (c) are more damaging than
useless, because they inflate the menu without exercising a new detection.

## 2. What the engine can emit today

This is the binding constraint on every proposal below, so it is stated first.

`replicant/profiles/fortigate.py` implements exactly five render paths:

| Render path | CEF category | Notes |
|---|---|---|
| `_traffic_forward` | `traffic:forward` | accept and deny, bytes, duration, session id |
| `_dns_query` | `dns:dns-query` | qname, qtype, qtypeval, qclass, xid. No response code |
| `_utm_ips` | `utm:ips` | attack name, attack id, severity, count |
| `_event_vpn` | `event:vpn` | duser, login success and failure, source country |
| `_event_system` | `event:system` | admin and system events |

`replicant/scenario/engine.py` dispatches through `_PLAN_BUILDERS`, a flat map of
technique id to `_plan_*` method. Adding a technique is therefore a bounded unit
of work: one catalog entry, one planner method, tests. It does not require
touching the CEF serializer or the transport.

Two consequences that shape the proposals:

1. `_dns_query` carries no `rcode`. Any detection whose signal is *failed*
   resolution (NXDOMAIN) needs a new `dns:dns-response` render path. The good
   news is that `docs/fortigate-cef-reference.md` line 224 records signature ID
   `54802` for `dns-response` as **confirmed**, unlike the `54803` query id which
   is still marked `[Unverified]`. So the risky part of that work is already
   settled.
2. There is no `utm:ssl`, `utm:app-ctrl`, `utm:webfilter`, or `utm:virus` path.
   Anything needing TLS handshake metadata, JA3-style client fingerprints, URL
   category, or file hashes is out of reach without a new render path plus seven
   new golden lines per vendor across three vendor profiles.

## 3. Candidate summary

Tier A needs no new render path. Tier B needs one new render path.

| Proposed | Name | Tier | Log path | Research anchor | Headline result |
|---|---|---|---|---|---|
| REP-012 | Jittered and fleet-aggregate C2 callback | A | `traffic:forward` | BAYWATCH (DSN 2016); UVA (ACSAC 2023) | 43% more periodic domains found only by cross-network aggregation |
| REP-013 | Self-propagating malware spread | A | `traffic:forward` | PORTFILER (IEEE CNS 2021) | precision > 0.94 on top-ranked alerts, WannaCry and Mirai patterns |
| REP-014 | Cryptomining pool session | A | `traffic:forward` | MineHunter (ACSAC 2021) | precision 97.0%, recall 99.7% over 28 TB, one month |
| REP-015 | Low-throughput DNS exfiltration | A | `dns:dns-query` | Nadler et al. (Computers & Security, 2019) | isolates a malware class that tunnel-rate thresholds miss entirely |
| REP-016 | DGA NXDOMAIN cluster | B | `dns:dns-response` | Pleiades (USENIX Sec 2012); Woodbridge et al. (2016) | 12 previously unknown DGA botnets over 15 months; AUC 0.9993 |
| REP-017 | Encrypted DNS (DoH) policy bypass | A | `traffic:forward` + `dns:dns-query` | CIRA-CIC-DoHBrw-2020 corpus and derived work | random forest reported at roughly 99.99% accuracy separating DoH from HTTPS |
| REP-018 | Lateral movement login chain | A | `event:vpn` + `traffic:forward` | Hopper (USENIX Sec 2021) | 94.5% detection, fewer than 9 alerts per day over 780M logins |
| REP-019 | Stealth scan below rate threshold | A | `traffic:forward` | TRW (Jung et al., IEEE S&P 2004) | the detector this technique is designed to defeat |
| REP-020 | First contact with a newly registered domain | A | `dns:dns-query` | PREDATOR (CCS 2016) | 70% detection at 0.35% false positive, days to weeks ahead of blacklists |

## 4. Detailed proposals

Each entry gives the reason it is distinct from what already exists, the paper
result, and a catalog-ready sketch. ATT&CK mappings follow the existing style.

Every mapping from "this log pattern" to "this detection fires" below is
**[Inference]**, my engineering judgment from the paper's stated features. The
measured results attributed to each paper are quoted from the published
abstracts and are verifiable at the links in section 8.

### REP-012 Jittered and fleet-aggregate C2 callback

**Distinct from REP-001.** REP-001 emits a fixed base interval with 10 to 20
percent jitter from one host to one destination. That is the easy case and any
periodicity test finds it. Two harder cases exist in the literature and neither
is currently in the catalog:

- Heavy jitter (50 to 100 percent) that flattens the per-host frequency signal.
- A fleet pattern where each host calls back too rarely to look periodic on its
  own, and the period is only visible when the signal is aggregated across many
  hosts contacting the same destination.

The ACSAC 2023 UVA study measured exactly this second effect across two campus
networks, 10 months and over 75 billion connections: aggregating across networks
surfaced 43 percent more periodic domains per day than single-network analysis,
and of 1,387 malicious domains their pipeline ranked, 781 (56 percent) were
unknown to major threat intelligence sources. BAYWATCH (DSN 2016) is the
companion anchor, an 8-step filter chain validated on more than 30 billion
events over 5 months across 130,000+ devices, whose central problem statement is
that legitimate software also calls back periodically.

This technique is the honest test of whether a customer's C2 rule is a naive
interval check or a real periodicity analysis.

```yaml
  - id: REP-012
    name: "Jittered and fleet-aggregate C2 callback"
    ndr_rule: "NDR-C2-011"
    ndr_uc: "UC-011"
    attack:
      tactics: ["TA0011 Command and Control"]
      techniques: ["T1071", "T1029"]
    fortigate:
      log_type: "traffic"
      subtype: "forward"
      signature_id: "00013"
      action: "accept"
    cef_fields_held: ["dst", "dpt", "proto"]      # note: src is NOT held
    cef_fields_varied: ["src", "rt", "out", "in", "externalId"]
    params:
      low:    { mode: "jitter", hosts: 1,  interval_s: 300, jitter_pct: 50,  duration_min: 240 }
      medium: { mode: "fleet",  hosts: 12, interval_s: 3600, jitter_pct: 80, duration_min: 480 }
      high:   { mode: "fleet",  hosts: 40, interval_s: 7200, jitter_pct: 100, duration_min: 720 }
    distributions:
      interval: "jitter mode: base +/- jitter_pct, deliberately wide. fleet mode: each src callbacks rarely, phases offset so the aggregate across src is periodic"
      out_bytes: "log-normal, low variance, same profile as REP-001"
    benign_baseline: "software update checks are also periodic; baseline emits a benign periodic destination so the detection must separate the two"
    references: ["BAYWATCH DSN 2016", "Zhang et al. ACSAC 2023 aggregation-based detection"]
    safety_notes: "single synthetic external destination from 203.0.113.0/24"
```

The `benign_baseline` here matters more than usual. Both papers name legitimate
periodic software as the dominant false positive source, so a run that emits
only the malicious pattern would overstate a detection's real quality.

### REP-013 Self-propagating malware spread

**Distinct from REP-003.** REP-003 is one source sweeping many destinations on
one port, and every record shares that one source. Self-propagation is
generational: host A reaches host B on 445, B is then a source itself, and the
count of *distinct sources* on that port grows geometrically. PORTFILER's
features are port-level aggregates over a time window, specifically connection
counts and distinct source and destination counts per port, taken from Zeek
connection logs at a network border. That is the same vantage point and
substantially the same fields a FortiGate `traffic:forward` log provides, which
makes this one of the closest research-to-Replicant fits in the set.

PORTFILER was evaluated on two university networks against WannaCry-like and
Mirai-like patterns, reported precision above 0.94 on top-ranked alerts, was
tested under evasion, and flagged live activity on one campus network that the
university SOC confirmed as malicious.

```yaml
  - id: REP-013
    name: "Self-propagating malware spread (worm-like)"
    ndr_rule: "NDR-LATERAL-012"
    ndr_uc: "UC-012"
    attack:
      tactics: ["TA0008 Lateral Movement", "TA0007 Discovery"]
      techniques: ["T1210", "T1021.002", "T1046"]
    fortigate:
      log_type: "traffic"
      subtype: "forward"
      signature_id: "00013"
      action: "accept"          # mixed with deny
    cef_fields_held: ["dpt"]
    cef_fields_varied: ["src", "dst", "act", "rt", "externalId"]
    params:
      low:    { seed_hosts: 1, generations: 3, fanout: 8,  port: 445, gen_gap_s: 120 }
      medium: { seed_hosts: 1, generations: 5, fanout: 12, port: 445, gen_gap_s: 60 }
      high:   { seed_hosts: 2, generations: 6, fanout: 20, port: 3389, gen_gap_s: 30 }
    distributions:
      growth: "generation N has seed_hosts * fanout^N infected sources; each new source begins probing after gen_gap_s"
      action_mix: "majority deny (host not vulnerable or not present), minority accept (successful spread, becomes next-generation source)"
      port_choices: [445, 3389, 22, 135]
    benign_baseline: "east-west SMB is normal but comes from a stable, small set of server sources, not a growing source population"
    references: ["PORTFILER IEEE CNS 2021"]
    safety_notes: "all sources and destinations from synthetic internal space; no code executes and nothing propagates, the growth curve is arithmetic on log records only"
```

The safety note is worth keeping verbatim in the catalog. "Self-propagating" is
the most alarming name in this proposal set and the entry should say plainly on
its face that the propagation is a counter in a loop.

### REP-014 Cryptomining pool session

**Distinct from REP-001 and REP-005.** Callback traffic is many short sessions.
Volume exfiltration is a large asymmetric transfer. Mining is neither: it is a
small number of very long-lived sessions carrying steady, low-rate, roughly
symmetric traffic, because the client is receiving jobs and submitting shares on
a loop. That combination of high `FTNTFGTduration`, low byte rate, and a near
1:1 in/out ratio is a distinct shape in a firewall log and the catalog has
nothing like it.

MineHunter (ACSAC 2021) was deployed for one month at the entrance of a large
campus building over more than 28 TB of traffic and reported precision of 97.0
percent and recall of 99.7 percent. The design point stated in the paper is that
it works at the network entrance rather than requiring agents on hosts, which is
the same constraint a firewall-log detection operates under.

```yaml
  - id: REP-014
    name: "Cryptomining pool session"
    ndr_rule: "NDR-IMPACT-013"
    ndr_uc: "UC-013"
    attack:
      tactics: ["TA0040 Impact"]
      techniques: ["T1496"]
    fortigate:
      log_type: "traffic"
      subtype: "forward"
      signature_id: "00013"
      action: "accept"
    cef_fields_held: ["src", "dst", "dpt", "proto"]
    cef_fields_varied: ["rt", "out", "in", "FTNTFGTduration", "externalId"]
    params:
      low:    { sessions: 1, session_min: 120, share_interval_s: 60, dpt: 3333 }
      medium: { sessions: 3, session_min: 480, share_interval_s: 30, dpt: 14444 }
      high:   { sessions: 6, session_min: 720, share_interval_s: 10, dpt: 443 }
    distributions:
      duration: "single sessions lasting hours, far above the per-host session duration norm"
      byte_ratio: "in:out close to 1:1, both small and steady; no large transfer at any point"
      dpt_choices: [3333, 4444, 5555, 7777, 14444, 443]
    benign_baseline: "long-lived business sessions exist but are bursty in bytes, not metronomic"
    references: ["MineHunter ACSAC 2021", "CJ-Sniffer RAID 2022"]
    safety_notes: "pool destinations are synthetic IPs from the documentation range. Do NOT reference real mining pool hostnames or real pool IPs in this entry"
```

Safety point specific to this entry: real mining pool addresses are well known
and are exactly the kind of value that would tempt a contributor to use a
"realistic" one. The documentation-range rule already forbids it; the entry
should say so explicitly because the temptation here is unusually high.

### REP-015 Low-throughput DNS exfiltration

**Distinct from REP-004.** REP-004 runs at 20 to 200 queries per second with 30
to 63 character labels. That is a tunnel and it trips volume thresholds. Nadler,
Aminov and Shabtai (Computers & Security volume 80, pages 36 to 53, 2019) make
the case that an entire class of malware sits below that line: it leaks payment
card data and credentials at a handful of queries per hour, and their stated
motivation is that prior work concentrated on DNS tunneling and left this class
unaddressed. They detect it with a one-class classifier (isolation forest and
one-class SVM) over long-window per-registered-domain aggregates rather than
per-minute rates.

For a detection engineer this is the highest-value item in the proposal set,
because it is the case where a rule tuned on REP-004 will report clean and still
be blind.

```yaml
  - id: REP-015
    name: "Low-throughput DNS exfiltration"
    ndr_rule: "NDR-EXFIL-014"
    ndr_uc: "UC-014"
    attack:
      tactics: ["TA0010 Exfiltration", "TA0011 Command and Control"]
      techniques: ["T1048.003", "T1071.004"]
    fortigate:
      log_type: "dns"
      subtype: "dns-query"
      signature_id: "54803"    # [Unverified] same caveat as REP-004
      action: "pass"
    cef_fields_held: ["src", "dst", "dpt", "proto"]
    cef_fields_varied: ["FTNTFGTqname", "FTNTFGTqtype", "rt", "FTNTFGTxid"]
    params:
      low:    { qph: 2,  duration_h: 72, label_len: [12, 20], unique_labels: 144 }
      medium: { qph: 6,  duration_h: 48, label_len: [16, 28], unique_labels: 288 }
      high:   { qph: 20, duration_h: 24, label_len: [20, 34], unique_labels: 480 }
    distributions:
      rate: "queries per HOUR, not per second. Deliberately below tunnel-rate thresholds"
      qname: "shorter labels than REP-004 and lower entropy, consistent with encoded card or credential records rather than a file transfer"
      qtype: "weighted to A and AAAA, not TXT, because the channel is the query itself"
      parent_domain: "one synthetic parent, stable across the whole run"
    benign_baseline: "a benign parent domain with comparable total query count but low unique-label cardinality, so rate alone cannot separate them"
    references: ["Nadler, Aminov, Shabtai, Computers & Security 80 (2019) 36-53"]
    safety_notes: "parent domains stay non-resolvable synthetic; run durations are long, so document the duration in the run summary"
```

Note the duration. `duration_h: 72` is far longer than anything currently in the
catalog and interacts with the `align` and `--anchor` handling. That is called
out in section 6.

### REP-016 DGA NXDOMAIN cluster (Tier B)

**Distinct from REP-004 and REP-015.** Both DNS entries above put many
subdomains under one parent and all of them resolve. A DGA does the opposite:
many *distinct registered domains*, short algorithmic labels, and the
overwhelming majority fail to resolve because the operator registered only a few
of the generated candidates. The detectable artifact is a cluster of NXDOMAIN
responses with similar syntactic features from one host in one epoch.

Pleiades (Antonakakis et al., USENIX Security 2012) built precisely on that
NXDOMAIN stream below a recursive resolver, ran 15 months in a production ISP,
and identified twelve new DGA-based botnets, roughly half never previously
reported. Woodbridge et al. (2016) give the modern per-name classifier anchor:
AUC 0.9993 for binary classification, micro-averaged F1 0.9906, and a 90 percent
detection rate at a 1:10000 false positive rate, which they state is a twentyfold
false positive improvement over the next best method at the time.

**This is the only Tier B item.** It needs a `dns:dns-response` render path
carrying a response code. Scoping honestly:

- FortiGate signature ID `54802` for `dns-response` is already recorded as
  confirmed in the reference doc, so the highest-risk unknown is resolved.
- Cost is a new `_dns_response` method in each of the three vendor profiles, a
  golden line added to each of the three reference docs, plus the usual catalog
  entry, planner, and tests.
- Payoff beyond this technique: a `dns:dns-response` path also makes fast-flux
  and DNS TTL anomaly techniques possible later, since both need resolved
  answers. It is infrastructure, not a one-off.

```yaml
  - id: REP-016
    name: "DGA NXDOMAIN cluster"
    ndr_rule: "NDR-C2-015"
    ndr_uc: "UC-015"
    attack:
      tactics: ["TA0011 Command and Control"]
      techniques: ["T1568.002", "T1071.004"]
    fortigate:
      log_type: "dns"
      subtype: "dns-response"
      signature_id: "54802"    # confirmed in fortigate-cef-reference.md
      action: "pass"
    cef_fields_held: ["src", "dst", "dpt"]
    cef_fields_varied: ["FTNTFGTqname", "rcode", "rt", "FTNTFGTxid"]
    params:
      low:    { domains_per_epoch: 50,  epochs: 4, label_len: [8, 12], nx_ratio: 0.95 }
      medium: { domains_per_epoch: 200, epochs: 6, label_len: [7, 16], nx_ratio: 0.97 }
      high:   { domains_per_epoch: 800, epochs: 8, label_len: [6, 20], nx_ratio: 0.99 }
    distributions:
      qname: "distinct second-level labels, algorithmic character distribution, all under synthetic reserved TLDs"
      rcode: "NXDOMAIN (3) for nx_ratio of queries, NOERROR for the small remainder representing the registered rendezvous domain"
      epochs: "domains regenerate per epoch, mirroring a time-seeded DGA"
    benign_baseline: "normal hosts produce a low, steady NXDOMAIN rate from typos and stale records, not clustered bursts of unseen labels"
    references: ["Pleiades USENIX Security 2012", "Woodbridge et al. 2016 arXiv:1611.00791"]
    safety_notes: "generated labels must sit under .invalid or another reserved TLD so no generated name can ever resolve, even by accident"
```

The safety note is load-bearing. A DGA technique generates thousands of unseen
domain strings. Under the existing `.invalid` rule none of them can resolve,
which is the property that makes this safe to ship. It should not be relaxed to
a "realistic looking" TLD.

### REP-017 Encrypted DNS (DoH) policy bypass

**Distinct from everything in the catalog**, because the signal is a correlation
across two log types rather than a pattern within one. A host that switches to
DNS over HTTPS goes quiet on the internal resolver, so its `dns:dns-query`
volume collapses toward zero, while it opens sustained TLS sessions on 443 to a
public DoH resolver. Neither half is suspicious alone. The absence is the signal,
and detections keyed on absence are the ones most likely to be missing from a
customer's content, which makes this a useful thing to be able to generate on
demand.

The CIRA-CIC-DoHBrw-2020 corpus is the standard anchor here: over 100 million
packets covering benign DoH, malicious DoH and plain HTTPS, produced with Chrome
and Firefox, the dns2tcp, iodine and DNScat2 tunneling tools, and four public DoH
resolvers. Published results on it are strong, including random forest reported
at roughly 99.99 percent accuracy for separating DoH from other HTTPS traffic,
and a three-stage scheme reporting 99.81 percent, 99.99 percent and 97.22 percent
across filtering, malicious-DoH detection, and tunnel-tool identification.

```yaml
  - id: REP-017
    name: "Encrypted DNS (DoH) policy bypass"
    ndr_rule: "NDR-C2-016"
    ndr_uc: "UC-016"
    attack:
      tactics: ["TA0011 Command and Control", "TA0005 Defense Evasion"]
      techniques: ["T1572", "T1071.004"]
    fortigate:
      log_type: "traffic"      # plus a dns:dns-query baseline phase
      subtype: "forward"
      signature_id: "00013"
      action: "accept"
    cef_fields_held: ["src", "dpt", "proto"]
    cef_fields_varied: ["dst", "rt", "out", "in", "externalId"]
    params:
      low:    { baseline_min: 120, switch_at_min: 60, doh_sessions: 20,  resolvers: 1 }
      medium: { baseline_min: 240, switch_at_min: 90, doh_sessions: 80,  resolvers: 2 }
      high:   { baseline_min: 240, switch_at_min: 60, doh_sessions: 200, resolvers: 3 }
    distributions:
      phase_1: "normal dns:dns-query volume to the internal resolver on 53"
      phase_2: "resolver queries stop; repeated small TLS sessions to synthetic DoH resolver IPs on 443 begin"
      byte_profile: "small request, small response, high session count, consistent with query-response over HTTPS"
    benign_baseline: "the pre-switch phase IS the baseline; the detection must notice the transition"
    references: ["CIRA-CIC-DoHBrw-2020 corpus and derived detection literature"]
    safety_notes: "DoH resolver addresses MUST be synthetic (203.0.113.0/24). Never use the real 1.1.1.1, 8.8.8.8, 9.9.9.9 or AdGuard addresses, even as labels"
```

That last safety note is the one I would most want reviewed. Naming a real
resolver IP would be the single most plausible way this entry could drift out of
the synthetic-entity rule, since the paper's own corpus is built on the four real
public resolvers.

This technique also shares the warm-up property of REP-008, so the run summary
must state when the baseline ends and the switch happens.

### REP-018 Lateral movement login chain

**Distinct from REP-007 and REP-011.** REP-007 is authentication failure volume
from one source. REP-011 is one user appearing in two countries. Neither models
a *path*. Hopper (Ho et al., USENIX Security 2021) builds a graph of internal
logins and looks for sequences: a login into A, then A to B, then B to C, where
the causal user changes partway through the path, which is the signature of a
credential switch during movement.

Their measured result is the strongest operational number in this whole set:
across a 15-month enterprise dataset of more than 780 million internal logins,
94.5 percent detection over 300+ realistic attack scenarios including a real red
team exercise, at fewer than 9 alerts per day, where matching prior
state-of-the-art detection would have cost close to eight times the false
positives.

```yaml
  - id: REP-018
    name: "Lateral movement login chain"
    ndr_rule: "NDR-LATERAL-017"
    ndr_uc: "UC-017"
    attack:
      tactics: ["TA0008 Lateral Movement", "TA0006 Credential Access"]
      techniques: ["T1021", "T1078", "T1550"]
    fortigate:
      log_type: "event"
      subtype: "vpn"           # plus traffic:forward east-west legs
      signature_id: "39947"    # [Unverified] same caveat as REP-011
      action: "tunnel-up"
    cef_fields_held: []
    cef_fields_varied: ["duser", "src", "dst", "rt"]
    params:
      low:    { path_len: 3, users: 2, switch_at_hop: 2, window_min: 60 }
      medium: { path_len: 5, users: 3, switch_at_hop: 3, window_min: 45 }
      high:   { path_len: 7, users: 4, switch_at_hop: 2, window_min: 30 }
    distributions:
      path: "successful login into hop 1, then each hop becomes the source of the next login"
      user_switch: "duser changes at switch_at_hop, modelling credential theft mid-path"
      timing: "hops separated by minutes, ordered, never overlapping"
    benign_baseline: "admins do log into several hosts, but as a star from one workstation, not as a chain where each host logs into the next"
    references: ["Hopper, USENIX Security 2021"]
    safety_notes: "usernames from the synthetic directory pool, same as REP-007"
```

The `benign_baseline` distinction (star versus chain) is the whole detection and
should be generated, not just documented, or the technique overstates the
detection's quality.

### REP-019 Stealth scan below rate threshold

**Distinct from REP-002 and REP-003 by parameterization, not by shape.** This is
deliberate. Jung, Paxson, Berger and Balakrishnan (IEEE S&P 2004) introduced
Threshold Random Walk, which detects a scanner from a small number of connection
attempts with proven bounds on missed detections and false alarms. TRW and its
descendants are what sits inside most commercial scan detections. This technique
is the control case: the same reconnaissance intent, parameterized to stay under
the thresholds, with long inter-probe gaps and source rotation.

The reason to include it is that REP-002 and REP-003 will trip essentially any
scan rule, so a green result on them proves less than an operator might assume.
REP-019 gives an honest negative control.

```yaml
  - id: REP-019
    name: "Stealth scan below rate threshold"
    ndr_rule: "NDR-RECON-018"
    ndr_uc: "UC-018"
    attack:
      tactics: ["TA0007 Discovery", "TA0043 Reconnaissance"]
      techniques: ["T1046", "T1595.001"]
    fortigate:
      log_type: "traffic"
      subtype: "forward"
      signature_id: "00013"
      action: "deny"
    cef_fields_held: []
    cef_fields_varied: ["src", "dst", "dpt", "rt", "externalId"]
    params:
      low:    { probes_per_dst: 1, gap_s: [300, 900], src_pool: 4, total_probes: 200,  order: "random" }
      medium: { probes_per_dst: 1, gap_s: [120, 600], src_pool: 8, total_probes: 600,  order: "random" }
      high:   { probes_per_dst: 2, gap_s: [60, 300],  src_pool: 16, total_probes: 1500, order: "random" }
    distributions:
      gap: "minutes between probes, so no rate window accumulates enough events"
      src_rotation: "probes distributed across src_pool so per-source counts stay under per-source thresholds"
      order: "randomized destination and port order, defeating sequential-sweep signatures"
    benign_baseline: "sparse policy denies look similar; separating them needs long-window aggregation across the source pool"
    references: ["Jung et al., Fast Portscan Detection Using Sequential Hypothesis Testing, IEEE S&P 2004"]
    safety_notes: "synthetic targets only; run durations are long by design"
```

### REP-020 First contact with a newly registered domain

**Distinct from REP-008.** REP-008 is newly observed *destination IP* relative to
one host's own baseline. This is organization-wide first contact with a *domain*
whose registration is recent, which is a different pivot (domain string, global
novelty) and a different data requirement (no per-host baseline needed).

PREDATOR (Hao et al., CCS 2016) established that registration-time features
alone predict abuse at a 70 percent detection rate with a 0.35 percent false
positive rate, and do so days or weeks before the domain appears on DNS
blacklists. That lead time is the operational argument for the detection and the
reason it is worth being able to exercise.

```yaml
  - id: REP-020
    name: "First contact with a newly registered domain"
    ndr_rule: "NDR-C2-019"
    ndr_uc: "UC-019"
    attack:
      tactics: ["TA0011 Command and Control", "TA0042 Resource Development"]
      techniques: ["T1583.001", "T1071"]
    fortigate:
      log_type: "dns"
      subtype: "dns-query"
      signature_id: "54803"    # [Unverified]
      action: "pass"
    cef_fields_held: ["dst", "dpt"]
    cef_fields_varied: ["src", "FTNTFGTqname", "rt", "FTNTFGTxid"]
    params:
      low:    { baseline_domains: 200, novel_domains: 1, hosts: 1, window_min: 60 }
      medium: { baseline_domains: 500, novel_domains: 3, hosts: 3, window_min: 30 }
      high:   { baseline_domains: 800, novel_domains: 8, hosts: 8, window_min: 15 }
    distributions:
      baseline: "a stable set of synthetic domains queried repeatedly across hosts, establishing organizational normal"
      novel: "domains never queried before by any host, low query count, contacted by few hosts"
    benign_baseline: "the baseline_domains phase is the baseline"
    references: ["PREDATOR, Hao et al., CCS 2016"]
    safety_notes: "novel domains use reserved TLDs; Replicant cannot and must not perform any registration or WHOIS lookup"
```

## 5. Considered and not proposed

Recording these so the same ground is not re-covered later.

| Idea | Anchor | Why not now |
|---|---|---|
| TLS client fingerprint anomaly | Anderson and McGrew, AISec 2016 (reported significant gains at a 0.00% false discovery rate using contextual flow data) | Needs TLS handshake metadata. No `utm:ssl` render path exists, and FortiGate CEF traffic logs do not carry a JA3-style fingerprint. Would need a new path in three profiles for one technique. Revisit only if an SSL path is added for other reasons. |
| Fast flux / DNS TTL anomaly | Holz et al. NDSS 2008; EXPOSURE, Bilge et al. NDSS 2011 | Needs resolved answer records and TTLs, so it depends on the same `dns:dns-response` work as REP-016. Natural follow-on, not a starting point. |
| Malicious file download | n/a | Needs `utm:virus` and file hashes. Hash-shaped fields in a synthetic generator invite someone to paste a real malware hash. Poor risk-to-value ratio. |
| Tor and anonymizer egress | n/a | The real detection is IP reputation lookup, so the generated log is just traffic to an address. Nearly no synthesis value, and listing real Tor node addresses would break the synthetic-entity rule. |
| Web attack payloads (SQLi, XSS) | n/a | Needs a WAF render path, and attack strings in payload fields move Replicant closer to carrying real exploit text than the current attack-name-as-label approach. Against the spirit of safety rule 3. |

## 6. Implementation notes and risks

1. **Long-duration techniques.** REP-015 (up to 72 hours) and REP-019 are much
   longer than any current entry. Memory of this project records an off-hours and
   `align` gotcha in the anchor handling. Any long-duration technique should be
   validated against `--anchor` and `align: next-off-hours` before it is called
   done. **[Inference]** this is where a bug is most likely to surface.
2. **Warm-up techniques.** REP-017 and REP-020 need a baseline phase, the same
   property REP-008 already has, and catalog note 4 requires the warm-up be
   stated in the run summary. Reuse that mechanism rather than adding a second one.
3. **Multi-log-type techniques.** REP-017 (traffic plus dns) and REP-018 (event
   plus traffic) emit across two render paths in one plan. Whether the current
   `EventRecord` and planner design supports that cleanly is **not verified**; I
   have not traced it. That question should be answered before either is
   committed to a milestone.
4. **Vendor parity.** Every Tier A technique must produce sensible output for
   FortiGate, Palo Alto and Check Point, since `--vendor` is a live flag. Tier A
   items reuse existing render paths, so parity should follow, but the golden
   tests are the proof.
5. **Naming.** Nine additions would take the catalog to twenty entries. The
   already-planned backlog item to group the catalog by MITRE tactic in the web
   UI left rail stops being cosmetic at that size and becomes close to a
   prerequisite for the menu staying usable.

## 7. Suggested sequencing

If the whole set is not wanted at once, the ordering I would argue for:

1. **REP-015** low-throughput DNS exfiltration. Highest detection value, smallest
   change, directly exposes a blind spot left by REP-004.
2. **REP-013** self-propagating spread. Closest research-to-implementation fit,
   reuses `traffic:forward` entirely.
3. **REP-012** jittered and fleet callback. Turns REP-001 from an easy case into
   a graded pair.
4. **REP-014** cryptomining, **REP-019** stealth scan, **REP-018** login chain.
5. **REP-016** DGA, once the `dns:dns-response` path is justified by wanting fast
   flux too.
6. **REP-017** DoH and **REP-020** newly registered domain, both of which depend
   on the warm-up mechanism being comfortable.

## 8. Sources

- [BAYWATCH: Robust Beaconing Detection to Identify Infected Hosts in Large-Scale Enterprise Networks (DSN 2016)](https://research.ibm.com/publications/baywatch-robust-beaconing-detection-to-identify-infected-hosts-in-large-scale-enterprise-networks)
- [Global Analysis with Aggregation-based Beaconing Detection across Large Campus Networks (ACSAC 2023)](https://dl.acm.org/doi/abs/10.1145/3627106.3627126)
- [PORTFILER: Port-Level Network Profiling for Self-Propagating Malware Detection (IEEE CNS 2021)](https://arxiv.org/abs/2112.13798)
- [MineHunter: A Practical Cryptomining Traffic Detection Algorithm Based on Time Series Tracking (ACSAC 2021)](https://www.semanticscholar.org/paper/MineHunter:-A-Practical-Cryptomining-Traffic-Based-Zhang-Wang/493a00d2a1f0836b917178da64c7ce5705a36ec1)
- [CJ-Sniffer: Measurement and Content-Agnostic Detection of Cryptojacking Traffic (RAID 2022)](https://dl.acm.org/doi/abs/10.1145/3545948.3545973)
- [Detection of Malicious and Low Throughput Data Exfiltration Over the DNS Protocol (Computers & Security, 2019)](https://arxiv.org/abs/1709.08395)
- [From Throw-Away Traffic to Bots: Detecting the Rise of DGA-Based Malware (USENIX Security 2012)](https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/antonakakis)
- [Predicting Domain Generation Algorithms with Long Short-Term Memory Networks (2016)](https://arxiv.org/abs/1611.00791)
- [CIRA-CIC-DoHBrw-2020 dataset](https://www.yorku.ca/research/bccc/ucs-technical/cybersecurity-datasets-cds/dns-over-https-bccc-cira-cic-dohbrw-2020/)
- [Real time detection of malicious DoH traffic using statistical analysis (Computer Networks)](https://www.sciencedirect.com/science/article/pii/S1389128623003559)
- [Hopper: Modeling and Detecting Lateral Movement (USENIX Security 2021)](https://www.usenix.org/conference/usenixsecurity21/presentation/ho)
- [Fast Portscan Detection Using Sequential Hypothesis Testing (IEEE S&P 2004)](https://ieeexplore.ieee.org/document/1301325/)
- [PREDATOR: Proactive Recognition and Elimination of Domain Abuse at Time-Of-Registration (CCS 2016)](https://dblp.uni-trier.de/rec/conf/ccs/HaoKMPF16.html)
- [Identifying Encrypted Malware Traffic with Contextual Flow Data (AISec 2016)](https://dl.acm.org/doi/10.1145/2996758.2996768)
- [EXPOSURE: Finding Malicious Domains Using Passive DNS Analysis (NDSS 2011)](https://www.ndss-symposium.org/ndss2011/exposure-finding-malicious-domains-using-passive-dns-analysis/)
