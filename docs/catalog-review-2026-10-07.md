# Catalog review, 2026-10-07: do the 26 techniques do what their text says?

## Scope and method

The security half of the same review is `security-review-2026-10-07.md`. This
record covers the technique catalog: whether each builder honours its own
presets, whether the benign foil the catalog promises is generated and whether
it can be separated from the attack on a feature the catalog does not name as
the discriminator, whether the ATT&CK mapping matches the emitted behaviour, and
what a firewall SIEM rule would actually key on.

Method: `ScenarioEngine.plan()` driven directly for all 26 techniques at all
three presets over seeds 1 to 25 plus 1337, splitting events by
`event.control`. Per technique: event count, span, inter-event gap statistics,
distinct sources and destinations, port, byte and duration distributions, and
the same statistics for the foil against the attack. The measurement scripts
were throwaway; what they found is now pinned by `tests/test_foil_parity.py`,
which sweeps the same seeds and presets in CI.

Prior catalog reviews this does not repeat: `catalog-review-2026-09-08.md`,
`catalog-research-review-2026-09-08.md`, `tasks/catalog-review-2026-08-plan.md`.

## Verdicts

Columns: presets honoured; foil generated (`emits_foil` against the code); the
feature the foil was separable on before this review; ATT&CK mapping; the rule a
firewall SIEM would plausibly build; grade before the fixes below.

| ID | Presets | Foil | Separable on (before) | ATT&CK | Plausible rule | Grade |
|---|---|---|---|---|---|---|
| REP-001 | yes, gap sd 34/5.3/1.8 s at 20/15/10% jitter | yes | nothing trivial | ok | same src, dst, dpt with gap CV below 0.15 over 4 h | A |
| REP-002 | window honoured; `gap_ms` accepted but ignored | yes | foil was itself a scan at medium and high (63 and 250 ports per pair) | ok | distinct dpt per src, dst in window above N | B- |
| REP-003 | yes | yes | foil was 16 sources each sweeping 16 to 256 hosts | ok | distinct dst per src, dpt above N | B- |
| REP-004 | yes, 300/1200/5000 unique labels, entropy 4.3 to 4.6 | yes, same qtype mix | none | ok | distinct qname per parent above N | B+ |
| REP-005 | yes, 0.75 to 1.0x total MB | yes | history windows carried one constant byte value on an exact grid | ok | sum(out) per src against own three-window history | C+ |
| REP-006 | yes | yes | count (intended axis is destination context) | ok | distinct dst per src in 5 min above N and not known-good | B |
| REP-007 | yes | yes at low and medium; high foil was 4 to 8 events | high: count | ok | fail ratio above 0.95 and distinct duser above N per src | B- |
| REP-008 | yes, 7/14/30 contacts per known dst | none, prose only, catalog-consistent | n/a | T1583 is adversary-side | dst never seen for this src in lookback | B |
| REP-009 | yes | yes, same hits over 60 min | rate only (intended) | ok | IPS count per dst in window above N | B+ |
| REP-010 | yes, spike-decay against flat foil | yes | foil at high was 63 denies per src per minute | ok | denies per src per minute above N | B |
| REP-011 | yes, 2 to 4 events, deterministic spacing | none, catalog-honest | n/a | ok, parser-only | same duser, two countries inside window | C |
| REP-012 | yes, fleet gap 1799 sd 445, aggregate 12 per bucket | yes, same jitter process | bytes, duration, port and interval at low | ok | callbacks per dst across fleet with period autocorrelation | B- |
| REP-013 | yes, src per generation monotonic in 21/21 seeds | yes | 12 constant records | high preset uses 3389 but listed only T1021.002 | distinct src on dpt growing per window | B- |
| REP-014 | yes, 10/30/60 s cadence | yes, bursty | 12 records against 120 to 25920, bytes 100x | ok | long session, out CV below 0.25, steady cadence | B- |
| REP-015 | yes, 143/287/480 unique against 18/36/60 | yes | none, both streams an exact metronome | ok | unique labels per parent per day above N at low qps | B |
| REP-016 | yes, NXDOMAIN 0.94 to 0.99, 100% unique | yes | count only (trickle, intended) | ok, parser-only | NXDOMAIN per src per hour above N with distinct SLDs | B |
| REP-017 | yes, 0 DNS after switch at 90 min | none, catalog-honest | n/a | ok | src DNS rate drops to 0 while 443 sessions to a new dst rise | B |
| REP-018 | yes | yes, star | constants 4200/12800/60 against 3900/11400/45; star port always 3389 | ok | login dst becomes next login src within window | C |
| REP-019 | yes, gaps inside range, 1 to 2 probes per dst | yes | foil was one source, port 445 only, fixed spacing | ok | distinct dst across src pool over 24 to 72 h above N | C |
| REP-020 | yes | embedded baseline | novel names were bare `<label>.invalid`, baseline under one parent, 21/21 seeds | T1583 is adversary-side | qname never seen org-wide | D |
| REP-021 | yes, heavy tail | calibration by design | n/a | ok | inbound deny from above N sources, must not fire outbound rules | B+ |
| REP-022 | yes, stage order and severity ascend in 21/21 seeds | yes, noise never on the victim pair | none | high emits an exfil stage with no TA0010 mapped | ordered recon, exploit, post on one pair | B+ |
| REP-023 | yes, bytes inside ranges | yes | catalog said dst count cannot separate; attack 1 dst, foil 89 to 184 | ok | N sessions to one dst on 443 with out CV below 0.15 | B- |
| REP-024 | yes, lag honest to integer time, out ratio 1.00 sd 0.017 | yes | foil pairs byte-identical in/out, attack pairs never, 21/21 seeds | ok | inbound to host then outbound within 2 s with matched bytes | D |
| REP-030 | yes, 5 fails per src, even spacing | yes, disjoint src and users | none | ok | distinct (src, user) failed edges portal-wide above N with no successes | A- |
| REP-043 | yes, alert, inbound, outbound order on one victim in 21/21 seeds | yes, reversed and blocked dialogs | none | ok | IPS dst equals accepted inbound dst equals later egress src | B+ |

The positive signals are in good shape. Every builder honours its presets,
ordering and growth properties held across every seed tested, no preset was
identical to another, and REP-001, REP-030, REP-043, REP-022, REP-009 and
REP-021 would fire a plausible rule as written.

## The finding behind the findings

Eleven of the twenty generated foils were separable on a constant, a copied
value, a hard-coded port or parent, or a count ceiling (12, 20, 16) that did not
scale with the preset, and two (REP-024, REP-020) were separable in 100% of
seeds on a single feature. This is exactly the class v0.7.0 named ("a benign
foil is a correctness requirement, not decoration"), and it survived because no
structural-foil guard measured byte, port or parent parity: the guards asserted
that a negative stream existed and that Tier 0's own threshold separated it,
and Tier 0's threshold equals the preset value, so a foil that is itself a scan
at a production threshold passed.

The fix pattern is the same in every case: **the foil must draw from the same
distributions and scale with the same parameters as the attack, preserving only
the feature the catalog names as the legitimate discriminator, and the guard
must assert that parity across seeds rather than that a negative stream
exists.**

## Defects and disposition

Every guard below was written first, run against the unfixed engine over seeds
1 to 20 at all three presets and observed to fail (figures at seed 1 unless
noted), then the fix was applied and the guard went green. The guard is
`tests/test_foil_parity.py`, a per-technique table of checks, so a failure
names the feature that leaked.

| ID | Defect (measured, before) | Positive control (unfixed engine) | Fix | After |
|---|---|---|---|---|
| REP-024 | Relay outbound legs scaled by uniform(0.97, 1.03); the sanctioned-proxy foil copied bytes verbatim, so foil pairs were byte-identical and attack pairs never. Foil pair count capped at 20. | `20/20 foil pairs are byte-identical against 0/30 attack pairs` (all presets, 20/20 seeds); `20 foil pairs against 150 relay pairs` (medium and high). | Proxy legs take the relay's forwarding draw (`_forwarded_bytes`); foil pair count equals the relay pair count. | Pairs 30/30, 150/150, 600/600 at low, medium, high; 0 identical. |
| REP-020 | Baseline names under one parent; novel names bare `<label>.invalid`, so "not under the baseline parent" scored perfectly. | `parents ['invalid'] are not documentation parents` (all presets, 20/20). | Baseline and novel labels from one draw (5 to 12 chars), each under a parent drawn from `entities.parents`. Nothing resolves. | Baseline uses all three parents; novel parents are a subset of them. |
| REP-002 | Foil volume divided over a hard-coded 16 sources, so the foil was itself a scan at medium and high. | `benign pair touched 63 distinct ports in 60 s, ceiling 10` (medium), `250` (high), 20/20. | Declared ceiling `BENIGN_PORTS_PER_MIN = 10`; source count derived from volume and span; `gap_ms` removed from the catalog and the builder because event time is integer seconds and a millisecond gap had no effect. | Seed 1337 high: max 4 ports per pair per minute over 253 pairs. The catalog states the ceiling and the guard checks the text. |
| REP-003 | Same shape: 16 sources each sweeping 16 to 256 hosts on one port. | `benign source reached 32 hosts in 60 s` (medium), `256` (high), 20/20. | `BENIGN_HOSTS_PER_MIN = 10`; source pool extended with internal targets, needed at high. | 9 hosts per source per minute over 456 sources at high. |
| REP-010 | Same shape: 63 denies per source per minute at high. | `benign source was denied 19 times in 60 s, ceiling 5` (medium), `63` (high), 20/20. | `BENIGN_DENIES_PER_MIN = 5`; same derivation. | 4 denies per source per minute over 250 sources at high. |
| REP-005 | History windows carried one constant byte value per window on an exact grid. | `history window 0 out_bytes CV 0.000 against current window CV 0.102` and `window 0 sits on an exact grid` (all presets, 20/20). | Every window draws per-session bytes with the current window's 0.8 to 1.2 factor and jitters each session inside its slot; negative history redrawn rather than copied. | Out-bytes CV per window 0.11 to 0.14 across all four windows; history still below 5% of current. |
| REP-019 | Foil was one source, port 445 only, 20 probes at fixed spacing, against 4 to 16 sources over 10 ports. | `foil is one source`, `foil ports [445] against attack [22, 23, 80, ...]`, `foil gaps are fixed spacing (CV 0.000)`, `foil 20 vs 200 probes` (all presets, 20/20). | As many benign sources as the probe pool, each retrying two fixed targets from the probe port list, gaps uniform over the attack's range, count equal to the probe total. | 4, 8, 16 sources; 8 to 9 ports; gap CV 0.29 to 0.38. |
| REP-018 | Chain legs constant 4200/12800/60, star 3900/11400/45, star port always 3389. | `star ports [3389] against chain [22, 445]`, `star out_bytes 3900..3900 never overlap chain 4200..4200` (all presets, 20/20). | Chain and star share one byte and duration draw (`_lateral_leg_shape`) and the 3389/445/22 rotation. | Guard asserts the star's ports are the chain's and its bytes sit in a band around the chain median. |
| REP-012 | Update-check foil in-bytes 2000 to 40000 and duration 1 to 20 against beacon 900 to 1300 and 1 to 180; interval 1800 against 300 at low. | `foil bytes out=547 in=29829 outside the beacon envelope [200, 1500]` (20/20, all presets); `foil mean gap 1698 s against beacon interval 300 s` (low); `foil durations capped at 16 s`. | Foil uses `interval_s`, the beacon's port, lognormal bytes and the 1 to 179 s duration draw; the fixed update interval constant is removed. | Gap mean 291, 1779, 3600 against 300, 1800, 3600; in-bytes max 1476. |
| REP-013 | Foil was 12 constant records, all accept, against 56 to 5520 mixed probes. | `foil out_bytes constant`, `foil actions ['accept'] against the worm's accept/deny mix`, `1.3 probes per generation against fanout 8` (all presets, 20/20). | Worm legs and the three baseline servers share one draw; servers probe `fanout` targets per generation with the worm's landed/denied split. | Foil 72, 180, 360 events, about 25% accept; the source-growth property is still asserted and green. |
| REP-007 | NAT foil was 4 to 8 events at high (`max(4, len(usernames))`). | `NAT foil is 4 events against 401 attack events (ratio 0.01)` (high, 20/20). | NAT user count is half the attack's pairs, floor 4. | 66/100, 710/1000, 288/401. |
| REP-023 | Catalog said destination count cannot separate the streams; attack was 1 destination with 120 sessions per pair, foil 89 to 184 with at most 3. Beacon had zero jitter and the foil copied its period. | `browsing foil is as periodic as the beacon (gap CV 0.000)` plus the catalog-text check (all presets, 20/20). | Catalog rewrite, chosen over forcing parity: destination count, per-pair session count and timing regularity are named as legitimate discriminators; the foil keeps count and port and is irregularly timed over the beacon's span. | Foil gap CV about 0.43; the guard checks the catalog text names the discriminators. |
| REP-022 | High preset's fifth stage emits an outbound-transfer alert labelled exfil with no TA0010 or exfil technique mapped. | Label. | `TA0010 Exfiltration` and `T1041` added. The alert's `direction` was still `incoming`; fixed the same day, below. | |
| REP-022 (follow-up, 2026-10-07) | The exfil stage rendered with `direction=incoming` on the adversary-to-victim pair, the shape of one more inbound hit. | `tests/test_followups_2026_10_07.py`: 20/20 seeds at high, `'incoming' == 'outgoing'`. | The exfil stage is the same pair reversed: src the victim, dst the adversary, direction outgoing, on all three vendors (PAN-OS zones follow the flow; Check Point derives it from dst). `cef_fields_held` is now empty, because the held thing is the unordered pair and the schema cannot say so; src and dst moved to varied with the reversal explained under `distributions.direction`. | Guard green at 20 seeds; the contract test that objected to a non-constant held `src` passes. |
| REP-013 | High preset spreads over 3389 but listed only T1021.002. | Label. | `T1021.001` added. | |
| REP-008, REP-020 | T1583 is adversary-side Resource Development and not observable in victim telemetry. | Label. | Technique ids kept; each entry's references state that T1583 is the adversary-side anchor and the observable is the first-contact behaviour. | |
| Header | Credential Access count said 1. | Label. | Now 2 (REP-007, REP-030). | |

Three checks were tightened after the first run because they were statistically
fragile rather than wrong: REP-005 windows split by count not time, REP-012's
duration envelope checked as 1 to 179 rather than max against max, REP-018's
bytes checked as a band around the chain median. The constant and port checks
that carry the positive control are unchanged.

Two existing tests changed with the engine. `test_scenario_engine_v020.py`'s
REP-013 overlap test keyed on the old 2400/8800/30 constant and now uses the
control label, and its REP-020 test splits by count and asserts the parent is in
the pool. `test_scenario_composer.py::test_single_stage_matches_direct_run` now
compares against the direct run's positive stream; it passed before only because
the pinned one-host pool gave REP-003 no foil.

## Scenarios

Kill-chain order and entity joins hold in all three scenarios across seeds:
SCEN-001's victim source is shared by every stage and one adversary IP is both
C2 and exfil destination; SCEN-002's victim is shared and REP-008's novel
destination is the adversary; SCEN-003's IPS source is the spray source and the
beacon destination. Two gaps:

1. `compose()` dropped every negative-control event, so scenario runs were
   attack-only. Fixed: `replicant scenario run --controls both` composes each
   stage's foil onto the same timeline (`security-review-2026-10-07.md`,
   "Related change"). The default is unchanged.
2. SCEN-003's REP-011 to REP-001 hop had no join key: the VPN login carried no
   assigned tunnel address and its sources are not the adversary. Fixed the same
   day: every REP-011 tunnel-up now carries `tunnelip`, drawn from the internal
   host pool, which under scenario pinning is the victim, so a rule can pivot
   `duser`, then `tunnelip`, then the beacon's `src`. The composer records the
   assignment per stage and the advisory names the pivot when it matches the
   victim (`vpn_pivot_stage_indices`). Rendered as `FTNTFGTtunnelip`,
   `PanOSPrivateIPv4` and `office_mode_ip`, each `[Unverified]` as a key name
   and each optional so the golden lines are unchanged. Guard:
   `tests/test_followups_2026_10_07.py`, failed on the unfixed engine at every
   seed and preset. This is the one item from the gate's "adds surface" class
   that was taken anyway, because without it the scenario's own description
   ("an anomalous VPN login, then an internal beacon") claimed a join the
   telemetry did not carry.

## Coverage tally and what to add next

Tactic tally, counting an entry under every tactic it lists (corrected from the
catalog header, which said Credential Access 1):

| Tactic | Entries | Log families |
|---|---:|---|
| TA0011 Command and Control | 13 | traffic:forward, dns:dns-query, dns:dns-response, utm:ips |
| TA0007 Discovery | 5 | traffic:forward |
| TA0001 Initial Access | 4 | utm:ips, event:vpn |
| TA0043 Reconnaissance | 3 | utm:ips, traffic:forward |
| TA0010 Exfiltration | 3 | dns:dns-query, traffic:forward |
| TA0006 Credential Access | 2 | event:vpn |
| TA0008 Lateral Movement | 2 | traffic:forward, event:vpn, event:system |
| TA0042 Resource Development | 2 | traffic:forward, dns:dns-query |
| TA0005 Defense Evasion | 1 | event:vpn, event:system, traffic:forward |
| TA0040 Impact | 1 | traffic:forward |
| Execution, Persistence, Privilege Escalation, Collection | 0 | |

All three vendor profiles render exactly six families (`traffic:forward`,
`dns:dns-query`, `dns:dns-response`, `utm:ips`, `event:vpn`, `event:system`)
and raise on anything else. No catalog entry claims a family it cannot render.
ICMP is not expressible because the traffic template requires ports; only
protocols 6 and 17 are ever emitted. Per-vendor field gaps (Check Point has no
`FTNTFGTqtype`, `externalId` or `cnt`) are disclosed through
`DetectionFieldCoverage.unavailable` and asserted by
`tests/test_detection_metadata.py`.

Ranked by the catalog header's tactic-gap rule. **This is a ranking, not an
authorisation: every one of these sits behind the launch gate in
`roadmap-2026-09.md`, and nothing that adds surface ships before the first
observed rule fire.** None was rejected in the four expansion triage rounds;
the parked ones are cited.

1. **Firewall admin login from an unexpected source, then a config-change
   burst** (Defense Evasion, T1562.004 and T1078; parked as round 3 REP-028).
   Implementation note (2026-10-07): built as REP-028 the same day, by the
   owner's decision and behind the launch gate, which is unchanged. The foil is
   the same burst from a new `mgmt_hosts` entity pool (10.20.1.0/28) so the
   source's asset role is the only separating feature, and the guard measures
   that over 20 seeds at 3 presets. The config-change record is new on all three
   vendors and `[Unverified]` on each.
   Honest because `event:system` already renders admin login with `src`,
   `duser`, `ui` and `method` on all three vendors and nothing uses it as a
   primary family; the config-change half needs one new logid constant per
   profile, FortiOS value `[Unverified]` until confirmed. Foil: the same count
   of logins and changes from the management jump host inside a change window.
2. **Ransomware-like SMB write fan-out** (Impact, T1486 network shadow; not in
   any triage doc; partial overlap with REP-013's source growth and REP-006's
   count). Entirely in `traffic:forward` fields the path already carries: one
   source, distinct internal destination count and out bytes over minutes on
   port 445, interzone only. Foil: a backup or patch server doing an in-heavy
   fan-out from a server-role asset in its scheduled window.
   Implementation note (2026-10-08): built as REP-052, by the owner's decision
   and behind the launch gate, which is unchanged. The foil sketched above was
   changed before it was built: a backup pull differs from the attack on two
   features (server role and read direction), and the parity rule allows one,
   so the foil is a software-distribution server pushing the same out-heavy
   fan-out from a new `server_hosts` pool (10.20.2.0/28), and role is the only
   separating feature. Positive controls, each on 20 seeds: a foil drawn from
   the workstation pool failed the role guard; the in-heavy foil as sketched
   failed the ratio parity guard; a foil pinned at twelve shares failed the
   count parity guard. The id is REP-052 because REP-029 is the parked MFA
   push-fatigue proposal of round 3 and every id up to REP-051 is named by a
   triage record.
3. **Internal reflector or outbound DDoS participation** (Impact, T1498.002;
   parked as round 3 REP-034 and round 4 REP-047). Honest only with the cap
   statement in the entry: out-to-in asymmetry per udp/123 or udp/161 session
   carries the signal, never event rate, because the events-per-second cap
   bounds rate by design. Foil: a sanctioned NTP server with symmetric small
   replies to many clients.
4. **Remote data staging fan-in then egress** (Collection, T1074.002 then
   T1041; parked as round 3 REP-036, "remains a scenario candidate" in the
   2026-09-08 review). Pure `traffic:forward` topology: many internal sources to
   one internal destination, then that destination becomes an egress source.
   Foil: a nightly backup fan-in with no egress follow. Could ship as SCEN-004
   first.
5. **VPN login from an unfamiliar source network** (Initial Access outside IPS,
   T1133 and T1078; parked as round 4 REP-046). Needs no GeoIP: a per-user
   source-prefix history over a REP-008-style warm-up. Foil: a user's second
   habitual network seen during warm-up.

Considered and set aside, with the reason: SMB or RDP east-west from a
workstation is a REP-006 preset with an internal destination pool and an
asset-role foil, not a new entry (round 3's REP-037 rule); non-standard port
protocol mismatch waits on `port_service()` no longer deriving `app` from the
port, and FortiGate `app` semantics without app-ctrl are `[Unverified]`;
sinkhole hits are half reputation (rejected class) and half REP-025 fast-flux
inverted; ICMP tunnelling needs a port-less traffic template (round 3 REP-027);
Tor, certificate anomalies, web-filter categories and destination-country
anomalies stay rejected for the reasons already recorded.
