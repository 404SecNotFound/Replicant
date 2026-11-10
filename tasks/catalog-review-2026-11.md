# Catalog review, 2026-11-10

Status. Review only. Nothing in the engine, the catalog or the tests was changed.
Every item under "Decisions" needs the owner's call before any build. The launch
gate is unchanged. No rule fire has been observed in the lab LogRhythm.

Implementation note (2026-11-10, same day). The owner accepted every recommendation in
section 7. D1, D2, D3, D5 and D6 are built. D4 is built as recommended (the same-pool
rule on REP-007 and REP-030, disclosure on REP-012, REP-014 and REP-023). D8 is done.
D7 is deferred. D9 is no, so no technique was added. D10 was left as the owner's call and
is not built. The sections below are the review as written before the fixes and describe
the unfixed engine. The CHANGELOG entry of the same date records what changed.
Two outcomes differ from the proposal text. F3's fix does not reach scenario-pinned runs,
so SCEN-002's REP-008 stage is still separable by subnet, and the catalog says so. F3's
"side effect to check" did not arise, because that stage's top destination was already a
benign one.

Implementation note (2026-11-10, rebase). The branch was rebased onto main after
`docs/detection-specs/REP-016.md` landed there. That draft spec described the unfixed
REP-016 foil and raised it as a finding. F5's fix answers the finding, and the spec is
updated in the same change. Its `min_nx_ratio` moved from 0.8 to 0.25, because the foil
shares the attack's host and a default run puts that host's NXDOMAIN share at 0.48 to
0.54 (seeds 1 to 20, all three presets). The threshold is the owner's to confirm.

Implementation note (2026-11-10, pinned runs). The owner asked for the pinned-run limit
to be fixed. The composer now keeps the whole adversary pool beside the pinned address,
so REP-008, REP-007 and REP-030 hold the pool rule inside a chain. The second outcome
recorded above (SCEN-002's REP-008 stage separable by subnet) no longer holds.

Implementation note (2026-11-10, D10). The owner said to build the fifth scenario. It is
SCEN-005, as sketched in section 6. Both joins the sketch named are measured by the
advisory. One differs from the sketch's wording. The join from REP-046 to REP-018 is the
VPN-assigned address, which every REP-046 login carries under pinning, so it does not
single out the unfamiliar login. The CHANGELOG entry of the same date has the detail.

Scope. All 31 techniques and the 4 scenarios at `575036b`.

## Method

1. Read every catalog entry and the builders the findings below cite.
2. Ran a generic separability scan. For each technique with a foil, at every
   preset, over seeds 1 to 10, it compares the positive and negative streams on
   every emitted field, on record families, counts, spans and entity pools.
   Each finding below was then re-measured on seeds 1 to 20 at all three presets
   (60 plans) unless a different count is stated.
3. Checked every candidate against the closed records (2026-08 plan,
   2026-09-08 review and research review, 2026-10-07 review, CHANGELOG) so no
   closed finding is reopened.
4. Composed each scenario on seeds 1 and 2 and read the stage joins.

Limits of this review, stated plainly.

- The scan compares streams. It does not prove a foil is good, only that no
  listed feature separates it. A feature the scan does not compute can still leak.
- Builders were read in full only for REP-014 and REP-022. The other entries
  were assessed from the catalog text plus measured output.
- The research records (rounds 1 to 5, round 3 triage) were summarised by a
  delegated reader, not read line by line by the reviewer. Statements about the
  reserved proposals in section 6 are marked [Unverified] where they rest on
  that summary alone.
- Every measurement is offline, on the plan. Nothing here was sent to a SIEM.

## 1. Inventory

Column notes. "Sep" is the single feature the catalog names as separating the
foil. "Fidelity guard" is the measured claim in `tests/test_catalog_fidelity.py`
unless a dedicated file is named. "Spec" is `docs/detection-specs/`. Only
REP-001 has one. "Markers" counts `[Unverified]` and `[Inference]` in the entry.
Vendor field mappings carry their own markers in the three CEF reference docs
(11 FortiGate, 6 Palo Alto, 7 Check Point) and are not repeated per row.

| ID | Objective (short) | ATT&CK | Foil and Sep | Fidelity guard | Markers | Finding |
|---|---|---|---|---|---|---|
| REP-001 | Beacon caught on interval regularity | TA0011; T1071, T1571 | Second destination, irregular timing. Sep is interval regularity | interval and small callbacks | 0 | none |
| REP-002 | One source, many ports on one host | TA0007; T1046 | Same volume over many pairs. Sep is per-pair unique ports | ports in window, deny mix | 0 | none |
| REP-003 | One port across many hosts | TA0007; T1046, T1018 | Same volume over many sources. Sep is per-source unique hosts | one port, many hosts | 0 | none |
| REP-004 | DNS tunnel on label cardinality | TA0011, TA0010; T1071.004, T1048.003 | Same-volume cache-key stream. Sep is unique-label cardinality | entropy, qtype mix | 0 | none |
| REP-005 | Egress spike against own baseline | TA0010; T1041, T1048 | Same host class with high-volume history. Sep is per-host history | out-heavy, off-hours | 0 | none |
| REP-006 | Sudden destination fan-out | TA0007; T1018, T1046 | Egress proxy fan-out. Sep is destination context | many dst, small bytes | 0 | none (count accepted in 2026-10-07) |
| REP-007 | Spray or brute against sparse failures | TA0006; T1110, .001, .003 | NAT egress with many users. Sep is fail ratio and successes | spray or brute shape | 0 | F4 |
| REP-008 | Per-host first-seen external dst | TA0011, TA0042; T1071, T1583 | No foil, embedded history | baseline then first-seen | 0 | F3 |
| REP-009 | IPS rate spike | TA0043, TA0001; T1595, T1190 | Same hits over 60 min. Sep is event rate | high severity in window | 0 | none |
| REP-010 | Denied egress burst | TA0011; T1071, T1090 | Same denies over many sources. Sep is per-source count and burst | spike then decay | 0 | none |
| REP-011 | VPN geovelocity | TA0001; T1078, T1133 | No foil, declared unsupported. Parser-only | country hop per login | 0 | none |
| REP-012 | Jittered and fleet beacon | TA0011; T1071 | Update check at the same cadence. Sep is fleet aggregate period | period shape by mode | 0 | F4 |
| REP-013 | Worm-like spread | TA0008, TA0007; T1210, T1021.001, .002, T1046 | Stable server set. Sep is a growing source population | sources grow by generation | 0 | none |
| REP-014 | Mining pool session | TA0040; T1496 | Long business session. Sep is metronomic against bursty bytes | long symmetric sessions | 0 | F2, F4 |
| REP-015 | Low-rate DNS exfil | TA0010, TA0011; T1048.003, T1071.004 | Same count parent. Sep is unique-label cardinality | per-hour rate, one parent | 0 | F7 |
| REP-016 | DGA NXDOMAIN cluster | TA0011; T1568.002, T1071.004 | NXDOMAIN trickle. Sep is clustering. Parser-only | distinct SLDs per epoch | 0 | F5 |
| REP-017 | DoH bypass noticed as an absence | TA0011; T1572, T1071.004 | No foil, phase 1 is the baseline | resolver stops, DoH begins | 0 | none |
| REP-018 | Login chain against admin star | TA0008, TA0005; T1021, T1078, T1550 | Admin star. Sep is chain shape | each hop is next source | 0 | none |
| REP-019 | Scan below rate threshold | TA0007; T1046 | Sparse denies, two targets each. Sep is long-window aggregate | slow rotated probes | 0 | none |
| REP-020 | Org-wide first contact, new domain | TA0011, TA0042; T1583.001, T1071 | No foil. Parser-only | novel absent from history | 0 | none |
| REP-021 | Inbound scan as a false-positive source | TA0043; T1595.001, .002 | No foil, calibration | heavy-tailed sources | 0 | none |
| REP-022 | Alert chain keyed on order | TA0043, TA0001, TA0011, TA0010; T1595, T1190, T1071, T1041 | Unrelated alert noise. Sep is kill-chain order | severity escalates in order | 0 | F1 |
| REP-023 | TLS 1.3 C2 on flow features | TA0011; T1071.001, T1573.002 | Browsing to 443. Sep is dst count, per-pair count, regularity, byte variance | low variance, no handshake | 0 | F4 |
| REP-024 | Unsanctioned relay against sanctioned proxy | TA0011; T1090, T1090.001 | Sanctioned proxy. Sep is asset role | lagged, byte-correlated legs | 0 | none |
| REP-028 | Admin login from outside mgmt pool, then changes | TA0005; T1562.004, T1078 | Same burst from jump host. Sep is source role | `test_rep028_admin_plane.py` | 1 U | F8 |
| REP-030 | Distributed low-and-slow spray | TA0006; T1110.003 | Failures that self-correct. Sep is fail ratio | one failure per user | 0 | F4, F7 |
| REP-043 | IPS alert joined to later egress | TA0001, TA0011; T1190, T1071 | Broken join, no continuation, reversed order. Sep is join and order | alert, inbound, egress | 0 | none |
| REP-046 | VPN login from a network new to the user | TA0001; T1078, T1133 | Login from own rare network. Sep is per-user novelty | `test_rep046_unfamiliar_vpn_source.py` | 1 U, 1 I | none |
| REP-052 | SMB write fan-out | TA0040; T1486 | Distribution server. Sep is source role | `test_rep052_smb_fanout.py` | 3 U, 1 I | F8 |
| REP-053 | Reflector amplification | TA0040; T1498.002 | Chatty poller. Sep is reply-to-request ratio | `test_rep053_reflector.py` | 5 U | F8 |
| REP-054 | Staging fan-in | TA0009; T1074.002 | Backup fan-in. Sep is destination role | `test_rep054_staging_fanin.py` | 1 U, 1 I | F8 |

## 2. Deduplication against closed records

Candidates the scan raised that are already closed, and so are NOT findings here.

| Candidate | Closed by |
|---|---|
| REP-006 separable on count and span | 2026-10-07, accepted as the intended axis |
| REP-009 separable on span | intended, event rate is the named feature |
| REP-016 separable on count | 2026-10-07, "count only (trickle, intended)". F5 below is a different feature |
| REP-023 separable on destination count and timing | 2026-10-07, catalog rewrite names them |
| REP-005 medians differ | intended, history is the named feature |
| REP-030 foil carries tunnel-up records | intended, self-correction is the named feature |
| REP-053 in-bytes disjoint | intended, the ratio is the named feature |
| REP-008, 011, 017, 020, 021 have no foil | disclosed limits, declared in the catalog |
| REP-018 srccountry differs between chain and star | random per stream in both directions, not systematic |

One candidate is open in the record rather than closed. The 2026-10-07 verdict
table lists REP-014 as separable on "12 records against 120 to 25920" and the
defect table of the same review has no REP-014 row. That is F2.

## 3. Findings, ranked by detection impact

Each guard below must be run against the unfixed engine and observed to fail on
the seeds and presets given, then pass after the fix.

### F1. REP-022. The noise is separable on severity alone, and no control tests order. High

- Objective claims the rule "keys on the kill-chain order of alerts rather than
  on how many arrived in a window".
- Measured, 60 of 60 plans. Every noise alert carries `ips_severity` low and
  action reset. The chain always carries alerts above low (minimum 4 at low,
  13 at medium, 34 at high). No noise pair carries more than 2 alerts.
- Consequence. A rule that reads "any alert above low severity" isolates the
  chain perfectly without looking at order. So does "3 or more alerts on one
  pair". A green result does not show the rule keys on order.
- Not found in 2026-10-07, whose REP-022 row records "none". That review
  checked the entity pair, not severity.
- Proposed fix. Two changes. Noise draws severity from the chain's own
  distribution. A second negative control puts the same signatures on one other
  pair in a non-kill-chain order (REP-043 already does this for its dialog).
  Order then becomes the only separating feature, which is what the entry says.
- Guard plan. Add REP-022 to `tests/test_foil_parity.py`. Check one asserts the
  noise severity set overlaps the chain's. Check two asserts a scrambled-order
  pair exists with the chain's alert count and severity multiset. Positive
  control expected to fail on all 60 plans today.

### F2. REP-014. The foil does not scale and uses a hard-coded port. High

- Measured, seed 1, all presets. Events 120, 2880, 25920 for the miner against
  12 for the foil at every preset. Destination port 3333 and 14444 for the miner
  at low and medium against 443 for the foil. Span 24.0 h against 7.3 h at
  medium and 72.0 h against 11.0 h at high. Pool sessions 3 and 6 against 1.
  The scan saw the count and port separation on 30 of 30 and 20 of 30 plans.
- Cause. `benign_steps = max(1, min(12, shares))`, port literal `443`, and the
  foil spans one session length, not `sessions` of them
  (`replicant/scenario/engine.py`, `_plan_cryptomining`).
- Consequence. "More than 12 records on one session" or "long session on a
  non-web port" separates the streams for free. The named feature is steady
  against bursty bytes. This is the count-ceiling class the 2026-10-07 review
  fixed on REP-007, REP-019 and REP-024.
- Proposed fix. The foil uses the miner's port, session count, span and record
  count, and keeps only the bursty byte draw.
- Guard plan. Add REP-014 to `tests/test_foil_parity.py`. Equal port set, record
  count within a stated ratio, span within a stated ratio, equal session count,
  and byte CV still above the miner's. Positive control expected to fail at
  every preset on every seed.
- Cost to state. At high the foil grows from 12 to about 25920 records, so the
  plan doubles.

### F3. REP-008. Novel destinations sit in a different /24 from the history. Medium to high

- Measured, 60 of 60 plans. Every baseline destination is in 198.51.100.0/24
  and every first-seen destination is in 203.0.113.0/24.
- Consequence. A subnet match finds the "novel" contacts with no history at
  all. The entry's point is that absence from this host's history is the mark.
  REP-020 had the same defect on DNS parents and it was fixed on 2026-10-07 with
  the wording "absence from the history is the only mark of novelty".
- Not raised before. The 2026-10-07 REP-008 row covers the T1583 label and the
  missing standalone foil only.
- Proposed fix. Draw the novel destinations from the same pool as the baseline,
  excluding the known set.
- Guard plan. In `tests/test_catalog_fidelity.py` or the parity file, assert the
  novel /24 set is a subset of the baseline /24 set and the novel addresses are
  absent from history. Expected to fail on 60 of 60 today.
- Side effect to check. SCEN-002's stage 2 currently lands on the adversary
  pool by this route. The advisory's adversary-stage index may move.

### F4. Five foils are separable on the address pool. Medium. Decision needed

- Measured, 60 of 60 plans each. REP-007 and REP-030 by source /24. REP-012,
  REP-014 and REP-023 by destination /24. Attack entities come from
  203.0.113.0/24 and foil entities from 198.51.100.0/24.
- The catalog already states the rule. REP-053 says "pool membership is not a
  free reputation feature" and REP-046 says "a second pool would be a free
  reputation feature". Both have guards that fail when the foil uses another
  pool. The five older entries predate that rule.
- Counter-argument, stated fairly. The adversary pool is a deliberate
  convention that keeps lab data readable, and REP-001's safety note relies on
  it. A real rule cannot key on a documentation range. So the harm is limited to
  a lab rule written against the subnet.
- Options. (a) Apply the REP-053 rule to all five. (b) Keep the convention and
  disclose it in each entry as a named non-feature. (c) Leave as is.
- Recommendation. (a) for REP-007 and REP-030, where the source is the only
  thing a spray rule aggregates on. (b) for the three C2 entries.
- Guard plan for (a). A shared `foil_shares_the_attack_pool` check in the parity
  table, per technique. Expected to fail on 60 of 60 today.

### F5. REP-016. The benign trickle is NXDOMAIN only and fixed at 12. Medium

- Measured, 60 of 60 plans. The foil is exactly 12 records, all NXDOMAIN, from
  the same source host as the cluster.
- Consequence. A benign host resolves mostly successfully and fails
  occasionally. A foil with a 100 percent failure ratio trips any ratio-based
  DGA rule harder than the attack does (attack ratio is 0.95 to 0.99). Count
  separation is accepted and intended. Ratio is not named.
- Proposed fix. The foil host also emits successful responses so its NXDOMAIN
  ratio is low, and the trickle scales with the run's span.
- Guard plan. Parity check on the foil's per-host NXDOMAIN ratio, below a stated
  ceiling. Expected to fail on 60 of 60 today.
- Open question. The DGA host itself emits no ordinary successful lookups
  beyond the rendezvous domain. Whether to add them is the same decision.

### F6. SCEN-003. The spray to login step has no measured join. Medium

- Measured, seeds 1 and 2. Stage 1 sprays 500 users from the pinned adversary
  address. Stage 2 logs in as `mkhan` from three other addresses, none of them
  the adversary. `mkhan` is in the sprayed set, as 1 of 500, and the spray stage
  contains no success.
- The advisory measures `vpn_pivot_stage_indices` (login to beacon) and nothing
  for spray to login.
- Already recorded as open. The 2026-09-08 review asked for user and victim
  continuity controls on SCEN-003. Only the `tunnelip` pivot was built.
- Proposed fix. The advisory measures whether the anomalous login's user is in
  the sprayed set and reports it, as it does for the other two pivots. No engine
  change is needed for that. Whether one login should come from the spray
  source is a design choice.
- Guard plan. A test in `tests/test_scenario_advisory.py` that reports the
  pivot, with a positive control that renames the stage 2 user and expects the
  pivot to be reported absent.

### F7. REP-015 and REP-030. The attack is an exact metronome. Low

- Measured, medium, seed 1. Gap CV 0.000 on both attack streams.
- The catalog text matches the code ("evenly sparse", and 2026-10-07 noted
  REP-015 with no defect raised). So this is a realism note, not a contradiction.
- Consequence. Perfect regularity is a detectable feature the entry does not
  name. A periodicity rule would fire on a spray.
- Proposed change if wanted. Jitter both streams and their foils with one
  process. Low priority.

### F8. REP-028, 052, 053, 054. "The same number" is a draw from the same range. Low, label

- Measured. REP-052 low seed 1 gives 23 attack records against 12 foil records.
  REP-028 high seed 1 gives 50 against 30. The scan saw a ratio of 1.5 or more
  on 5 to 8 of 30 plans per entry.
- The builders draw each stream's count independently from the preset range.
  That is defensible and the dedicated guards test it. The catalog text says
  "the same number", which is not what is emitted.
- Proposed fix. Reword the four `benign_baseline` strings to "a count drawn
  from the same range". No engine change.

### Process gaps, not defects

- Detection specs exist for 1 of 31 entries (REP-001).
- `tests/test_foil_parity.py` has rows for 11 of the 26 foil techniques. REP-014
  and REP-022 have no parity row anywhere, and both have findings above.

## 4. Scenarios

| Scenario | Stage joins measured (seeds 1, 2) | Finding |
|---|---|---|
| SCEN-001 | Victim is the source in all 3 stages. Beacon and exfil share the adversary destination | none |
| SCEN-002 | Victim is the source in all 3 stages. No destination join between stages 2 and 3, by design | F3 side effect |
| SCEN-003 | Login to beacon joins on `tunnelip`. Spray to login is unmeasured | F6 |
| SCEN-004 | Staging destination becomes exfil source, measured by the advisory | none |

Coverage of the chains. The four scenarios use 10 of 31 techniques. None
contains a Lateral Movement, Defense Evasion or Impact stage, and four of the
five newest entries appear in no chain.

## 5. Coverage tally (31 entries, counted today)

| Tactic | Entries |
|---|---:|
| TA0011 Command and Control | 13 |
| TA0007 Discovery | 5 |
| TA0001 Initial Access | 5 |
| TA0010 Exfiltration | 4 |
| TA0043 Reconnaissance | 3 |
| TA0040 Impact | 3 |
| TA0006 Credential Access | 2 |
| TA0042 Resource Development | 2 |
| TA0008 Lateral Movement | 2 |
| TA0005 Defense Evasion | 2 |
| TA0009 Collection | 1 |
| Execution, Persistence, Privilege Escalation | 0 |

Primary log family. traffic:forward 18, event:vpn 5, dns:dns-query 3,
utm:ips 3, dns:dns-response 1, event:system 1. Foils. 26 emit one, 5 do not.
Transferability. 28 transfers, 3 parser-only.

## 6. New techniques

Recommendation. Add none now. Three reasons.

1. The gate. No rule fire has been observed, and the roadmap says to prove the
   pipe before widening the catalog.
2. F1 to F5 change what a green result means on entries that already ship.
   Fixing them buys more than a 32nd entry.
3. The 2026-10-07 ranked backlog is fully built. The remaining gaps are the
   three host-only tactics the records call structurally absent.

If the owner wants one anyway, these are the candidates that fit the standing
rules. The ids are the reserved ones and must be kept. The next free id is
REP-055. Details of the original proposals are [Unverified] here, because they
come from a summary of rounds 3 and 4, and each needs its source record read
before a build.

| Rank | Id | Proposal | Tactic it fills | Expressible honestly in firewall CEF | Foil and single separating feature |
|---|---|---|---|---|---|
| 1 | REP-031 | Concurrent overlapping VPN sessions for one user | Credential use, thin tactics (Initial Access 5, Defense Evasion 2) | [Inference] Yes if a tunnel-down record renders on all three vendors. That must be checked first. If it does not, the entry fails the REP-016 test and should not be built | Same user, same two networks, sessions back to back. Sep is overlap in time |
| 2 | REP-042 | Size-limited chunked exfiltration (T1030) | Exfiltration, already 4 | [Inference] Yes, traffic:forward bytes per session | Chunked sync job to a destination in the host's history. Sep is per-host destination history, or chunk uniformity. The proposal must pick one |
| 3 | REP-044 | Server role reversal, inbound-only server starts egress | Labelled Persistence in round 4. The honest label is Command and Control | [Inference] Yes, traffic:forward direction | Server with established egress history. Sep is per-host direction history |

Not proposed, and why.

- REP-045, 048, 049, 050, 051. All Command and Control, which is 13 of 31. The
  catalog header calls a further beacon variant near-zero value.
- REP-025, 026, 027. Each waits on a field or template no profile renders.
- REP-029, 035, 041. Parked, the records cannot carry the signal.
- Anything under Execution, Persistence or Privilege Escalation. The records
  call that relabeling.

A scenario instead of a technique. A fifth chain would use existing entries and
add no catalog surface. Sketch, for decision only. REP-046 (unfamiliar VPN
source), then REP-018 (login chain), then REP-052 (SMB write fan-out). It adds
Lateral Movement and Impact to the chains. The join from REP-046's `tunnelip`
to REP-018's first hop and from the last hop to REP-052's source would have to
be measured by the advisory, not assumed. Web scenario support stays deferred.

## 7. Decisions for the owner

| # | Decision | Recommendation |
|---|---|---|
| D1 | Fix F1 (REP-022 severity and order control) | Yes |
| D2 | Fix F2 (REP-014 foil scale and port) | Yes |
| D3 | Fix F3 (REP-008 novel pool) | Yes |
| D4 | F4 pool split. Option a, b or c | a for REP-007 and REP-030, b for REP-012, 014, 023 |
| D5 | Fix F5 (REP-016 foil ratio) | Yes |
| D6 | F6 advisory measures the spray to login pivot | Yes, advisory only |
| D7 | F7 jitter REP-015 and REP-030 | Defer |
| D8 | F8 reword four baselines | Yes, text only |
| D9 | Add a technique now | No. If yes, REP-031 first after the field check |
| D10 | Build SCEN-005 from existing entries | Owner's call, after D1 to D5 |

Every approved fix ships with its guard, a positive control recorded in the PR,
and CHANGELOG, README table and catalog header updates in the same PR.
