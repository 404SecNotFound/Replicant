# Catalog research, round 5: stronger controls and temporal behavior

**Date:** 2026-09-08. **Reviewed revision:** `831beebf8d3b7b15e8ae27fe3d58d8c066ade026`.

**Status:** implemented research slice. The catalog now contains 26 techniques.
The final corrections and disposition are recorded in the
[all-round review](catalog-research-review-2026-09-08.md).
Mappings from papers to proposed synthetic behavior below are **[Inference]**,
not measured Replicant detection results.

The implemented order is harder comparison cases, DNS behavior that changes
across a run, beacon observation-window checks, REP-030 distributed password
spraying, then the corrected REP-043 cross-log correlation case.

This review checks the shipped catalog and the earlier
[round 3 triage](round3-expansion-triage.md) and
[round 4 proposals](technique-catalog-expansion-research-round4.md).
REP-025 through REP-051 remain proposal identifiers, including rejected and
parked entries. Nothing here reallocates them. The peer-community candidate below
has no assigned identifier.

## Evidence from additional primary papers

| Paper | Finding relevant to Replicant | Boundary |
|---|---|---|
| Liu et al., [Indicator of Benignity](https://www.ndss-symposium.org/wp-content/uploads/2026-f1869-paper.pdf), NDSS 2026 | Six years of user reports expose a long tail of legitimate domains missed by popularity-based lists. | User-reported cases do not establish a population-wide false-positive rate. A legitimate owner can also have a compromised domain. |
| Petrov et al., [Domainator](https://arxiv.org/html/2505.22220v1), ARES 2025, author preprint | Subdomain similarity within sliding windows captures behavior across handshake, idle, upload, and download recordings. | Evaluation covers seven tools or samples. Some idle and download cases are indistinguishable using these features. |
| Oškera et al., [Botnet Detection Through Periodic Patterns in Command-and-Control Network Traffic](https://dl.ifip.org/db/conf/cnsm/cnsm2025/1571190192.pdf), CNSM 2025 | CESNET-CC25 supports longer observations; the detector aggregates flows over time and evaluates different window sizes. | Short captures and differences between collection environments affect conclusions. Packet timing is richer than firewall event timing. |
| Gao et al., [GraphTunnel](https://zhangmx1997.github.io/papers/tifs24_dns_tunnel.pdf), IEEE TIFS 2024 | Wildcard DNS creates legitimate names whose surface features resemble tunneling. Recursive-resolution graphs provide additional context. | The full feature set needs information beyond Replicant's current DNS records, including TTL, packet bytes, and response timing. |
| Yang et al., [True Attacks, Attack Attempts, or Benign Triggers?](https://www.usenix.org/conference/usenixsecurity24/presentation/yang-limin), USENIX Security 2024 | A four-year, 115-million-alert SOC study distinguishes compromise, unsuccessful attempts, and business-justified triggers. | The findings describe one SOC. A matched network signature alone does not establish compromise. |
| Arp et al., [Dos and Don'ts of Machine Learning in Computer Security](https://www.usenix.org/conference/usenixsecurity22/presentation/arp), USENIX Security 2022 | Evaluation pitfalls include leakage, spurious correlations, and unrealistic experimental assumptions. | Synthetic generator tests alone cannot establish operational detection performance. |
| Zhuang and Chang, [PeerHunter](https://arxiv.org/pdf/1709.06440), IEEE DSC 2017, author preprint | Shared contacts and destination diversity help identify peer-to-peer host communities. | The published pipeline uses distinct external /16 networks, not merely distinct destination addresses. |
| Nagaraja et al., [BotGrep](https://www.usenix.org/events/sec10/tech/full_papers/Nagaraja.pdf), USENIX Security 2010 | Communication-graph structure can expose structured P2P communities. | Its aggregate network vantage and need to distinguish legitimate P2P limit direct transfer to a single firewall. |

These are additional anchors, not reproductions of their detectors. No paper's
headline accuracy is adopted as an expected Replicant result. No datasets,
malware, live domains, or third-party implementations were imported.

## Pre-implementation generator snapshot

This section records the state inspected before implementation. The
[catalog review](catalog-review-2026-09-08.md) and all-round review contain the
current contract. At this snapshot, twelve entries declared a negative stream. Eight still needed
purpose-built controls: REP-001 through REP-005 and REP-009 through REP-011.
REP-008, REP-017, and REP-020 include history inside their positive plans;
REP-021 is an inbound calibration baseline.

Local, in-memory probes used the default entity model, seed `1337`, and medium
presets without duration overrides:

| Entry | Observed plan | Implication |
|---|---|---|
| REP-001 | 243 positive records; no negative records. | Scheduled benign traffic remains an untested comparison. |
| REP-004 | 108,000 positive records, 1,200 distinct generated labels of length 40 to 55; no negative records. | The builder cycles a fixed label pool. It has no phase-specific label model. |
| REP-015 | 288 positive and 288 negative records. Positive labels have length 16 to 28; the foil cycles five familiar labels. | The existing foil tests query volume against cardinality. It does not test benign machine-generated names. |

Code inspection confirms that `EventRecord.eventtime` is integer seconds. DNS
queries expose `qname` and `qtype`; responses add `rcode` and an optional single
`ipaddr`. Adding `ttl` to an event's `extra` dictionary and rendering it emitted
no TTL field in any of the three profiles. Arbitrary extra keys are not a vendor
field contract. None of these probes opened a network connection.

## Ranked implementation recommendations

All designs and acceptance criteria in this section are **[Inference]**.

| Priority | Work | Catalog disposition | Readiness |
|---|---|---|---|
| 1 | Harder benign DNS and beacon comparisons | Extend REP-004/015 and REP-001/012 | Existing fields suffice; define the target analytic explicitly. |
| 2 | DNS phases and local similarity | Opt-in variants of REP-004/015 | Existing query fields suffice for the proposed subset. |
| 3 | Sparse and interrupted beacon observations | Opt-in variants of REP-001/012, then REP-023 | Existing flow fields suffice at whole-second resolution. |
| 4 | Distributed low-and-slow spray | Promote existing REP-030 proposal | Existing VPN fields suffice after primary-source re-anchoring. |
| 5 | Inbound alert followed by victim egress | Promote existing REP-043 proposal | Existing log families suffice; join and outcome contracts need implementation. |
| 6 | Mutual-contact peer community | New, unnumbered candidate | Conditional on a useful detector contract that works with synthetic ranges. |

### 1. Make the benign side demanding

For DNS, add synthetic service-discovery, cache-key, and security-agent-like names
with substantial label diversity. Match query count, record-type mix, label
length, and entropy where those are not the intended discriminator. GraphTunnel's
wildcard findings support testing these overlaps; the 2026 benignity study
supports looking beyond familiar popular names. These are proposed synthetic
workloads, not reconstructions of either dataset.

For beacons, add scheduled health checks and update polling with overlapping
intervals and byte counts. A timing-only rule may legitimately flag both. If the
desired distinction needs host role or an approved-service inventory, record
that prerequisite rather than giving the negative stream an artificial timing
advantage.

Acceptance requires a documented discriminator and its observable fields for
every pair. Class membership must not be recoverable solely from a literal
domain, address pool, session-ID range, or annotation. Controls that remain
indistinguishable with the available telemetry should be labeled as such.
Preserve REP-015's existing easy comparison as an explicit baseline.

### 2. Add phase-aware DNS variants

Domainator motivates a query-only model with synthetic setup, idle, and transfer
phases. Vary shared label segments, counters, and changing suffixes across windows
instead of cycling one random pool. Keep all strings under permitted synthetic
parents. No payload or working tunnel protocol is needed.

Test window composition and phase boundaries using the emitted `qname` sequence.
A shuffle across windows can be a diagnostic comparison; it is not automatically
benign traffic. Domainator averages all pairwise string similarities within a
window, so merely reordering that same window should not change those features.
No claim of reproducing Domainator's classifier or identifying malware follows.

Keep timestamps and query types visible, but do not fabricate response payloads,
TTL, or RTT to suggest full GraphTunnel coverage. Expose the variant separately
from intensity, retain existing defaults, and record its effective parameters in
the manifest. Add `emits_foil` only when a credible benign workload is implemented.

### 3. Test beacon observation limits

The CNSM work motivates testing how much observation a detector needs. Proposed
stress variants introduce missed callbacks, inactive periods, and changes of
interval. Those specific distributions are engineering choices, not values
measured from CESNET-CC25.

Evaluate explicit observation windows such as 5, 15, and 60 minutes, keeping the
underlying plan fixed. Record callback count and span; a window with too few
observations should report insufficient evidence. Match benign scheduled traffic
to expose false positives. Test multiple seeds and entity remappings.

Use event time for offline comparisons. For a live pilot, use plan pacing at
speed 1 and inspect any delay imposed by the EPS cap. Speed compression also
changes emitted event times in the current implementation. Do not interpret a
compressed run as an unchanged long-window experiment, or whole-second flow
timestamps as packet inter-arrival measurements.

### 4. Add REP-030 before REP-043

The full re-review found that Credential Access had one catalog entry while
Command and Control already had twelve. REP-030 was therefore implemented first,
after re-anchoring it to Araña and MITRE DET0487 and confirming that `event:vpn`
exposes the necessary source, user, outcome and time fields.

### 5. Implement the corrected REP-043 dialog

The SOC study strengthens the case for the existing
[REP-043 proposal](technique-catalog-expansion-research-round4.md#rep-043-inbound-exploit-to-egress-callback-dialog-correlation-bothunter-chain).
Construct an inbound IPS alert, an associated allowed inbound session, and later
outbound traffic from that same synthetic victim. Join the IPS destination and
inbound destination to the outbound source; use explicit time bounds.

Comparison cases should include a blocked attempt without continuation,
unrelated outbound traffic from another host, and reversed event order. These are
negative controls for the proposed progression analytic; a blocked attempt may
still correctly trigger an IPS rule.

Check that removing a stage or breaking the victim join changes the expected
correlation outcome. `utm:ips` and `traffic:forward` already carry the necessary
families; validate each vendor's normalized field mapping. The outcome is an
observable progression hypothesis, not proof of exploit execution. Use an
operator-authored detection and retain observed ingestion and alert evidence.

### 6. Investigate a peer-community candidate, with a narrower claim

Model several internal hosts contacting overlapping, changing external peer
sets. Pair them with a legitimate P2P workload of comparable size and volume.
This tests a community across hosts, distinct from REP-006's fan-out,
REP-024's two-leg relay, and proposed REP-051's similar flow shapes.

Current source, destination, time, protocol, and byte fields can represent that
graph subset. However, the default adversary pool occupies one /16, and the three
documentation IPv4 ranges provide only three distinct /16 prefixes. PeerHunter's
published evaluation uses a destination-diversity threshold of 50. Substituting
address counts or labeling private ranges as public networks would change the
analytic.

Keep this candidate in research until a useful shared-contact hypothesis and
credible benign P2P comparison are established. BotGrep also cautions against
equating graph structure with maliciousness. Do not promise an unchanged
PeerHunter benchmark or allocate a catalog ID yet.

## Implementation and validation gates

The approved slice added the DNS comparison workloads and phase behavior,
beacon controls and observation-window tests, the REP-009 signature selector,
REP-030, and the corrected REP-043. Each uses the existing control labels and
records its effective parameters in the manifest. No generic variant layer was
introduced.

Most generator work belongs in
[`replicant/scenario/engine.py`](../replicant/scenario/engine.py), with declared
parameters and signal contracts in
[`technique-catalog.yaml`](../replicant/data/technique-catalog.yaml).
Use the shared Orchestrator for new selection behavior. Keep default seeded
output stable where practical, and explicitly version and document any change.

Extend the existing statistical-fidelity, structural-foil, and rendered-signal
tests to check the intended invariant. For evaluation, hold out complete runs,
hosts, or time periods instead of randomly splitting adjacent overlapping
windows. Arp et al.'s findings motivate an explicit shortcut audit before
interpreting any score.

Use the current run identity and control-selection support rather than adding a
second labeling system. Keep ground-truth labels out of detector inputs. A live
result should identify the rule version, vendor and parser, timing mode,
observation window, positive and negative counts, and missing context. Include
false alerts per host-hour and detection latency where meaningful; precision
must state the tested class mixture.

Maintain deterministic generation, manifests, collector-only egress, EPS limits,
and synthetic entities. New source requires Apache headers and the repository's
normal tests, type checks, and CEF golden/loopback checks. These proposals require
no malware execution, packet replay, runtime model, or Internet enrichment.

The LogRhythm pilot and live Palo Alto/Check Point reference validation remain
external evidence gates. REP-011, REP-016, and REP-020 retain their current
enrichment limitations. Full recursive DNS, TLS fingerprint, authentication
provider, or host-execution claims need corresponding verified telemetry.

## Validation performed for this research change

- Reviewed the 24-entry catalog, three scenarios, prior proposals, entity pools,
  planner code, and all three DNS render paths.
- Ran the in-memory probes described above.
- Passed all 38 tests in `tests/test_statistical_fidelity.py`,
  `tests/test_structural_foils.py`, and `tests/test_catalog_signal_contracts.py`.
- Checked local documentation links and whitespace.

Generator checks are not evidence that a production SIEM ingested these
techniques or fired a detection.
