# Triage of the Round 3 catalog expansion proposal

A gap-analysis report proposing 17 new techniques (REP-025..REP-041) was produced
externally and reviewed on 2026-08-04. The source document is **not in this
repository by design**: it is working material, and what belongs here is the
decision, not the draft.

This is a decision record. Where a proposal is rejected the reason is stated so
it can be argued with rather than rediscovered, which is the same standard
`security-review-2026-08-response.md` uses.

**Nothing here is implemented.** Adopting any of it is a separate decision about
where the project's effort goes, and it belongs to the project owner.

## How the report was checked

Its claims about this codebase were verified against the code rather than taken
on trust. Most held: the `dns:dns-response` path really does carry `rcode` plus
at most one optional address and no TTL or rdata; `event:system` really is
rendered by all three profiles and used as the primary path by no catalog entry;
`_assert_synthetic` and the entity pools are as described.

**Two claims were wrong, and both changed a conclusion.**

1. It said `port_service()` renders UDP/443 as `tcp/443`. It does not: 443 is in
   `_PORT_SERVICE`, so it renders `HTTPS`. Only unmapped ports take the
   `tcp/<port>` label. The underlying suggestion (make `port_service` aware of
   protocol) is still worth doing; the symptom given for it was not real.
2. It listed a `qtype` whitelist as the blocker for REP-041. There is no
   whitelist: `qtype`/`qtypeval` pass through from `extra` as free strings in
   both FortiGate and Palo Alto. The blocker did not exist.

Citations were not verifiable in the review session (no network). By
recognition the pre-2025 academic anchors are real and correctly attributed.
Three weaknesses are worth carrying forward as **[Unverified] until checked
against primary sources**:

- **Citation laundering.** MITRE detection guidance sourced from a marketing
  site rather than from attack.mitre.org; industry reports cited via third-party
  summaries.
- **One unresolvable load-bearing anchor.** The strongest claim in the ICMP
  proposal (signature engines at 0% recall) rests on an issue-level journal link
  with no article, title or authors.
- **2026-dated vendor claims.** At least one reads as a year-shifted version of
  a real 2024/2025 event. Treat every 2026 date and CVE in that document as
  unconfirmed.

## Adopt, if the catalog is expanded again

Each is buildable on an existing render path and covers a shape no current entry
produces.

| id | shape | why it is not already covered |
|---|---|---|
| REP-030 | distributed low-and-slow password spray | inverts REP-007: one attempt per account from many sources, so per-IP and per-account thresholds both miss it |
| REP-029 | MFA push fatigue | REP-007 emits failures that stay failures; a failure-to-success transition per user is a signal nothing in the catalog produces |
| REP-031 | concurrent overlapping VPN sessions | overlap of tunnel lifetimes is a different join from REP-011's velocity arithmetic |
| REP-032 | single-signature IPS sweep | REP-009 mixes signatures and REP-022 orders them; neither produces attackid cardinality of one across many sources |
| REP-036 | internal staging fan-in, then egress | many-to-one internal aggregation is a topology no entry covers, and the phase transition is the analytic rather than the egress spike |
| REP-035 | persistent QUIC session C2 | a clean inverse of REP-023: no reconnections to count |
| REP-041 | ECH qtype=65 reconnaissance | cheap, and its stated blocker turned out not to exist |

## Adopt only with changes

- **Fast flux (REP-025).** This is the project's own deferred item and worth
  doing. But **do not invent a multi-answer-list field.** FortiOS emits one
  address per dns-response record, and fabricating an answer-list key across
  three profiles invents vendor behaviour the golden lines exist to prevent.
  Express answer-set churn as consecutive single-answer responses for one qname,
  and extend the path with `ttl` only.
- **Response-side TXT C2 (REP-026).** Same problem, worse: an rdata text field
  on dns-response is unverified on all three vendors. Confirm a real field
  exists first. If none does this fails the REP-016 test and should be dropped
  rather than degraded.
- **ICMP tunnel (REP-027).** Buildable and genuinely uncovered. Replace the
  unresolvable anchor before it enters a catalog entry.
- **Rogue admin and config burst (REP-028).** The right idea, and the only
  proposal that uses the unused `event:system` path as a primary. Re-anchor to
  the verifiable 2024/2025 campaign and confirm a real FortiOS logid.
- **Pre-disclosure scan surge (REP-033).** Distinct from REP-021. Re-anchor to
  checkable early-warning work.
- **Inbound reflection flood (REP-034).** Buildable, but the entry must state a
  tension it currently hides: safety rule 4 caps events per second, so a *flood*
  cannot be expressed as event rate here. Only bytes-in per session carries the
  signal. Saying so is the difference between an honest entry and one that
  teaches an operator to expect a spike Replicant will never produce.

## Rejected

- **DoT bypass (REP-037) and cloud-storage exfil ladder (REP-039).** By the
  report's own rule. It rejected FTP, SMB and SMTP exfil because they "collapse
  into REP-005 plus a parameter", then proposed two entries that do exactly
  that: one is REP-017 with a port parameter, the other REP-005 with a
  destination class. Parameterise, do not add.
- **DoQ (REP-038).** Self-flagged as needing a review-by date because its
  precision decays as deployment grows, and its own anchor says browsers chose
  DoH instead. A catalog entry with a maintenance timer, modelling something
  that barely happens.
- **Domain-fronted C2 (REP-040).** Cannot be expressed honestly, which is the
  REP-016 test. Half the signal is destination *reputation*, and CEF has no
  reputation field: in Replicant the "high-reputation CDN" is a 203.0.113.x
  address the operator's SIEM knows nothing about. What remains (low bytes, long
  duration, tcp/443) is already inside REP-023's envelope.

## The most valuable part was not a technique

The report's own "considered and rejected" section is better than its proposals.
Its telemetry-boundary rejections (Kerberoasting, DCShadow, device-code
phishing, application-layer floods, cache poisoning) are all correct calls and
they match this project's rules without having been told them. That table is
worth keeping whether or not a single technique is adopted.

Three other non-technique items worth taking:

1. **Measured `benign_baseline` values.** Several proposals cite real measured
   distributions rather than a described judgement. Retrofitting numbers to
   existing entries is cheap and upgrades a documented opinion into a citable
   figure.
2. **Protocol-aware `port_service()`.** A real defect on its own merits, even
   though the symptom offered for it was wrong.
3. **A scenario rather than a technique.** Pre-disclosure recon, then mass
   exploitation, then admin-plane persistence is a coherent SCEN chain, and
   plausibly worth more than any single entry above.
