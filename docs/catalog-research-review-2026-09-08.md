# Catalog research review across rounds 1 through 5

**Date:** 2026-09-08. **Implementation revision:** working tree based on
`831beebf8d3b7b15e8ae27fe3d58d8c066ade026`.

This review reconciles the five catalog research rounds with the shipped
generator. It corrects stale source claims and tactic counts, separates behavior
that the current firewall fields can represent from behavior that needs external
enrichment, and records the implementation decision. Generated plans and tests
are not evidence that a SIEM ingested the records or that a production rule
fired.

## Corrections to the research record

- The current pre-expansion catalog had one Credential Access entry, three
  Initial Access entries and twelve Command and Control entries. The tactic table
  in round 4 was stale. This made a distributed credential spray more valuable
  than another standalone C2 variant.
- BotHunter was not evaluated against roughly 9,000 infections over 90 days. The
  [primary USENIX paper](https://www.usenix.org/event/sec07/tech/full_papers/gu/gu.pdf)
  reports 2,019 successful infections over three weeks, with 1,920 detected
  (95.1 percent). Its separate false-alarm deployment ran for four months.
- The implemented REP-043 mapping omits T1105. An IPS alert and later network
  flows do not establish ingress tool transfer. The internal victim also changes
  role from destination to source, so no `src` or `dst` field can be declared
  held across the whole plan.
- Round 3 was triage, not implementation-ready research. It contained no verified
  primary-source list. REP-030 was re-anchored to the
  [Araña USENIX Security 2023 paper](https://www.usenix.org/system/files/sec23fall-prepub-22-islam.pdf)
  and [MITRE DET0487](https://attack.mitre.org/detectionstrategies/DET0487/)
  before implementation.
- Round 2 cited a later survey for AACT. The direct
  [AACT preprint](https://arxiv.org/abs/2505.09843) is the source for the reported
  six-month deployment, 61 percent alert reduction and 1.36 percent false
  negative rate.
- MineHunter and PREDATOR now link to primary conference or author copies rather
  than bibliographic indexes. The DNS-over-HTTPS and residential-proxy papers use
  packet timing, packet-size sequences or enrichment that Replicant's
  integer-second firewall summaries do not fully reproduce. Their catalog notes
  describe the transferable subset.

## Implemented decision

The implementation order was existing controls, the REP-009 selector, REP-030,
then REP-043.

1. REP-001 now includes a same-count, same-window, same-port and same-byte-envelope
   irregular control. Timing regularity is the intended discriminator. Tests
   measure callback availability in 5, 15 and 60 minute observation windows.
2. REP-004 and REP-015 now emit setup, idle and transfer label phases. Their
   machine-generated controls match query count, qtype sequence and label-length
   envelope while retaining lower unique-label cardinality. REP-004's medium and
   high preset durations were shortened so both equal-count streams remain under
   the 200,000-event plan limit without silently reducing the configured QPS.
3. REP-009 supports `--signature-mode mixed|single` through the CLI, Rich menu,
   web API and web form. Its control repeats the same hit count, signatures,
   severities and counters over a longer window, isolating event rate.
4. REP-030 distributes sparse VPN failures across many documentation-range
   sources and synthetic users. Its control preserves the failed source-user
   edges and follows each with a successful self-correction. This is a transfer of
   the distributed authentication shape from Araña, not a reproduction of that
   detector or service.
5. REP-043 emits an IPS alert, later accepted inbound traffic to the alerted
   victim, then egress from that victim. Controls omit continuation, break the
   victim join or reverse the order. The records establish an observable
   progression hypothesis only; they do not establish exploit success.

The subsequent offline-validation implementation completed four older catalog
control gaps. REP-002 and REP-003 preserve the global scan distributions while
spreading them across source/destination or source groups. REP-005 compares
matched current traffic against each host's preceding volume buckets. REP-010
preserves global deny fields while removing the single-source burst. REP-011
remains explicitly unsupported because supplied country strings cannot validate
external GeoIP or ASN enrichment or approved-travel context.

REP-032 remains a REP-009 mode rather than a new catalog entry. REP-036 remains a
scenario candidate. REP-029, REP-035 and REP-041 remain parked because current
records cannot establish MFA prompt delivery, QUIC identity or ECH reconnaissance.
The peer-community proposal remains deferred because the published PeerHunter
diversity threshold requires many external /16 networks that the permitted
documentation ranges cannot represent.

## Evidence boundary

All entities remain synthetic. No DNS name is resolved, no authentication is
attempted, and no exploit or callback is executed. The only permitted network
egress remains the operator-configured collector, under the existing EPS cap.
Every run continues to write its manifest.

Offline tests establish determinism, control separation, field contracts,
temporal order and vendor renderability. The first observed LogRhythm rule fire
remains the detection-validation gate. Palo Alto and Check Point output remains
`[Unverified]` until it is compared with live appliances.
