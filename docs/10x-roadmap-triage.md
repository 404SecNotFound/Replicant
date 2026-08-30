# Triage of the "10x" feature roadmap

An eight-feature roadmap totalling roughly 58 to 62 person-weeks was produced
externally and reviewed on 2026-08-30 against `v0.7.0`. The source documents are
**not in this repository by design**: they are working material, and what belongs
here is the decision, not the draft. Same standard as
`round3-expansion-triage.md` and `security-review-2026-08-response.md`.

**Nothing here is implemented.** Adopting any of it is a separate decision about
where the project's effort goes.

## The quality of the proposal

Higher than round 3. The plans were written against a fresh clone, cite
file:line evidence, and respect the project's own invariants rather than
proposing around them: engine stays I/O free, sends stay fail-closed, entity
pools stay synthetic, no heavyweight runtime dependency is introduced, the
banned word "verified" stays banned from output, and the deliberate absence of a
scenario web surface is treated as a decision rather than an oversight. The
integration document also found seven contradictions **between** its own eight
plans, including a three-way collision on the `replicant verify` verb with
conflicting exit codes, and resolved them before proposing anything.

Its central code claim was checked rather than believed, and it is true. See
below.

## The defect it found, confirmed

All three vendor golden tests assert that the reference document contains eight
golden lines, assert that the event fixtures match that count, and then
byte-compare only `range(7)`:

- `tests/test_fortigate_golden.py:265`
- `tests/test_paloalto_golden.py:260`
- `tests/test_checkpoint_golden.py:260`

**The eighth golden line of every vendor reference has never been compared to
anything.** Measured on 2026-08-30: changing all three to `range(8)` leaves 30 of
30 tests passing, so the eighth line is correct and was simply never checked.

That makes it a coverage hole rather than a live defect, and it is still the most
important thing in the whole roadmap. This project's correctness story *is* the
golden oracle, and the oracle was quietly proving seven eighths of what its own
test names claimed. It is the same class as the REP-013 guard whose seed avoided
the collision, and the Check Point golden line that only ever exercised one of
two verdicts.

Cost to fix: one character per file.

## The constraint that drives every other decision

**The LogRhythm lab test has still never run.** Every delivery and timing claim
in this project is loopback-only, and has been since v0.1.0.

Features 1 and 2 are verification layers: they ask a SIEM whether the telemetry
Replicant sent actually fired a rule. Building those on a send path that has
never once been observed working end to end is building on sand. This is not a
reason to reject verification work. It is the reason the offline half of it
comes first and the live-SIEM half waits.

## Decisions

### Adopt

| Feature | Effort | Why |
|---|---|---|
| **F8 P0 only**, the golden-line fix | minutes | Above. Free, and it closes a hole in the oracle everything else trusts. |
| **F2**, detection regression in CI (`replicant verify suite`) | 4.5 pw | The best value-to-effort ratio in the set, and the only one that needs **no SIEM licence**: its Tier 1 runs offline against `rsyslog` writing to a file. It changes what Replicant is for, from a generator you drive by hand into a gate that fails a build when a detection stops firing. |
| **F5**, continuous benign baseline noise | 5.5 to 6.5 pw | **Two independent reviews converged on this gap.** The 2026-08 catalog review named a whole-network benign background as its single largest non-catalog enhancement and "the real false-positive-measurement gap"; this roadmap arrived at the same place separately. Self-contained, no new dependencies, and it is the missing half of the foil convention the catalog already follows per technique. |
| **F1, contract and Fixture/FileLog verifiers only** | ~1 pw of 8 | The four-value verdict (`pass` / `fail_no_alert` / `fail_no_events` / `inconclusive`) is the right model, and F2 consumes it. A boolean would reproduce exactly the "nothing fired, and we cannot say why" ambiguity this project exists to remove. |

Roughly **13 person-weeks**, against 58 to 62 proposed.

### Reject

**F1's live SIEM adapters (Splunk, Sentinel, Elastic, Chronicle).** The roadmap
marks their API paths `[confirm]`, meaning coded from documentation and never
executed. This lab runs LogRhythm. Shipping three adapters that cannot be tested
here reintroduces precisely the `[Unverified]` debt the last two releases spent
their effort removing, and it does it in the component whose entire job is
saying whether something is true. Revisit per adapter, when there is an instance
to run it against.

**F3, Sigma-rule-aware generation** (8 pw). The value is real: emit telemetry
that must trigger a given rule, plus a near-miss that must not. The method is the
problem. It proposes a self-written Sigma subset parser to avoid a runtime
dependency, which trades a dependency for a permanent maintenance liability in a
format that changes underneath you, and the near-miss guarantee is easy to
believe and hard to prove. Not at this cost.

**F7, STIX threat-intel scenario packs** (5.5 pw). It re-orders techniques the
catalog already has, grouped by actor. The plan is honest that the existing T-IDs
make it a data join. That is a presentation feature, not a detection capability,
and it buys nothing a detection engineer could not get by reading the catalog.

**F4, multi-source telemetry** (13 pw). Sysmon, Zeek and CloudTrail. The single
largest cost in the set, and it changes what this project *is*: Replicant is a
firewall and network telemetry generator whose value comes from being narrow and
correct there. Zeek output is a real gap against comparable tools, and it is
still a different product. If any of it is ever revisited, Sysmon alone fills the
biggest ATT&CK tactic gap and ships file-only with no new egress.

**F8 beyond P0.** Cisco ASA and Fortinet raw syslog profiles, and the field
validation kit. Blocked on the same thing as the existing `[Unverified]` markers
on Palo Alto and Check Point: real appliances. Adding two more unverified vendor
profiles makes that debt larger, not smaller.

### Defer

**F6, coverage scorecard and ATT&CK heatmap** (5.5 pw). Wanted, but not yet.
Without real verdicts flowing from F2 it can only redraw what the catalog already
states, and a heatmap that shows coverage nobody observed is the kind of readout
this project removed from the run panel on purpose. Revisit once F2 is producing
verdicts.

## Sequencing, if the adopted set is built

1. The golden-line fix. Independent of everything, and everything below trusts
   the oracle it repairs.
2. **The lab test.** Not part of the roadmap, and it gates the honesty of
   anything F2 reports about delivery.
3. F1's verdict contract and the Fixture/FileLog verifiers.
4. F2, offline tier first.
5. F5.
6. Re-open F6, and re-open the live-SIEM adapters one at a time against real
   instances.

## What this triage does not claim

It is a judgement about fit and cost, not a code review of the eight plans. The
one code claim material to the decision was checked and confirmed; the rest of
their internal detail was read for feasibility, not audited line by line. If a
rejected feature is revived, its plan deserves that audit before anyone starts.
