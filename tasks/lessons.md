# Lessons

Patterns worth not repeating. Append after any correction or review finding.

---

## A test that cannot fail is worse than no test

**2026-07-20, Phase 4 review.** `test_events_sorted_by_eventtime` did this:

```python
times = [e.eventtime for e in plan.events]
assert times == sorted(times)
```

`compose()` sorts by `eventtime` immediately before returning, so the assertion was true by construction and could never fail. It read like timeline coverage while verifying nothing, and it sat directly on top of a Critical bug: SCEN-001 emitted bulk exfil roughly 17 hours *before* the recon that precedes it.

**Rule:** before writing an assertion, ask what production change would make it fail. If the answer is "none", it is decoration. Assert the *semantic* property (stage k begins at or after `anchor + offset_k`), not the property the code just finished enforcing.

**Corollary:** when fixing a bug, prove the new test fails against the old behaviour. Here that meant composing the scenario both ways in memory and showing the pre-fix window (`07-15 00:00`) sits below the intended start.

---

## Parametrize over the whole catalog, not the convenient entry

**2026-07-20, Phase 4 review.** Every scenario test exercised SCEN-001 only. SCEN-001 happens to be the one chain where the hard-coded advisory text was accidentally true (all stages host-based; the chain really does contain both C2 and exfil). SCEN-003 exposed the advisory listing Exfiltration as a gap and then asserting "C2 and exfil share dst" four lines later, plus a "victim threads the chain" claim that held in 1 of 4 stages.

**Rule:** when a data file drives behaviour, parametrize across every entry in it (`ALL_SCENARIOS = [s.id for s in SCEN.scenarios]`), not one hand-picked example. Cache the composition if the larger entries are expensive; determinism makes that safe.

---

## Do not infer a rule where the domain needs an explicit flag

**2026-07-20, Phase 4.** The tempting fix for the timeline bug was generic: "shift any stage whose events start before its anchor." That would have corrupted REP-008, whose warm-up baseline is *supposed* to precede its anchor. Two behaviours that look identical to a heuristic had opposite intent.

**Rule:** when two cases are indistinguishable from the data but differ in intent, make the caller declare it (`align: "next-off-hours"`) instead of guessing. An opt-in flag that changes nothing by default cannot regress existing behaviour.

---

## Documenting a limitation in a test comment does not count

**2026-07-20, Phase 4 review.** The off-hours anchoring quirk was accurately described in a comment inside `test_scenario_composer.py`, and the test deliberately routed around it. The knowledge never reached the design spec, the composer, the advisory, or the catalog, so the shipped flagship scenario still tripped over it and the operator-facing advisory printed a span derived from the bug.

**Rule:** a caveat that only exists where tests are read is invisible to the operator. Put it where the consequence lands: the spec, the emitted artifact, and the data file that triggers it.
