# Phase 4 review fixes

Post-review remediation on `feature/phase4-scenario-composition` (review of `0b0507c..6fce027`).
Verdict was "merge with fixes": one Critical, three Important. This plan covers the Critical plus
the advisory rewrite and the test gaps that let both through a green suite.

## Findings being fixed

1. **Critical - composed timeline is reversed for SCEN-001.** REP-005 pins events to 00:00-06:00 of
   the *anchor's day* (`_off_hours_start`, engine.py:74), so its `start_offset: 6h` is discarded and
   "bulk exfil" emits ~17h *before* the recon that caused it. Knock-on: the advisory reports a
   ~22.6h span for a chain intended to span ~6h and tells the reader to key a rule on that window.
2. **Important - advisory states falsehoods on mixed chains.** The through-line and correlation
   lines are hard-coded. On SCEN-003 the document lists Exfiltration as a gap and then claims
   "C2 and exfil share dst"; the pinned victim is `src` in only 1 of 4 stages.
3. **Important - stage truncation never reaches the scenario manifest**, unlike `run()` which
   records it. SCEN-002 already composes ~181k events against a 200k cap.
4. **Important - test gaps.** Every scenario test exercises only SCEN-001, and
   `test_events_sorted_by_eventtime` is tautological (sorts, then asserts sorted) so it structurally
   cannot catch finding 1.

## Approach

Explicit per-stage alignment, chosen over a blanket "shift any stage whose events precede its
anchor" rule because REP-008's warm-up baseline *legitimately* emits before its anchor and a blanket
rule would corrupt it. Also chosen over retuning `start_offset` in YAML, which only works for the
current default anchor time-of-day and breaks for others.

## Tasks

- [x] **1. `ScenarioStage.align`** - new optional field, `"anchor"` (default) or `"next-off-hours"`.
      No change to existing scenarios' behavior.
- [x] **2. Composer alignment** - when a stage declares `next-off-hours`, advance its anchor by whole
      days (bounded) until the earliest planned event lands at/after the intended stage start, then
      re-plan with the *same* stage seed. Events are identical except for time, so determinism holds.
- [x] **3. Composer records reality** - `StageResult` gains actual `start_epoch` / `end_epoch`,
      `truncated`, and the dominant `src` / `dst` / `duser` with counts, so downstream consumers
      report observed values instead of assumed ones.
- [x] **4. SCEN-001** - mark the REP-005 exfil stage `align: next-off-hours`.
- [x] **5. Advisory rewrite** - derive the through-line and correlation section from the composed
      events. Emit only claims the data supports, name the real cross-stage key per stage, add an
      actual-window column to the kill-chain table, and gate the C2/exfil line on the chain actually
      covering both tactics.
- [x] **6. Manifest fidelity** - `ScenarioStageRecord` carries the actual window and `truncated`;
      `run_scenario` folds a truncation note in exactly as `run()` does.
- [x] **7. Tests** - replace the tautological ordering test with a real per-stage window assertion;
      parametrize composer and advisory tests over all three scenarios; cover `intensity_override`
      propagation, warm-up note aggregation, and the advisory making no unsupported claim.
- [x] **8. Full gate** - pytest / black / ruff / mypy / webui build, then commit.

## Out of scope (tracked, not done here)

- Engine-level fix so off-hours windows snap forward from the anchor. Would change shipped Phase 2
  REP-005 single-run behavior; deferred.
- Minor review items: double `compose()` in the preview paths, preview using `EntityModel.build()`
  instead of the orchestrator's entities, `KeyError` from `run_scenario` on an unknown id,
  `/tmp/x.log` in a CLI test, theoretical UDP loopback flakiness.
