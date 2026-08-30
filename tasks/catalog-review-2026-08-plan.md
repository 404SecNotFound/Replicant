# Catalog review 2026-08: triage and phased plan

**Reviewed artefact:** `replicant-catalog-review.md` + `replicant-catalog-review.patch`, an
external review of the technique catalog written against `main @ 815f951` (v0.5.2).
**Our tree:** `main @ ec27996` (v0.6.0 tagged, v0.6.1 pending). **Triaged:** 2026-08-30.

The review's own claims were not taken on trust. Every defect below was re-derived from the
current source, and the patch was applied to a throwaway worktree of our `main` and measured.
What follows separates what is verified from what is a judgment call.

---

## 1. Verdict

**The review is sound and its patch is worth taking.** Three behavioral defects are real and
matter more than ordinary bugs: in each case the emitted telemetry contradicts the catalog text
that a detection engineer reads before trusting it. Two ATT&CK mappings are wrong in ways that
would mislead. The minor findings are all genuine. Nothing in the patch was found to be wrong.

Measured on our tree, not quoted from the report:

| Measurement | Result |
|---|---|
| Patch applies to `main @ ec27996` | Clean on all 10 files. `CHANGELOG.md` is the only conflict, because we are two releases past the review's base. |
| Full suite, patch applied | **966 passed**, 54s. Matches the review's claim exactly. |
| Positive control (source fixes reverted, new tests kept) | **12 failed, 954 passed.** The guards catch what they claim to catch. |
| Golden CEF lines | Untouched. No vendor golden test appears in either the pass or fail set as changed. |

## 2. Two things the review did not say

Both found by the positive control, and both go in the plan.

1. **Two of the fourteen new tests are guards of unknown value.**
   `test_rep013_benign_servers_never_overlap_infected_sources` and
   `test_readme_table_covers_every_catalog_entry` both pass against the *unfixed* source. The
   REP-013 one is the problem: it is sold as the guard for finding 14 (benign baseline servers
   colliding with worm seed hosts at the high preset) and it does not fail on the code that has
   the collision. Either it does not reach the colliding preset/seed, or the collision is not
   reachable at all and finding 14 is theoretical. **This must be resolved before merge**, per
   the standing rule that a guard which has never failed is of unknown value. The README-coverage
   one is a companion assertion rather than a defect guard, and is fine as it stands.

2. **Fixing REP-002 makes `replicant run REP-002 --intensity low` take 120 seconds, not ~6.**
   That is the correct behaviour (the preset declares a 120s window and the plan must fill it),
   but it is a user-visible slowdown on a demo path, and it is why the patch had to rewrite
   `tests/test_plan_pacing.py` to override `window_s` down to 5s. Honest handling, correctly
   commented, but it belongs in the release note rather than being discovered by an operator.

Also worth recording: I initially read the REP-024 foil as emitting its outbound leg *before*
its own inbound leg. It does not. `when` already carries the +3 pair offset, so the foil's lag
is a fixed +1s, exactly as the review describes.

## 3. Triage

Severity is the review's; the verdict column is ours, from the current source.

### Behavioral defects — the tool's core claim

| # | Issue | Verdict | Evidence on our tree |
|---|---|---|---|
| 1 | REP-024 relay lag constant at 1s for every preset | **Valid, major** | `engine.py:2485`, `max(1, int(rng.integers(lag_lo, lag_hi + 1)) // 1000)`. Shipped `lag_ms` ranges are sub-second to 1500ms, so the floor-divide yields 0 or 1 and the clamp makes it 1. The technique exists to defeat fixed-window timing correlation and was emitting the fixed window. |
| 2 | REP-002 ignores `window_s` and `--duration` | **Valid, major** | `_plan_vertical_scan` (`engine.py:434`) reads `unique_ports` and `gap_ms` only. The catalog declares `window_s` 120/60/30 per preset. The `duration_override_s` parameter is accepted and never referenced, so `--duration 1h` returns a byte-identical plan. |
| 3 | REP-014 benign foil is trivially separable on duration | **Valid, major** | Foil spacing is `share_interval_s * 4` over `min(12, shares)` steps (`engine.py:1531`), while the miner session reaches 43,200s at the high preset. A duration threshold alone scores perfectly, which is precisely what the foil exists to deny. |

### ATT&CK mappings

| # | Issue | Verdict |
|---|---|---|
| 4 | REP-007 maps T1110.004 Credential Stuffing | **Valid, major.** Catalog carries `T1110, T1110.003, T1110.004`. Credential Stuffing means replaying breached credential pairs; the builder models one user against many attempts, which is T1110.001. |
| 5 | REP-012 maps T1029 Scheduled Transfer | **Valid, major.** Catalog carries `T1071, T1029` under `TA0011` alone. T1029 is an Exfiltration (TA0010) technique on an entry with no exfiltration behaviour and no TA0010 in its own tactic list. |
| 6 | Tactic lists unsupported by their own techniques | **Valid, minor.** Confirmed all three: REP-009 lists TA0043 while carrying T1190 (Initial Access); REP-017 lists TA0005 with only C2 techniques; REP-018 lists TA0006 while carrying T1021/T1078/T1550, none of which MITRE assigns to Credential Access. |
| 7 | README shows bare `T1110` for REP-007 | **Valid, minor.** Confirmed at `README.md:198`; REP-012's row already matches. The review's claim that this is the *only* ID drift across 24 rows is consistent with what the new sync test finds. |

### Robustness and consistency

| # | Issue | Verdict |
|---|---|---|
| 8 | Engine docstring says REP-016 has no builder | **Valid, trivial.** `engine.py:22`; the builder is registered at line 303. |
| 9 | `jittered_interval` unbounded above 100% | **Valid, minor — but not operator-reachable.** `distributions.py:58` has no clamp. Correction to the review's framing: `param_overrides` reaches the engine only from scenario-catalog stages and programmatic callers. The CLI exposes no `--param` and the web `RunBody` does not carry it, so this is defensive hardening, not validation at a trust boundary. |
| 10 | DNS labels can exceed the 63-octet limit | **Valid, minor.** Same reachability caveat as #9. |
| 11 | REP-016 benign trickle runs past the plan window | **Valid, minor.** `anchor + index * max(epoch_s // 2, 1)` over 12 items against a window of `epochs * epoch_s`. |
| 12 | Catalog text drifted from code in six places | **Accepted, not independently re-verified line by line.** Spot checks held. Documentation-only. |
| 13 | `business_hours_weight` is dead code | **Valid** (`distributions.py:113`, no builder calls it), **but the deletion collides with a live backlog item.** `tasks/todo.md` lists "off-hours/business-hours weighting beyond REP-005" as one of four open items, and this helper is its starting point. Four lines, trivially re-addable — delete it, but strike the backlog line in the same change so the two do not contradict each other. `docs/blueprint.md:112,214` also reference it; the review flags this and leaves it, which is right for a historical design doc. |
| 14 | REP-013 benign servers can collide with worm seeds | **Unproven.** See §2.1. The fix is harmless; its guard does not demonstrate the bug. |
| 15 | Test gaps let 1-3, 6, 9, 10 survive 952 tests | **Valid, and the most important finding in the review.** No test asserted that the code does what the catalog text promises. That is the class of defect this project is least able to catch, and the sync test plus the distribution-honouring tests are the structural fix. |

---

## 4. The plan

### Phase 0 — ship v0.6.1 unchanged (in flight, do not fold this work in)

The v0.6.1 release note is already written and covers only the web UI diagram fix. Its version
bump is sitting in the working tree and the suite is green at 952. Cutting it first keeps a
UI-only patch release honest and keeps the catalog work out of a tag that does not describe it.

- Version bump (`pyproject.toml:8`, `replicant/__init__.py:20`), CHANGELOG heading + link ref,
  `.gitignore` entry for `re-fresh-*.md`. **All four edits are already made locally.**
- PR, merge, tag `v0.6.1`, then build the wheel from a clean clone of the tag and smoke-test it
  in an empty venv outside the repo.
- README screenshots do not need regenerating: they show REP-001 and REP-004, whose diagrams
  did not change.

### Phase 1 — behavioral defects and their guards (PR 1 of 2)

Findings 1, 2, 3, 14, plus the fourteen new tests and the `test_plan_pacing.py` accommodation.
This is the phase that restores the tool's central claim, so it goes first and alone.

1. Apply the patch's `engine.py`, `distributions.py`, and `tests/` hunks.
2. **Resolve the REP-013 guard before merge.** Either find the preset/seed where the collision
   actually occurs and make the test fail against unfixed code, or downgrade finding 14 to a
   documented defensive change and say in the commit that the guard is a property assertion, not
   a regression test. Do not merge a guard that silently proves nothing.
3. Re-run the positive control after any edit to the tests: revert the source fixes, confirm red,
   restore.
4. Record in the release note that REP-002 low now occupies its full 120s window, and that plans
   for REP-002, REP-013, REP-014, REP-016 and REP-024 differ from every prior release at the same
   seed. Determinism is preserved; the output is not the same output.

**Acceptance:** 966 green, positive control red on every new guard, no golden CEF line changed,
`black`/`ruff`/`mypy replicant` clean.

### Phase 2 — mappings, catalog text, README sync (PR 2 of 2)

Findings 4-8, 12, 13, and the two README/catalog sync tests. Separated from Phase 1 because it
carries different risk (nothing here changes emitted telemetry) and deserves different attention
(every line is a factual claim about MITRE or about our own code).

1. Apply the `technique-catalog.yaml`, `README.md`, and `tests/test_readme_catalog_sync.py` hunks.
2. Strike the off-hours weighting item from `tasks/todo.md` alongside deleting
   `business_hours_weight`, or keep both. Not one without the other.
3. Leave the historical `CHANGELOG.md` 0.1.0 table and `docs/blueprint.md` alone, as the review
   recommends. Release history is not a living document.

**Acceptance:** the sync test fails when a README ATT&CK cell is edited away from the YAML
(positive control), and passes on the corrected tree.

### Phase 3 — release

Cut **v0.7.0**, not v0.6.2. Under 0.x the minor bump is the signal available for "the telemetry
this emits has changed shape"; five techniques now plan differently at the same seed, and anyone
who tuned a rule against REP-002's six-second scan needs to see that in the version, not in a
patch-level note.

### Phase 4 — the round-4 research document (decision, then docs-only)

The patch also carries `docs/technique-catalog-expansion-research-round4.md`: 655 lines proposing
REP-042 through REP-051, in the established house format, each anchored to a published detector,
each requiring no new render path. The IDs do not collide with round 3's REP-025..041.

Merging the document commits nothing to code, and the repo already keeps round 1, 2 and 3
research docs as a decision record. **Recommendation: take it as a separate docs-only PR after
Phase 3**, on the same terms as round 3 — research recorded, implementation not scheduled.

### Not scheduled

- **Implementing REP-042..051, or round 3's adopted REP-025..041.** Round 3 has been triaged and
  unimplemented since v0.5.2. Adding a fourth research round ahead of it would grow the backlog,
  not the catalog. Whether the catalog grows at all is a product decision that belongs with the
  Impact/Initial-Access coverage argument, not with a defect fix.
- **The benign-background generator**, which the review names as the single largest structural
  gap (no way to measure false positives against a whole-network baseline). Correct diagnosis,
  and much larger than anything in this plan.
- **Zeek/packet-layer output, paired detection rules, TLS-fingerprint techniques.** Rejected in
  the review for reasons that match positions this repo already holds.

---

## 5. Decisions needed

1. **REP-018's tactic list.** The review proposes TA0008 alone. Defensible, and TA0006 is
   certainly wrong. But T1078 and T1550 both carry TA0005 Defense Evasion, so `TA0008 + TA0005`
   is equally honest and keeps more of the entry's meaning. Either is fine; pick one.
2. **REP-002's 120-second low preset.** Correct per the catalog, twenty times slower than what
   ships today. Accept, or shorten the declared window instead of the plan.
3. **Round-4 doc: merge as a record, or hold.** Recommendation above is merge.
4. **Unchanged and still yours:** F-08 (the eps cap is per-process) and F-14 (the remaining npm
   advisories need vite 8 + vitest 4, which drop the Node 18 floor `scripts/install.sh`
   declares). `docs/security-review-2026-08-response.md`.
