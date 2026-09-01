# Roadmap: Replicant as a detection validation platform

**Status:** proposed, not started. Authored 2026-08-31 against `main @ af5a9bd` (v0.8.0),
Python suite green at 972 passed / 3 skipped.
**Analysis this executes:** `docs/detection-validation-platform-review.md`.
**Prior decisions it respects:** `docs/10x-roadmap-triage.md`,
`docs/round3-expansion-triage.md`, `docs/security-review-2026-08-response.md`.

The product shift in one line:

> from "generate realistic firewall logs" to "prove that your detection works, and say
> plainly what the proof does not cover."

---

## 1. The three rules this roadmap is built on

Everything below follows from these. If a proposed change violates one, it is out.

**R1. Every milestone ships something usable on its own.** No milestone exists only to
set up the next one. M0 closes a blueprint safety promise. M1 makes the catalog
machine-checkable against its own text. M2 produces the first observed end-to-end
delivery in the project's history. Each is a release someone would want.

**R2. Nothing before M6 needs a SIEM, a licence, or the lab.** The LogRhythm lab test has
never run, and every delivery and timing claim in this project is loopback-only. A
verdict engine built on an unobserved send path cannot distinguish "the detection is
broken" from "the sender is broken", and that ambiguity is the exact thing this product
exists to remove. So the whole offline half comes first, and the lab test is a hard gate,
not a task.

**R3. A guard that has never failed is of unknown value.** Every item below names its
positive control: the specific thing to break, and the specific test that must go red.
Where an item has no runnable positive control, it says so and that is a reason not to
merge it yet.

---

## 2. Milestones at a glance

| # | Milestone | Delivers | Needs a SIEM | [Inference] size | Suggested tag |
|---|---|---|---|---|---|
| **M0** | Identity and controls | run id in telemetry + manifest, `benign_marker` wired, `control` field, `--controls` | no | 2 wk | v0.9.0 |
| **M1** | Contracts and Tier 0 | contract schema, 24 contracts, plan-assertion verdicts, `validate` verb | no | 3 wk | v0.10.0 |
| **M2** | Ingestion truth (Tier 1) | `TelemetrySource`, `FileLogSource`, real send-and-read-back, CI job | no | 2 wk | v0.11.0 |
| **M3** | Evidence | evidence packs, `REPORT.md`, field mapping, `replicant replay` | no | 2 wk | v0.12.0 |
| **M4** | The ten missing foils | REP-001 first, then nine more, `separable_by` enforced | no | 3 to 4 wk | v0.13.0 |
| **M5** | Regression and portability | `validate suite`, CI gate, cross-vendor matrix, boundary controls, web UI | no | 3 wk | v0.14.0 |
| **GATE** | **The LogRhythm lab test** | **not code.** Blocks M6 and nothing else. | yes | n/a | n/a |
| **M6** | Tier 2, LogRhythm only | `DetectionSource`, alert verdicts, latency, safety rule 1 amendment | yes | unknown until the lab exists | v1.0.0 |

**Total before the gate: [Inference] 15 to 16 person-weeks.** Compare 58 to 62 for the
externally proposed roadmap that `10x-roadmap-triage.md` cut to 13.

**If the budget is halved: do M0, M1, M2.** Seven weeks, and at the end of them the
catalog checks itself, a run is traceable, and delivery is observed rather than assumed.
That is the largest honesty gain per week available anywhere in this project.

---

## 3. Dependency graph

```
M0  identity + controls
 |     run_id ------------------+-------------------+
 |     control field -----+     |                   |
 v                        v     v                   v
M1  contracts + Tier 0   M4  foils            M2  Tier 1 ingest
 |        |                    ^                    |
 |        +--------------------+                    |
 v                                                  v
M3  evidence packs  <-------------------------------+
 |
 v
M5  suite + regression + portability + web UI
 |
 +--> [GATE: lab test] --> M6  Tier 2
```

Only two edges are hard:

- **M1 needs `run_id` and `control` from M0.** A contract cannot assert anything about a
  negative control that has no discriminator, and Tier 1 cannot match events back to a
  run that has no identifier.
- **M6 needs the gate.** Nothing else does.

M4 can run in parallel with M2 and M3 by a second person. It is the only item in the set
that is mostly technique design rather than plumbing.

---

## 4. M0: Identity and controls

**Why first:** three defects in the current tree, each small, each blocking everything
else. Full evidence in the review's section 3 (C2, C3, C4, C5).

- Nothing in an emitted CEF line says which run produced it. `run_id` exists only in
  `replicant/web/runner.py:214`, as a uuid the CLI never produces and the manifest never
  records. No validator can ever ask a SIEM about a specific run.
- `Settings.benign_marker` is declared at `replicant/config/settings.py:127` and read
  nowhere. `docs/blueprint.md:58` promises it as a safety affordance. Setting it true
  does nothing and says nothing.
- `benign_baseline` carries three meanings. 13 builders emit a foil; 10 emit nothing and
  carry descriptive prose instead; REP-021 declares itself the baseline. Measured:
  `plan(REP-001, medium, seed 1337)` returns 243 events, one source, one destination, no
  foil at all.

### Work items

- [ ] **M0.1 `run_id` on the request, the manifest, and the result.**
      Files: `replicant/core/models.py:176,204`, `replicant/core/orchestrator.py:347`,
      `replicant/cli/app.py:359`, `replicant/audit/manifest.py:65`.
      Generated once in `Orchestrator.run()` so the CLI, the menu and the web share one.
      Format: `RUN-YYYYMMDDTHHMMSSZ-<6 hex>`, sortable and greppable.
      *Guard:* `run_id` present in every manifest on every exit path, including the error
      path that `attach_run_record` covers.
      *Positive control:* remove the assignment on the failure branch; the error-path test
      must go red.
      *Compatibility:* additive and defaulted, like `pace`, `speed` and `vendor` before it.

- [ ] **M0.2 Name manifests by `run_id`.**
      File: `replicant/audit/manifest.py:41`. Keep the timestamp prefix so listings stay
      chronological; replace the random token with the run id's suffix.
      *Guard:* the manifest filename contains the run id it records.
      *Check before doing it:* grep for anything globbing manifest filenames. [Inference]
      nothing does, because manifests carry their identity inside.

- [ ] **M0.3 Wire `Settings.benign_marker` to a real CEF field.**
      Files: `replicant/config/settings.py:127`, one shared helper used by all three
      profiles rather than 18 template edits.
      Emits a labelled custom string carrying the marker and, when `--mark-run` is on, the
      run id beside it.
      *Guard:* golden lines byte-identical with the marker off; changed with it on.
      *Positive control:* revert the helper and watch the marker-on assertion go red. The
      golden tests already cover the other direction.
      *Compatibility:* off by default. Fidelity stays the default everywhere in this
      project, and this changes the wire format.

- [ ] **M0.4 `control: Literal["positive","negative"]` on `EventRecord`.**
      File: `replicant/core/models.py:53`. Defaulted to `"positive"`, so no builder
      changes behaviour until it is tagged.

- [ ] **M0.5 Tag the foils in the 13 builders that emit one.**
      File: `replicant/scenario/engine.py`. REP-008, 012, 013, 014, 015, 016, 017, 018,
      019, 020, 022, 023, 024.
      *Guard:* for each, `control="negative"` events exist and are a minority, checked
      across 20 seeds, not seed 1337. The REP-013 lesson is that a guard whose seed avoids
      the case has never failed.
      *Positive control:* untag one builder; its parametrized case must go red.

- [ ] **M0.6 Split `benign_baseline` from a new `foil:` block in the catalog.**
      File: `replicant/data/technique-catalog.yaml`, `replicant/core/models.py:93`.
      `benign_baseline` keeps its descriptive meaning for all 24, because it is genuinely
      useful prose for a detection engineer. `foil:` describes what the builder emits and
      is **absent** on the ten that emit nothing.
      *Guard:* `tests/test_foil_declaration.py`, parametrized over all 24 at all 3
      intensities: a `foil:` block is present exactly when the plan contains
      `control="negative"` events.
      *Positive control:* add a `foil:` block to REP-001 and watch it go red.
      **This is the item that turns an invisible ten-entry gap into an enumerable one.**
      It does not close the gap. M4 does.

- [ ] **M0.7 `--controls {both,positive,negative}` on `run`, default `both`.**
      Files: `replicant/cli/app.py:199`, `replicant/core/orchestrator.py:347`.
      *Guard:* `--controls negative` on a foil-bearing technique emits only foil events,
      and that stream fails the assertion the positive stream passes. A negative control
      that would also pass is not a negative control.

- [ ] **M0.8 `--mark-run` flag, and print the run id in the run summary.**
      The id goes in the manifest regardless; the flag only decides whether it reaches the
      wire.

### M0 exit criteria

1. Every run on every surface produces a manifest carrying a `run_id`, on all three exit
   paths (done, stopped, error).
2. `replicant run REP-014 --controls negative --to-file x.log --no-send` writes only foil
   events.
3. Every one of the 24 techniques either declares `foil:` and emits negative-control
   events, or declares neither.
4. Golden lines for all three vendors are byte-identical with default settings.
5. Every guard above has been observed to fail against the unfixed code.

---

## 5. M1: Contracts and Tier 0

**Why second:** the v0.7.0 finding was that **no test asserted that the code does what the
catalog text promises**, and three defects lived in that gap. `test_readme_catalog_sync.py`
closed one edge of it. Tier 0 closes the whole thing, generalised, and hands it to the
operator rather than keeping it in CI.

This milestone needs no SIEM, no collector and no socket. It is pure logic over a plan.

### Work items

- [ ] **M1.1 Contract models, loader, and packaging.**
      New: `replicant/validation/contract.py`. Modify: `replicant/resources.py` to add
      `DETECTION_CONTRACTS`. Contracts live at
      `replicant/data/detection-contracts/REP-NNN.yaml`, **inside the package**, per
      v0.3.1: anything resolving a repository-relative path is a defect.
      *Guard:* `tests/test_packaging.py` extended; contracts present in a built wheel.

- [ ] **M1.2 The contract schema document.**
      New: `docs/detection-contract-reference.md`. Carries the three rules from the
      review's section 7, which are the ones that keep contracts honest:
      1. **A contract restates nothing.** Numbers derive from the technique's own presets.
         A contract that duplicates a preset is a second source of truth that will drift,
         which is exactly why `test_readme_catalog_sync.py` had to exist.
      2. **`emitted` and `detection_expectation` are separate blocks**, because one is
         checkable offline and one needs a SIEM. Collapsing them makes the contract
         unusable in CI, which is where most of its value is.
      3. **`separable_by: []` is an assertion, not a comment.** Given both streams, if any
         single canonical field partitions them cleanly, the check fails and names it.

- [ ] **M1.3 `replicant/core/semantics.py`: declare the `extra` vocabulary.**
      All three profiles read the same ~30 keys out of `EventRecord.extra` (`policyid`,
      `service`, `app`, `trandisp`, `duration`, `sentpkt`, `rcvdpkt`, ...). It is a shared
      canonical vocabulary that is untyped, undocumented, unversioned, FortiOS-named, and
      enforced only by `KeyError` at render time on one event in production.
      *Guard:* every key read by any profile template is declared, and every declared key
      is read by at least one.
      *Positive control:* add an undeclared key to a profile template; watch it go red.

- [ ] **M1.4 Rename `Technique.fortigate` to `Technique.telemetry`, aliased.**
      File: `replicant/core/models.py:93`. Already on the backlog as optional cleanup; it
      becomes load-bearing here because contracts have to name a telemetry class and the
      values are already vendor-neutral. Pydantic `AliasChoices` accepts both for one
      release. **Do it before writing 24 contracts, not after.**

- [ ] **M1.5 `Verdict` and `ValidationResult`.**
      New: `replicant/validation/verdict.py`.
      `Verdict = Literal["pass", "fail_no_alert", "fail_no_events", "inconclusive"]`.
      Four values, adopted in `10x-roadmap-triage.md`. A boolean reproduces the "nothing
      fired and we cannot say why" ambiguity this project exists to remove.

- [ ] **M1.6 The Tier 0 evaluator.** New: `replicant/validation/evaluator.py`. Pure:
      `evaluate(contract, plan) -> ValidationResult`. No I/O.

- [ ] **M1.7 The `validate` verb, and the exit-code contract.**
      File: `replicant/cli/app.py:126`. `10x-roadmap-triage.md` records three separate
      external plans colliding on this verb with conflicting exit codes. Settle it once:

      ```
      replicant validate REP-001 --tier plan
      replicant validate show REP-001          # print the contract, run nothing

      exit 0  all contracts PASS
      exit 1  at least one FAIL
      exit 2  at least one INCONCLUSIVE and no FAIL
      exit 3  usage or configuration error
      ```

      Exit 2 distinct from 1 is what lets CI treat "we could not tell" differently from
      "the detection is broken". Without it, a gate that goes amber gets disabled.
      *Guard:* all four exit codes reached by a test.

- [ ] **M1.8 Contracts for REP-001 and REP-015**, the two flagships. See section 8.

- [ ] **M1.9 Contracts for the remaining 22**, one commit per tactic group. Each declares
      `negative: {present: false, reason: ...}` honestly where no foil exists yet.

### M1 exit criteria

1. `replicant validate REP-NNN --tier plan` returns a verdict for all 24, at all 3
   intensities, across 20 seeds.
2. A parametrized test asserts every contract's numbers match the catalog's presets rather
   than restating them.
3. All four exit codes are reachable and tested.
4. The contract for every entry without a foil says so, rather than asserting a negative
   control that is not there.

---

## 6. M2: Ingestion truth (Tier 1)

**Why this is the highest-value milestone in the set.** Every delivery claim in this
project is loopback-only and unobserved. This is the closest thing to answering that
without a LogRhythm instance: Replicant sends over a real UDP socket, an `rsyslog`
receiver writes to a file, `FileLogSource` reads it back, and the verdict is measured
rather than assumed. **No licence, no lab, no vendor.** And it runs in CI.

It also delivers the brief's "same REP through generic syslog to prove REP behaviour is
independent of a SIEM" for free, because that is literally the same code path with a
different source.

### Work items

- [ ] **M2.1 The source protocols.** New: `replicant/validation/sources/base.py`.
      ```python
      class TelemetrySource(Protocol):
          name: str
          def fetch(self, run_id: str, window: tuple[int, int]) -> Observation: ...

      class DetectionSource(Protocol):
          def alerts(self, run_id: str, window: tuple[int, int]) -> list[Alert]: ...
      ```
      **Split deliberately.** A source may provide telemetry and not detections, and must
      say which. That split is what makes `fail_no_events` distinguishable from
      `fail_no_alert`, which is the entire point of the four-value verdict.
      `Observation` carries what was found, which fields were present, **and what the
      source could not determine.**

- [ ] **M2.2 `FixtureSource`.** Reads a JSON list of events. Offline, deterministic. This
      is what makes the evaluator testable without any socket at all.

- [ ] **M2.3 `FileLogSource` + `docs/rsyslog-receiver.conf`.**
      One documented minimal receiver config in the repo, and only one. Keep the supported
      surface small; an rsyslog config that grows features becomes a second product.

- [ ] **M2.4 Tier 1 in the evaluator, and `validate --tier ingest`.**
      Matches on `run_id`, which is why M0 comes first.

- [ ] **M2.5 A `validate` CI job.**
      File: `.github/workflows/ci.yml`, beside `python`, `frontend`, `shell`, `installer`,
      `systemd-unit`, `wheel`. Sends to a local receiver on an ephemeral port, reads back,
      asserts 100% of events found with all required fields.
      *Guard, and it is the whole job:* drop one event on the receive side; the job must
      go red with `fail_no_events` and a count, not a crash.

- [ ] **M2.6 Verdict disclosure lines.** Every tier states what it does not prove, in the
      output, not in the docs. Tier 0: "does not prove anything reached a collector."
      Tier 1: "proves delivery and parseability; does not prove any rule fired." This is
      the F-08 lesson: a green `verified` shipped against an unreachable collector across
      two lab sessions, and the word is now banned from the codebase. What replaced it is
      disclosure, and every new verdict inherits that obligation.

### M2 exit criteria

1. A CI job performs a real send-and-read-back and asserts on the result.
2. `fail_no_events` is reachable by a deliberately dropped event, and reports a count.
3. Every verdict printed anywhere names its own limits.
4. The word "verified" still appears nowhere in the codebase.

---

## 7. M3: Evidence

The portable artefact. A directory, not a bundle format, written beside the manifest:

```
evidence/RUN-20260831T142212Z-a3f9c1/
  manifest.json     the existing RunManifest, unchanged
  contract.yaml     the contract as evaluated, verbatim
  result.json       verdict vector, latencies, and the rows that did not run
  telemetry.cef     emitted lines, bounded
  telemetry.json    canonical EventRecords, control field included
  mapping.md        canonical -> vendor -> SIEM field table
  REPORT.md         the human-readable pack, generated
  replay.json       seed, params, anchor, version: everything to reproduce
```

### Work items

- [ ] **M3.1 The pack writer.** New: `replicant/evidence/pack.py`.
      **Bounded.** REP-004 at high intensity is 180,000 events. Above 10,000, telemetry is
      written as first / middle / last plus a count and a pointer, **and the pack says it
      truncated.** A pack that silently truncates is worse than one that says so.

- [ ] **M3.2 The mapping table, generated from the profiles.**
      New: `replicant/evidence/mapping.py`. Three columns come free by rendering the same
      event through all three `VendorProfile.render()` paths. **The SIEM column is only
      filled for a SIEM an adapter has actually read from, and is absent otherwise rather
      than guessed.**

- [ ] **M3.3 `REPORT.md`, generated and never authored.**
      Same rule as `replicant/scenario/advisory.py`: every claim derived from what the run
      actually did. **A pack from a run that reached no collector says so in its first
      paragraph**, because that exact situation was invisible for two lab sessions.

- [ ] **M3.4 `replicant replay PATH`.**
      Reads `replay.json`, reconstructs the `RunRequest`. A version mismatch **warns and
      continues** rather than refusing: reproducing a v0.9.0 failure under v0.12.0 is the
      interesting case, not an error.
      *Guard:* replay of a pack reproduces the plan byte for byte.

### M3 exit criteria

1. A pack from a Tier 1 run replays to a byte-identical plan.
2. A no-destination run produces a pack that says so in its first paragraph.
3. An oversize run produces a pack that says it truncated and by how much.
4. No column in `mapping.md` contains a value nobody has observed.

---

## 8. M4: The ten missing foils

The substantive half of C4, and the only milestone that is technique design rather than
plumbing. Can run in parallel with M2 and M3.

Ten entries declare a `benign_baseline` and emit nothing: **REP-001, 002, 003, 004, 005,
006, 007, 009, 010, 011.** They predate the v0.2.0 convention that CLAUDE.md records and
were never brought forward.

### The rule that governs this milestone

**A trivially separable foil is worse than none, because it reports as coverage.** Two of
the three v0.7.0 behavioural defects were exactly that. So an entry stays
`negative: {present: false}` until its foil is genuinely inseparable, and `separable_by`
is the machine check, not a reviewer's judgement.

### Order, and why

1. **REP-001 first.** It is the M1 flagship, so its contract already exists and the foil
   completes it. It is also the hard case done first: the foil its own catalog text
   describes is a benign session **to the same destination** with far fewer records and
   much higher bytes and duration, which cannot be separated by peer identity. If the
   flagship's foil is easy, the mechanism has not been tested.
2. REP-010, 002, 003, 007: counts and rates are presets, the foils are the
   well-understood "sparse benign version of the same thing" shape, and they set up
   M5.4's boundary controls on the same entries.
3. REP-004, 005, 006, 009: volume and cardinality foils.
4. **REP-011 last, and it may not close.** Geovelocity has no obvious benign counterpart
   that is not just "a user who does not travel". If no inseparable foil exists, it stays
   `present: false` with a reason, and that is an honest outcome rather than a failure.

*Fallback for M1:* if REP-001's foil proves too hard, **REP-012 (jittered C2) becomes the
flagship**. Same tactic, a foil that already exists at `engine.py:1365`, a plan already
spanning two destinations. The cost is that jitter makes the periodicity assertion
fuzzier, which is a worse first contract but a working one. Decide this at M1.8, not at M4.

### M4 exit criteria

1. Every one of the 24 either has a foil whose `separable_by` check passes, or declares
   `present: false` with a stated reason.
2. Each foil was checked across 20 seeds and 3 intensities.
3. `separable_by` was observed to fail: reintroduce the v0.7.0 REP-014 duration defect in
   a scratch branch and watch the check name `duration`. **If it does not, the check is
   testing nothing and M4 does not merge.**

---

## 9. M5: Regression and portability

Where Replicant stops being a tool you drive and becomes a gate that fails a build.

- [ ] **M5.1 `validate suite`.** Runs a named set of contracts, reports a verdict matrix,
      exits per M1.7. Note `sending_lock()` makes suites serial by construction, which is
      correct and bounds runtime.
- [ ] **M5.2 CI regression gate.** Extends the M2.5 job. *Positive control:* corrupt one
      contract's expected periodicity; the build must go red naming that contract.
- [ ] **M5.3 Cross-vendor portability verdicts.** A loop over `VENDORS` once M1 and M2
      exist. **[Inference] the strongest single differentiator in the whole roadmap**: a
      rule written against FortiGate field names silently failing on PAN-OS is one of the
      most common real detection-engineering failures, nothing tests it, and Replicant is
      one of very few tools that could, because the same behaviour already renders three
      ways from one plan. Must carry the `[Unverified]` caveat on Palo Alto and Check
      Point field names.
- [ ] **M5.4 Boundary controls, where they are honest.**
      **The test:** a boundary block is honest only when **the axis the detection
      thresholds on is a Replicant preset.** Not "the technique has a numeric preset";
      most do. The axis has to be the same one.

      Clearly honest: REP-002 (`unique_ports`/`window_s`), REP-003
      (`unique_hosts`/`window_s`), REP-007 (`users`/`attempts_each`/`window_min`),
      REP-010 (`denies`/`window_s`), REP-021 (`unique_src`/`aggressive_probes`). A scan
      or burst rule thresholds on exactly those counts.

      Clearly not: REP-020, where the rule thresholds on **domain age** and Replicant does
      not model age at all; and REP-008, where novelty is a function of **the SIEM's own
      observation history**, not of anything in the plan. `novel_domains: 3` looks like a
      threshold and is not the rule's threshold.

      Borderline, and decided per technique inside M5.4 rather than here: REP-011, whose
      `window_min` is arguably the travel-velocity axis, and REP-016, whose `label_len`
      is arguably the entropy axis. **Default to no block when it is arguable.**

      A `boundary` block on a technique that cannot express one is decoration, and this
      project dropped the v0.3.0 vendor filter for exactly that reason: a control whose
      output cannot change is decoration.
- [ ] **M5.5 Web UI surfaces.** Contract in `TechniqueDetail.tsx`; normalized-field table
      beside the CEF sample lines in the preview; a validation result panel showing the
      verdict vector with `NOT RUN` visibly distinct from `PASS`. New `/api/validate`
      mirroring the CLI, per the standing one-orchestrator rule.
      **Not** a validation history dashboard yet: without verdicts flowing it can only
      list runs, which the manifest directory already is.

---

## 10. The gate, and M6

**GATE: run the LogRhythm lab test.** It is `tasks/uat-plan.md` Suite H, authored at r3 on
2026-07-29 and never executed. It is the oldest open item in the project and it predates
v0.1.0. It is not an engineering task and it cannot be worked around.

**M6 is one adapter: LogRhythm.** Sizing is unknown until an instance exists, and any
figure given now would be the thing this project keeps deleting.

Explicitly **not** in M6: Exabeam, Splunk, Sentinel, Elastic, QRadar, Chronicle,
OpenSearch, Wazuh. `10x-roadmap-triage.md` rejected the equivalent proposal and the
reasoning is unchanged: an adapter coded from documentation and never executed
reintroduces exactly the `[Unverified]` debt v0.7.0 and v0.8.0 spent their effort removing,
and it does it **in the component whose entire job is saying whether something is true.**
A `SiemSource` returning `fail_no_events` because its query syntax is subtly wrong is
worse than no adapter, because it reports as a detection failure.

One adapter per instance somebody can actually run it against. The protocol in M2.1 exists
precisely so the second one is cheap.

M6 also carries the **safety rule 1 amendment**, and it ships in the same commit as the
adapter, not after:

> The only network egress is to operator-configured endpoints: the collector for emitted
> telemetry, and, when a validation run explicitly requests it, the validation endpoint.
> Both are configured by the operator; neither is discovered, defaulted, or inferred. With
> no validation endpoint configured, validation runs offline and reports `inconclusive`
> rather than reaching anywhere.

Files: `CLAUDE.md`, `docs/blueprint.md`, `README.md`.

---

## 11. Risk register

| # | Risk | Mitigation | Owner milestone |
|---|---|---|---|
| **K1** | Contracts drift from the catalog, recreating the README/catalog divergence v0.7.0 had to fix | Contracts derive numbers, never restate them. Parametrized all-24 test. | M1 |
| **K2** | A weak foil written to close the M4 gap reports as coverage | `separable_by` is a machine check with a positive control. An entry stays `present: false` rather than getting a bad foil. | M4 |
| **K3** | The run marker changes the wire format and breaks a lab parser | Off by default. Golden lines are the guard in both directions. | M0 |
| **K4** | `rsyslog` config becomes a supported surface that grows | Exactly one minimal config in the repo, documented as the only supported one. | M2 |
| **K5** | Scope creep into multi-telemetry (Sysmon, Zeek, CloudTrail) | Rejected in `10x-roadmap-triage.md` at 13 pw as a change to what the project is. `telemetry.class` and the `(log_type, subtype)` dispatch key keep the door open. **Leave the door open, do not walk through it.** | all |
| **K6** | Tier 2 gets built before the lab test to unblock a demo | R2. The gate is a gate. A verdict from an unobserved send path is the failure mode this product exists to prevent. | M6 |
| **K7** | An aggregate "validation score" gets added because it demos well | Rejected: five of six rows in the proposed example need a live SIEM, and a single percentage is a weighting choice presented as a measurement. The verdict vector with visible `NOT RUN` rows replaces it. | M5 |
| **K8** | 24 contracts get written before the `Technique.fortigate` rename | M1.4 is ordered before M1.8 for this reason. | M1 |

---

## 12. What is deliberately not in this roadmap

Each of these was considered and declined, with the reason, so that reviving one is a
decision rather than a drift.

| Item | Why not |
|---|---|
| Exabeam and the other six SIEM adapters | Section 10. No instance to run them against. |
| Multi-source telemetry (DNS, proxy, EDR, NDR, Windows, cloud) | K5. 13 pw, and it changes what the project is. The architecture does not prevent it. |
| Coverage matrices and ATT&CK heatmaps | Deferred in `10x-roadmap-triage.md` (F6) until real verdicts exist. A heatmap of coverage nobody observed is the readout class this project removed from the run panel on purpose. |
| An aggregate validation score | K7. |
| Sigma rule generation | Rejected (F3), and it collides with the standing constraint that Replicant does not author detection logic. |
| STIX threat-intel scenario packs | Rejected (F7). A data join over T-IDs the catalog already has. |
| Cisco ASA and Fortinet raw-syslog profiles | Blocked on the same thing as the existing `[Unverified]` markers: real appliances. Two more unverified profiles makes that debt larger. |
| A seven-step validation wizard in the web UI | The current run panel is one screen with every control visible. Seven page loads for a 30-second task is worse. What was missing is the *content* of the preview, not the steps. |
| Validation history dashboard | M5.5. Nothing to have a history of until verdicts flow. |
| Renaming `src`/`dst`/`spt`/`dpt` to `src_ip`/`dst_ip`/... | They are the CEF key names, they are what the golden lines contain, and they are what a detection engineer reads. Renaming costs the suite and buys a prettier JSON. Friendly aliases belong in the evidence pack's mapping table, where the reader is. |

---

## 13. Definition of done for the roadmap as a whole

At the end of M5, before the gate, a detection engineer **with no SIEM licence** can:

1. Select a behaviour from the catalog and read its objective.  ✅ today
2. Read the detection hypothesis.  M1
3. Select a firewall telemetry profile.  ✅ today
4. Select a destination or run dry.  ✅ today
5. Preview the exact synthetic events.  ✅ today
6. See the expected normalized fields.  M3 / M5.5
7. Send them safely.  ✅ today
8. **Confirm the telemetry arrived.**  M2
9. Determine whether the detection fired.  **M6, gated**
10. Run a negative control.  M0 / M4
11. Identify potential false positives.  M1
12. Tune the detection.  **M6, gated**
13. Repeat the validation.  M5
14. Export a complete evidence pack.  M3
15. Reproduce the test later.  M3

**Thirteen of fifteen, with zero live-SIEM dependency.** The two that are gated are the two
that genuinely need a SIEM, and they are behind the lab test rather than behind more code.

---

## 14. Immediate next step

M0.1: `run_id` on `RunRequest`, `RunManifest` and `RunResult`, generated in
`Orchestrator.run()`, printed by the CLI, present on all three exit paths. One commit, one
guard, one positive control on the error path.

It is a day of work and it unblocks the other fifteen weeks.
