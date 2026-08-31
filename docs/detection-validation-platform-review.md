# Replicant as a detection validation platform: architecture review and roadmap

Reviewed against `main` at `af5a9bd` (v0.8.0) on 2026-08-31. Read for this review: the
Python package (10,786 lines across 34 modules), the 24-entry technique catalog, the
3-entry scenario catalog, the FastAPI surface, and the React UI's data layer and
component list. The React components were read for structure, not audited. The
Python test suite was installed and run at the start of this review: **972 passed, 3
skipped**, so every claim below is made against a green tree. The frontend suite was not
run (no `node_modules` in this container) and nothing below depends on it.

**Nothing here is implemented.** This is a decision document in the same family as
`10x-roadmap-triage.md`, `round3-expansion-triage.md` and
`security-review-2026-08-response.md`. Adopting any of it is a separate call about where
the project's effort goes.

## 0. Three corrections to the brief, before anything else

These change what the work is, so they come first.

**0.1 REP-015 is not periodic beaconing.** The brief nominates REP-015 as the flagship
reference and sketches its contract as "Detect periodic outbound beaconing, periodicity
60s, tolerance 10s". REP-015 is **low-throughput DNS exfiltration**
(`replicant/data/technique-catalog.yaml:454`). Its whole point is that the query rate is
normal and cardinality is the only thing left to key on, and its presets run 24 to 72
simulated hours. The technique the brief actually describes is REP-001 (periodic C2
callback, `interval_s` + `jitter_pct`) or REP-012 (jittered C2). This is not a quibble:
a 48-hour contract is the single hardest first target for a live validation loop, and a
60-second one is the easiest. Section 13 resolves it by splitting the flagship role.

**0.2 REP-028 does not exist.** The catalog is REP-001 through REP-024, 24 entries. The
regression example in the brief names REP-028 and REP-021; only the latter is real.

**0.3 Most of this brief has already been triaged, and some of it was rejected on
evidence.** `docs/10x-roadmap-triage.md` (2026-08-30, one day before this review)
assessed a near-identical proposal. It **adopted** the four-value verdict contract and
offline verifiers plus CI regression, **rejected** live SIEM adapters coded from
documentation, **rejected** multi-source telemetry, and **deferred** the coverage
scorecard. Re-proposing the rejected items without new evidence is not a reason to
re-open them. Sections 14 and 15 say which parts of this brief are genuinely new (the
detection contract as a per-REP artefact, boundary controls, evidence packs, replay) and
which are a repeat.

---

## 1. Current architecture assessment

The pipeline the brief asks for in section 11 is, near enough, the pipeline that already
ships:

```
Technique (YAML catalog)
   -> ScenarioEngine.plan()          pure, seeded, no I/O      replicant/scenario/engine.py:319
   -> list[EventRecord]              vendor-neutral            replicant/core/models.py:53
   -> VendorProfile.render()         3 implementations         replicant/profiles/base.py:38
   -> to_cef(header, extension)      escaping oracle           replicant/cef/serializer.py:49
   -> SyslogEmitter.send() | FileSink.write()                  replicant/transport/syslog.py:728
```

Orchestrated by `Orchestrator.run()` (`replicant/core/orchestrator.py:347`), which is the
single entry point for the CLI (`replicant/cli/app.py:359`), the Rich menu, and the web
API (`replicant/web/server.py:861`). The "no behavior lives only in the TUI" rule in
CLAUDE.md holds: I could not find a code path reachable from one surface and not the
others.

Layers, and how cleanly they separate:

| Layer | Module | Separation |
|---|---|---|
| Behaviour | `data/technique-catalog.yaml` + 24 builders in `engine.py` | Clean. Pure and seeded. |
| Canonical telemetry | `EventRecord` | **Partial. See 1.2.** |
| Vendor representation | `profiles/{fortigate,paloalto,checkpoint}.py` | Clean, oracle-backed. |
| Serialization | `cef/serializer.py` | Clean. 3 functions, no state. |
| Transport | `transport/{syslog,filesink}.py` | Clean. |
| Detection platform | **absent** | The brief's real gap. |
| Validation | **absent** | The brief's real gap. |

### 1.1 What is already right, and load-bearing

The determinism boundary is real. `ScenarioEngine` does no I/O, takes a seed, and
`(seed, technique, params, anchor)` fixes the plan byte for byte. `compress_timeline`
and `send_offsets` (`replicant/core/pacing.py:77,111`) keep the pacing arithmetic pure
and out of the emit loop, which does only the waiting. This is exactly the property a
validation platform needs and most log generators do not have.

The golden-line oracle is the correctness story. Eight `[Constructed]` reference lines
per vendor, byte-compared. It was proving seven eighths of what it claimed until
2026-08-30; it now compares all eight.

The manifest already covers most of the brief's section 15 (reproducibility): seed,
params, entities, target, transport, vendor, anchor, pace, speed, duration, rate,
`send_stats`, status, error (`replicant/core/models.py:204`). It is written on every exit
path including the ones that raise.

### 1.2 The canonical event model already exists, and is undeclared

`EventRecord` is the canonical schema the brief asks for in section 11. Every field in
the brief's proposed JSON except `rep_id` and `run_id` is already there, typed.

The problem is `extra: dict[str, str]`. It is not vendor-specific scratch space; all
three profiles read the **same keys** from it:

- `policyid`, `service`, `app`, `trandisp`, `duration`, `sentpkt`, `rcvdpkt`
  are read by `fortigate.py:155`, `paloalto.py:126` and `checkpoint.py:164` alike.
- Check Point turns `trandisp == "snat"` into `sourceTranslatedAddress`
  (`checkpoint.py:180`); FortiGate turns it into `FTNTFGTtrandisp`.

So a shared canonical vocabulary exists, and it is:

- **untyped** (`dict[str, str]`, pre-stringified),
- **undocumented** (no schema, no list, no test that a key means one thing),
- **unversioned** (nothing to migrate against),
- **named after one vendor** (`policyid` and `trandisp` are FortiOS words), and
- **enforced only by `KeyError`**, at render time, on one event, in production.

That is the single largest structural constraint on everything the brief wants. A
detection contract that says "required_fields: [src_ip, dst_port, action]" has nothing
to check those names against.

### 1.3 The dispatch key is vendor-neutral and vendor-named

`VendorProfile.render()` dispatches on `(event.log_type, event.subtype)`, six pairs:
`traffic:forward`, `dns:dns-query`, `dns:dns-response`, `utm:ips`, `event:vpn`,
`event:system` (`fortigate.py:99`). All three vendors implement the same six. The values
are neutral; the catalog field that carries them is `Technique.fortigate`
(`models.py:98`), a `FortigateBinding`. Renaming it is already on the backlog
(`tasks/backlog-and-recommendations.md`, "Actually open"). It becomes load-bearing the
moment a contract or an adapter has to name a telemetry class.

---

## 2. Current strengths (KEEP, unchanged)

1. **KEEP: the determinism contract.** Pure engine, seeded RNG, no I/O. Everything the
   brief calls "reproducibility" is downstream of this and already paid for.
2. **KEEP: the golden-line oracle** and the `[Constructed]` licensing position in
   `docs/prior-art-and-licensing.md` section 3.
3. **KEEP: the five safety rules**, including the fail-closed send
   (`orchestrator.py:353`) and the host-scoped `flock` (`core/sendlock.py:76`). The brief's
   section 16 asks for a safety model Replicant already has and enforces.
4. **KEEP: the manifest-on-every-exit-path discipline**, including
   `attach_run_record` so a failure still surfaces its partial record.
5. **KEEP: the one-orchestrator rule.** It is what makes `replicant validate` possible as
   one implementation rather than three.
6. **KEEP: `benign_baseline` as a thing builders generate**, not just document. This is
   the negative-control primitive, already half built. See 6.
7. **KEEP: the disclosure-over-assertion stance.** The word "verified" was removed from
   the codebase because a green `verified` shipped against an unreachable collector for
   two lab sessions. Every verdict this brief proposes has to clear that bar.
8. **KEEP: `PathReport`** (`transport/syslog.py:323`). It prints source beside
   destination rather than claiming reachability. It is the correct model for a
   validation verdict, at a smaller scale.
9. **KEEP: the pacing model.** `--pace plan` with `--anchor now` sends an event at the
   moment its own timestamp says it happened. A beacon contract with a 60s periodicity
   assertion is only meaningful because this exists.

---

## 3. Technical constraints

Ranked by how much they bound the work.

**C1. The LogRhythm lab test has never run.** Every delivery and timing claim in this
project is loopback-only, and has been since v0.1.0. Sections 4, 7 and 13 of the brief
all ask Replicant to query a SIEM and report PASS or FAIL about telemetry it sent. Built
on an unobserved send path, a `FAIL` is indistinguishable from a bug in the sender, and
the tool's whole proposition is that its verdicts mean something. **This gates the live
half of everything below and is not itself an engineering task.**

**C2. There is no run identifier in the emitted telemetry, and none in the manifest.**
`run_id` exists only inside `replicant/web/runner.py:214`, as a uuid4 the CLI never
produces and the manifest never records. Manifests are named by timestamp plus a random
token (`audit/manifest.py:41`), so there is no stable handle. A validator cannot ask a
SIEM "did *this run's* events arrive" because nothing in the CEF says which run it was.
**This is the hard blocker for the entire validation loop**, and it is small.

**C3. `Settings.benign_marker` is declared and never read.** One hit in the whole tree
(`config/settings.py:127`). `docs/blueprint.md:58` promises it as a safety affordance:
"a config switch can stamp a benign marker field so lab data is separable from
production if the collector is shared". An operator who sets it true gets no marker and
no error. This is the same class as every defect the last three releases found: locally
true, contextually false, silent. It is also exactly the field C2 needs.

**C4. `benign_baseline` means two different things, and nothing says which.** All 24
techniques declare a `benign_baseline`. Counted per builder over the actual method
bodies, the field splits three ways:

- **13 builders emit one**: REP-008, 012, 013, 014, 015, 016, 017, 018, 019, 020, 022,
  023, 024. Here `benign_baseline` describes events the plan contains.
- **10 emit nothing**: REP-001, 002, 003, 004, 005, 006, 007, 009, 010, 011, the Phase 1
  and Phase 2 originals. Here `benign_baseline` is descriptive prose about production
  normality ("browsing to same dst shows fewer records, far higher out/in and duration";
  "IPS hit rate is low and steady per segment"), and the builder produces none of it.
  REP-006 references `entities.benign_external`, but only to concatenate it into a
  destination pool, which is not a foil.
- **1 is a deliberate third case**: REP-021 says the technique *is* the baseline and is
  meant to be run alongside REP-002 and REP-003.

Measured, not inferred. `ScenarioEngine.plan(REP-001, medium, seed 1337)` returns **243
events, one source, one destination**. There is no foil in it, so any detection scores
perfectly against it. REP-015 at the same seed returns 576 events also across one source
and one destination, and its foil is a second DNS *parent* rather than a second peer,
which is why a check cruder than a `control` field would misclassify it too.

This is one field carrying three meanings with no discriminator in the schema, no type
distinction and no test, and the second group directly contradicts the convention
CLAUDE.md records for v0.2.0: "`benign_baseline` is a property to **generate**, not just
document. A plan that emits only the malicious pattern lets any detection score
perfectly." Ten entries predate that convention and were never brought forward, and
nothing in the catalog, the models or the suite says so.

**C5. Negative controls, where they exist, are not addressable.** The foils are appended
into the same `events` list as the pattern, with no field on `EventRecord` marking which
is which. So the negative control **cannot be emitted alone**, and a validator receiving
events back from a SIEM **cannot tell which ones were the foil**. Together with C4, both
halves of the brief's section 6 are blocked, and a contract that asserted
`negative: {present: true}` would be simply false for ten entries with nothing in the
catalog to warn you.

**C6. `extra` has no schema.** See 1.2.

**C7. There is no read path anywhere in the codebase.** Safety rule 1 says the only
network egress is the operator-configured collector. A SIEM query adapter is a second
egress destination. This is not a reason to refuse it, but it is a rule change and has
to be written as one, not slipped in. See 8.3.

**C8. Two of three vendor references are `[Unverified]`.** Palo Alto and Check Point
field names are constructed from documentation. A validation verdict that depends on a
field name nobody has confirmed against an appliance inherits that uncertainty and
should say so.

**C9. `eventtime` is integer epoch seconds.** One second is the finest interval a plan
can express. A boundary test on a sub-second threshold is not expressible.

**C10. Single sending run per host, enforced.** `sending_lock()` refuses a second sending
run. A validation *suite* that runs five REPs is therefore serial by construction. That
is correct, and it bounds suite runtime: five REP-015 runs at `--pace plan` is 240
simulated hours.

---

## 4. Proposed target architecture

Six layers. The first four exist. Two are new.

```
  Behaviour        technique-catalog.yaml + engine builders          KEEP
       |
  Contract         detection-contracts/REP-NNN.yaml                  ADD
       |           (what must be true for this to count as validated)
       v
  Canonical        EventRecord + a declared `semantics` vocabulary   MODIFY
       |           + run_id + control ("positive" | "negative")
       v
  Vendor           VendorProfile.render()                            KEEP
       |
  Serialization    to_cef()                                          KEEP
       |
  Egress           SyslogEmitter | FileSink                          KEEP
       |
       v
  Ingress          TelemetrySource: read events back                 ADD
       |           file | fixture | (later) a real SIEM
       v
  Verdict          Validator: contract x observed -> Verdict         ADD
       |
  Evidence         EvidencePack: manifest + contract + verdict       ADD
```

Two boundaries do the work.

**The contract boundary.** A contract is data, not code, and it never names a SIEM. It
says what the telemetry must contain and what the detection must do. Adapters translate
it. This is what stops the brief's section 3 fear (tying to one SIEM) from happening in
the file where it would be hardest to undo.

**The `TelemetrySource` boundary.** Everything that reads events back is behind one
interface with three implementations at P0/P1, of which only one talks to a SIEM:

- `FixtureSource` reads a JSON list of events. Offline, deterministic, no I/O beyond a
  file. This is what makes the validator testable at all.
- `FileLogSource` reads the syslog file an `rsyslog` receiver wrote. **Offline, no
  licence, and it is a real end-to-end path**: Replicant sends over UDP, rsyslog
  receives and writes, the source reads back. It proves ingestion for real without a
  SIEM. This is the highest-value single component in the whole roadmap.
- `SiemSource` (P1, one implementation, LogRhythm, gated on C1).

**What must NOT be added:** a `Detection` or `Rule` object that Replicant authors. The
project's standing constraint is that Replicant presents coverage and correlation
context and the human authors the rule (`scenario/advisory.py:35`). A contract states an
*expectation about a detection*; it does not contain detection logic. Keep that line.

---

## 5. Canonical event model

**MODIFY `EventRecord`. Do not add a parallel model.**

Adding a second canonical type beside `EventRecord` would give the project two, and the
one the engine emits would win. Three additive fields, all defaulted, no existing
builder touched:

```python
class EventRecord(BaseModel):
    # ... 14 existing fields unchanged ...

    #: Which emitted stream this event belongs to. "positive" is the technique's
    #: own pattern; "negative" is the benign_baseline foil. Today the two are
    #: interleaved with nothing to tell them apart (C4), which makes the foil
    #: impossible to emit alone and impossible to identify after ingestion.
    control: Literal["positive", "negative"] = "positive"

    #: Stable per-run correlation id, stamped into the CEF when a marker is on.
    #: Nothing in the emitted telemetry currently says which run produced it (C2).
    run_id: str | None = None

    #: Already-declared semantic values. Same dict, given a name and a schema.
    extra: dict[str, str] = Field(default_factory=dict)
```

Field names: the brief proposes `src_ip` / `dst_port`. **Do not rename.** `src`, `dst`,
`spt`, `dpt` are the CEF key names, they are what the golden lines contain, and they are
what a detection engineer reading a CEF line sees. Renaming buys a prettier JSON and
costs the whole test suite. If a friendlier alias set is wanted, generate it in the
evidence pack's mapping table (section 10), which is where the reader is.

**ADD: a declared `extra` vocabulary.** One module, `replicant/core/semantics.py`, with
the ~30 keys the three profiles actually read, each with a one-line meaning and the
render paths that consume it. Guarded by a test that walks every profile's `render`
templates and asserts every key read is declared, and every declared key is read by at
least one. That test would have caught the `benign_marker` class of defect. Cheap, and it
turns 1.2 from a latent constraint into a documented interface.

**Schema versioning.** `Catalog.version` already exists. Add `semantics_version` to the
same file and record it in the manifest. Contracts declare the version they were written
against. A contract written against v1 loaded under v2 warns rather than silently
matching nothing.

---

## 6. REP schema evolution

`Technique` (`models.py:93`) already carries most of what the brief's section 9 asks for:
`objective`, `attack`, `cef_fields_held`, `cef_fields_varied`, `distributions`,
`benign_baseline`, `references`, `safety_notes`, plus per-intensity `params`. The gaps
are specific.

| Brief asks for | Status | Action |
|---|---|---|
| threat description | `name` + `objective` | KEEP |
| ATT&CK mapping | `attack` | KEEP |
| detection hypothesis | **absent**, implied by `ndr_rule`/`ndr_uc` | ADD, in the contract not the catalog |
| telemetry requirements | `cef_fields_held`/`varied` | MODIFY: these say what varies, not what a rule needs |
| generated telemetry | the builder | KEEP |
| vendor variations | 3 profiles | KEEP |
| expected normalized fields | **absent** | ADD, derivable from 5 |
| detection logic | out of scope by standing constraint | do NOT add |
| positive test | the builder | KEEP |
| negative test | `benign_baseline`, generated by 16 of 24 and unaddressable in all of them (C4, C5) | MODIFY |
| boundary test | **absent** | ADD, and only where honest. See below. |
| false-positive analysis | partly in `benign_baseline` prose | ADD |
| tuning recommendations | **absent** | ADD |
| validation criteria | **absent** | ADD, the contract |
| known limitations | `safety_notes`, partly | MODIFY |

**Two changes in the catalog and the builders, and they are not the same size.**

*The mechanical one:* every builder that already appends a foil tags those records
`control="negative"`. Then `--controls {both,positive,negative}` becomes possible and a
validator can partition what it received. Small and well-tested.

*The substantive one:* the ten entries from C4 need a foil written, or their
`benign_baseline` field renamed to say what it actually is. Both are defensible; what is
not defensible is leaving one field meaning two things. Recommended: **split the field.**
`benign_baseline` keeps its descriptive meaning for all 24 (it is genuinely useful prose
for a detection engineer), and a new `foil:` block describes what the builder emits, is
absent when nothing is emitted, and is checked by a parametrized test asserting the block
is present exactly when `control="negative"` events are. That turns an invisible
ten-entry gap into a visible, enumerable one, which is the precondition for closing it
rather than the closure itself.

Writing ten foils is real work and it is not free: REP-011 (geovelocity) in particular
has no obvious benign counterpart that is not just "a user who does not travel". Do the
split first, close the gap technique by technique, and let the contract for an entry
without a foil say `negative: {present: false, reason: ...}` honestly in the meantime.

**Boundary tests: add them only where a threshold is a parameter Replicant controls.**
The brief's example (9 connections vs 10 vs 20) is honest for REP-010 (denied burst),
REP-003 (horizontal sweep), REP-002 (vertical scan), REP-007 (spray) and REP-021
(inbound scan), where a count or a rate is literally a preset key. It is **not** honest
for REP-011 (geovelocity) or REP-020 (newly registered domain), where the threshold lives
in the detection's own logic and Replicant cannot know it. A `boundary` block on a
technique that cannot express one is decoration, and this project has a rule about
controls whose output cannot change: the v0.3.0 vendor filter was dropped for exactly
that. **Boundary is opt-in per technique, and a technique without one says so.**

---

## 7. Detection contract design

One file per REP under `replicant/data/detection-contracts/`, shipped in the package
(`resources.py` is the only thing that knows where; anything resolving a
repository-relative path is a defect, per v0.3.1).

```yaml
contract_version: 1
semantics_version: 1
rep: REP-001
objective: >-
  Prove the beacon rule fires on a fixed-interval callback and is not
  defeated by the benign periodic update-check running beside it.

# What the telemetry must carry for the detection to be possible at all.
# Names come from replicant/core/semantics.py, never from a vendor or a SIEM.
telemetry:
  class: traffic:forward          # the render-path key, already vendor-neutral
  required_fields: [src, dst, dpt, proto, act, eventtime, out_bytes]
  vendors: [fortigate, paloalto, checkpoint]

# Assertions about the emitted stream. Checked OFFLINE against the plan, every
# run, with no SIEM. This is the half that works today.
emitted:
  positive:
    min_events: 20
    periodicity_s: {value: 60, tolerance_s: 6}   # from params, not restated
    distinct_dst: 1
  negative:
    present: true
    separable_by: []              # empty means: no single field separates the
                                  # foil from the pattern. A non-empty list here
                                  # is a defect report, not a feature.

# What the detection is expected to do. Replicant does NOT author the rule.
detection_expectation:
  hypothesis: >-
    A rule keying on repeated same-src/same-dst sessions at a low-variance
    interval over a 30 minute window.
  positive: {should_alert: true, within_s: 900}
  negative: {should_alert: false}
  boundary:
    - {param: interval_s, value: 300, should_alert: [unknown]}  # [Unverified]

false_positives:
  - "software update checks on a fixed cadence to a CDN"
  - "monitoring agents with a fixed poll interval"
limitations:
  - "synthetic telemetry proves the rule matches these fields; it does not prove
     the rule survives production volume or a different firewall's field set"
  - "Palo Alto and Check Point field names are [Unverified] against real appliances"
```

Three design decisions worth defending.

**The contract restates nothing.** `periodicity_s` is derived from the technique's own
`params.medium.interval_s`, not typed again. A contract that duplicates a preset is a
second source of truth that will drift, and this project has a test
(`test_readme_catalog_sync.py`) that exists because exactly that happened between the
README and the catalog. A parametrized test asserts every contract's numbers match the
catalog's, for all 24 entries, per the `--duration` lesson: a flag that works on most
entries is worse than one that works on none.

**`emitted` and `detection_expectation` are separate blocks, because one works today and
one needs a SIEM.** Collapsing them produces a contract that can never be fully evaluated
offline, which means it can never be evaluated in CI, which is where its value is.

**`separable_by: []` is an assertion, not a comment.** The v0.7.0 lesson was that two of
three behavioural defects were foils a detection could separate for free, and that a
trivially separable foil is worse than none because it reports as coverage. This makes
that checkable: given both streams, if any single canonical field partitions them
cleanly, the check fails and names the field.

---

## 8. SIEM adapter design

### 8.1 The interface

```python
class TelemetrySource(Protocol):
    """Reads emitted events back. The only component that talks to a SIEM."""
    name: str
    def fetch(self, run_id: str, window: tuple[int, int]) -> Observation: ...

class DetectionSource(Protocol):
    """Asks whether a named detection fired for a run. Optional; a source may
    provide telemetry and not detections, and must say which."""
    def alerts(self, run_id: str, window: tuple[int, int]) -> list[Alert]: ...
```

`Observation` carries the events found, the fields present per event, and **what the
source could not determine**. Splitting `TelemetrySource` from `DetectionSource` is what
makes `fail_no_events` distinguishable from `fail_no_alert`, which is the whole point of
the four-value verdict.

### 8.2 Which adapters to build

| Adapter | Reads telemetry | Reads alerts | Recommendation |
|---|---|---|---|
| `FixtureSource` | yes | yes | **ADD, P0.** Offline. Makes the validator testable. |
| `FileLogSource` (rsyslog) | yes | no | **ADD, P0.** Offline, no licence, real socket path. |
| `LogRhythmSource` | yes | yes | **ADD, P1, after C1.** The lab that exists. |
| Generic Syslog | n/a | n/a | Already shipped. It is `CollectorProfile` with any host. |
| `ExabeamSource` | yes | yes | **REJECT for now.** See 8.4. |
| Splunk / Sentinel / Elastic / QRadar / Chronicle / OpenSearch / Wazuh | | | **REJECT for now.** Same reason. |

### 8.3 The safety-rule change, written as one

A `TelemetrySource` that queries a SIEM is a second egress destination, and safety rule 1
currently says there is exactly one. The honest change:

> The only network egress is to operator-configured endpoints: the collector for
> emitted telemetry, and, when a validation run explicitly requests it, the
> validation endpoint. Both are configured by the operator; neither is discovered,
> defaulted, or inferred. With no validation endpoint configured, validation runs
> offline and reports `inconclusive` rather than reaching anywhere.

`--validate` therefore requires an explicitly configured validation endpoint, exactly as
sending requires an explicitly configured collector, and fails closed the same way. Add
it to the safety rules in CLAUDE.md, the blueprint and the README **in the same commit
as the first adapter**, not after.

### 8.4 Why not Exabeam, Splunk, Sentinel, and the rest

The brief names Exabeam New-Scale as a P0 target output. `10x-roadmap-triage.md` already
rejected the equivalent proposal, and the reasoning holds without modification: an
adapter coded from documentation and never executed reintroduces the `[Unverified]` debt
that v0.7.0 and v0.8.0 spent their effort removing, and it does it **in the component
whose entire job is saying whether something is true**. A `SiemSource` that returns
`fail_no_events` because its query syntax is subtly wrong is worse than no adapter,
because it reports as a detection failure.

This is not a permanent no. It is: one adapter per instance somebody can actually run it
against, and the abstraction in 8.1 exists precisely so the second one is cheap. Build
the boundary now, build one implementation, and let the count grow with the lab access.

As an output *destination*, Exabeam needs nothing new: it accepts syslog, and
`CollectorProfile` already points anywhere. What it does not have is a *read* path, and
that is the part that cannot be honestly built from a PDF.

---

## 9. Validation engine design

```python
Verdict = Literal["pass", "fail_no_alert", "fail_no_events", "inconclusive"]
```

Four values, adopted in `10x-roadmap-triage.md` and correct. A boolean reproduces the
"nothing fired and we cannot say why" ambiguity the project exists to remove.

The engine is a pure function, which is what lets it be tested without a SIEM:

```python
def evaluate(contract: Contract, plan: ScenarioPlan,
             observed: Observation | None, alerts: list[Alert] | None) -> ValidationResult
```

It runs in three tiers, and **each tier states what it does not prove**, per the F-08
lesson that a verdict must disclose its own limits:

**Tier 0, plan checks. No I/O, no collector, works today.** Contract `emitted` block
against the built plan. Does the technique produce what it claims: the event count, the
periodicity, the cardinality, the foil's presence and inseparability. Proves the
generator honours its own catalog text. **Does not prove anything reached a collector.**

Tier 0 alone is worth building even if no other tier ever ships. The v0.7.0 finding was
that *no test asserted the code does what the catalog text promises*, and three defects
sat in that gap. Tier 0 is that test, generalised and made the operator's, not just CI's.

**Tier 1, ingestion checks. Real socket, no SIEM.** Send to an rsyslog receiver writing
to a file, read the file back through `FileLogSource`, match on `run_id`. Verdicts:
`pass` (all events found, all required fields present), `fail_no_events`, or
`inconclusive` with the count found. **Proves delivery and parseability. Does not prove
any rule fired.**

**Tier 2, detection checks. Requires a SIEM. Gated on C1.** Adds `DetectionSource`.
`pass` requires: events found, required fields present, the positive control alerted
within `within_s`, and the negative control did not. Detection latency is
`alert_time - last_positive_event_time`, reported only when both timestamps come from
the same clock, and `inconclusive` otherwise. **Does not prove the rule survives
production volume, a different vendor's field set, or a tuned threshold.**

**Rejecting the aggregate score (brief section 7).** The brief's own example prints
"Validation Score: 83%" over six rows of which five require a live SIEM. Two standing
rules apply. `docs/webui-factory-design.md`: no readout renders that the stream cannot
measure. And the brief itself: "do not create an arbitrary vanity score". A single
percentage is not observable; it is a weighting choice presented as a measurement, and
83% invites comparison between two REPs whose rows mean different things.

**What to render instead: the verdict vector, with the unrun rows named as unrun.**

```
REP-001  Periodic C2 callback           fortigate -> lab-lr-01
  Plan assertions      PASS    5/5      periodicity 60s +/-6s, foil inseparable
  Ingestion            PASS    240/240  events found, 8/8 required fields
  Positive control     PASS             alert 7.2s after last event
  Negative control     PASS             no alert
  Boundary             NOT RUN          contract declares none for REP-001
  RESULT: PASS (tier 2)
  Does not prove: production volume, non-FortiGate field sets, threshold correctness
```

Six rows and a verdict, every row observable, `NOT RUN` visibly different from `PASS`.
That is more useful to a detection engineer than any number, and it cannot be gamed by
reweighting.

---

## 10. Evidence pack design

A directory, not a bundle format, written next to the manifest:

```
evidence/REP-001-20260831T142212Z-a3f9/
  manifest.json          the existing RunManifest, unchanged, + run_id
  contract.yaml          the contract as evaluated, copied verbatim
  result.json            the ValidationResult: verdict vector, latencies, unrun rows
  telemetry.cef          the emitted lines (bounded; see below)
  telemetry.json         the canonical EventRecords, control field included
  mapping.md             canonical -> vendor -> SIEM field table
  REPORT.md              the human-readable pack, generated from the above
  replay.json            everything needed to reproduce: seed, params, anchor, version
```

Decisions:

**Generated, never authored.** Same rule as `scenario/advisory.py`: every claim derived
from what the run actually did, nothing assumed. A pack from a run that reached no
collector says so in the first paragraph, because the F-08 lesson is that this exact
situation was invisible for two lab sessions.

**Bounded.** REP-004 at high intensity is 180,000 events. Full telemetry above a
threshold (10,000) is written as first/middle/last plus a count and a pointer to the
`--to-file` path, and the pack says which it did. A pack that silently truncates is
worse than one that says it truncated.

**The mapping table is generated from the profiles, not typed.** Three columns come free:
canonical name, and what each of the three `VendorProfile.render()` paths emitted for it.
The SIEM column is only filled in for a SIEM an adapter has actually read from, and is
absent otherwise rather than guessed. The brief's example table has a LogRhythm and an
Exabeam column; the Exabeam one would be a guess today, so it does not render.

**`replay.json` and section 15.** `replicant replay <path-to-pack>` reads `replay.json`
and reconstructs the `RunRequest`. It needs C2 (a run id) and one thing more: a
`replicant_version` compatibility check that **warns and continues** rather than
refusing, because reproducing a v0.8.0 failure under v0.9.0 is the interesting case.

---

## 11. Proposed CLI evolution

**KEEP every existing verb and flag.** `list`, `connect`, `run`, `scenario`, `menu`,
`web` and all their options keep working with identical behaviour and identical output.
Backward compatibility here is cheap and the catalog IDs are a public interface.

**ADD one verb, `validate`, with three subcommands.** `10x-roadmap-triage.md` records
that three separate plans collided on this verb with conflicting exit codes, so fix the
exit codes once, here:

```
replicant validate REP-001 --vendor fortigate --tier plan
replicant validate REP-001 --vendor fortigate --tier ingest --collector lab
replicant validate REP-001 --vendor fortigate --tier detect --to logrhythm
replicant validate suite --contracts REP-001,REP-004,REP-015 --tier plan
replicant validate show REP-001            # print the contract, run nothing

exit 0  all contracts PASS
exit 1  at least one FAIL (no_alert or no_events)
exit 2  at least one INCONCLUSIVE and no FAIL
exit 3  usage or configuration error
```

Exit 2 distinct from 1 is what lets CI treat "we could not tell" differently from "the
detection is broken", which is the difference between a useful gate and one people
disable.

**ADD three flags to `run`,** all defaulted to today's behaviour:

- `--controls {both,positive,negative}`, default `both`. Needs the `control` field (6).
- `--mark-run`, stamps `run_id` into the CEF. Off by default: it changes the wire
  format, and fidelity is the default everywhere else in this project.
- `--evidence PATH`, writes a pack. Implies nothing about sending.

**ADD `replicant replay PATH`.** Section 10.

**MODIFY `run` output: print the run id.** It goes in the manifest regardless of
`--mark-run`; the flag only controls whether it reaches the wire.

**REMOVE nothing.** I found no CLI surface that has stopped earning its place.

---

## 12. Proposed UI workflow

The brief proposes replacing "select scenario, generate logs" with a seven-step wizard.
**MODIFY rather than replace**, for a specific reason: the current run panel is one
screen where every control is visible at once, and that is a real property. A seven-step
wizard makes a 30-second task into seven page loads, and steps 3 and 4 (telemetry
profile, destination) are already single selects on the existing form.

What is genuinely missing from the current UI is not the steps. It is that **step 5,
preview, shows three CEF lines and nothing else** (`/api/catalog/{id}/sample`,
`server.py:659`), and step 7, validate, does not exist.

Recommended shape, in priority order:

1. **MODIFY the detail panel: add the contract.** Detection hypothesis, required fields,
   controls, false positives, limitations. This is `TechniqueDetail.tsx` gaining a
   section, and it answers the brief's UX question 1 ("what behaviour am I testing?")
   properly for the first time. No new endpoint beyond `/api/catalog/{id}/contract`.
2. **MODIFY the preview: add the normalized-field table** beside the CEF lines.
   Canonical name, value, and what each vendor calls it. Answers UX question 2. The data
   is already computed; only the render is missing.
3. **ADD a validation result panel.** The verdict vector from 9, `NOT RUN` rows visibly
   distinct. Answers UX question 3.
4. **ADD `/api/validate` mirroring the CLI.** One orchestrator, per the standing rule.

**Do NOT add a validation history dashboard yet.** The brief lists it under P1. Without
tier 2 verdicts flowing it can only show a list of runs, which the manifest directory
already is. Same call `10x-roadmap-triage.md` made on the coverage heatmap.

**Terminology (brief section 17): adopt it.** "Validation", "hypothesis", "positive
control", "negative control", "expected", "observed", "evidence". Cheap, and it is the
vocabulary the target user already has.

---

## 13. REP-015 reference implementation plan

**Split the flagship role**, because of 0.1.

**REP-001 (periodic C2 callback) is the first contract, and it is also the first foil to
write.** `interval_s` and `jitter_pct` are presets, so periodicity is a numeric assertion
the contract can state and Tier 0 can check. The medium preset is 243 events over about
four hours of event time, so a `--pace plan --anchor now --speed 60` live run finishes in
four minutes. It exercises `traffic:forward`, the most-used render path, and boundary
tests are expressible by varying `interval_s`.

**It has no negative control today** (C4: 243 events, one source, one destination,
measured). So the flagship does double duty: it is where the contract mechanism gets
built *and* the first of the ten missing foils. The foil to write is the one its own
catalog text already describes, a benign session to the same destination with far fewer
records and much higher bytes and duration. That is a genuinely hard foil precisely
because it shares the destination, which is the right difficulty for a reference
implementation. If it proves too hard to make inseparable, **REP-012 (jittered C2) is the
fallback**: same tactic, a foil that already exists (`engine.py:1365`, a benign periodic
destination at a fixed 1800s cadence), and a plan spanning two destinations already. The
cost of the fallback is that jitter makes the periodicity assertion fuzzier, which is a
worse first contract but a working one.

**REP-015 is the flagship evidence pack and the honesty demonstration.** It is the
harder and more interesting case, and the pack is where that shows:

- Its detection hypothesis cannot key on rate, by construction. The contract has to say
  cardinality, which is a genuinely different assertion from REP-001's and proves the
  contract schema is not overfitted to one shape.
- Its foil has matched total query volume and low unique-label cardinality
  (`engine.py:1630`), so `separable_by: []` is a real claim about a real foil.
- Its 24 to 72 simulated hours force the pack to be honest about what a compressed run
  proves. A `--speed 60` REP-015 run delivers 48 hours of event times in 48 minutes, and
  a rule with a 24-hour window will see it; a rule keyed on wall-clock arrival will not.
  **That distinction belongs in the limitations section of the pack**, and REP-015 is the
  entry that forces it to be written.
- Its parents are `.invalid`, so the demonstration is safe to run anywhere.

**The generic-syslog leg** the brief asks for (same REP through a non-SIEM output, to
prove REP behaviour is platform-independent) is Tier 1 with `FileLogSource` against
rsyslog. It is not an extra demo; it is the same code path with a different
`TelemetrySource`, which is the point being demonstrated.

Sequence: contract schema and Tier 0 on REP-001. Then REP-015's contract, which is the
schema's first real stress test. Then Tier 1 on both. Then the pack. Then, after C1,
Tier 2 on REP-001 only.

---

## 14. Top ten innovations

Scored against the brief's own instruction not to propose things because they sound
advanced. Ranked by value per unit of effort. Effort is [Inference] from the code I read.

**1. A run id in the telemetry and the manifest (C2, C3).**
*Problem:* nothing in an emitted CEF line says which run produced it, so no validator can
ever ask a SIEM about a specific run, and `replicant replay` has nothing to key on.
*Value:* unblocks the entire validation loop. Also closes a blueprint safety promise that
has been a dead config field since v0.1.0.
*Approach:* stamp `run_id` on `EventRecord`; wire `Settings.benign_marker` to a CEF
custom-string label; add `run_id` to `RunManifest`; generate it in `Orchestrator.run()`
so the CLI and the web share one.
*Difficulty:* small (2 to 3 days). *Dependencies:* none. *Risk:* changes the wire format
when enabled, so it is off by default and golden lines are untouched. *Priority:* **P0,
first.**

**2. Tier 0 plan assertions against the contract.**
*Problem:* v0.7.0's finding was that no test asserted the code does what the catalog text
promises, and three defects lived in that gap. It is still true for anything added since.
*Value:* every technique gets a machine-checkable statement of its own claims, offline,
in CI, with no SIEM and no licence. Differentiates from every synthetic log generator,
none of which can tell you their output is wrong.
*Difficulty:* medium (2 weeks including 24 contracts). *Dependencies:* contract schema.
*Risk:* contracts drifting from presets, mitigated by deriving rather than restating.
*Priority:* **P0.**

**3. Addressable negative controls, and the ten missing foils (C4, C5).**
*Problem:* two problems wearing one field. Foils that exist are unaddressable, so you
cannot emit one alone or identify it after ingestion. And ten entries declare a
baseline they never emit, which the catalog does not reveal, so a run of REP-001 today
produces 243 events of pure signal against which any detection scores perfectly.
*Value:* makes the brief's section 6 possible, makes `separable_by` checkable (the check
that would have caught two of the three v0.7.0 behavioural defects), and closes a
convention gap the project has asserted since v0.2.0 but never enforced.
*Approach:* `control` field and tagging first (about a week, 13 builders). Then split
`benign_baseline` from a new `foil:` block with a parametrized presence test (a few days).
Then the ten foils, one at a time, each its own commit and its own guard.
*Difficulty:* small for the mechanism, medium for the ten foils (3 to 4 weeks total).
*Dependencies:* the `control` field. *Risk:* writing a weak foil to close a gap. A
trivially separable foil reports as coverage and is worse than none, so an entry stays
`present: false` until its foil is genuinely inseparable.
*Priority:* **P0 for the mechanism, P1 for the ten foils.**

**4. `FileLogSource` and Tier 1 ingestion verdicts.**
*Problem:* every delivery claim in this project is loopback-only and unmeasured (C1).
*Value:* a real, observed, end-to-end send-and-read-back path, with **no SIEM licence
and no lab dependency**. It is the closest thing to answering C1 that can be built
without a LogRhythm instance, and it is the tier CI can run.
*Difficulty:* medium (1.5 weeks). *Dependencies:* 1. *Risk:* rsyslog config becomes a
supported surface; keep it to one documented minimal receiver config in the repo.
*Priority:* **P0.**

**5. Evidence packs.**
*Problem:* the output of a validation is currently a manifest, a log file and whatever
the operator remembers. Nothing portable, nothing a consultant can hand to a client, and
nothing that states its own limits.
*Value:* this is the genuinely novel item in the brief. BAS platforms produce dashboards;
detection testing frameworks produce pass/fail. A pack that carries the telemetry, the
contract, the verdict, the field mapping **and an explicit "does not prove" section** is
something none of the comparison classes ship.
*Difficulty:* medium (1.5 to 2 weeks). *Dependencies:* 1, 2. *Priority:* **P0.**

**6. Detection regression in CI (`validate suite`).**
*Problem:* a SIEM rule edit can silently stop detecting, and nothing notices until an
incident.
*Value:* changes what Replicant is for: from a generator you drive by hand to a gate that
fails a build. Already adopted in `10x-roadmap-triage.md` (F2, 4.5 pw).
*Difficulty:* medium (3 weeks). *Dependencies:* 2, 4. *Priority:* **P1.**

**7. Boundary controls on the techniques that can express one.**
*Problem:* validation proves a rule fires on an obvious case, which is the case least
likely to be broken.
*Value:* tests the threshold, not the rule's existence. This is the difference between
validating ingestion and validating detection logic, and it is the brief's sharpest idea.
*Difficulty:* medium (1.5 weeks for the 5 techniques where it is honest).
*Dependencies:* 2, 3. *Risk:* the temptation to add boundary blocks to techniques that
cannot express one. *Priority:* **P1.**

**8. `replicant replay`.**
*Problem:* a failed validation cannot be reproduced exactly by someone who was not there.
*Value:* the reproducibility half of the brief's definition of done. Mostly already paid
for by the determinism contract; the missing pieces are an id and a serialised request.
*Difficulty:* small (4 to 5 days). *Dependencies:* 1, 5. *Priority:* **P1.**

**9. One live SIEM adapter, LogRhythm, after the lab test.**
*Problem:* Tier 2 does not exist without one.
*Value:* the first verdict about a real detection. *Difficulty:* medium and
unpredictable until an instance exists. *Dependencies:* **C1, hard.** *Risk:* high, and
entirely in the "coded from documentation" failure mode if built before the lab runs.
*Priority:* **P1, blocked.**

**10. Cross-vendor portability verdicts.**
*Problem:* a rule written against FortiGate field names silently fails on PAN-OS. This is
one of the most common real detection-engineering failures and nothing tests it.
*Value:* run one contract against all three profiles and report per-vendor. Replicant is
one of very few tools that could, because the same behaviour already renders three ways
from one plan. **[Inference]** this is the strongest single differentiator in the list
against BAS platforms, which emulate on one endpoint agent and have no vendor axis.
*Difficulty:* small once 2 and 4 exist, because it is a loop over `VENDORS`.
*Dependencies:* 2, 4, and honesty about C8. *Priority:* **P1, cheap.**

**Explicitly not in the list, and why:**

- *Multi-telemetry (DNS/proxy/EDR/Zeek/Sysmon).* Rejected in `10x-roadmap-triage.md`
  (F4, 13 pw) as the largest cost in the set and a change to what the project is. The
  brief's section 12 asks only that the architecture not prevent it, and the architecture
  in section 4 does not: `telemetry.class` in the contract and the `(log_type, subtype)`
  dispatch key are already the extension point. **Leave the door open, do not walk
  through it.**
- *Coverage matrices and ATT&CK heatmaps.* Deferred in `10x-roadmap-triage.md` (F6) until
  real verdicts exist, and that reasoning is unchanged: a heatmap of coverage nobody
  observed is the readout class this project removed from the run panel on purpose.
- *An aggregate validation score.* Section 9.
- *Sigma generation.* Rejected (F3), and it collides with the standing constraint that
  Replicant does not author detection logic.

---

## 15. P0 / P1 / P2 roadmap

**P0, foundation. Everything offline, no SIEM, no licence, no lab.** [Inference] 7 to 9
person-weeks.

1. Run id + wire `benign_marker` (innovation 1). Unblocks everything.
2. `control` field + tag the 13 foils that exist; split `benign_baseline` prose from a
   new `foil:` block so the ten-entry gap becomes enumerable (innovation 3).
3. `replicant/core/semantics.py`: declare the `extra` vocabulary, guard it (section 5).
4. Contract schema + loader + `validate show` (section 7).
5. Contracts for REP-001 and REP-015 (section 13).
6. Tier 0 evaluator + `validate --tier plan` (innovation 2).
7. `FixtureSource` + `FileLogSource` + Tier 1 (innovation 4).
8. Evidence packs + `REPORT.md` (innovation 5).
9. Contracts for the remaining 22 techniques, each honestly declaring
   `negative: {present: false}` where no foil exists yet.
10. Rename `Technique.fortigate` to `Technique.telemetry` with a back-compatible alias
    (already on the backlog; it becomes load-bearing here).

**P1, validation engine.** [Inference] 6 to 8 person-weeks, plus a blocked item.

11. `replicant replay` (innovation 8).
12. The ten missing foils, one commit each, REP-001 first (innovation 3, second half).
13. Boundary controls on the 5 techniques that can express one (innovation 7).
14. Cross-vendor portability verdicts (innovation 10).
15. `validate suite` + CI regression + exit-code contract (innovation 6).
16. Web UI: contract in the detail panel, normalized-field table in the preview,
    validation result panel (section 12).
17. **The LogRhythm lab test.** Not an engineering task. Gates 18.
18. `LogRhythmSource` + Tier 2 + the safety-rule amendment (innovation 9, section 8.3).

**P2, strategic.** Do not schedule. Re-open when P1 is producing verdicts.

19. Validation history, once there are verdicts to have a history of.
20. Coverage matrices, per the F6 deferral.
21. A second live SIEM adapter, per instance, per lab access.
22. Multi-telemetry, only if the project decides it wants to be a different product.

**The sequencing rule:** P0 delivers a complete, useful, honest product on its own. A
detection engineer with no SIEM licence can, at the end of P0, state a hypothesis, check
that the generator honours it, send it through a real socket, confirm it arrived and
parsed, run the negative control, and export a pack that says what it did not prove.
That is 13 of the brief's 15 definition-of-done items, with zero live-SIEM dependency.
Items 9 and 12 ("did the expected detection fire", "tune the detection") are the only
two that need P1, and they are the two gated on C1.

---

## 16. Files and modules requiring modification

| File | Change | Tag |
|---|---|---|
| `replicant/core/models.py:53` | `EventRecord`: `control`, `run_id`. Defaulted, additive. | MODIFY |
| `replicant/core/models.py:93` | `Technique`: rename `fortigate` -> `telemetry`, aliased. | MODIFY |
| `replicant/core/models.py:204` | `RunManifest`: `run_id`, `semantics_version`, `contract_id`. Defaulted, so old manifests still load. | MODIFY |
| `replicant/core/models.py:176` | `RunRequest`: `controls`, `mark_run`, `evidence_dir`. | MODIFY |
| `replicant/core/orchestrator.py:347` | Generate `run_id`; filter by `controls`; write the pack. | MODIFY |
| `replicant/core/orchestrator.py:453` | `_emit`: no change. Keep the render/wait split intact. | KEEP |
| `replicant/scenario/engine.py` (13 builders) | Tag foil records `control="negative"`. | MODIFY |
| `replicant/scenario/engine.py` (10 builders) | Write the missing foils. P1, one at a time. | MODIFY |
| `replicant/data/technique-catalog.yaml` | Split `benign_baseline` prose from a new `foil:` block. | MODIFY |
| `replicant/profiles/*.py` (3 x 6 templates) | Emit the marker + run id when enabled. One shared helper, not 18 edits. | MODIFY |
| `replicant/config/settings.py:127` | `benign_marker` actually read; add `marker_label`. | MODIFY |
| `replicant/cli/app.py:126` | `validate` and `replay` subparsers; 3 flags on `run`. | MODIFY |
| `replicant/web/server.py` | `/api/catalog/{id}/contract`, `/api/validate`. | MODIFY |
| `replicant/resources.py` | `DETECTION_CONTRACTS` path. Packaged. | MODIFY |
| `replicant/audit/manifest.py:41` | Name manifests by `run_id` rather than a random token. | MODIFY |
| `pyproject.toml` | Package the contracts directory. | MODIFY |
| `webui/src/components/TechniqueDetail.tsx` | Contract section. | MODIFY |
| `webui/src/components/RunPanel.tsx` | Controls selector, evidence toggle. | MODIFY |
| `README.md`, `CLAUDE.md`, `docs/blueprint.md` | Safety rule 1 amendment, at the first adapter. | MODIFY |

Nothing in `cef/serializer.py`, `transport/`, or `core/pacing.py` needs to change. That
is the strongest evidence that the existing architecture supports this work.

---

## 17. New files and modules required

```
replicant/core/semantics.py           the declared `extra` vocabulary
replicant/validation/__init__.py
replicant/validation/contract.py      Contract models + loader
replicant/validation/verdict.py       Verdict, ValidationResult, the vector
replicant/validation/evaluator.py     evaluate(): pure, the tier logic
replicant/validation/sources/base.py  TelemetrySource / DetectionSource protocols
replicant/validation/sources/fixture.py
replicant/validation/sources/filelog.py
replicant/validation/sources/logrhythm.py    P1, after the lab test
replicant/evidence/pack.py            writer
replicant/evidence/report.py          REPORT.md generator
replicant/evidence/mapping.py         canonical -> vendor table, from the profiles
replicant/data/detection-contracts/REP-001.yaml ... REP-024.yaml
docs/detection-contract-reference.md  the schema, with the rules from section 7
docs/rsyslog-receiver.conf            the one supported Tier 1 receiver config
```

Every one of these is either pure logic or a data file, except the three sources. That
proportion is the design working: the parts that touch the world are three files behind
one protocol.

---

## 18. Testing strategy

The project's own two rules apply and are not negotiable here.

**A new guard must be run against the unfixed code and observed to fail.** For this work
that has a specific shape, because most of the guards are about *the absence of a
claim*:

- The `separable_by: []` check must be run against a technique with a deliberately
  separable foil (reintroduce the v0.7.0 REP-014 duration defect in a scratch branch) and
  observed to go red. If it does not, it is checking nothing.
- The Tier 0 periodicity check must be run against REP-002 before its `window_s` fix, or
  an equivalent injected drift, and observed to fail.
- The `control` tagging must be checked by asserting `--controls negative` produces a
  stream that the positive detection assertion **fails** on. A negative control that
  would also pass is not a negative control.
- The run-id marker must be checked by asserting the CEF line changes when enabled and is
  byte-identical to the golden lines when not.
- **Seeds are part of the guard.** Every contract assertion is checked across at least 20
  seeds, not seed 1337. The REP-013 lesson is that a guard whose seed avoids the defect
  has never failed, and a periodicity or cardinality assertion is exactly the shape that
  can pass by luck.

**Tests must not touch host-global state.** `tests/conftest.py` already redirects
`REPLICANT_CONFIG_DIR`. Evidence packs and Tier 1's rsyslog file must go through the same
isolation, and the Tier 1 test must bind an ephemeral port.

New test files, roughly:

| File | Asserts |
|---|---|
| `test_semantics.py` | every `extra` key read by a profile is declared; every declared key is read |
| `test_contract_schema.py` | all 24 contracts load; numbers match the catalog presets (parametrized over the catalog, per the `--duration` lesson) |
| `test_controls.py` | every foil-bearing builder tags `control="negative"`; `--controls` partitions correctly |
| `test_foil_declaration.py` | a `foil:` block is present exactly when the builder emits `control="negative"` events, parametrized over all 24 at all 3 intensities |
| `test_run_id.py` | id in manifest always; in CEF only when marked; golden lines unchanged when not |
| `test_tier0.py` | evaluator verdicts, including the four failure modes, over 20 seeds |
| `test_tier1_filelog.py` | send to an ephemeral rsyslog-shaped receiver, read back, match |
| `test_evidence_pack.py` | pack completeness; bounded telemetry says it truncated; a no-destination run says so in the first paragraph |
| `test_replay.py` | replay of a pack reproduces the plan byte for byte |
| `test_validate_cli.py` | exit codes 0/1/2/3, each reached |

**The one test that matters most:** a parametrized test over all 24 techniques asserting
each has a contract and that contract's `emitted` block passes against its own plan at
every intensity. That is the generalisation of `test_duration.py` and
`test_catalog_objectives.py`, and it is what makes the contract mechanism trustworthy
rather than decorative.

---

## 19. Migration and backward compatibility

The compatibility surface is larger than it looks, because REP ids and CEF output are
both public interfaces.

**Unbreakable, and none of this breaks them:**

- REP ids, `ndr_uc` values, scenario ids. Untouched.
- Existing CLI verbs, flags and output. Untouched; every new flag defaults to today.
- The wire format with default settings. The run-id marker is opt-in, and the golden
  tests are the guard that it stayed opt-in.
- Existing manifests. Every new field is defaulted, exactly as `pace`, `speed`, `vendor`
  and `duration` were added.

**Two changes need care:**

*`Technique.fortigate` -> `Technique.telemetry`.* Pydantic `AliasChoices` accepts both
names for one release; the shipped catalog moves to the new name; a deprecation note in
the CHANGELOG; the alias is removed at the release after. Anyone with a private catalog
YAML keeps working for one cycle. Do this early in P0, because 24 contracts written
against the old name is a worse migration than one done now.

*Manifest naming by `run_id`.* `_write_unique` currently names by timestamp plus a random
token. Changing it changes filenames on disk. Nothing in the codebase globs them, and the
manifests already carry their own identity inside, so [Inference] this is safe. Confirm
by grep before doing it, and keep the timestamp prefix so directory listings stay
chronological.

**The contract-version story.** `contract_version` and `semantics_version` in every
contract, both recorded in the manifest. A contract whose `semantics_version` is behind
the running one **warns and evaluates** rather than refusing, and the warning names the
keys that moved. Refusing would make a version bump a flag day across 24 files.

---

## 20. Implementation backlog

P0, in dependency order. Each item is one commit-sized change with its own guard.

1. `run_id` on `RunManifest` and `RunRequest`; generated in `Orchestrator.run()`; printed
   by the CLI. Guard: id present in every manifest on every exit path including error.
2. Wire `Settings.benign_marker` to a real CEF field via one shared profile helper;
   `--mark-run` stamps `run_id` beside it. Guard: golden lines byte-identical with the
   marker off, changed with it on. Positive control: revert the helper, watch the "on"
   assertion go red.
3. `control` on `EventRecord`; tag the foils in the 13 builders that emit one. Guard: for
   each, `control="negative"` events exist and are a minority; 20 seeds.
3b. Split `benign_baseline` prose from a `foil:` block in the catalog. Guard: the block is
   present exactly when the builder emits negative-control events, all 24, all 3
   intensities. Positive control: add a `foil:` block to REP-001, watch it go red.
4. `--controls {both,positive,negative}` on `run`. Guard: the negative stream fails the
   positive assertion.
5. `replicant/core/semantics.py` + the declaration guard. Positive control: add an
   undeclared key to a profile template, watch it go red.
6. Rename `Technique.fortigate` -> `telemetry`, aliased. Guard: both names load; the
   shipped catalog uses the new one.
7. `Contract` models, loader, packaging, `resources.DETECTION_CONTRACTS`,
   `validate show`. Guard: `test_packaging.py` extended, contracts present in the wheel.
8. `docs/detection-contract-reference.md`. The schema and section 7's three rules.
9. Contracts for REP-001 and REP-015. Guard: numbers derive from presets, not restated.
10. Tier 0 evaluator + `Verdict` + `ValidationResult`. Pure, no I/O.
11. `validate --tier plan` + the exit-code contract. Guard: all four exit codes reached.
12. `FixtureSource` + the protocol. Guard: the evaluator runs end to end offline.
13. `FileLogSource` + `docs/rsyslog-receiver.conf` + Tier 1. Guard: ephemeral-port
    send-and-read-back, isolated per test.
14. Evidence pack writer + `REPORT.md` + the mapping table generated from the profiles.
    Guard: no-destination run says so first; oversize run says it truncated.
15. Contracts for the remaining 22 techniques, one commit per group of tactics. Guard:
    the parametrized all-24 contract test from section 18.

P1 begins at item 16 and is listed in section 15. **Item 16 is the LogRhythm lab test,
and it is not code.**

---

## What this review does not claim

It is a judgement about architecture and fit, made from reading the tree, not a line-by-
line audit of the 24 builders or the React app. The three findings material to the
recommendations (no run id anywhere in the telemetry, `benign_marker` declared and never
read, foils generated without a discriminator) were each checked by grep across the whole
tree and are stated as fact. Effort figures are marked [Inference] and are worth what
such figures usually are.

The single most important sentence in it is not new: **the LogRhythm lab test has still
never run**, and until it does, every P1 item that asks a SIEM a question is being
designed against a send path nobody has watched work. P0 is arranged so that none of it
depends on that, which is the only reason it can be started now.
