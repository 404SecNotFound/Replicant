# Phase 4: ATT&CK scenario composition (design spec)

Status: approved in brainstorm 2026-07-19, ready for implementation planning.
Author: DJR/RZA with Claude Code.
Scope: the composition engine, emit path, advisory output, and CLI + Rich menu surfaces. Web UI is a deferred fast-follow.

## 1. Goal

Blueprint Phase 4: *"a technique-selection and scenario-composition helper that assembles multi-step scenarios from ATT&CK. Keep any AI assist advisory; the human authors the detection design. AI must not write the LogRhythm rule design notes."*

Replicant today emits one technique per run. Phase 4 composes the existing 11 techniques (REP-001..011) into ordered multi-stage attack chains that **emit chained CEF telemetry on one realistic timeline**, plus a deterministic **advisory coverage document** to help a detection engineer author cross-stage (e.g. LogRhythm AIE) correlation rules. The human still authors the detection design.

## 2. Locked decisions (brainstorm)

1. **Output:** emit + advisory (a scenario emits a chained run AND writes an advisory coverage doc).
2. **AI:** deterministic, no LLM. The "advisory" is rule-based composition from catalog ATT&CK metadata. Keeps "only egress is the collector" intact, no new deps. A clean seam is left for a future optional LLM advisor.
3. **Definition:** a curated `data/scenario-catalog.yaml`, mirroring the technique catalog.
4. **Surfaces:** CLI + Rich menu now; web UI as a separate fast-follow.

## 3. Approach: one composed timeline (Approach C)

Rejected: sequential wall-clock runs with real dwell sleeps (a realistic chain would take hours to emit).

Chosen: the composer reuses the existing per-technique engine to plan each stage, places each stage at its offset **along one deterministic timeline**, and merges all stages into one time-ordered CEF stream emitted through the existing orchestrator. The realistic inter-stage dwell lives in the event `eventtime` fields, not in wall-clock: so a multi-hour chain emits in seconds and `--to-file` is byte-identical per seed.

Two properties make it valuable for cross-stage detection:

- **Shared entities are the correlation through-line.** The same synthetic victim host / adversary IP thread across all stages, which is what a cross-stage correlation rule keys on.
- **Determinism holds.** One scenario seed derives per-stage seeds; same scenario + seed → same whole chain. The technique engine is not modified.

Data flow: `scenario-catalog.yaml -> ScenarioCatalog -> composer (reuses ScenarioEngine.plan per stage, pinned shared entities) -> ComposedPlan -> Orchestrator._emit (shared with single-technique runs) -> vendor profile + CEF + transport`, and in parallel `ComposedPlan + catalog metadata -> ScenarioManifest + advisory.md`.

## 4. Data model (`core/models.py` + `data/scenario-catalog.yaml`)

```python
class ScenarioStage(BaseModel):
    technique_id: str                # ref to an existing REP-### in the technique catalog
    label: str | None = None         # phase label, e.g. "external recon"
    intensity: Intensity = "medium"  # per-stage; reuses low/medium/high presets
    start_offset: str = "0s"         # start time relative to the scenario anchor (parse_duration)
    param_overrides: dict[str, Any] = Field(default_factory=dict)  # reuses engine's override path

class Scenario(BaseModel):
    id: str                          # SCEN-###
    name: str
    description: str
    stages: list[ScenarioStage]
    kill_chain: list[str] = []       # optional; else derived from stages' attack.tactics
    references: list[str] = []
    safety_notes: str | None = None

class ScenarioCatalog(BaseModel):
    version: str
    scenarios: list[Scenario]
```

Example:

```yaml
version: 0.1.0
scenarios:
  - id: SCEN-001
    name: "Perimeter intrusion to exfiltration"
    description: "External recon, then low-and-slow C2, then bulk exfil from the same host."
    stages:
      - { technique_id: REP-003, label: "external recon", intensity: medium, start_offset: "0s" }
      - { technique_id: REP-001, label: "C2 established",  intensity: low,    start_offset: "1h" }
      - { technique_id: REP-005, label: "bulk exfil",      intensity: high,   start_offset: "6h" }
    references: ["ATT&CK chain: TA0007 Discovery -> TA0011 C2 -> TA0010 Exfiltration"]
```

Decisions:

- **`start_offset` is absolute from the scenario anchor** (a duration string parsed by the existing `parse_duration`). Stage k occupies `[anchor + offset_k, anchor + offset_k + its own technique duration]`. Stages may be sequential or overlap; the composer merges by `eventtime`.
- **Entities are not in the catalog.** The composer owns a shared, pinned `EntityModel` built from the synthetic pools, so syntheticity is guaranteed by construction and nothing in YAML can introduce a real entity.
- **Cross-catalog validation at load:** a loader validates unique `SCEN-###` ids and that every `stage.technique_id` exists in the technique catalog (fail loud on a typo).
- **Per-stage `intensity` + `param_overrides` reuse the engine's existing knobs** (no new parameter machinery).

## 5. Composition engine (`replicant/scenario/composer.py`)

A new pure, I/O-free, seedable module that produces a plan and does not emit (keeps "the scenario engine does no I/O").

**Entity continuity without any engine change.** Every technique does `src = rng.choice(entities.internal_hosts)` and dst from `entities.adversary_external` (`scenario/engine.py`). So the composer builds a scenario-scoped `EntityModel` whose **through-line pools are narrowed to one deterministically-chosen synthetic value each** (`internal_hosts = [victim]`, `adversary_external = [adversary_ip]`), picked from the full synthetic pools using the scenario seed. Then every stage's `rng.choice(...)` returns the same victim/adversary, so the compromised host is the correlation key across stages and C2/exfil share infra. Multi-target pools (`sweep_hosts`, `internal_targets`, `benign_external`) stay full, so recon still fans across many hosts. Because the engine and profiles are untouched, the golden tests and per-technique determinism are unaffected. The narrowed `EntityModel` is re-validated synthetic by the model's existing construction path.

The pin applies to techniques whose `src` is drawn from `internal_hosts` (the host-based techniques). VPN/credential techniques (REP-007 spray, REP-011 geovelocity) and the external-scan technique (REP-009) key on a user or remote IP rather than the internal host; for chains that mix these (e.g. SCEN-003) the advisory reports the actual correlation key per stage.

**`compose(scenario, technique_catalog, engine, seed, anchor) -> ComposedPlan`:**

1. Derive a deterministic integer seed per stage from the scenario seed via `numpy.SeedSequence(seed).spawn(n_stages)`, converting each spawned child to an int (`child.generate_state(1)[0]`), so the engine's existing `seed: int` contract is unchanged. Independent substreams, fully deterministic.
2. Build the pinned scenario `EntityModel` (seeded from the scenario seed).
3. For each stage i: `plan_i = engine.plan(technique, stage.intensity, pinned_entities, stage_seed_i, anchor_epoch = scenario_anchor + parse_duration(stage.start_offset), param_overrides=stage.param_overrides)`. Record a `StageResult` (index, technique_id, label, intensity, start_offset, event count, ATT&CK tactics/techniques, `ndr_uc`).
4. Merge all stages' events, stable-sort by `(eventtime, stage_index)`.
5. Return `ComposedPlan { events (time-ordered), stages: list[StageResult], entities_summary, anchor_epoch, total_count, scenario_id, seed }`.

Determinism: same scenario + seed → same pinned actors → same per-stage plans → same merge → byte-identical output. `engine.plan(...)` is used verbatim (it already accepts `entities`, `seed`, `anchor_epoch`, `param_overrides`); there is no change to the technique engine.

## 6. Orchestrator / emit integration

**Refactor:** extract the emit loop from `Orchestrator.run()` (`orchestrator.py:199-234`) into a private `_emit(events, target, transport, send, sink, on_event, on_progress) -> (count, stopped)` owning sink/emitter setup, eps-cap pacing, the stop flag, and counting. Both `run()` and the new `run_scenario()` call it. One emit path, no duplication.

**`Orchestrator.run_scenario(req: ScenarioRunRequest)`:**

1. `composed = compose(scenario, self.catalog, self.engine, seed=req.seed, anchor=req.anchor_epoch or settings.anchor_epoch)`, passing `self.entities` base pools in.
2. Fail-closed check identical to `run()`: send wanted + no collector + no `to_file` → `RuntimeError`.
3. `count, stopped = self._emit(composed.events, ...)`: reuses eps cap, UDP/TCP/TLS transport, kill switch, and the selected `--vendor` profile unchanged.
4. Write the `ScenarioManifest` + advisory doc, return a `ScenarioRunResult`.

```python
class ScenarioRunRequest(BaseModel):
    scenario_id: str
    seed: int = 1337
    intensity_override: Intensity | None = None   # optional: override every stage
    to_file: str | None = None
    no_send: bool = False
    rate_override: int | None = None
    collector: CollectorProfile | None = None
    anchor_epoch: int | None = None
```

The whole merged timeline emits as one stream, paced by the eps cap when sending (instant to file); the multi-hour dwell is in `eventtime`, so a scenario emits in seconds. The kill switch stops it mid-chain.

## 7. Scenario manifest + advisory doc

**`ScenarioManifest`** (safety rule 5), written to `manifests/{scenario_id}-seed{seed}-{ts}.json`:

```python
class ScenarioStageRecord(BaseModel):
    index: int; technique_id: str; label: str | None; ndr_uc: str
    intensity: str; start_offset: str; event_count: int
    tactics: list[str]; techniques: list[str]

class ScenarioManifest(BaseModel):
    replicant_version: str; scenario_id: str; scenario_name: str; seed: int
    entities: dict[str, Any]          # pinned through-line: victim host, adversary ip
    target: str; transport: str; vendor: str; accepted_as: str | None
    total_event_count: int; stages: list[ScenarioStageRecord]
    started_at: str; ended_at: str; anchor_epoch: int; warmup_note: str | None
    coverage: dict[str, Any]          # machine-readable mirror of the advisory
```

**Advisory doc**: a deterministic markdown at `manifests/{scenario_id}-seed{seed}-{ts}.advisory.md`, generated from catalog metadata + the composed plan (no LLM). Five parts:

1. **Boundary header**: states plainly this is advisory context (coverage + correlation prompts); the human authors the detection/AIE rule design; no rule logic is generated.
2. **Through-line**: the pinned victim host / adversary IP / user, "correlate on these."
3. **Kill-chain table**: ordered stages: tactic -> technique -> `ndr_uc` -> `start_offset` -> event count.
4. **Coverage vs gaps**: tactics exercised (in ATT&CK order) vs tactics the catalog could exercise but this chain does not, naming the candidate technique for each gap (e.g. "Credential Access not in this chain; REP-007 covers it").
5. **Cross-stage correlation opportunities**: factual prompts: "stages 1-3 share `src=<victim>` across Discovery->C2->Exfiltration within a 6h span", "C2 and exfil share `dst=<adversary_ip>`".

Same scenario + seed → same advisory (modulo run timestamps). It presents facts and prompts; it never writes the rule design.

## 8. CLI + Rich menu (parity)

Both surfaces resolve to `Orchestrator.run_scenario`; nothing lives only in the TUI.

CLI: a new `scenario` verb with three actions in `cli/app.py`:

```
replicant scenario list                 # id, name, stage count, tactic span
replicant scenario show SCEN-001        # composed stage breakdown + coverage/advisory to stdout, no emit
replicant scenario run SCEN-001 --seed 1337 --vendor fortigate --to-file ./out/s1.log --no-send
```

`scenario run` reuses the same collector/transport/TLS/`--no-send`/`--rate`/`--profile`/`--vendor` flags as `replicant run`. Per-stage intensity comes from the catalog; a single optional `--intensity` overrides all stages. `show` is a dry preview (the advisory rendered to the terminal without emitting).

Rich menu: add `[a] attack scenario` to the prompt (`[1-11] technique · [a] scenario · [c] connection · [v] vendor · [s] seed · [q] quit`). `[a]` shows a numbered scenario picker; selecting one prints the `show` preview then runs it using the menu's existing connection/vendor/seed state.

## 9. Starter scenarios (`data/scenario-catalog.yaml`)

| id | name | stages (offset) | ATT&CK chain | through-line |
|----|------|-----------------|--------------|--------------|
| SCEN-001 | Perimeter intrusion to exfiltration | REP-003 sweep (0) -> REP-001 C2 (+1h) -> REP-005 exfil (+6h) | Discovery -> C2 -> Exfiltration | victim `src`; C2+exfil share adversary IP |
| SCEN-002 | Recon, first contact, DNS exfil | REP-002 vscan (0) -> REP-008 new-dst (+45m) -> REP-004 DNS tunnel (+3h) | Discovery -> C2 -> Exfil-over-DNS | victim `src` |
| SCEN-003 | External access to foothold | REP-009 IPS spike (0) -> REP-007 spray (+30m) -> REP-011 geovelocity (+2h) -> REP-001 C2 (+3h) | Recon -> Credential Access -> Initial Access -> C2 | mixed: user (spray->geo), then host (C2) |

SCEN-001/002 are clean single-host chains (correlate on `src`). SCEN-003 is a richer multi-domain chain; the advisory surfaces the user key for the credential stages and the host key for the C2 stage. User-pinning across a spray is a noted future refinement, not v1. The set exists to prove the feature; the operator curates the real library, and adding a scenario is one YAML block.

## 10. Testing (TDD)

- **`test_scenario_catalog.py`**: YAML validates against `ScenarioCatalog`; unique `SCEN-###`; every `stage.technique_id` resolves in the technique catalog; `start_offset`s parse; the three starter scenarios well-formed.
- **`test_scenario_composer.py`**: determinism (same scenario+seed → identical plan and byte-identical rendered lines); entity continuity (pinned victim `src` in every stage; C2+exfil share adversary IP); timeline non-decreasing by `eventtime`, each stage starts at `anchor+offset`; multi-target pools stay unpinned; a single-stage scenario composes identically to running that technique directly (zero engine drift).
- **`test_scenario_advisory.py`**: deterministic content; contains through-line, kill-chain table, covered tactics, gap tactics with suggested catalog technique; boundary disclaimer present and no rule-design language emitted.
- **`test_scenario_orchestrator.py`**: `run_scenario` to file byte-identical across runs; fail-closed with send-wanted+no-collector+no-file; loopback UDP send delivers all lines; `--vendor paloalto` renders PAN-OS headers; kill switch stops mid-chain; `ScenarioManifest` complete.
- **CLI/menu**: `scenario list/show/run` parsing and the menu `[a]` picker dispatch (mirrors `test_menu.py`).

Key safety assertion: because the engine and profiles are untouched, the CEF golden tests stay green unchanged. The whole suite (185 + new) stays green; black/ruff/mypy clean.

## 11. Safety analysis (all five rules hold by construction)

1. **Only egress is the collector, fail closed**: `run_scenario` uses the same fail-closed check and the same transport as `run()`.
2. **Synthetic entities**: the composer pins the through-line *from* the synthetic pools; the narrowed `EntityModel` is re-validated synthetic; no catalog field can introduce a real entity.
3. **No real attacks / strings only**: the shared `_emit` path renders `EventRecord`s to CEF strings; no new I/O or execution.
4. **eps cap**: the shared `_emit` enforces the cap for the whole scenario stream; `--rate` overrides as today.
5. **Manifest per run**: every `run_scenario` writes a `ScenarioManifest` (plus the advisory doc).

## 12. New and changed files

New: `data/scenario-catalog.yaml`, `replicant/scenario/composer.py`, `tests/test_scenario_catalog.py`, `tests/test_scenario_composer.py`, `tests/test_scenario_advisory.py`, `tests/test_scenario_orchestrator.py`.
Changed: `replicant/core/models.py` (scenario models + loader), `replicant/core/orchestrator.py` (`_emit` refactor + `run_scenario`), `replicant/audit/manifest.py` (scenario manifest + advisory writers), `replicant/cli/app.py` (`scenario` verb), `replicant/cli/menu.py` (`[a]` picker), `tests/test_menu.py`, and `docs/blueprint.md` (mark Phase 4 done). New source carries the Apache header.

## 13. Non-goals / deferred

- **Web UI scenario support**: a focused fast-follow (scenario browser, chain timeline, run) after this lands.
- **Optional LLM advisor**: a clean seam is left (the advisory generator is a single deterministic module); adding an opt-in, gated LLM advisor is a separate scope with its own egress carve-out.
- **User-pinning across credential-spray stages**: a refinement for tighter SCEN-003 correlation; v1 pins host + adversary IP.
- **Ad-hoc chains from CLI args**: the composer supports it trivially (an ordered list of technique ids), but v1 ships the curated catalog only.
