# Phase 4 Scenario Composition Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Compose the existing 11 techniques into ordered multi-stage attack chains that emit one deterministic CEF timeline with a shared synthetic through-line, plus a deterministic advisory coverage doc, driven from a curated `data/scenario-catalog.yaml` over CLI and the Rich menu.

**Architecture:** A new pure composer reuses `ScenarioEngine.plan()` per stage (unchanged engine) against a scenario-scoped `EntityModel` whose through-line pools are pinned to one synthetic victim/adversary, places each stage at `anchor + start_offset`, and merges events by `eventtime`. `Orchestrator.run_scenario` emits the merged stream through a shared `_emit` (refactored out of `run()`), then writes a `ScenarioManifest` + advisory markdown. No engine or profile change, so the CEF golden tests stay green.

**Tech Stack:** Python 3.12, Pydantic v2, numpy (`SeedSequence`/`default_rng`), argparse, Rich, pytest. Run tools via the repo venv: `./.venv/bin/pytest`, `./.venv/bin/black`, `./.venv/bin/ruff`, `./.venv/bin/mypy`.

Spec: `docs/phase4-scenario-composition-design.md`. Branch: `feature/phase4-scenario-composition`.

---

## File structure

- `data/scenario-catalog.yaml` (new) - curated scenarios; mirrors `technique-catalog.yaml`.
- `replicant/core/models.py` (modify) - `ScenarioStage`, `Scenario`, `ScenarioCatalog`, `load_scenario_catalog`, `ScenarioRunRequest`, `ScenarioStageRecord`, `ScenarioManifest`.
- `replicant/scenario/composer.py` (new) - `StageResult`, `ComposedPlan`, `compose(...)`, entity pinning. Pure, I/O-free.
- `replicant/scenario/advisory.py` (new) - `build_advisory(...) -> (markdown, coverage)`. Pure.
- `replicant/audit/manifest.py` (modify) - `write_scenario_manifest`, `write_advisory`.
- `replicant/core/orchestrator.py` (modify) - extract `_emit`; add `run_scenario`, `ScenarioRunResult`.
- `replicant/cli/app.py` (modify) - `scenario` verb (`list`/`show`/`run`) + `cmd_scenario`.
- `replicant/cli/menu.py` (modify) - `[a]` picker + `_run_scenario`.
- `tests/test_scenario_catalog.py`, `tests/test_scenario_composer.py`, `tests/test_scenario_advisory.py`, `tests/test_scenario_orchestrator.py`, `tests/test_scenario_cli.py` (new); `tests/test_menu.py` (modify).
- `docs/blueprint.md`, `README.md` (modify) - mark Phase 4 done.

Reference constant used by tests and the CLI (repo-root data dir), placed in `models.py` next to `load_catalog`:
```python
from pathlib import Path
SCENARIO_CATALOG_PATH = Path(__file__).resolve().parents[2] / "data" / "scenario-catalog.yaml"
```

---

## Task 1: Scenario catalog data model + YAML

**Files:**
- Modify: `replicant/core/models.py` (add after the `Technique`/`Catalog`/`load_catalog` block)
- Create: `data/scenario-catalog.yaml`
- Test: `tests/test_scenario_catalog.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_scenario_catalog.py
from __future__ import annotations

from pathlib import Path

import pytest

from replicant.core.models import (
    ScenarioCatalog,
    load_catalog,
    load_scenario_catalog,
)

ROOT = Path(__file__).resolve().parents[1]
TECH = load_catalog(ROOT / "data" / "technique-catalog.yaml")
SCEN_PATH = ROOT / "data" / "scenario-catalog.yaml"


def test_scenario_catalog_loads_and_validates() -> None:
    catalog = load_scenario_catalog(SCEN_PATH, TECH)
    assert isinstance(catalog, ScenarioCatalog)
    assert {s.id for s in catalog.scenarios} >= {"SCEN-001", "SCEN-002", "SCEN-003"}


def test_every_stage_references_a_real_technique() -> None:
    catalog = load_scenario_catalog(SCEN_PATH, TECH)
    known = {t.id for t in TECH.techniques}
    for scenario in catalog.scenarios:
        assert scenario.stages, f"{scenario.id} has no stages"
        for stage in scenario.stages:
            assert stage.technique_id in known


def test_duplicate_scenario_id_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate scenario id"):
        ScenarioCatalog.model_validate(
            {
                "version": "0.1.0",
                "scenarios": [
                    {"id": "SCEN-001", "name": "a", "description": "d", "stages": [{"technique_id": "REP-001"}]},
                    {"id": "SCEN-001", "name": "b", "description": "d", "stages": [{"technique_id": "REP-001"}]},
                ],
            }
        )


def test_unknown_technique_ref_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "version: 0.1.0\nscenarios:\n"
        "  - id: SCEN-999\n    name: bad\n    description: d\n"
        "    stages:\n      - { technique_id: REP-404 }\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unknown technique REP-404"):
        load_scenario_catalog(bad, TECH)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/pytest tests/test_scenario_catalog.py -q`
Expected: FAIL with `ImportError` (`load_scenario_catalog` / `ScenarioCatalog` not defined).

- [ ] **Step 3: Add the models + loader**

Append to `replicant/core/models.py` (after `load_catalog`). `BaseModel`, `Field`, `field_validator`, `yaml`, `Path`, `Any`, `Intensity`, `CollectorProfile` are already imported.

```python
SCENARIO_CATALOG_PATH = Path(__file__).resolve().parents[2] / "data" / "scenario-catalog.yaml"


class ScenarioStage(BaseModel):
    """One stage of a scenario: a reference to an existing technique + timing."""

    technique_id: str
    label: str | None = None
    intensity: Intensity = "medium"
    start_offset: str = "0s"  # start time relative to the scenario anchor (parse_duration)
    param_overrides: dict[str, Any] = Field(default_factory=dict)


class Scenario(BaseModel):
    id: str
    name: str
    description: str
    stages: list[ScenarioStage]
    kill_chain: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    safety_notes: str | None = None


class ScenarioCatalog(BaseModel):
    version: str
    scenarios: list[Scenario]

    @field_validator("scenarios")
    @classmethod
    def _unique_ids(cls, scenarios: list[Scenario]) -> list[Scenario]:
        seen: set[str] = set()
        for scenario in scenarios:
            if scenario.id in seen:
                raise ValueError(f"duplicate scenario id: {scenario.id}")
            seen.add(scenario.id)
        return scenarios

    def by_id(self, scenario_id: str) -> Scenario:
        for scenario in self.scenarios:
            if scenario.id == scenario_id:
                return scenario
        raise KeyError(f"unknown scenario id: {scenario_id}")


def load_scenario_catalog(path: str | Path, technique_catalog: Catalog) -> ScenarioCatalog:
    """Load the scenario catalog and validate every stage reference against the techniques."""

    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    catalog = ScenarioCatalog.model_validate(raw)
    known = {technique.id for technique in technique_catalog.techniques}
    for scenario in catalog.scenarios:
        for stage in scenario.stages:
            if stage.technique_id not in known:
                raise ValueError(
                    f"scenario {scenario.id} references unknown technique {stage.technique_id}"
                )
    return catalog
```

- [ ] **Step 4: Create `data/scenario-catalog.yaml`**

```yaml
# Replicant scenario catalog: multi-stage ATT&CK chains composed from the technique catalog.
# Each stage references an existing REP-### technique; start_offset is relative to the scenario
# anchor. Entities are pinned by the composer (synthetic by construction); none are declared here.
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

  - id: SCEN-002
    name: "Recon, first contact, DNS exfil"
    description: "Vertical scan, first contact to a new external destination, then DNS-channel exfil."
    stages:
      - { technique_id: REP-002, label: "port scan",        intensity: medium, start_offset: "0s" }
      - { technique_id: REP-008, label: "new destination",  intensity: medium, start_offset: "45m" }
      - { technique_id: REP-004, label: "dns exfil",        intensity: high,   start_offset: "3h" }
    references: ["ATT&CK chain: TA0007 Discovery -> TA0011 C2 -> TA0010 Exfil-over-DNS"]

  - id: SCEN-003
    name: "External access to foothold"
    description: "Scanning noise, password spray, an anomalous VPN login, then an internal beacon."
    stages:
      - { technique_id: REP-009, label: "ids spike",        intensity: medium, start_offset: "0s" }
      - { technique_id: REP-007, label: "password spray",   intensity: high,   start_offset: "30m" }
      - { technique_id: REP-011, label: "geo anomaly",      intensity: medium, start_offset: "2h" }
      - { technique_id: REP-001, label: "internal beacon",  intensity: low,    start_offset: "3h" }
    references: ["ATT&CK chain: TA0043 Recon -> TA0006 Credential Access -> TA0001 Initial Access -> TA0011 C2"]
```

- [ ] **Step 5: Run test to verify it passes**

Run: `./.venv/bin/pytest tests/test_scenario_catalog.py -q`
Expected: PASS (4 passed).

- [ ] **Step 6: Commit**

```bash
git add replicant/core/models.py data/scenario-catalog.yaml tests/test_scenario_catalog.py
git commit -m "feat(scenario): scenario catalog model, loader, and starter scenarios"
```

---

## Task 2: Composer (pinned entities, per-stage seeds, merged timeline)

**Files:**
- Create: `replicant/scenario/composer.py`
- Test: `tests/test_scenario_composer.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_scenario_composer.py
from __future__ import annotations

from pathlib import Path

from replicant.core.models import load_catalog, load_scenario_catalog
from replicant.entities.model import EntityModel
from replicant.scenario.composer import compose
from replicant.scenario.engine import ScenarioEngine

ROOT = Path(__file__).resolve().parents[1]
TECH = load_catalog(ROOT / "data" / "technique-catalog.yaml")
SCEN = load_scenario_catalog(ROOT / "data" / "scenario-catalog.yaml", TECH)
ANCHOR = 1_752_586_800


def _compose(scenario_id: str, seed: int = 1337):
    scenario = SCEN.by_id(scenario_id)
    return compose(scenario, TECH.by_id, ScenarioEngine(), seed, ANCHOR, EntityModel.build())


def test_compose_is_deterministic() -> None:
    a = _compose("SCEN-001")
    b = _compose("SCEN-001")
    assert a.total_count == b.total_count and a.total_count > 0
    assert [e.eventtime for e in a.events] == [e.eventtime for e in b.events]
    assert a.victim == b.victim and a.adversary == b.adversary


def test_events_sorted_by_eventtime() -> None:
    plan = _compose("SCEN-001")
    times = [e.eventtime for e in plan.events]
    assert times == sorted(times)


def test_pinned_victim_is_the_src_for_host_based_stages() -> None:
    plan = _compose("SCEN-001")  # REP-003, REP-001, REP-005 all use internal_hosts as src
    srcs = {e.src for e in plan.events if e.src is not None}
    assert srcs == {plan.victim}


def test_stage_offsets_applied() -> None:
    plan = _compose("SCEN-001")
    # stage 1 (REP-001) starts at anchor + 1h; its earliest event is >= that
    stage1 = [r for r in plan.stages if r.index == 1][0]
    assert stage1.start_offset == "1h"
    assert plan.stages[0].event_count + plan.stages[1].event_count + plan.stages[2].event_count == plan.total_count


def test_single_stage_matches_direct_run() -> None:
    # a one-stage scenario composed == running that technique directly with the same seed/anchor/entities
    scenario = SCEN.by_id("SCEN-001").model_copy(update={"stages": [SCEN.by_id("SCEN-001").stages[0]]})
    engine = ScenarioEngine()
    entities = EntityModel.build()
    composed = compose(scenario, TECH.by_id, engine, 1337, ANCHOR, entities)
    # reproduce the composer's pinned entities + stage seed for a direct call
    import numpy as np
    from dataclasses import replace

    rng = np.random.default_rng(1337)
    victim = str(rng.choice(entities.internal_hosts))
    adversary = str(rng.choice(entities.adversary_external))
    pinned = replace(entities, internal_hosts=[victim], adversary_external=[adversary])
    stage_seed = int(np.random.SeedSequence(1337).spawn(1)[0].generate_state(1)[0])
    direct = engine.plan(TECH.by_id("REP-003"), "medium", pinned, stage_seed, anchor_epoch=ANCHOR)
    assert [e.eventtime for e in composed.events] == [e.eventtime for e in direct.events]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/pytest tests/test_scenario_composer.py -q`
Expected: FAIL with `ModuleNotFoundError: replicant.scenario.composer`.

- [ ] **Step 3: Implement the composer**

```python
# replicant/scenario/composer.py
# Copyright 2026 Imran Hafeez (RZA)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Deterministic, I/O-free composition of a scenario into one merged event timeline.

Reuses ``ScenarioEngine.plan`` per stage against a scenario-scoped ``EntityModel``
whose through-line pools are pinned to one synthetic victim/adversary, so the same
actor threads across stages (the cross-stage correlation key). No engine change.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Callable

import numpy as np

from replicant.config.settings import parse_duration
from replicant.core.models import EventRecord, Scenario, Technique
from replicant.entities.model import EntityModel
from replicant.scenario.engine import ScenarioEngine


@dataclass
class StageResult:
    index: int
    technique_id: str
    label: str | None
    ndr_uc: str
    intensity: str
    start_offset: str
    event_count: int
    tactics: list[str]
    techniques: list[str]


@dataclass
class ComposedPlan:
    scenario_id: str
    seed: int
    anchor_epoch: int
    events: list[EventRecord]
    stages: list[StageResult]
    entities: dict[str, Any]
    victim: str
    adversary: str
    total_count: int = 0
    warmup_notes: list[str] = field(default_factory=list)


def _pin_entities(base: EntityModel, seed: int) -> tuple[EntityModel, str, str]:
    """Pick one victim + one adversary from the already-synthetic pools, deterministically,
    and narrow the through-line pools to them. Values come from validated pools, so the
    narrowed model stays synthetic."""
    rng = np.random.default_rng(seed)
    victim = str(rng.choice(base.internal_hosts))
    adversary = str(rng.choice(base.adversary_external))
    pinned = replace(base, internal_hosts=[victim], adversary_external=[adversary])
    return pinned, victim, adversary


def compose(
    scenario: Scenario,
    technique_by_id: Callable[[str], Technique],
    engine: ScenarioEngine,
    seed: int,
    anchor_epoch: int,
    base_entities: EntityModel,
    intensity_override: str | None = None,
) -> ComposedPlan:
    pinned, victim, adversary = _pin_entities(base_entities, seed)
    children = np.random.SeedSequence(seed).spawn(len(scenario.stages))
    tagged: list[tuple[int, int, EventRecord]] = []  # (eventtime, stage_index, event)
    stages: list[StageResult] = []
    warmups: list[str] = []
    for i, stage in enumerate(scenario.stages):
        technique = technique_by_id(stage.technique_id)
        stage_seed = int(children[i].generate_state(1)[0])
        stage_anchor = anchor_epoch + parse_duration(stage.start_offset)
        intensity = intensity_override or stage.intensity
        plan = engine.plan(
            technique,
            intensity,
            pinned,
            stage_seed,
            anchor_epoch=stage_anchor,
            param_overrides=stage.param_overrides or None,
        )
        for event in plan.events:
            tagged.append((event.eventtime, i, event))
        if plan.warmup_note:
            warmups.append(f"stage {i} ({stage.technique_id}): {plan.warmup_note}")
        stages.append(
            StageResult(
                index=i,
                technique_id=stage.technique_id,
                label=stage.label,
                ndr_uc=technique.ndr_uc,
                intensity=intensity,
                start_offset=stage.start_offset,
                event_count=len(plan.events),
                tactics=list(technique.attack.tactics),
                techniques=list(technique.attack.techniques),
            )
        )
    tagged.sort(key=lambda item: (item[0], item[1]))
    events = [item[2] for item in tagged]
    return ComposedPlan(
        scenario_id=scenario.id,
        seed=seed,
        anchor_epoch=anchor_epoch,
        events=events,
        stages=stages,
        entities=pinned.summary(),
        victim=victim,
        adversary=adversary,
        total_count=len(events),
        warmup_notes=warmups,
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/pytest tests/test_scenario_composer.py -q`
Expected: PASS (5 passed). If `test_pinned_victim_is_the_src_for_host_based_stages` fails, confirm SCEN-001's three techniques all draw `src` from `internal_hosts` (they do: REP-003/001/005).

- [ ] **Step 5: Commit**

```bash
git add replicant/scenario/composer.py tests/test_scenario_composer.py
git commit -m "feat(scenario): deterministic composer with pinned through-line entities"
```

---

## Task 3: Advisory generator

**Files:**
- Create: `replicant/scenario/advisory.py`
- Test: `tests/test_scenario_advisory.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_scenario_advisory.py
from __future__ import annotations

from pathlib import Path

from replicant.core.models import load_catalog, load_scenario_catalog
from replicant.entities.model import EntityModel
from replicant.scenario.advisory import build_advisory
from replicant.scenario.composer import compose
from replicant.scenario.engine import ScenarioEngine

ROOT = Path(__file__).resolve().parents[1]
TECH = load_catalog(ROOT / "data" / "technique-catalog.yaml")
SCEN = load_scenario_catalog(ROOT / "data" / "scenario-catalog.yaml", TECH)


def _advisory(scenario_id: str):
    scenario = SCEN.by_id(scenario_id)
    composed = compose(scenario, TECH.by_id, ScenarioEngine(), 1337, 1_752_586_800, EntityModel.build())
    return build_advisory(scenario, composed, TECH), composed


def test_advisory_is_deterministic() -> None:
    (text_a, cov_a), _ = _advisory("SCEN-001")
    (text_b, cov_b), _ = _advisory("SCEN-001")
    assert text_a == text_b and cov_a == cov_b


def test_advisory_has_boundary_and_through_line() -> None:
    (text, _), composed = _advisory("SCEN-001")
    assert "You author the detection" in text  # boundary disclaimer present
    assert composed.victim in text and composed.adversary in text


def test_advisory_reports_coverage_and_gaps() -> None:
    (_, coverage), _ = _advisory("SCEN-001")
    assert "TA0007 Discovery" in " ".join(coverage["covered_tactics"])
    # a gap names a concrete catalog technique to fill it
    assert coverage["gap_tactics"], "expected some uncovered tactic"
    assert all(g["suggested_technique"].startswith("REP-") for g in coverage["gap_tactics"])


def test_advisory_does_not_write_rule_design() -> None:
    (text, _), _ = _advisory("SCEN-001")
    lowered = text.lower()
    for banned in ("aie rule:", "detection rule:", "def rule", "```sql", "```kql"):
        assert banned not in lowered
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/pytest tests/test_scenario_advisory.py -q`
Expected: FAIL with `ModuleNotFoundError: replicant.scenario.advisory`.

- [ ] **Step 3: Implement the advisory generator**

```python
# replicant/scenario/advisory.py
# Copyright 2026 Imran Hafeez (RZA)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Deterministic advisory coverage document for a composed scenario.

Presents facts and correlation prompts from catalog metadata. It never writes the
detection/AIE rule design (blueprint constraint); the human authors that.
"""

from __future__ import annotations

from typing import Any

from replicant.core.models import Catalog, Scenario
from replicant.scenario.composer import ComposedPlan

_BOUNDARY = (
    "> Advisory context only: coverage and correlation prompts. "
    "You author the detection/AIE rule design; no rule logic is generated here."
)


def _tactic_to_technique(catalog: Catalog) -> dict[str, str]:
    index: dict[str, str] = {}
    for technique in catalog.techniques:
        for tactic in technique.attack.tactics:
            index.setdefault(tactic, technique.id)
    return index


def build_advisory(
    scenario: Scenario, composed: ComposedPlan, technique_catalog: Catalog
) -> tuple[str, dict[str, Any]]:
    covered: list[str] = []
    for stage in composed.stages:
        for tactic in stage.tactics:
            if tactic not in covered:
                covered.append(tactic)
    tactic_index = _tactic_to_technique(technique_catalog)
    gaps = [
        {"tactic": tactic, "suggested_technique": tid}
        for tactic, tid in tactic_index.items()
        if tactic not in covered
    ]
    span = (composed.events[-1].eventtime - composed.events[0].eventtime) if composed.events else 0
    coverage = {"covered_tactics": covered, "gap_tactics": gaps, "span_seconds": span}

    lines: list[str] = []
    lines.append(f"# Advisory: {scenario.name} ({scenario.id})")
    lines.append("")
    lines.append(_BOUNDARY)
    lines.append("")
    lines.append("## Through-line (correlate on these)")
    lines.append(f"- victim host (src): `{composed.victim}`")
    lines.append(f"- adversary IP (dst): `{composed.adversary}`")
    lines.append(f"- chain span: {span} seconds across {len(composed.stages)} stages")
    lines.append("")
    lines.append("## Kill chain")
    lines.append("| # | stage | technique | tactic(s) | ndr_uc | start | events |")
    lines.append("|---|-------|-----------|-----------|--------|-------|--------|")
    for stage in composed.stages:
        tactics = ", ".join(stage.tactics) or "-"
        label = stage.label or ""
        lines.append(
            f"| {stage.index} | {label} | {stage.technique_id} | {tactics} | "
            f"{stage.ndr_uc} | {stage.start_offset} | {stage.event_count} |"
        )
    lines.append("")
    lines.append("## ATT&CK coverage")
    lines.append("Covered: " + (", ".join(covered) or "none"))
    if gaps:
        lines.append("")
        lines.append("Gaps (the catalog can exercise these; this chain does not):")
        for gap in gaps:
            lines.append(f"- {gap['tactic']}: consider {gap['suggested_technique']}")
    lines.append("")
    lines.append("## Cross-stage correlation opportunities")
    lines.append(
        f"- The compromised host `src={composed.victim}` recurs across the host-based stages; "
        f"a rule keyed on it over the {span}s window links the chain."
    )
    lines.append(
        f"- C2 and exfil share `dst={composed.adversary}` (same synthetic adversary infrastructure)."
    )
    return "\n".join(lines) + "\n", coverage
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/pytest tests/test_scenario_advisory.py -q`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add replicant/scenario/advisory.py tests/test_scenario_advisory.py
git commit -m "feat(scenario): deterministic advisory coverage document"
```

---

## Task 4: Scenario manifest models + writers

**Files:**
- Modify: `replicant/core/models.py` (add after `RunManifest`)
- Modify: `replicant/audit/manifest.py` (add two writers)
- Test: `tests/test_scenario_manifest.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_scenario_manifest.py
from __future__ import annotations

import json
from pathlib import Path

from replicant.audit.manifest import write_advisory, write_scenario_manifest
from replicant.core.models import ScenarioManifest, ScenarioStageRecord


def _manifest() -> ScenarioManifest:
    return ScenarioManifest(
        replicant_version="test",
        scenario_id="SCEN-001",
        scenario_name="x",
        seed=1337,
        entities={"internal_hosts": 1},
        target="dry-run",
        transport="none",
        vendor="fortigate",
        total_event_count=3,
        stages=[
            ScenarioStageRecord(
                index=0, technique_id="REP-003", label="recon", ndr_uc="UC-002b",
                intensity="medium", start_offset="0s", event_count=3,
                tactics=["TA0007 Discovery"], techniques=["T1046"],
            )
        ],
        started_at="2026-07-19T14:00:00+04:00",
        ended_at="2026-07-19T14:00:01+04:00",
        anchor_epoch=1_752_586_800,
        coverage={"covered_tactics": ["TA0007 Discovery"]},
    )


def test_write_scenario_manifest_and_advisory(tmp_path: Path) -> None:
    manifest = _manifest()
    manifest_path = write_scenario_manifest(manifest, tmp_path)
    assert manifest_path.exists()
    assert manifest_path.name.startswith("SCEN-001-seed1337-")
    data = json.loads(manifest_path.read_text())
    assert data["total_event_count"] == 3 and data["stages"][0]["technique_id"] == "REP-003"

    advisory_path = write_advisory("# advisory\n", manifest_path)
    assert advisory_path.exists()
    assert advisory_path.name == manifest_path.stem + ".advisory.md"
    assert advisory_path.read_text().endswith("\n")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/pytest tests/test_scenario_manifest.py -q`
Expected: FAIL with `ImportError` (`ScenarioManifest` / `write_scenario_manifest` not defined).

- [ ] **Step 3: Add manifest models to `core/models.py`**

Append after `RunManifest`:

```python
class ScenarioRunRequest(BaseModel):
    scenario_id: str
    seed: int = 1337
    intensity_override: Intensity | None = None
    to_file: str | None = None
    no_send: bool = False
    rate_override: int | None = None
    collector: CollectorProfile | None = None
    anchor_epoch: int | None = None


class ScenarioStageRecord(BaseModel):
    index: int
    technique_id: str
    label: str | None
    ndr_uc: str
    intensity: str
    start_offset: str
    event_count: int
    tactics: list[str]
    techniques: list[str]


class ScenarioManifest(BaseModel):
    """Audit record for a scenario run (safety rule 5)."""

    replicant_version: str
    scenario_id: str
    scenario_name: str
    seed: int
    entities: dict[str, Any]
    target: str
    transport: str
    vendor: str
    accepted_as: str | None = None
    total_event_count: int
    stages: list[ScenarioStageRecord]
    started_at: str
    ended_at: str
    anchor_epoch: int
    warmup_note: str | None = None
    coverage: dict[str, Any] = Field(default_factory=dict)
```

- [ ] **Step 4: Add the writers to `audit/manifest.py`**

`json`, `Path`, and `_stamp_for_filename` already exist in this module. Add:

```python
from replicant.core.models import ScenarioManifest  # add to the existing imports block


def write_scenario_manifest(manifest: ScenarioManifest, out_dir: str | Path) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"{manifest.scenario_id}-seed{manifest.seed}-{_stamp_for_filename()}.json"
    path.write_text(
        json.dumps(manifest.model_dump(), indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )
    return path


def write_advisory(text: str, manifest_path: Path) -> Path:
    """Write the advisory next to its manifest with the paired name."""
    path = manifest_path.parent / f"{manifest_path.stem}.advisory.md"
    path.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
    return path
```

Note: if `audit/manifest.py` already imports from `replicant.core.models`, add `ScenarioManifest` to that line rather than a new import (avoid a circular-import surprise; `core.models` does not import `audit.manifest`).

- [ ] **Step 5: Run test to verify it passes**

Run: `./.venv/bin/pytest tests/test_scenario_manifest.py -q`
Expected: PASS (1 passed).

- [ ] **Step 6: Commit**

```bash
git add replicant/core/models.py replicant/audit/manifest.py tests/test_scenario_manifest.py
git commit -m "feat(scenario): scenario manifest models and writers"
```

---

## Task 5: Orchestrator `_emit` refactor + `run_scenario`

**Files:**
- Modify: `replicant/core/orchestrator.py`
- Test: `tests/test_scenario_orchestrator.py`

- [ ] **Step 1: Refactor the emit loop out of `run()` (no behavior change)**

Extract lines 199-234 of `run()` into a shared method. Add this method to `Orchestrator`:

```python
def _emit(
    self,
    events: list[EventRecord],
    *,
    send: bool,
    collector: CollectorProfile | None,
    to_file: str | None,
    eps_cap: int,
    on_event: EventCallback | None = None,
    on_progress: ProgressCallback | None = None,
) -> tuple[int, bool]:
    """Render + send/write a list of events. Shared by run() and run_scenario()."""
    count = 0
    stopped = False
    sink = FileSink(to_file) if to_file else None
    emitter = (
        SyslogEmitter(collector, hostname=self.settings.hostname)
        if send and collector is not None
        else None
    )
    total = len(events)
    try:
        if sink is not None:
            sink.open()
        if emitter is not None:
            emitter.connect()
        window_start = time.monotonic()
        in_window = 0
        for event in events:
            if self._stop.is_set():
                stopped = True
                break
            header, extension = self.profile.render(event)
            line = to_cef(header, extension)
            if on_event is not None:
                on_event(line, event)
            if sink is not None:
                sink.write(line)
            if emitter is not None:
                emitter.send(line, level=event.level)
                in_window += 1
                if eps_cap > 0 and in_window >= eps_cap:
                    elapsed = time.monotonic() - window_start
                    if elapsed < 1.0:
                        time.sleep(1.0 - elapsed)
                    window_start = time.monotonic()
                    in_window = 0
            count += 1
            if on_progress is not None and count % 100 == 0:
                on_progress(count, total)
    except KeyboardInterrupt:
        stopped = True
    finally:
        if sink is not None:
            sink.close()
        if emitter is not None:
            emitter.close()
    return count, stopped
```

Then replace the body of `run()` from the `sink = ...`/`emitter = ...` setup through the emit `try/finally` (orchestrator.py:192-234) with:

```python
        count, stopped = self._emit(
            plan.events,
            send=send,
            collector=request.collector,
            to_file=file_path,
            eps_cap=eps_cap,
            on_event=on_event,
            on_progress=on_progress,
        )
```

Keep everything before (fail-closed, `build_plan`, `_describe_target`, `eps_cap`, `started_at`) and after (`ended_at`, manifest build/write, `return RunResult(...)`).

- [ ] **Step 2: Run the existing suite to prove the refactor is behavior-preserving**

Run: `./.venv/bin/pytest tests/test_orchestrator.py tests/test_transport_loopback.py -q`
Expected: PASS (unchanged counts). This is the regression gate for the refactor.

- [ ] **Step 3: Write the failing scenario test**

```python
# tests/test_scenario_orchestrator.py
from __future__ import annotations

import socket
import threading
from pathlib import Path

import pytest

from replicant.core.models import (
    CollectorProfile,
    ScenarioRunRequest,
    load_catalog,
    load_scenario_catalog,
)
from replicant.core.orchestrator import Orchestrator

ROOT = Path(__file__).resolve().parents[1]
TECH = load_catalog(ROOT / "data" / "technique-catalog.yaml")
SCEN = load_scenario_catalog(ROOT / "data" / "scenario-catalog.yaml", TECH)


def _orch(tmp_path: Path, vendor: str = "fortigate") -> Orchestrator:
    from replicant.config.settings import Settings

    return Orchestrator(TECH, Settings(manifest_dir=str(tmp_path / "m"), vendor=vendor))


def test_scenario_to_file_is_byte_identical(tmp_path: Path) -> None:
    orch = _orch(tmp_path)
    a = tmp_path / "a.log"
    b = tmp_path / "b.log"
    orch.run_scenario(ScenarioRunRequest(scenario_id="SCEN-001", seed=1337, to_file=str(a), no_send=True), SCEN)
    orch.run_scenario(ScenarioRunRequest(scenario_id="SCEN-001", seed=1337, to_file=str(b), no_send=True), SCEN)
    assert a.read_bytes() == b.read_bytes() and a.stat().st_size > 0


def test_scenario_fails_closed(tmp_path: Path) -> None:
    orch = _orch(tmp_path)
    with pytest.raises(RuntimeError, match="fail-closed"):
        orch.run_scenario(ScenarioRunRequest(scenario_id="SCEN-001", no_send=False), SCEN)


def test_scenario_writes_manifest_and_advisory(tmp_path: Path) -> None:
    orch = _orch(tmp_path)
    result = orch.run_scenario(
        ScenarioRunRequest(scenario_id="SCEN-001", seed=1337, to_file=str(tmp_path / "s.log"), no_send=True),
        SCEN,
    )
    assert result.manifest_path.exists() and result.advisory_path.exists()
    assert result.manifest.total_event_count == result.event_count > 0
    assert len(result.manifest.stages) == 3
    assert result.manifest.coverage["covered_tactics"]


def test_scenario_vendor_renders_panos(tmp_path: Path) -> None:
    orch = _orch(tmp_path, vendor="paloalto")
    out = tmp_path / "pan.log"
    orch.run_scenario(ScenarioRunRequest(scenario_id="SCEN-001", seed=1337, to_file=str(out), no_send=True), SCEN)
    first = out.read_text().splitlines()[0]
    assert first.startswith("CEF:0|Palo Alto Networks|PAN-OS")


def test_scenario_loopback_udp_delivers(tmp_path: Path) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(2.0)
    port = sock.getsockname()[1]
    received: list[bytes] = []

    def rx() -> None:
        try:
            while True:
                received.append(sock.recvfrom(65535)[0])
        except OSError:
            pass

    thread = threading.Thread(target=rx, daemon=True)
    thread.start()
    orch = _orch(tmp_path)
    collector = CollectorProfile(name="t", host="127.0.0.1", port=port, transport="udp")
    result = orch.run_scenario(
        ScenarioRunRequest(scenario_id="SCEN-001", seed=1337, collector=collector, no_send=False),
        SCEN,
    )
    sock.close()
    thread.join(timeout=2)
    assert len(received) == result.event_count > 0
```

- [ ] **Step 4: Run scenario test to verify it fails**

Run: `./.venv/bin/pytest tests/test_scenario_orchestrator.py -q`
Expected: FAIL with `AttributeError: 'Orchestrator' object has no attribute 'run_scenario'`.

- [ ] **Step 5: Implement `run_scenario` + `ScenarioRunResult`**

Add imports at the top of `orchestrator.py` (extend the existing `replicant.core.models` import and add the new modules):

```python
from replicant.core.models import (
    Catalog, CollectorProfile, EventRecord, RunManifest, RunRequest,
    ScenarioCatalog, ScenarioManifest, ScenarioRunRequest, ScenarioStageRecord,
)
from replicant.audit.manifest import (
    human_summary, now_dubai_iso, write_advisory, write_manifest, write_scenario_manifest,
)
from replicant.scenario.advisory import build_advisory
from replicant.scenario.composer import ComposedPlan, compose
```

Add the result dataclass near `RunResult`:

```python
@dataclass
class ScenarioRunResult:
    manifest: ScenarioManifest
    manifest_path: Path
    advisory_path: Path
    event_count: int
    plan: ComposedPlan
    stopped: bool
```

Add the method to `Orchestrator`:

```python
def run_scenario(
    self,
    request: ScenarioRunRequest,
    scenario_catalog: ScenarioCatalog,
    on_progress: ProgressCallback | None = None,
    on_event: EventCallback | None = None,
) -> ScenarioRunResult:
    scenario = scenario_catalog.by_id(request.scenario_id)

    want_send = not request.no_send
    if want_send and request.collector is None and request.to_file is None:
        raise RuntimeError(
            "fail-closed: sending requested but no collector is configured and no "
            "--to-file was given. Configure a collector or use --to-file/--no-send."
        )
    send = want_send and request.collector is not None

    self.reset()
    composed = compose(
        scenario,
        self.catalog.by_id,
        self.engine,
        request.seed,
        request.anchor_epoch or self.settings.anchor_epoch,
        self.entities,
        intensity_override=request.intensity_override,
    )
    target, transport = self._describe_target(request, send)
    eps_cap = request.rate_override or self.settings.eps_cap

    started_at = now_dubai_iso()
    count, stopped = self._emit(
        composed.events,
        send=send,
        collector=request.collector,
        to_file=request.to_file,
        eps_cap=eps_cap,
        on_event=on_event,
        on_progress=on_progress,
    )
    ended_at = now_dubai_iso()

    advisory_text, coverage = build_advisory(scenario, composed, self.catalog)
    manifest = ScenarioManifest(
        replicant_version=__version__,
        scenario_id=scenario.id,
        scenario_name=scenario.name,
        seed=request.seed,
        entities=composed.entities | {"victim": composed.victim, "adversary": composed.adversary},
        target=target,
        transport=transport,
        vendor=self.settings.vendor,
        accepted_as=self.settings.accepted_as,
        total_event_count=count,
        stages=[
            ScenarioStageRecord(
                index=s.index, technique_id=s.technique_id, label=s.label, ndr_uc=s.ndr_uc,
                intensity=s.intensity, start_offset=s.start_offset, event_count=s.event_count,
                tactics=s.tactics, techniques=s.techniques,
            )
            for s in composed.stages
        ],
        started_at=started_at,
        ended_at=ended_at,
        anchor_epoch=composed.anchor_epoch,
        warmup_note="; ".join(composed.warmup_notes) or None,
        coverage=coverage,
    )
    manifest_path = write_scenario_manifest(manifest, self.settings.manifest_dir)
    advisory_path = write_advisory(advisory_text, manifest_path)
    return ScenarioRunResult(manifest, manifest_path, advisory_path, count, composed, stopped)
```

Note: `_describe_target(request, send)` (orchestrator.py:264) only reads `request.collector` and `request.to_file`, both present on `ScenarioRunRequest`, so it is reused directly.

- [ ] **Step 6: Run scenario test to verify it passes**

Run: `./.venv/bin/pytest tests/test_scenario_orchestrator.py -q`
Expected: PASS (5 passed).

- [ ] **Step 7: Commit**

```bash
git add replicant/core/orchestrator.py tests/test_scenario_orchestrator.py
git commit -m "feat(scenario): shared _emit refactor and Orchestrator.run_scenario"
```

---

## Task 6: CLI `scenario` verb (list / show / run)

**Files:**
- Modify: `replicant/cli/app.py`
- Test: `tests/test_scenario_cli.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_scenario_cli.py
from __future__ import annotations

from pathlib import Path

from replicant.cli.app import main


def test_scenario_list(capsys) -> None:
    rc = main(["scenario", "list"])
    out = capsys.readouterr().out
    assert rc == 0 and "SCEN-001" in out and "SCEN-003" in out


def test_scenario_show(capsys) -> None:
    rc = main(["scenario", "show", "SCEN-001"])
    out = capsys.readouterr().out
    assert rc == 0 and "Kill chain" in out and "correlate on these" in out.lower()


def test_scenario_run_to_file(tmp_path: Path, capsys) -> None:
    out = tmp_path / "s.log"
    rc = main(["scenario", "run", "SCEN-001", "--seed", "1337", "--to-file", str(out), "--no-send"])
    assert rc == 0 and out.exists() and out.stat().st_size > 0


def test_scenario_run_unknown_id(capsys) -> None:
    rc = main(["scenario", "run", "SCEN-404", "--to-file", "/tmp/x.log", "--no-send"])
    assert rc == 1 and "unknown scenario" in capsys.readouterr().out.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/pytest tests/test_scenario_cli.py -q`
Expected: FAIL (argparse errors on the unknown `scenario` command, or `main` returns nonzero with "invalid choice").

- [ ] **Step 3: Add the `scenario` subparser in `build_parser()`**

After the `run` verb block in `build_parser()`:

```python
    scenario = sub.add_parser("scenario", help="compose and run a multi-stage scenario")
    scen_actions = scenario.add_subparsers(dest="action")
    scen_actions.add_parser("list", help="list scenarios")
    scen_show = scen_actions.add_parser("show", help="show a scenario's stages + coverage, no emit")
    scen_show.add_argument("id", help="scenario id, e.g. SCEN-001")
    scen_run = scen_actions.add_parser("run", help="run a scenario")
    scen_run.add_argument("id", help="scenario id, e.g. SCEN-001")
    scen_run.add_argument("--seed", type=int)
    scen_run.add_argument("--intensity", choices=["low", "medium", "high"], help="override all stages")
    scen_run.add_argument("--to-file", dest="to_file")
    scen_run.add_argument("--no-send", dest="no_send", action="store_true")
    scen_run.add_argument("--rate", type=int)
    scen_run.add_argument("--host")
    scen_run.add_argument("--port", type=int, default=514)
    scen_run.add_argument("--transport", choices=["udp", "tcp", "tls"], default="udp")
    scen_run.add_argument("--tls-cafile", dest="tls_cafile")
    scen_run.add_argument("--tls-insecure", dest="tls_insecure", action="store_true")
    scen_run.add_argument("--profile", help="saved collector profile name")
    scen_run.add_argument("--vendor", choices=list(VENDORS))
```

`VENDORS` is already imported in `app.py` (used by the existing `run`/`connect` verbs). If not, add `from replicant.config.settings import VENDORS`.

- [ ] **Step 4: Add the `cmd_scenario` handler and dispatch**

Add near `cmd_run` in `app.py` (imports: `from replicant.core.models import load_scenario_catalog, ScenarioRunRequest, SCENARIO_CATALOG_PATH`; `from replicant.scenario.advisory import build_advisory`; `from replicant.scenario.composer import compose`):

```python
def cmd_scenario(args, catalog, settings, console) -> int:
    scenarios = load_scenario_catalog(SCENARIO_CATALOG_PATH, catalog)
    action = args.action or "list"

    if action == "list":
        for scenario in scenarios.scenarios:
            tactics = sorted({t for stage in scenario.stages
                              for t in catalog.by_id(stage.technique_id).attack.tactics})
            console.print(f"[bold]{scenario.id}[/bold]  {scenario.name}  "
                          f"[dim]{len(scenario.stages)} stages · {', '.join(tactics)}[/dim]")
        return 0

    try:
        scenario = scenarios.by_id(args.id)
    except KeyError:
        console.print(f"[red]unknown scenario[/red]: {args.id}. Try 'replicant scenario list'.")
        return 1

    if action == "show":
        from replicant.scenario.engine import ScenarioEngine
        from replicant.entities.model import EntityModel
        composed = compose(scenario, catalog.by_id, ScenarioEngine(), settings.default_seed,
                           settings.anchor_epoch, EntityModel.build())
        text, _ = build_advisory(scenario, composed, catalog)
        console.print(text)
        return 0

    # action == "run"
    collector, ok = _resolve_collector(args, console)
    if not ok:
        return 1
    request = ScenarioRunRequest(
        scenario_id=args.id,
        seed=args.seed if args.seed is not None else settings.default_seed,
        intensity_override=args.intensity,
        to_file=args.to_file,
        no_send=args.no_send,
        rate_override=args.rate,
        collector=collector,
    )
    orchestrator = Orchestrator(catalog, settings)
    try:
        result = orchestrator.run_scenario(request, scenarios)
    except (RuntimeError, NotImplementedError) as exc:
        console.print(f"[red]run refused[/red]: {exc}")
        return 1
    console.print(f"scenario {result.manifest.scenario_id}: {result.event_count} events across "
                  f"{len(result.manifest.stages)} stages")
    console.print(f"manifest: {result.manifest_path}")
    console.print(f"advisory: {result.advisory_path}")
    if result.stopped:
        console.print("[yellow]run stopped early (kill switch)[/yellow]")
    return 0
```

Add the dispatch branch in `main()` next to `if command == "run":`:

```python
    if command == "scenario":
        return cmd_scenario(args, catalog, settings, console)
```

Note: `--vendor` on `scenario run` must apply before dispatch, exactly like `run`. Confirm the existing pre-dispatch `settings = settings.model_copy(update={"vendor": args.vendor})` (app.py:245) also fires for `scenario` (guard it with `getattr(args, "vendor", None)` so `scenario list`/`show`, which have no `--vendor`, do not crash).

- [ ] **Step 5: Run test to verify it passes**

Run: `./.venv/bin/pytest tests/test_scenario_cli.py -q`
Expected: PASS (4 passed).

- [ ] **Step 6: Commit**

```bash
git add replicant/cli/app.py tests/test_scenario_cli.py
git commit -m "feat(scenario): CLI scenario list/show/run verb"
```

---

## Task 7: Rich menu `[a]` scenario picker

**Files:**
- Modify: `replicant/cli/menu.py`
- Test: `tests/test_menu.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_menu.py` (follow the file's existing pattern for building a menu/orchestrator; adjust the import if `run_menu`'s helpers differ):

```python
def test_pick_scenario_returns_selection(monkeypatch) -> None:
    from rich.console import Console
    from replicant.cli.menu import _pick_scenario
    from replicant.core.models import load_catalog, load_scenario_catalog
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    tech = load_catalog(root / "data" / "technique-catalog.yaml")
    scen = load_scenario_catalog(root / "data" / "scenario-catalog.yaml", tech)
    monkeypatch.setattr("replicant.cli.menu.Prompt.ask", staticmethod(lambda *a, **k: "1"))
    chosen = _pick_scenario(Console(), scen)
    assert chosen.id == scen.scenarios[0].id
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/pytest tests/test_menu.py -q`
Expected: FAIL with `ImportError: cannot import name '_pick_scenario'`.

- [ ] **Step 3: Add the picker + run helper + `[a]` branch**

Add near `_pick_vendor` in `menu.py` (imports: `from replicant.core.models import ScenarioCatalog, ScenarioRunRequest, Scenario, load_scenario_catalog, SCENARIO_CATALOG_PATH`; `from replicant.scenario.advisory import build_advisory`; `from replicant.scenario.composer import compose`):

```python
def _pick_scenario(console: Console, scenarios: "ScenarioCatalog") -> "Scenario":
    console.print("  [bold]Attack scenario[/bold]")
    for index, scenario in enumerate(scenarios.scenarios, start=1):
        console.print(f"    [{index}] {scenario.id}  {scenario.name} "
                      f"[dim]({len(scenario.stages)} stages)[/dim]")
    choices = [str(i) for i in range(1, len(scenarios.scenarios) + 1)]
    choice = Prompt.ask("  Select scenario", choices=choices, default="1")
    return scenarios.scenarios[int(choice) - 1]


def _run_scenario(orchestrator, scenario, scenarios, seed, collector, console) -> None:
    from rich.progress import Progress
    scenario_obj = scenario
    request = ScenarioRunRequest(
        scenario_id=scenario_obj.id, seed=seed, collector=collector,
        no_send=collector is None,
        to_file=None if collector is not None else None,
    )
    # show the coverage preview first
    from replicant.scenario.engine import ScenarioEngine
    from replicant.entities.model import EntityModel
    composed = compose(scenario_obj, orchestrator.catalog.by_id, ScenarioEngine(), seed,
                       orchestrator.settings.anchor_epoch, EntityModel.build())
    text, _ = build_advisory(scenario_obj, composed, orchestrator.catalog)
    console.print(text)
    if collector is None:
        console.print("  [yellow]no collector set; use [c] to connect, or run headless with "
                      "'replicant scenario run --to-file'[/yellow]")
        return
    with Progress() as progress:
        task = progress.add_task(f"emitting {scenario_obj.id}", total=composed.total_count)
        result = orchestrator.run_scenario(
            request, scenarios, on_progress=lambda c, t: progress.update(task, completed=c))
    console.print(f"  {result.event_count} events · manifest {result.manifest_path}")
    console.print(f"  advisory {result.advisory_path}")
```

In `run_menu`, load the scenario catalog once after building the orchestrator:

```python
    scenarios = load_scenario_catalog(SCENARIO_CATALOG_PATH, catalog)
```

Update the prompt line (menu.py:223) to include `[a]`:

```python
    console.print("  [dim][1-11] technique   [a] scenario   [c] connection   "
                  "[v] vendor   [s] seed   [q] quit[/dim]")
```

Add the branch **before** the digit guard (before menu.py:242):

```python
        if choice == "a":
            scenario = _pick_scenario(console, scenarios)
            _run_scenario(orchestrator, scenario, scenarios, seed, collector, console)
            continue
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/pytest tests/test_menu.py -q`
Expected: PASS (existing menu tests + the new one).

- [ ] **Step 5: Commit**

```bash
git add replicant/cli/menu.py tests/test_menu.py
git commit -m "feat(scenario): Rich menu [a] scenario picker and run"
```

---

## Task 8: Docs + full quality gate

**Files:**
- Modify: `docs/blueprint.md` (Phase 4 line), `README.md` (test count + a scenario usage line)

- [ ] **Step 1: Mark Phase 4 done in the blueprint**

In `docs/blueprint.md`, append to the Phase 4 line (around line 306): ` Done 2026-07-19: data/scenario-catalog.yaml + replicant/scenario/composer.py + advisory.py + Orchestrator.run_scenario, CLI 'scenario' verb and Rich menu [a]. Deterministic, no LLM. Web UI deferred.`

- [ ] **Step 2: Add a scenario line to the README run section**

Under the run examples, add:

```
replicant scenario list
replicant scenario show SCEN-001
replicant scenario run SCEN-001 --seed 1337 --to-file ./out/s1.log --no-send
```

Update the `# 185 tests` comment to the new count from Step 3.

- [ ] **Step 3: Full quality gate**

Run:
```bash
./.venv/bin/pytest -q
./.venv/bin/black --check replicant tests
./.venv/bin/ruff check replicant tests
./.venv/bin/mypy replicant
(cd webui && npm run build)   # unchanged; confirm still green
```
Expected: all pass; note the new total test count (185 + roughly 19 new). The CEF golden tests pass unchanged (no engine/profile edit).

- [ ] **Step 4: Commit**

```bash
git add docs/blueprint.md README.md
git commit -m "docs(scenario): mark Phase 4 done and document the scenario CLI"
```

- [ ] **Step 5: Push and open the PR (only when the user asks)**

```bash
git push -u origin feature/phase4-scenario-composition
gh pr create -R 404SecNotFound/Replicant --base main --head feature/phase4-scenario-composition \
  --title "Phase 4: ATT&CK scenario composition" --body-file docs/phase4-scenario-composition-design.md
```

---

## Self-review notes (author checklist, done)

- **Spec coverage:** data model (T1), composer + pinned through-line (T2), advisory + coverage/gaps (T3), manifest (T4), `_emit` refactor + `run_scenario` + safety/vendor/loopback/determinism (T5), CLI list/show/run (T6), menu `[a]` (T7), docs + gate (T8). All spec sections map to a task.
- **Placeholder scan:** none; every code step has full code and exact commands.
- **Type consistency:** `compose(scenario, technique_by_id, engine, seed, anchor_epoch, base_entities, intensity_override=None)` is called identically in T5/T6/T7; `ComposedPlan.victim/adversary/stages/events/total_count`, `StageResult`, `ScenarioStageRecord`, and `ScenarioManifest` field names match across tasks; `run_scenario(request, scenario_catalog, ...)` signature is consistent; `_emit(events, *, send, collector, to_file, eps_cap, on_event, on_progress)` matches both call sites.
- **Known implementation checks to honor (flagged from recon):** `EntityModel` is a dataclass, pin via `dataclasses.replace` from validated pools (T2); `engine.plan` takes `entities`/`seed` positionally (T2); `human_summary` takes a Path not a dir (unused here, do not misuse); add `ScenarioManifest` to `audit/manifest.py` imports without creating a circular import (T4); guard the pre-dispatch `--vendor` copy for `scenario list/show` which lack that flag (T6).
