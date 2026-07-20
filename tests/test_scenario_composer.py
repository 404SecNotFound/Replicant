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
# tests/test_scenario_composer.py
from __future__ import annotations

from pathlib import Path

import pytest

from replicant.config.settings import parse_duration
from replicant.core.models import load_catalog, load_scenario_catalog
from replicant.entities.model import EntityModel
from replicant.scenario.composer import ComposedPlan, compose
from replicant.scenario.engine import ScenarioEngine

ROOT = Path(__file__).resolve().parents[1]
TECH = load_catalog(ROOT / "data" / "technique-catalog.yaml")
SCEN = load_scenario_catalog(ROOT / "data" / "scenario-catalog.yaml", TECH)
ANCHOR = 1_752_586_800
ALL_SCENARIOS = [s.id for s in SCEN.scenarios]

_COMPOSED: dict[str, ComposedPlan] = {}


def _compose(scenario_id: str, seed: int = 1337) -> ComposedPlan:
    """A fresh composition. Use where independence between calls matters."""

    scenario = SCEN.by_id(scenario_id)
    return compose(scenario, TECH.by_id, ScenarioEngine(), seed, ANCHOR, EntityModel.build())


def _composed(scenario_id: str) -> ComposedPlan:
    """Cached composition for read-only assertions. Safe because compose is deterministic,
    and it keeps the larger scenarios (SCEN-002 emits ~181k events) from being rebuilt per test."""

    if scenario_id not in _COMPOSED:
        _COMPOSED[scenario_id] = _compose(scenario_id)
    return _COMPOSED[scenario_id]


@pytest.mark.parametrize("scenario_id", ALL_SCENARIOS)
def test_compose_is_deterministic(scenario_id: str) -> None:
    a = _compose(scenario_id)
    b = _compose(scenario_id)
    assert a.total_count == b.total_count and a.total_count > 0
    assert [e.eventtime for e in a.events] == [e.eventtime for e in b.events]
    assert a.victim == b.victim and a.adversary == b.adversary


@pytest.mark.parametrize("scenario_id", ALL_SCENARIOS)
def test_merge_preserves_every_stage_event(scenario_id: str) -> None:
    """The merge drops nothing and duplicates nothing, and the timeline is ordered."""

    plan = _composed(scenario_id)
    assert sum(stage.event_count for stage in plan.stages) == plan.total_count
    assert plan.total_count == len(plan.events)
    times = [event.eventtime for event in plan.events]
    assert times == sorted(times)


@pytest.mark.parametrize("scenario_id", ALL_SCENARIOS)
def test_every_stage_starts_at_or_after_its_offset(scenario_id: str) -> None:
    """The ordering guarantee composition promises: stage k emits at/after anchor + offset_k.

    This is the regression gate for techniques whose builder anchors to an internal window
    instead of the stage anchor (REP-005 pins to the off-hours window of its anchor's day).
    Warm-up stages are exempt: REP-008's baseline legitimately precedes its own anchor.
    """

    plan = _composed(scenario_id)
    for stage in plan.stages:
        if stage.has_warmup:
            continue
        expected = ANCHOR + parse_duration(stage.start_offset)
        assert stage.start_epoch is not None
        assert stage.start_epoch >= expected, (
            f"{scenario_id} stage {stage.index} ({stage.technique_id}) begins "
            f"{expected - stage.start_epoch}s before its start_offset"
        )


def test_stages_do_not_run_backwards() -> None:
    """SCEN-001's exfil finale must not precede the recon that causes it (review finding)."""

    plan = _composed("SCEN-001")
    recon, c2, exfil = plan.stages
    assert recon.technique_id == "REP-003" and exfil.technique_id == "REP-005"
    assert exfil.aligned_days == 1, "the off-hours exfil stage should be advanced one day"
    assert recon.start_epoch is not None and exfil.start_epoch is not None
    assert c2.start_epoch is not None and c2.end_epoch is not None
    assert exfil.start_epoch > recon.start_epoch
    assert exfil.start_epoch >= c2.end_epoch


def test_pinned_victim_is_the_src_for_host_based_stages() -> None:
    plan = _compose("SCEN-001")  # REP-003, REP-001, REP-005 all use internal_hosts as src
    srcs = {e.src for e in plan.events if e.src is not None}
    assert srcs == {plan.victim}


def test_stage_offsets_applied() -> None:
    plan = _compose("SCEN-001")
    # stage 1 (REP-001) starts at anchor + 1h; its earliest event is >= that
    stage1 = [r for r in plan.stages if r.index == 1][0]
    assert stage1.start_offset == "1h"
    assert (
        plan.stages[0].event_count + plan.stages[1].event_count + plan.stages[2].event_count
        == plan.total_count
    )
    # Mutation guard on the offset arithmetic itself. Stage 1 is REP-001 at start_offset "1h";
    # its beacons run victim -> adversary from stage_anchor = ANCHOR + 3600 onward, and its
    # earliest beacon lands exactly on that anchor. (REP-005 at "6h" is not usable here: its
    # builder anchors to the off-hours window, not the stage anchor.) The victim->adversary
    # events at/after ANCHOR are exactly those REP-001 beacons; REP-005's victim->adversary
    # events all fall before ANCHOR. If the composer dropped `+ parse_duration(start_offset)`,
    # the first beacon would land on ANCHOR instead, so this fails.
    c2_beacons = [
        e.eventtime
        for e in plan.events
        if e.src == plan.victim and e.dst == plan.adversary and e.eventtime >= ANCHOR
    ]
    assert c2_beacons  # the "1h" C2 stage produced beacons after the anchor
    assert min(c2_beacons) >= ANCHOR + 3600


def test_intensity_override_applies_to_every_stage() -> None:
    scenario = SCEN.by_id("SCEN-001")
    plan = compose(
        scenario,
        TECH.by_id,
        ScenarioEngine(),
        1337,
        ANCHOR,
        EntityModel.build(),
        intensity_override="high",
    )
    assert {stage.intensity for stage in plan.stages} == {"high"}
    # the override reaches the engine, not just the record
    assert plan.total_count != _composed("SCEN-001").total_count


def test_warmup_notes_are_aggregated() -> None:
    """SCEN-002 contains REP-008, whose builder emits a warm-up baseline note."""

    plan = _composed("SCEN-002")
    assert plan.warmup_notes, "expected REP-008 to contribute a warm-up note"
    assert any("REP-008" in note for note in plan.warmup_notes)
    assert any(stage.has_warmup for stage in plan.stages)


def test_stage_records_carry_the_observed_window() -> None:
    for scenario_id in ALL_SCENARIOS:
        plan = _composed(scenario_id)
        for stage in plan.stages:
            assert stage.start_epoch is not None and stage.end_epoch is not None
            assert stage.start_epoch <= stage.end_epoch
            stage_events = [
                e for e in plan.events if stage.start_epoch <= e.eventtime <= stage.end_epoch
            ]
            assert stage_events, f"{scenario_id} stage {stage.index} window contains no events"


def test_single_stage_matches_direct_run() -> None:
    # a one-stage scenario composed == running the technique directly, same seed/anchor/entities
    scenario = SCEN.by_id("SCEN-001").model_copy(
        update={"stages": [SCEN.by_id("SCEN-001").stages[0]]}
    )
    engine = ScenarioEngine()
    entities = EntityModel.build()
    composed = compose(scenario, TECH.by_id, engine, 1337, ANCHOR, entities)
    # reproduce the composer's pinned entities + stage seed for a direct call
    from dataclasses import replace

    import numpy as np

    rng = np.random.default_rng(1337)
    victim = str(rng.choice(entities.internal_hosts))
    adversary = str(rng.choice(entities.adversary_external))
    pinned = replace(entities, internal_hosts=[victim], adversary_external=[adversary])
    stage_seed = int(np.random.SeedSequence(1337).spawn(1)[0].generate_state(1)[0])
    direct = engine.plan(TECH.by_id("REP-003"), "medium", pinned, stage_seed, anchor_epoch=ANCHOR)
    assert [e.eventtime for e in composed.events] == [e.eventtime for e in direct.events]
