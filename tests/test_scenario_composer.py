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
