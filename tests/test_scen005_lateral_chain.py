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

"""SCEN-005: unfamiliar VPN source, a login chain, then an SMB write fan-out.

The chain needed three things the composer could not do before 2026-11-10, and
each has a guard here that was run against the code without it:

- REP-018 could not be planned under scenario pinning at all. The pinned
  workstation pool held one host and a path needs several. The composer keeps
  the whole pool in ``internal_network`` and the path starts at the pinned
  victim. With the victim-first rule removed, the entry join guard goes red.
- The fan-out has to leave from the host the path ended on, not from the host
  it started on. ``source_host: previous-path-end`` hands that host to the
  stage. With the handoff removed, the handoff guard goes red.
- Both joins are measured by the advisory from the composed events. A chain
  with no VPN stage, or with no stage after the path, claims neither.

Seeds are part of the guard: every property is asserted on seeds 1 to 20.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from replicant.core.models import Scenario, ScenarioStage, load_catalog, load_scenario_catalog
from replicant.entities.model import EntityModel
from replicant.resources import SCENARIO_CATALOG, TECHNIQUE_CATALOG
from replicant.scenario.advisory import build_advisory
from replicant.scenario.composer import ComposedPlan, _lateral_path, _pin_entities, compose
from replicant.scenario.engine import ScenarioEngine

CATALOG = load_catalog(TECHNIQUE_CATALOG)
SCENARIOS = load_scenario_catalog(SCENARIO_CATALOG, CATALOG)
ENTITIES = EntityModel.build()
ENGINE = ScenarioEngine()
ANCHOR = 1_800_000_000
SEEDS = tuple(range(1, 21))
SCEN = SCENARIOS.by_id("SCEN-005")


def _compose(seed: int, scenario: Scenario = SCEN, controls: str = "positive") -> ComposedPlan:
    return compose(scenario, CATALOG.by_id, ENGINE, seed, ANCHOR, ENTITIES, controls=controls)


def test_scen005_is_the_three_stages_in_order() -> None:
    assert [s.technique_id for s in SCEN.stages] == ["REP-046", "REP-018", "REP-052"]
    assert [s.source_host for s in SCEN.stages] == ["victim", "victim", "previous-path-end"]


@pytest.mark.parametrize("intensity", ["low", "medium", "high"])
def test_rep018_plans_under_pinning_and_starts_at_the_victim(intensity: str) -> None:
    technique = CATALOG.by_id("REP-018")
    for seed in SEEDS:
        pinned, victim, _adversary = _pin_entities(ENTITIES, seed)
        plan = ENGINE.plan(technique, intensity, pinned, seed, anchor_epoch=ANCHOR)
        path = _lateral_path([e for e in plan.events if e.control == "positive"])
        assert len(path) == int(plan.effective_params["path_len"]), (intensity, seed, path)
        assert path[0] == victim, (intensity, seed, path)
        assert len(set(path)) == len(path), (intensity, seed, path)
        entry = next(e for e in plan.events if e.control == "positive" and e.action == "tunnel-up")
        assert entry.extra["tunnelip"] == victim, (intensity, seed)
        # The benign star's source is off the path, so it is not also a hop.
        star = {e.src for e in plan.events if e.control == "negative" and e.action == "login"}
        assert star and not star & set(path), (intensity, seed, star)


def test_rep018_standalone_plan_is_unchanged_by_the_pinned_branch() -> None:
    """Outside a scenario the hops are drawn exactly as before: the first hop is
    whatever the draw returns, not a fixed host."""

    technique = CATALOG.by_id("REP-018")
    firsts = set()
    for seed in SEEDS:
        plan = ENGINE.plan(technique, "medium", ENTITIES, seed, anchor_epoch=ANCHOR)
        firsts.add(_lateral_path([e for e in plan.events if e.control == "positive"])[0])
    assert len(firsts) > 10, firsts


@pytest.mark.parametrize("seed", SEEDS)
def test_scen005_joins_are_emitted_and_measured(seed: int) -> None:
    composed = _compose(seed)
    vpn, chain, fanout = composed.stages
    # Stage order on the clock: no stage starts before the one before it ends.
    assert vpn.end_epoch is not None and chain.start_epoch is not None
    assert chain.end_epoch is not None and fanout.start_epoch is not None
    assert vpn.end_epoch < chain.start_epoch < chain.end_epoch < fanout.start_epoch
    # Entry join: the VPN stage's assignment is the path's first host, the victim.
    assert vpn.top_tunnelip == composed.victim
    assert chain.path and chain.path[0] == composed.victim, f"seed {seed}: {chain.path}"
    # Handoff join: the fan-out's only source is the path's last host, not its first.
    assert chain.path[-1] != composed.victim
    assert fanout.top_src == chain.path[-1], f"seed {seed}: fan-out left from {fanout.top_src}"
    assert fanout.top_src_count == fanout.event_count
    assert not vpn.path and not fanout.path

    text, coverage = build_advisory(SCEN, composed, CATALOG)
    assert coverage["lateral_path_stage_indices"] == [1]
    assert coverage["lateral_entry_stage_indices"] == [1]
    assert coverage["lateral_handoff_stage_indices"] == [2]
    for tactic in ("TA0001 Initial Access", "TA0008 Lateral Movement", "TA0040 Impact"):
        assert tactic in coverage["covered_tactics"]
    assert f"stage 1's path starts at `{composed.victim}`" in text
    assert "it does not single one of them out" in text
    assert f"`src={chain.path[-1]}` is the dominant source in stage 2" in text
    assert f"| src={chain.path[-1]} |" in text
    assert "no stage here carries one that matches the victim" not in text


def test_scen005_joins_are_measured_not_assumed() -> None:
    composed = _compose(1337)
    # No stage after the path: nothing is handed on, and the advisory says nothing joins.
    no_fanout = replace(composed, stages=composed.stages[:2])
    _, coverage = build_advisory(SCEN, no_fanout, CATALOG)
    assert coverage["lateral_handoff_stage_indices"] == []
    # No VPN stage before the path: the entry join is not claimed.
    no_vpn = replace(composed, stages=composed.stages[1:])
    text, coverage = build_advisory(SCEN, no_vpn, CATALOG)
    assert coverage["lateral_entry_stage_indices"] == []
    assert "is the join into the path" not in text
    # A fan-out that leaves from the victim instead: the path is reported, the
    # handoff is not, and the text says so.
    unhanded = Scenario(
        id="SCEN-T",
        name="t",
        description="d",
        stages=[SCEN.stages[0], SCEN.stages[1], replace_stage(SCEN.stages[2])],
    )
    composed = _compose(1337, unhanded)
    text, coverage = build_advisory(unhanded, composed, CATALOG)
    assert composed.stages[2].top_src == composed.victim
    assert coverage["lateral_path_stage_indices"] == [1]
    assert coverage["lateral_handoff_stage_indices"] == []
    assert "so nothing here joins the path to what follows" in text


def replace_stage(stage: ScenarioStage) -> ScenarioStage:
    return stage.model_copy(update={"source_host": "victim"})


def test_a_handoff_with_no_earlier_path_is_refused() -> None:
    orphan = Scenario(id="SCEN-T", name="t", description="d", stages=[SCEN.stages[2]])
    with pytest.raises(ValueError, match="no earlier stage emitted one"):
        _compose(1, orphan)


@pytest.mark.parametrize("controls", ["both", "negative"])
def test_scen005_hands_the_same_host_on_whichever_streams_are_emitted(controls: str) -> None:
    """The handoff reads the stage's whole positive stream, so a foils-only run
    composes, and the SMB stage's foil is the one a positive run would pair with."""

    positive = _compose(7)
    other = _compose(7, controls=controls)
    assert other.negative_count > 0
    if controls == "both":
        assert other.stages[2].top_src == positive.stages[2].top_src
    wanted = [e for e in positive.events]
    emitted_positive = [e for e in other.events if e.control == "positive"]
    assert emitted_positive == (wanted if controls == "both" else [])


@pytest.mark.parametrize("scenario_id", ["SCEN-001", "SCEN-002", "SCEN-003", "SCEN-004"])
def test_the_other_chains_report_no_lateral_path(scenario_id: str) -> None:
    scenario = SCENARIOS.by_id(scenario_id)
    for seed in (1, 7, 1337):
        composed = _compose(seed, scenario)
        _, coverage = build_advisory(scenario, composed, CATALOG)
        assert coverage["lateral_path_stage_indices"] == [], (scenario_id, seed)
        assert coverage["lateral_handoff_stage_indices"] == []


def test_scen005_fits_a_requested_duration() -> None:
    from replicant.scenario.composer import compose as compose_timed

    composed = compose_timed(
        SCEN, CATALOG.by_id, ENGINE, 1337, ANCHOR, ENTITIES, duration_s=2 * 3600
    )
    chain, fanout = composed.stages[1], composed.stages[2]
    assert chain.path and fanout.top_src == chain.path[-1]
    times = [e.eventtime for e in composed.events]
    assert max(times) - min(times) <= 2 * 3600
