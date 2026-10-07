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
"""Scenarios can carry their stages' benign foils (2026-10-07 review).

Until this change ``compose()`` dropped every negative-control event, so a
scenario run was attack-only: the one condition the catalog header says lets
any detection score perfectly. The default is unchanged (positive only), so
older runs, manifests and advisories mean what they meant. ``--controls both``
composes the foils onto the same timeline; stage statistics and the advisory
count the attack stream only, whichever streams are emitted.

Positive control: on the code before this change ``compose()`` has no
``controls`` parameter, so every test here fails with a ``TypeError``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from replicant.config.settings import Settings
from replicant.core.models import ScenarioRunRequest, load_catalog, load_scenario_catalog
from replicant.core.orchestrator import Orchestrator
from replicant.entities.model import EntityModel
from replicant.resources import SCENARIO_CATALOG, TECHNIQUE_CATALOG
from replicant.scenario.advisory import build_advisory
from replicant.scenario.composer import compose
from replicant.scenario.engine import ScenarioEngine

CATALOG = load_catalog(TECHNIQUE_CATALOG)
SCENARIOS = load_scenario_catalog(SCENARIO_CATALOG, CATALOG)
ANCHOR = 1_800_000_000


def _compose(scenario_id: str, controls: str, seed: int = 1337):
    return compose(
        SCENARIOS.by_id(scenario_id),
        CATALOG.by_id,
        ScenarioEngine(),
        seed,
        ANCHOR,
        EntityModel.build(),
        controls=controls,
    )


def _foil_scenarios() -> list[str]:
    return [
        scenario.id
        for scenario in SCENARIOS.scenarios
        if any(CATALOG.by_id(stage.technique_id).emits_foil for stage in scenario.stages)
    ]


@pytest.mark.parametrize("scenario_id", [s.id for s in SCENARIOS.scenarios])
def test_the_default_is_the_attack_alone_as_before(scenario_id: str) -> None:
    composed = _compose(scenario_id, "positive")
    assert composed.controls == "positive"
    assert composed.negative_count == 0
    assert all(event.control == "positive" for event in composed.events)


@pytest.mark.parametrize("scenario_id", _foil_scenarios())
@pytest.mark.parametrize("seed", [1, 7, 1337])
def test_both_composes_the_foils_onto_the_same_timeline(scenario_id: str, seed: int) -> None:
    positive = _compose(scenario_id, "positive", seed)
    both = _compose(scenario_id, "both", seed)
    negative = _compose(scenario_id, "negative", seed)

    assert both.negative_count > 0
    assert sum(1 for e in both.events if e.control != "positive") == both.negative_count
    # The attack stream is exactly what a positive-only run emits, in the same
    # order, and the negative-only run is exactly the foils.
    assert [e for e in both.events if e.control == "positive"] == positive.events
    assert [e for e in both.events if e.control != "positive"] == negative.events
    assert both.total_count == len(positive.events) + len(negative.events)
    # Time order holds across the merged streams.
    times = [e.eventtime for e in both.events]
    assert times == sorted(times)


@pytest.mark.parametrize("scenario_id", _foil_scenarios())
def test_stage_statistics_and_the_advisory_count_the_attack_only(scenario_id: str) -> None:
    positive = _compose(scenario_id, "positive")
    both = _compose(scenario_id, "both")
    negative = _compose(scenario_id, "negative")

    for a, b, n in zip(positive.stages, both.stages, negative.stages, strict=True):
        assert (a.event_count, a.top_src, a.top_src_count, a.top_dst, a.top_dst_count) == (
            b.event_count,
            b.top_src,
            b.top_src_count,
            b.top_dst,
            b.top_dst_count,
        )
        assert n.event_count == 0  # a foils-only run has no attack to count

    scenario = SCENARIOS.by_id(scenario_id)
    text_positive, coverage_positive = build_advisory(scenario, positive, CATALOG)
    text_both, coverage_both = build_advisory(scenario, both, CATALOG)
    assert coverage_both["covered_tactics"] == coverage_positive["covered_tactics"]
    assert coverage_both["victim_stage_indices"] == coverage_positive["victim_stage_indices"]
    assert "Benign foils" in text_both and "false positive" in text_both
    assert "Benign foils" not in text_positive


def test_the_manifest_records_the_streams_it_carried(tmp_path: Path) -> None:
    scenario_id = _foil_scenarios()[0]
    settings = Settings(manifest_dir=str(tmp_path / "manifests"))
    orchestrator = Orchestrator(CATALOG, settings)
    request = ScenarioRunRequest(
        scenario_id=scenario_id,
        seed=1337,
        no_send=True,
        to_file=str(tmp_path / "out.log"),
        controls="both",
        anchor_epoch=ANCHOR,
        pace="burst",
    )
    result = orchestrator.run_scenario(request, SCENARIOS)
    manifest = result.manifest
    assert manifest.controls == "both"
    assert manifest.negative_event_count > 0
    assert manifest.planned_event_count == sum(s.event_count for s in manifest.stages) + (
        manifest.negative_event_count
    )
    assert manifest.total_event_count == manifest.planned_event_count


def test_the_request_default_is_positive() -> None:
    assert ScenarioRunRequest(scenario_id="SCEN-001").controls == "positive"
