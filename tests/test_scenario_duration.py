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
"""A scenario can be asked how long it should take.

Single techniques have taken ``--duration`` since Phase 1. Scenarios could not:
their span was whatever the stage offsets in the catalog happened to add up to,
so SCEN-001 was 12h 14m and nothing could ask it to be two hours. The only lever
was ``--speed``, which is a different thing entirely -- it keeps the event count
and divides every interval, producing a fast-forward whose beacons no longer
beacon at their own cadence.

Duration scales the composition instead: stage start offsets move proportionally
and each stage is planned for a proportionally shorter window, so the chain keeps
its order and its spacing while every technique inside it keeps its own
characteristic interval and simply emits fewer events.

One thing deliberately cannot be scaled. A stage pinned to an absolute window
(REP-005 is off-hours bulk transfer, and off-hours is 00:00-06:00) answers to the
clock rather than to the scenario, so it can push the run past the requested
duration. That is recorded rather than hidden.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from replicant.config.settings import Settings
from replicant.core.models import ScenarioRunRequest, load_catalog, load_scenario_catalog
from replicant.core.orchestrator import Orchestrator
from replicant.entities.model import EntityModel
from replicant.resources import SCENARIO_CATALOG, TECHNIQUE_CATALOG
from replicant.scenario.composer import compose
from replicant.scenario.engine import ScenarioEngine

CATALOG = load_catalog(TECHNIQUE_CATALOG)
SCENARIOS = load_scenario_catalog(SCENARIO_CATALOG, CATALOG)
SETTINGS = Settings()
TWO_HOURS = 7200

# SCEN-003 is the one to assert timing on: four stages, 653 events, and no stage
# pinned to an absolute window, so the composition is free to be scaled. SCEN-001
# carries the off-hours stage and is used below for exactly that reason.
FREE = "SCEN-003"
PINNED = "SCEN-001"


def _compose(scenario_id: str, duration_s: int | None = None):
    return compose(
        SCENARIOS.by_id(scenario_id),
        CATALOG.by_id,
        ScenarioEngine(),
        1337,
        SETTINGS.anchor_epoch,
        EntityModel.build(),
        duration_s=duration_s,
    )


def _span(composed) -> int:
    times = [event.eventtime for event in composed.events]
    return (max(times) - min(times)) if times else 0


def test_a_scenario_runs_for_the_duration_it_was_asked_for() -> None:
    natural = _span(_compose(FREE))
    assert natural > TWO_HOURS, "fixture assumption: the natural chain is longer than 2h"

    asked = _span(_compose(FREE, TWO_HOURS))

    assert asked == pytest.approx(
        TWO_HOURS, rel=0.15
    ), f"asked for 2h, composed {asked / 3600:.2f}h"


def test_the_chain_keeps_its_order_when_compressed() -> None:
    """A kill chain that reorders under compression is not the same kill chain.
    Recon has to still precede exfiltration."""

    natural = _compose(FREE)
    asked = _compose(FREE, TWO_HOURS)

    natural_order = [
        s.technique_id for s in sorted(natural.stages, key=lambda s: s.start_epoch or 0)
    ]
    asked_order = [s.technique_id for s in sorted(asked.stages, key=lambda s: s.start_epoch or 0)]

    assert asked_order == natural_order


def test_every_stage_still_emits_something() -> None:
    """Compression that empties a stage has removed a step from the chain rather
    than shortening it."""

    asked = _compose(FREE, TWO_HOURS)

    empty = [s.technique_id for s in asked.stages if s.event_count == 0]
    assert not empty, f"stages emptied by compression: {empty}"


def test_no_duration_leaves_the_composition_untouched() -> None:
    """The default path has to stay byte-identical, or every scenario golden
    comparison and every determinism claim is a lie."""

    before = _compose(FREE)
    after = _compose(FREE, None)

    assert [e.eventtime for e in before.events] == [e.eventtime for e in after.events]
    assert len(before.events) == len(after.events)


def test_a_stage_pinned_to_an_absolute_window_is_reported_not_hidden() -> None:
    """SCEN-001 has an off-hours stage that answers to the clock, so a two hour
    request cannot be met. The composition says so rather than returning a run
    that is quietly twelve hours long."""

    asked = _compose(PINNED, TWO_HOURS)

    span = _span(asked)
    if span > TWO_HOURS * 1.15:
        assert any("duration" in note.lower() for note in asked.warmup_notes), (
            f"composed {span / 3600:.2f}h for a 2h request and recorded no note: "
            f"{asked.warmup_notes}"
        )


# -- through the orchestrator and the request model ---------------------------


def test_the_request_carries_a_duration(tmp_path: Path) -> None:
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))

    preview = orch.preview_scenario_pacing(
        ScenarioRunRequest(scenario_id=FREE, duration="2h", pace="plan"),
        SCENARIOS,
        sending=True,
    )

    assert preview.plan_span_s == pytest.approx(TWO_HOURS, rel=0.15)
    # Plan paced, the wall clock is the span. That is the point of asking.
    assert preview.projected_s == pytest.approx(preview.plan_span_s, rel=0.05)


def test_the_manifest_records_the_duration_that_was_asked_for(tmp_path: Path) -> None:
    """Safety rule 5. Two runs of the same scenario and seed can now cover very
    different windows, so the window is part of the audit record."""

    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))

    result = orch.run_scenario(
        ScenarioRunRequest(
            scenario_id=FREE,
            duration="2h",
            no_send=True,
            to_file=str(tmp_path / "s.log"),
        ),
        SCENARIOS,
    )

    assert result.manifest.duration == "2h"
