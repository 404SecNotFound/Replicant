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
"""Benign foils are labelled, addressable, and honestly declared.

Every technique carries a benign_baseline prose line describing production
normality, and the catalog read as if all 24 emitted a matching foil. Measured,
only some do: a run of a foil-less technique is pure attack traffic, against
which any detection scores perfectly, and nothing in the catalog said which
techniques those were.

Two things are now true and tested here:

1. Foil events carry control="negative", so --controls can emit them alone (to
   measure a detection's false-positive rate) or exclude them.
2. Technique.emits_foil declares whether a foil exists, and this test asserts it
   equals what the builder actually produces, for all 24 at every intensity over
   several seeds. A foil documented in prose but never generated (the original
   defect) fails this, and so does a foil generated but not declared.

The seed is part of the guard: the review's own REP-013 test passed against the
buggy code because seed 1337 avoided the case, so emission is checked over a
spread of seeds, not the default alone.
"""

from __future__ import annotations

import pytest

from replicant.config.settings import Settings
from replicant.core.models import RunRequest, load_catalog
from replicant.core.orchestrator import Orchestrator
from replicant.entities.model import EntityModel
from replicant.resources import TECHNIQUE_CATALOG
from replicant.scenario.engine import ScenarioEngine

CATALOG = load_catalog(TECHNIQUE_CATALOG)
SEEDS = (1, 7, 1337, 99_999, 424_242)

# The ten techniques whose builders append a labelled, isolable benign foil.
# Kept here as an explicit expectation so a builder that silently gains or loses
# a foil is caught, not just quietly re-derived.
EXPECTED_FOIL = frozenset(
    {
        "REP-012",
        "REP-013",
        "REP-014",
        "REP-015",
        "REP-016",
        "REP-018",
        "REP-019",
        "REP-022",
        "REP-023",
        "REP-024",
    }
)


def _emits_negative(technique, intensity: str) -> bool:
    engine = ScenarioEngine()
    entities = EntityModel.build()
    for seed in SEEDS:
        plan = engine.plan(technique, intensity, entities, seed)
        if any(event.control == "negative" for event in plan.events):
            return True
    return False


def test_the_declared_foil_set_is_the_expected_ten() -> None:
    declared = {t.id for t in CATALOG.techniques if t.emits_foil}
    assert declared == EXPECTED_FOIL


@pytest.mark.parametrize("technique", CATALOG.techniques, ids=lambda t: t.id)
def test_declaration_matches_emission(technique) -> None:
    """The core guard: emits_foil is true exactly when a foil is produced.

    Reverting any builder's _mark_negative call (a foil generated but no longer
    labelled) turns this red for that technique, as does flipping an emits_foil
    flag away from what the builder does."""

    for intensity in technique.params:
        emitted = _emits_negative(technique, intensity)
        assert emitted == technique.emits_foil, (
            f"{technique.id} at {intensity}: emits_foil={technique.emits_foil} "
            f"but builder emitted negatives={emitted}"
        )


@pytest.mark.parametrize("technique_id", sorted(EXPECTED_FOIL))
def test_both_streams_are_non_empty(technique_id: str) -> None:
    """A foil technique must emit both the attack and the foil.

    Volume is deliberately NOT asserted here: several foils are designed to match
    the attack's volume (REP-015's same-volume benign parent, REP-023's
    concurrent browsing), because a foil a detection could separate on volume
    alone is worse than none. The requirement is that both streams exist, so the
    attack is never emitted bare and the foil is never the whole plan."""

    engine = ScenarioEngine()
    entities = EntityModel.build()
    technique = CATALOG.by_id(technique_id)
    plan = engine.plan(technique, "medium", entities, 1337)
    negatives = sum(1 for e in plan.events if e.control == "negative")
    positives = sum(1 for e in plan.events if e.control == "positive")
    assert negatives > 0, f"{technique_id}: emits_foil but produced no negative events"
    assert positives > 0, f"{technique_id}: produced only foil, no attack"


def _run_to_file(tmp_path, technique_id: str, controls: str) -> Orchestrator:
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
    orch.run(
        RunRequest(
            technique_id=technique_id,
            intensity="medium",
            controls=controls,
            to_file=str(tmp_path / f"{controls}.log"),
            no_send=True,
        )
    )
    return orch


def test_controls_negative_isolates_the_foil(tmp_path) -> None:
    """--controls negative on a foil technique yields only foil events."""

    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
    plan = orch.build_plan(
        RunRequest(technique_id="REP-014", intensity="medium", controls="negative", no_send=True)
    )
    assert plan.events, "negative-only plan was empty for a foil technique"
    assert all(e.control == "negative" for e in plan.events)


def test_controls_positive_excludes_the_foil(tmp_path) -> None:
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
    plan = orch.build_plan(
        RunRequest(technique_id="REP-014", intensity="medium", controls="positive", no_send=True)
    )
    assert plan.events
    assert all(e.control == "positive" for e in plan.events)


def test_positive_plus_negative_equals_both() -> None:
    orch = Orchestrator(CATALOG, Settings())

    def _count(controls: str) -> int:
        return len(
            orch.build_plan(
                RunRequest(
                    technique_id="REP-014",
                    intensity="medium",
                    controls=controls,
                    no_send=True,
                )
            ).events
        )

    assert _count("positive") + _count("negative") == _count("both")


def test_controls_negative_on_a_foil_less_technique_is_empty() -> None:
    """REP-001 has no foil; asking for the negative stream yields nothing rather
    than silently sending the attack."""

    orch = Orchestrator(CATALOG, Settings())
    plan = orch.build_plan(
        RunRequest(technique_id="REP-001", intensity="low", controls="negative", no_send=True)
    )
    assert plan.events == []


def test_default_run_carries_both_streams(tmp_path) -> None:
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
    plan = orch.build_plan(RunRequest(technique_id="REP-014", intensity="medium", no_send=True))
    controls = {e.control for e in plan.events}
    assert controls == {"positive", "negative"}
