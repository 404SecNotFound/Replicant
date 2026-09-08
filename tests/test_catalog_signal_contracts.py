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
"""Catalog signal contracts must agree with values the builders render."""

from __future__ import annotations

import pytest

from replicant.core.models import Technique, load_catalog
from replicant.entities.model import EntityModel
from replicant.profiles.fortigate import FortiGateProfile
from replicant.resources import TECHNIQUE_CATALOG
from replicant.scenario.engine import ScenarioEngine

CATALOG = load_catalog(TECHNIQUE_CATALOG)
ENTITIES = EntityModel.build()
PROFILE = FortiGateProfile()
INTENSITIES = ("low", "medium", "high")


def _rendered_values(technique: Technique, intensity: str, field: str) -> set[str]:
    plan = ScenarioEngine(max_events=2_000).plan(technique, intensity, ENTITIES, seed=1337)
    values: set[str] = set()
    for event in plan.events:
        if event.control != "positive":
            continue
        native = PROFILE.detection_field_name(
            field,
            log_type=event.log_type,
            subtype=event.subtype,
        )
        if native is None:
            continue
        _, extension = PROFILE.render(event)
        if native in extension:
            values.add(extension[native])
    return values


@pytest.mark.parametrize("technique", CATALOG.techniques, ids=lambda item: item.id)
def test_held_and_varied_fields_match_rendered_positive_events(technique: Technique) -> None:
    """Held fields stay fixed per run; varied fields vary in at least one preset."""

    for field in technique.cef_fields_held:
        for intensity in INTENSITIES:
            values = _rendered_values(technique, intensity, field)
            assert len(values) == 1, (
                f"{technique.id}/{intensity}: held field {field!r} rendered "
                f"{len(values)} distinct values"
            )

    for field in technique.cef_fields_varied:
        value_counts = [
            len(_rendered_values(technique, intensity, field)) for intensity in INTENSITIES
        ]
        assert max(value_counts) > 1, (
            f"{technique.id}: varied field {field!r} never rendered multiple values "
            f"across presets (counts={value_counts})"
        )
