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
from __future__ import annotations

from pathlib import Path

import pytest

from replicant.core.models import (
    ScenarioCatalog,
    load_catalog,
    load_scenario_catalog,
)

ROOT = Path(__file__).resolve().parents[1]
TECH = load_catalog(ROOT / "replicant" / "data" / "technique-catalog.yaml")
SCEN_PATH = ROOT / "replicant" / "data" / "scenario-catalog.yaml"


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


def test_curated_scenario_labels_and_presets_match_the_selected_builders() -> None:
    catalog = load_scenario_catalog(SCEN_PATH, TECH)
    first = catalog.by_id("SCEN-001")
    assert first.name == "Internal discovery to exfiltration"
    assert first.stages[0].label == "internal discovery"

    spray = catalog.by_id("SCEN-003").stages[1]
    assert spray.label == "password spray"
    assert TECH.by_id(spray.technique_id).params[spray.intensity]["mode"] == "spray"


def test_empty_scenario_rejected() -> None:
    with pytest.raises(ValueError, match="at least 1 item"):
        ScenarioCatalog.model_validate(
            {
                "version": "0.1.0",
                "scenarios": [
                    {"id": "SCEN-001", "name": "empty", "description": "d", "stages": []}
                ],
            }
        )


def test_duplicate_scenario_id_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate scenario id"):
        ScenarioCatalog.model_validate(
            {
                "version": "0.1.0",
                "scenarios": [
                    {
                        "id": "SCEN-001",
                        "name": "a",
                        "description": "d",
                        "stages": [{"technique_id": "REP-001"}],
                    },
                    {
                        "id": "SCEN-001",
                        "name": "b",
                        "description": "d",
                        "stages": [{"technique_id": "REP-001"}],
                    },
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


def test_invalid_stage_offset_rejected_during_catalog_load(tmp_path: Path) -> None:
    bad = tmp_path / "bad-offset.yaml"
    bad.write_text(
        "version: 0.1.0\nscenarios:\n"
        "  - id: SCEN-999\n    name: bad\n    description: d\n"
        "    stages:\n      - { technique_id: REP-001, start_offset: later }\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="invalid start_offset 'later'"):
        load_scenario_catalog(bad, TECH)


def test_unknown_stage_parameter_override_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "bad-override.yaml"
    bad.write_text(
        "version: 0.1.0\nscenarios:\n"
        "  - id: SCEN-999\n    name: bad\n    description: d\n"
        "    stages:\n"
        "      - { technique_id: REP-001, param_overrides: { interval_typo: 30 } }\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unknown parameter override.*interval_typo"):
        load_scenario_catalog(bad, TECH)
