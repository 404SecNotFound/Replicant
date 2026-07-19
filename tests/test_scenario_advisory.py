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
    composed = compose(
        scenario, TECH.by_id, ScenarioEngine(), 1337, 1_752_586_800, EntityModel.build()
    )
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
