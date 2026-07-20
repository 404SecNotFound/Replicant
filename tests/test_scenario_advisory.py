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
from typing import Any

import pytest

from replicant.core.models import load_catalog, load_scenario_catalog
from replicant.entities.model import EntityModel
from replicant.scenario.advisory import build_advisory
from replicant.scenario.composer import ComposedPlan, compose
from replicant.scenario.engine import ScenarioEngine

ROOT = Path(__file__).resolve().parents[1]
TECH = load_catalog(ROOT / "data" / "technique-catalog.yaml")
SCEN = load_scenario_catalog(ROOT / "data" / "scenario-catalog.yaml", TECH)
ANCHOR = 1_752_586_800
ALL_SCENARIOS = [s.id for s in SCEN.scenarios]

_CACHE: dict[str, tuple[tuple[str, dict[str, Any]], ComposedPlan]] = {}


def _advisory(scenario_id: str) -> tuple[tuple[str, dict[str, Any]], ComposedPlan]:
    scenario = SCEN.by_id(scenario_id)
    composed = compose(scenario, TECH.by_id, ScenarioEngine(), 1337, ANCHOR, EntityModel.build())
    return build_advisory(scenario, composed, TECH), composed


def _cached(scenario_id: str) -> tuple[tuple[str, dict[str, Any]], ComposedPlan]:
    """Read-only advisory, built once per scenario. Composition is deterministic."""

    if scenario_id not in _CACHE:
        _CACHE[scenario_id] = _advisory(scenario_id)
    return _CACHE[scenario_id]


def _correlation_section(text: str) -> str:
    return text.split("## Cross-stage correlation opportunities")[1]


@pytest.mark.parametrize("scenario_id", ALL_SCENARIOS)
def test_advisory_is_deterministic(scenario_id: str) -> None:
    (text_a, cov_a), _ = _advisory(scenario_id)
    (text_b, cov_b), _ = _advisory(scenario_id)
    assert text_a == text_b and cov_a == cov_b


@pytest.mark.parametrize("scenario_id", ALL_SCENARIOS)
def test_advisory_has_boundary_and_through_line(scenario_id: str) -> None:
    (text, _), composed = _cached(scenario_id)
    assert "You author the detection" in text  # boundary disclaimer present
    assert composed.victim in text and composed.adversary in text


def test_advisory_reports_coverage_and_gaps() -> None:
    (_, coverage), _ = _cached("SCEN-001")
    assert "TA0007 Discovery" in " ".join(coverage["covered_tactics"])
    # a gap names a concrete catalog technique to fill it
    assert coverage["gap_tactics"], "expected some uncovered tactic"
    assert all(g["suggested_technique"].startswith("REP-") for g in coverage["gap_tactics"])


@pytest.mark.parametrize("scenario_id", ALL_SCENARIOS)
def test_advisory_does_not_write_rule_design(scenario_id: str) -> None:
    (text, _), _ = _cached(scenario_id)
    lowered = text.lower()
    for banned in ("aie rule:", "detection rule:", "def rule", "```sql", "```kql"):
        assert banned not in lowered


@pytest.mark.parametrize("scenario_id", ALL_SCENARIOS)
def test_advisory_never_claims_a_tactic_it_lists_as_a_gap(scenario_id: str) -> None:
    """The document must not contradict itself.

    Regression gate for the hard-coded correlation section, which listed Exfiltration as a
    gap on SCEN-003 and then asserted "C2 and exfil share dst" four lines later.
    """

    (text, coverage), _ = _cached(scenario_id)
    correlation = _correlation_section(text)
    for gap in coverage["gap_tactics"]:
        code = gap["tactic"].split()[0]  # e.g. "TA0010"
        assert code not in correlation, (
            f"{scenario_id} lists {gap['tactic']} as a gap but the correlation "
            f"section references it as covered"
        )


@pytest.mark.parametrize("scenario_id", ALL_SCENARIOS)
def test_advisory_correlation_claims_match_the_events(scenario_id: str) -> None:
    """Every through-line claim is measured, not assumed."""

    (text, coverage), composed = _cached(scenario_id)
    correlation = _correlation_section(text)
    victim_stages = coverage["victim_stage_indices"]
    # The victim is only advertised as threading the chain when it actually dominates >1 stage.
    threads = f"`src={composed.victim}` is the dominant source across stages" in correlation
    assert threads == (len(victim_stages) > 1)
    # Stages really are the ones named.
    for stage in composed.stages:
        if stage.top_src == composed.victim:
            assert stage.index in victim_stages


def test_advisory_surfaces_credential_key_on_mixed_chain() -> None:
    """SCEN-003 mixes credential-keyed and host-keyed stages.

    The pinned victim dominates only one of the four stages here, so the advisory must say
    plainly that it does not thread the chain, and must name the key that actually does.
    This is the regression gate for the hard-coded through-line.
    """

    (text, coverage), composed = _cached("SCEN-003")
    user_stages = [s for s in composed.stages if s.top_user]
    assert user_stages, "SCEN-003 should contain at least one credential-keyed stage"
    assert "duser=" in text
    correlation = _correlation_section(text)
    assert len(coverage["victim_stage_indices"]) == 1
    assert "does not by itself thread this chain" in correlation
    # the adversary is the key that actually recurs across stages
    assert len(coverage["adversary_stage_indices"]) > 1
    assert f"`{composed.adversary}` is the external peer across stages" in correlation
    assert "correlate on `duser`, not on `src`" in correlation


def test_advisory_reports_the_actual_window_and_alignment() -> None:
    """SCEN-001's exfil stage is day-aligned; the kill chain table must show it."""

    (text, coverage), composed = _cached("SCEN-001")
    assert "window (UTC+04:00)" in text
    assert "(+1d aligned)" in text
    # span is measured from the real first/last event, not assumed
    assert coverage["span_seconds"] == (
        composed.events[-1].eventtime - composed.events[0].eventtime
    )
