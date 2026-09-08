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
"""Contract coverage, Tier 0 behavior, and the four-way verdict contract."""

from __future__ import annotations

import pytest

from replicant.config.settings import Settings
from replicant.core.models import RunRequest, load_catalog
from replicant.core.orchestrator import Orchestrator
from replicant.resources import TECHNIQUE_CATALOG
from replicant.validation.contract import load_contracts
from replicant.validation.evaluator import evaluate_detection, evaluate_plan
from replicant.validation.sources.base import Alert
from replicant.validation.verdict import ValidationResult, Verdict, exit_code

CATALOG = load_catalog(TECHNIQUE_CATALOG)
CONTRACTS = load_contracts(CATALOG)
ORCHESTRATOR = Orchestrator(CATALOG, Settings())


def test_every_catalog_technique_has_one_resolved_contract() -> None:
    assert len(CATALOG.techniques) == 26
    assert [contract.technique_id for contract in CONTRACTS.contracts] == [
        technique.id for technique in CATALOG.techniques
    ]


@pytest.mark.parametrize("technique", CATALOG.techniques, ids=lambda item: item.id)
@pytest.mark.parametrize("intensity", ("low", "medium", "high"))
def test_every_preset_passes_tier_zero(technique, intensity: str) -> None:
    plan = ORCHESTRATOR.build_plan(
        RunRequest(
            technique_id=technique.id,
            intensity=intensity,
            seed=1337,
            no_send=True,
        )
    )
    result = evaluate_plan(CONTRACTS.by_id(technique.id), plan, seed=1337)
    failures = [check for check in result.checks if check.status == "fail"]
    assert result.verdict == Verdict.PASS, failures
    assert result.dimensions["delivery"] == "not_run"
    assert result.dimensions["detection"] == "not_run"
    assert "does not prove" in result.does_not_prove.lower()


def test_missing_positive_events_is_a_named_failure() -> None:
    request = RunRequest(technique_id="REP-001", intensity="low", seed=7, no_send=True)
    plan = ORCHESTRATOR.build_plan(request)
    plan.events = [event for event in plan.events if event.control == "negative"]
    result = evaluate_plan(CONTRACTS.by_id("REP-001"), plan, seed=7)
    assert result.verdict == Verdict.FAIL_NO_EVENTS
    assert any(check.id == "positive-events" and check.status == "fail" for check in result.checks)


def test_rep011_declares_the_geoip_control_unsupported() -> None:
    contract = CONTRACTS.by_id("REP-011")
    assert contract.negative_control.mode == "unsupported"
    assert contract.negative_control.present is False
    assert "GeoIP/ASN enrichment" in contract.negative_control.reason


def _result(verdict: Verdict) -> ValidationResult:
    return ValidationResult(
        technique_id="REP-001",
        tier="plan",
        verdict=verdict,
        intensity="low",
        seed=1,
        expected_events=1,
        observed_events=1,
        dimensions={
            "plan": "pass",
            "delivery": "not_run",
            "detection": "not_run",
        },
        proves="test",
        does_not_prove="test",
    )


def test_all_four_verdicts_and_exit_codes_are_reachable() -> None:
    assert exit_code(_result(Verdict.PASS)) == 0
    assert exit_code(_result(Verdict.FAIL_NO_EVENTS)) == 1
    assert exit_code(_result(Verdict.FAIL_NO_ALERT)) == 1
    assert exit_code(_result(Verdict.INCONCLUSIVE)) == 2


def test_no_alert_is_only_a_detection_failure_after_ingest_passed() -> None:
    ingest = _result(Verdict.PASS).model_copy(
        update={
            "tier": "ingest",
            "dimensions": {"plan": "pass", "delivery": "pass", "detection": "not_run"},
        }
    )
    assert evaluate_detection(ingest, []).verdict == Verdict.FAIL_NO_ALERT
    alert = Alert(source="fixture", run_id="RUN-X", rule_id="NDR-C2-001")
    assert evaluate_detection(ingest, [alert]).verdict == Verdict.PASS
