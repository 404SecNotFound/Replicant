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
"""Validation verdict and result models shared by CLI, web, and evidence packs."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field


class Verdict(StrEnum):
    PASS = "pass"
    FAIL_NO_EVENTS = "fail_no_events"
    FAIL_NO_ALERT = "fail_no_alert"
    INCONCLUSIVE = "inconclusive"


DimensionStatus = Literal["pass", "fail_no_events", "fail_no_alert", "inconclusive", "not_run"]
CheckStatus = Literal["pass", "fail", "not_run"]


class ValidationCheck(BaseModel):
    id: str
    status: CheckStatus
    expected: str
    observed: str
    detail: str


class ValidationResult(BaseModel):
    technique_id: str
    tier: Literal["plan", "ingest", "detect"]
    verdict: Verdict
    intensity: str
    seed: int
    run_id: str | None = None
    expected_events: int
    observed_events: int
    dimensions: dict[str, DimensionStatus]
    checks: list[ValidationCheck] = Field(default_factory=list)
    proves: str
    does_not_prove: str
    limitations: list[str] = Field(default_factory=list)
    evidence_path: str | None = None
    evidence_archive: str | None = None


def exit_code(result: ValidationResult) -> int:
    """Stable CLI exit mapping for one result."""

    if result.verdict in {Verdict.FAIL_NO_EVENTS, Verdict.FAIL_NO_ALERT}:
        return 1
    if result.verdict == Verdict.INCONCLUSIVE:
        return 2
    return 0
