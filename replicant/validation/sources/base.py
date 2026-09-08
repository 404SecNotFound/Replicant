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
"""Separate telemetry and detection-source protocols.

A receiver may prove telemetry delivery without providing any alert interface.
Keeping these protocols separate prevents "no event" from being reported as
"no alert", which would blame a detection for a broken ingestion path.
"""

from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel, Field


class Observation(BaseModel):
    source: str
    run_id: str
    window: tuple[int, int]
    records: list[dict[str, str]] = Field(default_factory=list)
    raw_lines: list[str] = Field(default_factory=list)
    undetermined: list[str] = Field(default_factory=list)


class Alert(BaseModel):
    source: str
    run_id: str
    eventtime: int | None = None
    rule_id: str | None = None
    fields: dict[str, str] = Field(default_factory=dict)


class TelemetrySource(Protocol):
    name: str

    def fetch(self, run_id: str, window: tuple[int, int]) -> Observation:
        """Return records observed for this run and event-time window."""


class DetectionSource(Protocol):
    name: str

    def alerts(self, run_id: str, window: tuple[int, int]) -> list[Alert]:
        """Return observed alerts for this run and event-time window."""
