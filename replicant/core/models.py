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
"""Pydantic v2 models for Replicant.

These types are vendor-neutral. FortiGate-specific knowledge lives in
``replicant.profiles.fortigate``; the only concession here is that ``EventRecord``
carries an ``extra`` bag of already-stringified semantic values that a vendor
profile lays out into its own field order.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

from replicant.core.pacing import MAX_SPEED, SPEED_WITHOUT_PLAN, Pace
from replicant.resources import SCENARIO_CATALOG

Intensity = Literal["low", "medium", "high"]
Transport = Literal["udp", "tcp", "tls"]


class CefHeader(BaseModel):
    """The seven CEF header fields (the eighth section is the extension)."""

    version: int = 0
    device_vendor: str
    device_product: str
    device_version: str
    signature_id: str
    name: str
    # CEF permits either a 0-10 integer (FortiGate, PAN-OS) or a severity string
    # such as Unknown/Low/Medium/High/Very-High (Check Point Log Exporter).
    severity: int | str


class EventRecord(BaseModel):
    """A single vendor-neutral event before serialization.

    Common network fields are typed. Everything template-specific (service, app,
    qname, attack, tunnel fields, msg, ...) rides in ``extra`` as pre-stringified
    values so the model stays vendor-neutral while a profile controls field order.
    """

    log_type: str
    subtype: str
    action: str
    level: str
    eventtime: int

    src: str | None = None
    spt: int | None = None
    dst: str | None = None
    dpt: int | None = None
    proto: int | None = None

    session_id: int | None = None
    out_bytes: int | None = None
    in_bytes: int | None = None
    duser: str | None = None

    extra: dict[str, str] = Field(default_factory=dict)


class AttackMapping(BaseModel):
    tactics: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)


class FortigateBinding(BaseModel):
    log_type: str
    subtype: str
    signature_id: str
    action: str | None = None


class Technique(BaseModel):
    """One catalog entry. Drives the menu, the CLI ``list``, and the engine."""

    id: str
    name: str
    ndr_rule: str
    ndr_uc: str
    attack: AttackMapping = Field(default_factory=AttackMapping)
    fortigate: FortigateBinding
    cef_fields_held: list[str] = Field(default_factory=list)
    cef_fields_varied: list[str] = Field(default_factory=list)
    params: dict[str, dict[str, Any]] = Field(default_factory=dict)
    distributions: dict[str, Any] = Field(default_factory=dict)
    benign_baseline: str | None = None
    references: list[str] = Field(default_factory=list)
    safety_notes: str | None = None

    def preset(self, intensity: Intensity) -> dict[str, Any]:
        if intensity not in self.params:
            raise KeyError(f"technique {self.id} has no '{intensity}' intensity preset")
        return dict(self.params[intensity])


class Catalog(BaseModel):
    version: str
    vendor_profile: str
    timezone: str
    default_entities_ref: str | None = None
    techniques: list[Technique]

    @field_validator("techniques")
    @classmethod
    def _unique_uc(cls, techniques: list[Technique]) -> list[Technique]:
        seen_ids: set[str] = set()
        seen_uc: set[str] = set()
        for tech in techniques:
            if tech.id in seen_ids:
                raise ValueError(f"duplicate technique id: {tech.id}")
            if tech.ndr_uc in seen_uc:
                raise ValueError(f"duplicate ndr_uc: {tech.ndr_uc}")
            seen_ids.add(tech.id)
            seen_uc.add(tech.ndr_uc)
        return techniques

    def by_id(self, technique_id: str) -> Technique:
        for tech in self.techniques:
            if tech.id == technique_id:
                return tech
        raise KeyError(f"unknown technique id: {technique_id}")


class CollectorProfile(BaseModel):
    """A saved or ad-hoc syslog collector target. The only permitted socket peer."""

    name: str = "default"
    host: str
    port: int = Field(default=514, ge=1, le=65535)
    transport: Transport = "udp"
    facility: int = Field(default=23, ge=0, le=23)  # syslog facility 0..23, 23=local7
    app_name: str | None = None
    tls_verify: bool = True  # verify the collector certificate (transport="tls")
    tls_cafile: str | None = None  # path to a CA bundle for a private/lab collector CA

    def endpoint(self) -> str:
        return f"{self.host}:{self.port}/{self.transport}"


class Entity(BaseModel):
    """A synthetic actor in the generated world (host, external IP, user, ...)."""

    kind: str
    value: str
    country: str | None = None


class RunRequest(BaseModel):
    technique_id: str
    intensity: Intensity = "medium"
    seed: int = 1337
    duration: str | None = None
    to_file: str | None = None
    no_send: bool = False
    # A non-positive override disables the emit-loop rate limiter (safety rule 4),
    # so it must be a positive events-per-second value when present.
    rate_override: int | None = Field(default=None, gt=0)
    collector: CollectorProfile | None = None
    anchor_epoch: int | None = None
    param_overrides: dict[str, Any] = Field(default_factory=dict)
    # How the plan's own timeline reaches the wire. None resolves by destination
    # (plan to a collector, burst to a file) in replicant.core.pacing.resolve_pace,
    # so an operator who does not know the option exists still gets a stream rather
    # than a snapshot.
    pace: Pace | None = None
    # Compresses the plan's timeline, event times included. 1.0 is untouched.
    speed: float = Field(default=1.0, gt=0, le=MAX_SPEED)

    @model_validator(mode="after")
    def _speed_needs_a_timeline(self) -> RunRequest:
        if self.pace == "burst" and self.speed != 1.0:
            raise ValueError(SPEED_WITHOUT_PLAN)
        return self


class RunManifest(BaseModel):
    """Audit record written for every run (safety rule 5, blueprint s4)."""

    replicant_version: str
    technique_id: str
    technique_name: str
    ndr_uc: str
    intensity: str
    seed: int
    params: dict[str, Any]
    entities: dict[str, Any]
    target: str
    transport: str
    accepted_as: str | None = None
    event_count: int
    started_at: str
    ended_at: str
    anchor_epoch: int
    warmup_note: str | None = None
    # How the events were delivered. Two runs of the same seed and technique can
    # now put very different shapes on the wire, so the shape is part of the audit
    # record (safety rule 5). Defaulted, so manifests written before this existed
    # still load: they were all burst.
    pace: str = "burst"
    speed: float = 1.0


def load_catalog(path: str | Path) -> Catalog:
    """Load and validate the technique catalog YAML into a :class:`Catalog`."""

    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return Catalog.model_validate(raw)


SCENARIO_CATALOG_PATH = SCENARIO_CATALOG


class ScenarioStage(BaseModel):
    """One stage of a scenario: a reference to an existing technique + timing."""

    technique_id: str
    label: str | None = None
    intensity: Intensity = "medium"
    start_offset: str = "0s"  # start time relative to the scenario anchor (parse_duration)
    param_overrides: dict[str, Any] = Field(default_factory=dict)
    # Techniques whose builder anchors to an internal window rather than to the stage anchor
    # (REP-005 pins to 00:00-06:00 of the anchor's day) would emit before the stage they follow.
    # "next-off-hours" tells the composer to advance this stage by whole days until it clears
    # its intended start. Opt-in, because a warm-up baseline (REP-008) legitimately precedes.
    align: Literal["anchor", "next-off-hours"] = "anchor"


class Scenario(BaseModel):
    id: str
    name: str
    description: str
    stages: list[ScenarioStage]
    kill_chain: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    safety_notes: str | None = None


class ScenarioCatalog(BaseModel):
    version: str
    scenarios: list[Scenario]

    @field_validator("scenarios")
    @classmethod
    def _unique_ids(cls, scenarios: list[Scenario]) -> list[Scenario]:
        seen: set[str] = set()
        for scenario in scenarios:
            if scenario.id in seen:
                raise ValueError(f"duplicate scenario id: {scenario.id}")
            seen.add(scenario.id)
        return scenarios

    def by_id(self, scenario_id: str) -> Scenario:
        for scenario in self.scenarios:
            if scenario.id == scenario_id:
                return scenario
        raise KeyError(f"unknown scenario id: {scenario_id}")


def load_scenario_catalog(path: str | Path, technique_catalog: Catalog) -> ScenarioCatalog:
    """Load the scenario catalog and validate every stage reference against the techniques."""

    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    catalog = ScenarioCatalog.model_validate(raw)
    known = {technique.id for technique in technique_catalog.techniques}
    for scenario in catalog.scenarios:
        for stage in scenario.stages:
            if stage.technique_id not in known:
                raise ValueError(
                    f"scenario {scenario.id} references unknown technique {stage.technique_id}"
                )
    return catalog


class ScenarioRunRequest(BaseModel):
    scenario_id: str
    seed: int = 1337
    intensity_override: Intensity | None = None
    # How long the whole chain should take. Scales stage offsets and each stage's
    # own window, so the chain keeps its order and every technique in it keeps
    # its characteristic interval. Unrelated to `speed`, which divides intervals
    # instead of reducing counts.
    duration: str | None = None
    to_file: str | None = None
    no_send: bool = False
    # Positive when present; a non-positive value would disable the rate limiter.
    rate_override: int | None = Field(default=None, gt=0)
    collector: CollectorProfile | None = None
    anchor_epoch: int | None = None
    # Same rules as RunRequest: a scenario is a longer timeline, so pacing matters
    # more there, not less.
    pace: Pace | None = None
    speed: float = Field(default=1.0, gt=0, le=MAX_SPEED)

    @model_validator(mode="after")
    def _speed_needs_a_timeline(self) -> ScenarioRunRequest:
        if self.pace == "burst" and self.speed != 1.0:
            raise ValueError(SPEED_WITHOUT_PLAN)
        return self


class ScenarioStageRecord(BaseModel):
    index: int
    technique_id: str
    label: str | None
    ndr_uc: str
    intensity: str
    start_offset: str
    event_count: int
    tactics: list[str]
    techniques: list[str]
    # The window the stage actually occupied, so the manifest records what was emitted
    # rather than what was requested (safety rule 5).
    start_epoch: int | None = None
    end_epoch: int | None = None
    truncated: bool = False
    aligned_days: int = 0


class ScenarioManifest(BaseModel):
    """Audit record for a scenario run (safety rule 5)."""

    replicant_version: str
    scenario_id: str
    scenario_name: str
    seed: int
    entities: dict[str, Any]
    target: str
    transport: str
    vendor: str
    accepted_as: str | None = None
    total_event_count: int
    stages: list[ScenarioStageRecord]
    started_at: str
    ended_at: str
    anchor_epoch: int
    warmup_note: str | None = None
    coverage: dict[str, Any] = Field(default_factory=dict)
    # See RunManifest: the delivered shape is part of the audit record.
    pace: str = "burst"
    speed: float = 1.0
    # The window the chain was asked to cover. Two runs of the same scenario and
    # seed can now span very different amounts of time (safety rule 5).
    duration: str | None = None
