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
from pydantic import BaseModel, Field, field_validator

Intensity = Literal["low", "medium", "high"]
Transport = Literal["udp", "tcp"]


class CefHeader(BaseModel):
    """The seven CEF header fields (the eighth section is the extension)."""

    version: int = 0
    device_vendor: str
    device_product: str
    device_version: str
    signature_id: str
    name: str
    severity: int


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
    port: int = 514
    transport: Transport = "udp"
    facility: int = 23  # local7
    app_name: str | None = None

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
    rate_override: int | None = None
    collector: CollectorProfile | None = None
    anchor_epoch: int | None = None
    param_overrides: dict[str, Any] = Field(default_factory=dict)


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


def load_catalog(path: str | Path) -> Catalog:
    """Load and validate the technique catalog YAML into a :class:`Catalog`."""

    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return Catalog.model_validate(raw)
