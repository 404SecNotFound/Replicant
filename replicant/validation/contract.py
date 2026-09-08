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
"""Machine-readable detection contracts resolved against the technique catalog.

The packaged registry declares only validation semantics. Event families, signal
fields, preset values, foil presence, and transferability are copied from the
validated catalog at load time. This keeps the catalog as the source of truth and
turns a mismatch into a load error instead of silent contract drift.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

from replicant.core.models import Catalog, Technique, Transferability
from replicant.resources import DETECTION_CONTRACTS

AxisMetric = Literal[
    "cadence_cv",
    "distinct",
    "event_count",
    "field_presence",
    "ordered_families",
    "sum",
    "temporal_span",
]
NegativeMode = Literal["standalone", "embedded", "calibration", "unsupported"]


class ObservationWindow(BaseModel):
    """How the plan's measurement window is derived from its selected preset."""

    parameters: list[str] = Field(default_factory=list)
    fixed_seconds: int | None = Field(default=None, gt=0)
    description: str

    @model_validator(mode="after")
    def _has_source(self) -> ObservationWindow:
        if not self.parameters and self.fixed_seconds is None:
            raise ValueError("observation window needs a preset parameter or fixed_seconds")
        return self


class MeasurementAxis(BaseModel):
    """One deterministic property the Tier 0 evaluator measures in a plan."""

    id: str
    description: str
    metric: AxisMetric
    field: str | None = None
    group_by: list[str] = Field(default_factory=list)
    parameter: str | None = None
    scale: float = Field(default=1.0, gt=0)
    minimum_ratio: float = Field(default=0.75, gt=0, le=1)
    ordered_families: list[str] = Field(default_factory=list)
    compare_negative: bool = False

    @model_validator(mode="after")
    def _metric_inputs(self) -> MeasurementAxis:
        if self.metric in {"cadence_cv", "distinct", "field_presence", "sum"} and not self.field:
            raise ValueError(f"axis {self.id}: metric {self.metric} requires field")
        if self.metric == "ordered_families" and not self.ordered_families:
            raise ValueError(f"axis {self.id}: ordered_families cannot be empty")
        return self


class NegativeTemplate(BaseModel):
    mode: NegativeMode
    reason: str
    separable_by: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _standalone_has_discriminator(self) -> NegativeTemplate:
        if self.mode == "standalone" and not self.separable_by:
            raise ValueError("standalone negative control needs separable_by")
        return self


class ContractTemplate(BaseModel):
    technique_id: str
    observation_window: ObservationWindow
    measurable_axes: list[MeasurementAxis] = Field(min_length=1)
    negative: NegativeTemplate

    @field_validator("measurable_axes")
    @classmethod
    def _axis_ids_unique(cls, axes: list[MeasurementAxis]) -> list[MeasurementAxis]:
        ids = [axis.id for axis in axes]
        if len(ids) != len(set(ids)):
            raise ValueError("measurement axis ids must be unique")
        return axes


class RawContractCatalog(BaseModel):
    version: str
    contracts: list[ContractTemplate]


class SignalFields(BaseModel):
    held: list[str]
    varied: list[str]


class PositiveRequirement(BaseModel):
    required: bool = True
    expectation: str


class NegativeRequirement(BaseModel):
    mode: NegativeMode
    present: bool
    reason: str
    separable_by: list[str]


class ValidationContract(BaseModel):
    """Fully resolved, serializable contract presented to evaluators and users."""

    schema_version: str
    technique_id: str
    technique_name: str
    detection_rule: str
    expected_event_families: list[str]
    signal_fields: SignalFields
    observation_window: ObservationWindow
    positive_control: PositiveRequirement
    negative_control: NegativeRequirement
    measurable_axes: list[MeasurementAxis]
    transferability: Transferability
    limitations: list[str]


class ContractCatalog(BaseModel):
    version: str
    contracts: list[ValidationContract]

    def by_id(self, technique_id: str) -> ValidationContract:
        for contract in self.contracts:
            if contract.technique_id == technique_id:
                return contract
        raise KeyError(f"unknown validation contract: {technique_id}")


_EVENT_FIELDS = {
    "act",
    "dpt",
    "dst",
    "duser",
    "externalId",
    "in",
    "out",
    "proto",
    "rt",
    "spt",
    "src",
}


def _validate_template(template: ContractTemplate, technique: Technique) -> None:
    preset_names = [set(values) for values in technique.params.values()]
    for parameter in template.observation_window.parameters:
        if not all(parameter in names for names in preset_names):
            raise ValueError(
                f"{technique.id}: observation parameter {parameter!r} is absent from a preset"
            )
    catalog_fields = set(technique.cef_fields_held) | set(technique.cef_fields_varied)
    for axis in template.measurable_axes:
        if axis.parameter and not all(axis.parameter in names for names in preset_names):
            raise ValueError(
                f"{technique.id}: axis {axis.id} parameter {axis.parameter!r} "
                "is absent from a preset"
            )
        for field in [axis.field, *axis.group_by]:
            if field and field not in catalog_fields and field not in _EVENT_FIELDS:
                raise ValueError(
                    f"{technique.id}: axis {axis.id} uses undeclared signal field {field!r}"
                )
    standalone = template.negative.mode == "standalone"
    if standalone != technique.emits_foil:
        raise ValueError(
            f"{technique.id}: negative mode {template.negative.mode!r} disagrees with "
            f"catalog emits_foil={technique.emits_foil}"
        )


def load_contracts(catalog: Catalog, path: str | Path = DETECTION_CONTRACTS) -> ContractCatalog:
    """Load every contract and resolve catalog-owned facts into it."""

    raw = RawContractCatalog.model_validate(yaml.safe_load(Path(path).read_text(encoding="utf-8")))
    templates = {item.technique_id: item for item in raw.contracts}
    if len(templates) != len(raw.contracts):
        raise ValueError("duplicate validation contract technique_id")
    catalog_ids = {technique.id for technique in catalog.techniques}
    if set(templates) != catalog_ids:
        missing = sorted(catalog_ids - set(templates))
        extra = sorted(set(templates) - catalog_ids)
        raise ValueError(f"validation contract coverage mismatch: missing={missing}, extra={extra}")

    resolved: list[ValidationContract] = []
    for technique in catalog.techniques:
        template = templates[technique.id]
        _validate_template(template, technique)
        limitations = [
            "Tier 0 evaluates generated plan structure only; it does not prove collector receipt "
            "or a detection alert.",
            "Tier 1 proves delivery and parseability on the observed receiver path only; it does "
            "not prove any SIEM rule fired.",
        ]
        if technique.transferability_note:
            limitations.append(technique.transferability_note)
        resolved.append(
            ValidationContract(
                schema_version=raw.version,
                technique_id=technique.id,
                technique_name=technique.name,
                detection_rule=technique.ndr_rule,
                expected_event_families=[
                    f"{log_type}:{subtype}" for log_type, subtype in technique.logical_families()
                ],
                signal_fields=SignalFields(
                    held=list(technique.cef_fields_held),
                    varied=list(technique.cef_fields_varied),
                ),
                observation_window=template.observation_window,
                positive_control=PositiveRequirement(
                    expectation=technique.objective,
                ),
                negative_control=NegativeRequirement(
                    mode=template.negative.mode,
                    present=technique.emits_foil,
                    reason=template.negative.reason,
                    separable_by=template.negative.separable_by,
                ),
                measurable_axes=template.measurable_axes,
                transferability=technique.transferability,
                limitations=limitations,
            )
        )
    return ContractCatalog(version=raw.version, contracts=resolved)
