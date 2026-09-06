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
"""Catalog detection metadata must describe the selected renderer's output."""

from __future__ import annotations

from collections import defaultdict
from functools import cache

import pytest

from replicant.config.settings import VENDORS, Settings
from replicant.core.models import CefHeader, EventRecord, RunRequest, Technique, load_catalog
from replicant.core.orchestrator import Orchestrator, build_profile
from replicant.profiles.base import VendorProfile
from replicant.resources import TECHNIQUE_CATALOG

CATALOG = load_catalog(TECHNIQUE_CATALOG)


class _ExternalProfile(VendorProfile):
    """Minimal third-party profile written before detection metadata existed."""

    name = "external"
    hostname = "external-lab"
    accepted_as = "external-cef"

    def render(self, event: EventRecord) -> tuple[CefHeader, dict[str, str]]:
        raise NotImplementedError

    def severity(self, level: str) -> int:
        return 1


@cache
def _events(technique_id: str) -> tuple[EventRecord, ...]:
    orchestrator = Orchestrator(CATALOG, Settings())
    plan = orchestrator.build_plan(
        RunRequest(technique_id=technique_id, intensity="low", no_send=True)
    )
    return tuple(plan.events)


def test_new_detection_metadata_hooks_do_not_break_external_profile_instantiation() -> None:
    """Older profiles remain constructible and fail closed only when queried."""

    profile = _ExternalProfile()
    with pytest.raises(NotImplementedError, match="no detection metadata mapping"):
        profile.detection_metadata("traffic", "forward", "1", "accept")
    with pytest.raises(ValueError, match="unknown catalog detection field"):
        profile.detection_field_name("src", log_type="traffic", subtype="forward")


@pytest.mark.parametrize("vendor", VENDORS)
def test_unknown_catalog_detection_field_is_refused(vendor: str) -> None:
    """A new signal must be deliberately mapped, never identity-passed."""

    profile = build_profile(Settings(vendor=vendor))
    with pytest.raises(ValueError, match="unknown catalog detection field"):
        profile.detection_field_name(
            "new_unmapped_field",
            log_type="traffic",
            subtype="forward",
        )


@pytest.mark.parametrize("technique", CATALOG.techniques, ids=lambda t: t.id)
def test_declared_logical_families_match_the_rendered_plan(technique: Technique) -> None:
    """Mixed plans disclose every family while retaining one primary binding."""

    emitted = {(event.log_type, event.subtype) for event in _events(technique.id)}
    declared = set(technique.logical_families())
    assert declared == emitted


@pytest.mark.parametrize("vendor", VENDORS)
@pytest.mark.parametrize("technique", CATALOG.techniques, ids=lambda t: t.id)
def test_detection_metadata_matches_rendered_profile(
    vendor: str,
    technique: Technique,
) -> None:
    """Every advertised native key is rendered; every gap is named explicitly.

    The catalog's primary logical family is intentionally separate. FortiGate
    exposes a category/subtype pair, PAN-OS uses CEF name/signature, and Check
    Point uses CEF product/signature. Treating those as one universal concept
    recreated the original hard-coded-FortiGate defect under a different name.
    """

    profile = build_profile(Settings(vendor=vendor))
    binding = technique.fortigate
    metadata = profile.detection_metadata(
        binding.log_type,
        binding.subtype,
        binding.signature_id,
        binding.action,
    )
    assert metadata.semantics.startswith("Primary ")

    rendered_keys: dict[tuple[str, str], set[str]] = defaultdict(set)
    primary: list[tuple[CefHeader, dict[str, str]]] = []
    for event in _events(technique.id):
        header, extension = profile.render(event)
        rendered_keys[(event.log_type, event.subtype)].update(extension)
        if (event.log_type, event.subtype) == (binding.log_type, binding.subtype):
            primary.append((header, extension))

    assert primary, f"{technique.id} did not emit its cataloged logical family"
    matching = [
        (header, extension)
        for header, extension in primary
        if header.signature_id == metadata.signature_id
        and (extension.get("act") or extension.get("FTNTFGTaction")) == metadata.action
    ]
    assert matching, f"{technique.id}/{vendor} native signature/action is not rendered"

    header, extension = matching[0]
    if vendor == "fortigate":
        assert extension["cat"] == f"{metadata.log_type}:{metadata.subtype}"
        assert extension["FTNTFGTsubtype"] == metadata.subtype
    elif vendor == "paloalto":
        assert header.name == metadata.log_type
        assert header.signature_id == metadata.subtype
    else:
        assert header.device_product == metadata.log_type
        assert header.signature_id == metadata.subtype

    for log_type, subtype in technique.logical_families():
        family_keys = rendered_keys[(log_type, subtype)]
        assert family_keys, f"{technique.id} did not render {log_type}:{subtype}"
        for fields in (technique.cef_fields_held, technique.cef_fields_varied):
            coverage = profile.detection_fields(
                fields,
                log_type=log_type,
                subtype=subtype,
            )
            assert set(coverage.available) <= family_keys
            for source in fields:
                native = profile.detection_field_name(
                    source,
                    log_type=log_type,
                    subtype=subtype,
                )
                if native is None:
                    assert source in coverage.unavailable
                else:
                    assert native in coverage.available
