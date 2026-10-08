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
"""Catalog validation: every entry parses, ids and ndr_uc are unique."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from replicant.core.models import Catalog, Technique, load_catalog

CATALOG_PATH = Path(__file__).resolve().parents[1] / "replicant" / "data" / "technique-catalog.yaml"
CATALOG = load_catalog(CATALOG_PATH)


def test_catalog_loads() -> None:
    assert CATALOG.vendor_profile == "fortigate"
    assert CATALOG.timezone == "UTC+04:00"


def test_catalog_technique_count() -> None:
    # 11 original + 13 from v0.2.0 + two from the 2026-09-08 research review.
    assert len(CATALOG.techniques) == 28


def test_ids_and_uc_unique() -> None:
    ids = [t.id for t in CATALOG.techniques]
    ucs = [t.ndr_uc for t in CATALOG.techniques]
    assert len(set(ids)) == len(ids)
    assert len(set(ucs)) == len(ucs)


@pytest.mark.parametrize("technique", CATALOG.techniques, ids=lambda item: item.id)
def test_every_entry_has_complete_consistent_intensity_presets(technique: Technique) -> None:
    """The CLI offers exactly these presets, so every one must be runnable."""

    params = technique.params
    assert set(params) == {"low", "medium", "high"}
    parameter_sets = {frozenset(preset) for preset in params.values()}
    assert len(parameter_sets) == 1, "parameter names drift between intensity presets"


@pytest.mark.parametrize("technique", CATALOG.techniques, ids=lambda item: item.id)
def test_signal_contract_fields_are_unique_and_disjoint(technique: Technique) -> None:
    held = technique.cef_fields_held
    varied = technique.cef_fields_varied
    assert len(held) == len(set(held))
    assert len(varied) == len(set(varied))
    assert set(held).isdisjoint(varied)


def test_every_entry_has_fortigate_binding() -> None:
    for technique in CATALOG.techniques:
        assert technique.fortigate.log_type
        assert technique.fortigate.subtype
        assert technique.fortigate.signature_id


def test_phase1_techniques_present() -> None:
    ids = {t.id for t in CATALOG.techniques}
    assert {"REP-001", "REP-002", "REP-004"}.issubset(ids)


def test_by_id_raises_for_unknown() -> None:
    with pytest.raises(KeyError):
        CATALOG.by_id("REP-999")


def test_search_aliases_are_optional_for_custom_catalogs() -> None:
    raw = CATALOG.by_id("REP-001").model_dump(exclude={"search_aliases"})
    first = Technique.model_validate(raw)
    second = Technique.model_validate(raw)
    assert first.search_aliases == []
    first.search_aliases.append("custom phrase")
    assert second.search_aliases == []


def test_search_aliases_normalize_whitespace_and_preserve_spelling() -> None:
    raw = CATALOG.by_id("REP-001").model_dump()
    raw["search_aliases"] = ["  Phone\t home  ", "regular\ncallbacks"]
    assert Technique.model_validate(raw).search_aliases == ["Phone home", "regular callbacks"]


@pytest.mark.parametrize(
    "aliases",
    [
        [""],
        [" \n\t"],
        ["phone home", "PHONE HOME"],
        ["phone  home", " phone\thome "],
    ],
)
def test_blank_or_duplicate_search_aliases_are_rejected(aliases: list[str]) -> None:
    raw = CATALOG.by_id("REP-001").model_dump()
    raw["search_aliases"] = aliases
    with pytest.raises(ValidationError, match="search_aliases"):
        Technique.model_validate(raw)


def test_every_shipped_technique_has_search_aliases() -> None:
    assert all(technique.search_aliases for technique in CATALOG.techniques)


@pytest.mark.parametrize(
    ("phrase", "technique_id"),
    [
        ("phone home", "REP-001"),
        ("many ports on one host", "REP-002"),
        ("one server many services", "REP-002"),
        ("one port across many hosts", "REP-003"),
        ("first seen by this workstation", "REP-008"),
        ("impossible travel", "REP-011"),
        ("fleet beaconing", "REP-012"),
        ("slow DNS leak", "REP-015"),
        ("DNS over HTTPS", "REP-017"),
        ("first seen domain", "REP-020"),
        ("portal wide login failures", "REP-030"),
        ("IPS and traffic join", "REP-043"),
        ("rogue admin", "REP-028"),
        ("share encryption", "REP-052"),
    ],
)
def test_operator_phrases_are_attached_to_the_intended_technique(
    phrase: str, technique_id: str
) -> None:
    assert {
        technique.id for technique in CATALOG.techniques if phrase in technique.search_aliases
    } == {technique_id}


def test_duplicate_uc_rejected() -> None:
    raw = {
        "version": "0.1.0",
        "vendor_profile": "fortigate",
        "timezone": "UTC+04:00",
        "techniques": [
            {
                "id": "REP-001",
                "name": "A",
                "ndr_rule": "r",
                "ndr_uc": "UC-001",
                "fortigate": {"log_type": "traffic", "subtype": "forward", "signature_id": "00013"},
            },
            {
                "id": "REP-002",
                "name": "B",
                "ndr_rule": "r",
                "ndr_uc": "UC-001",  # duplicate
                "fortigate": {"log_type": "traffic", "subtype": "forward", "signature_id": "00013"},
            },
        ],
    }
    with pytest.raises(ValidationError):
        Catalog.model_validate(raw)
