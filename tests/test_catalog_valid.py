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

from replicant.core.models import Catalog, load_catalog

CATALOG_PATH = Path(__file__).resolve().parents[1] / "data" / "technique-catalog.yaml"
CATALOG = load_catalog(CATALOG_PATH)


def test_catalog_loads() -> None:
    assert CATALOG.vendor_profile == "fortigate"
    assert CATALOG.timezone == "UTC+04:00"


def test_catalog_has_eleven_techniques() -> None:
    assert len(CATALOG.techniques) == 11


def test_ids_and_uc_unique() -> None:
    ids = [t.id for t in CATALOG.techniques]
    ucs = [t.ndr_uc for t in CATALOG.techniques]
    assert len(set(ids)) == len(ids)
    assert len(set(ucs)) == len(ucs)


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
