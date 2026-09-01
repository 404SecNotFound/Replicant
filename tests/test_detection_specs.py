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
"""Reference detection specs stay in sync with the catalog (roadmap item 8).

A spec that names a rule id, use case, ATT&CK technique or transferability the
catalog no longer holds is worse than no spec: it reads as authoritative and is
wrong. These guards fail when the catalog moves and a spec does not follow.
"""

from __future__ import annotations

from pathlib import Path

from replicant.core.models import load_catalog
from replicant.resources import TECHNIQUE_CATALOG

CATALOG = load_catalog(TECHNIQUE_CATALOG)
SPECS = Path(__file__).resolve().parents[1] / "docs" / "detection-specs"
CATALOG_IDS = {t.id for t in CATALOG.techniques}


def test_rep001_spec_stays_in_sync_with_the_catalog() -> None:
    technique = CATALOG.by_id("REP-001")
    spec = (SPECS / "REP-001.md").read_text(encoding="utf-8")
    assert technique.ndr_rule in spec  # NDR-C2-001
    assert technique.ndr_uc in spec  # UC-001
    for tech_id in technique.attack.techniques:  # T1071, T1571
        assert tech_id in spec, tech_id
    # the spec must state the same transferability verdict the catalog holds
    assert technique.transferability in spec


def test_spec_index_lists_the_rep001_spec() -> None:
    index = (SPECS / "README.md").read_text(encoding="utf-8")
    assert "REP-001.md" in index
    assert CATALOG.by_id("REP-001").ndr_rule in index


def test_every_spec_file_names_a_real_technique() -> None:
    for path in SPECS.glob("REP-*.md"):
        assert path.stem in CATALOG_IDS, path.stem
