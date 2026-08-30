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
"""The README technique table must not drift from technique-catalog.yaml.

The catalog is the single source of truth, but the README table is what a
reader actually scans, and the two have drifted before (stale ATT&CK ids).
Technique names and log-type wording may differ editorially, so only the
stable identifiers are asserted: REP id, UC id, and the ATT&CK technique set.
"""

from __future__ import annotations

import re
from pathlib import Path

from replicant.core.models import load_catalog

ROOT = Path(__file__).resolve().parents[1]
CATALOG = load_catalog(ROOT / "replicant" / "data" / "technique-catalog.yaml")

_ROW = re.compile(r"^\|\s*(REP-\d+)\s*\|")


def _readme_rows() -> dict[str, tuple[str, frozenset[str]]]:
    """REP id -> (UC id, ATT&CK technique set) parsed from the README table."""
    rows: dict[str, tuple[str, frozenset[str]]] = {}
    for line in (ROOT / "README.md").read_text(encoding="utf-8").splitlines():
        if not _ROW.match(line):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        rep_id, _, _, uc_id, attack = cells[0], cells[1], cells[2], cells[3], cells[4]
        techniques = frozenset(t.strip() for t in attack.split(",") if t.strip())
        rows[rep_id] = (uc_id, techniques)
    return rows


def test_readme_table_covers_every_catalog_entry() -> None:
    rows = _readme_rows()
    catalog_ids = {technique.id for technique in CATALOG.techniques}
    assert set(rows) == catalog_ids
    assert len(rows) == 24


def test_readme_rows_match_catalog_uc_and_attack_ids() -> None:
    rows = _readme_rows()
    for technique in CATALOG.techniques:
        uc_id, attack = rows[technique.id]
        assert uc_id == technique.ndr_uc, f"{technique.id} UC id drifted"
        assert attack == frozenset(technique.attack.techniques), (
            f"{technique.id} ATT&CK drifted: README {sorted(attack)} vs "
            f"catalog {sorted(technique.attack.techniques)}"
        )
