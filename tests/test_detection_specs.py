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

A spec that names a rule id, use case, ATT&CK technique, transferability or preset
the catalog no longer holds is worse than no spec: it reads as authoritative and
is wrong. These guards are table-authoritative (they parse the spec's own header
table, not just search the prose) and generic (every REP-*.md is checked), so a
new spec is guarded the moment it lands, and a catalog change that a spec does not
follow turns the suite red.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from replicant.core.models import load_catalog
from replicant.resources import TECHNIQUE_CATALOG

CATALOG = load_catalog(TECHNIQUE_CATALOG)
SPECS = Path(__file__).resolve().parents[1] / "docs" / "detection-specs"
CATALOG_IDS = {t.id for t in CATALOG.techniques}
SPEC_FILES = sorted(SPECS.glob("REP-*.md"))
_ATTACK = re.compile(r"T\d{4}(?:\.\d+)?")


def _header_table(spec_text: str) -> dict[str, str]:
    """Parse the leading `| key | value |` table into a dict.

    Reads the first contiguous block of table rows (the header table) and stops,
    so later tables (presets) do not pollute it. Skips the empty header row and
    the `---` separator.
    """

    table: dict[str, str] = {}
    started = False
    for line in spec_text.splitlines():
        if line.startswith("|"):
            started = True
            cells = [c.strip() for c in line.strip("|").split("|")]
            if len(cells) >= 2 and cells[0] and set(cells[0]) != {"-"}:
                table[cells[0]] = cells[1]
        elif started:
            break
    return table


def test_a_spec_exists_so_these_guards_are_not_vacuous() -> None:
    # The glob-driven tests below pass trivially on an empty match set; pin that
    # the pilot spec is present so they are actually exercising something.
    assert (SPECS / "REP-001.md").exists()
    assert SPEC_FILES


@pytest.mark.parametrize("spec_path", SPEC_FILES, ids=lambda p: p.stem)
def test_spec_header_matches_the_catalog(spec_path: Path) -> None:
    technique = CATALOG.by_id(spec_path.stem)  # raises if the file is not a real id
    table = _header_table(spec_path.read_text(encoding="utf-8"))
    assert table.get("Rule id") == technique.ndr_rule
    assert table.get("Use case") == technique.ndr_uc
    assert table.get("Technique", "").startswith(technique.id)
    # Exact ATT&CK set: catches a spec that still names a technique the catalog
    # dropped, not just one that omits a current technique.
    spec_techs = set(_ATTACK.findall(table.get("ATT&CK", "")))
    assert spec_techs == set(technique.attack.techniques), (spec_path.stem, spec_techs)
    # Transferability read from the header cell, not matched anywhere in prose.
    assert technique.transferability in table.get("Transferability", "")


def test_rep001_spec_cites_its_catalog_presets() -> None:
    """The load-bearing numbers: a preset change that the spec does not follow
    (interval, ports) turns this red, per the README's 'every threshold ties to a
    catalog preset' promise."""

    technique = CATALOG.by_id("REP-001")
    spec = (SPECS / "REP-001.md").read_text(encoding="utf-8")
    for intensity in ("low", "medium", "high"):
        interval = technique.params[intensity]["interval_s"]
        assert f"{interval} s" in spec, (intensity, interval)
    for port in technique.distributions["dpt_choices"]:
        assert str(port) in spec, port


def test_rep011_spec_cites_its_catalog_presets() -> None:
    """The gap between logins is window / logins, and the spec's distance table
    is derived from it; a preset change the spec does not follow turns this red."""

    technique = CATALOG.by_id("REP-011")
    spec = (SPECS / "REP-011.md").read_text(encoding="utf-8")
    for intensity in ("low", "medium", "high"):
        preset = technique.params[intensity]
        gap = preset["window_min"] * 60 // preset["logins"]
        assert f"{gap} s (window_min {preset['window_min']})" in spec, (intensity, gap)


def test_rep016_spec_cites_its_catalog_presets() -> None:
    technique = CATALOG.by_id("REP-016")
    spec = (SPECS / "REP-016.md").read_text(encoding="utf-8")
    for intensity in ("low", "medium", "high"):
        preset = technique.params[intensity]
        per, epochs = preset["domains_per_epoch"], preset["epochs"]
        assert f"{per} x {epochs} = {per * epochs}" in spec, intensity
        assert f"| {preset['nx_ratio']}" in spec, intensity
        lo, hi = preset["label_len"]
        assert f"{lo} to {hi}" in spec, intensity


def test_rep020_spec_cites_its_catalog_presets() -> None:
    technique = CATALOG.by_id("REP-020")
    spec = (SPECS / "REP-020.md").read_text(encoding="utf-8")
    for intensity in ("low", "medium", "high"):
        preset = technique.params[intensity]
        row = f"| {intensity} | {preset['baseline_domains']} | {preset['hosts']} | " f"about"
        assert row in spec, intensity
        assert f"(window_min {preset['window_min']}) | {preset['novel_domains']} |" in spec


# -- the drafts' findings are claims about the engine, so they are measured -------


def _plan(tid: str, intensity: str, seed: int):  # type: ignore[no-untyped-def]
    from replicant.entities.model import EntityModel
    from replicant.scenario.engine import ScenarioEngine

    return ScenarioEngine().plan(
        CATALOG.by_id(tid), intensity, EntityModel.build(), seed, anchor_epoch=1_800_000_000
    )


@pytest.mark.parametrize("intensity", ["low", "medium", "high"])
def test_rep020_spec_lab_problem_still_holds(intensity: str) -> None:
    """The REP-020 draft says every history name is queried once by one host,
    first contact follows within seconds, and no known name is queried after the
    history. If the engine changes any of that, this goes red and the spec's lab
    section must be rewritten rather than left describing a problem that is gone."""

    for seed in range(1, 21):
        plan = _plan("REP-020", intensity, seed)
        events = sorted(plan.events, key=lambda e: e.eventtime)
        n = int(plan.effective_params["baseline_domains"])
        history, window = events[:n], events[n:]
        names = [e.extra["qname"] for e in history]
        assert len(set(names)) == len(names), "a history name is queried twice"
        assert not {e.extra["qname"] for e in window} & set(names), "a known name re-queried"
        gap = window[0].eventtime - history[-1].eventtime
        assert 0 <= gap <= 18, (intensity, seed, gap)


@pytest.mark.parametrize("intensity", ["low", "medium", "high"])
def test_rep016_spec_trickle_description_still_holds(intensity: str) -> None:
    """The REP-016 draft describes the benign trickle as 12 NXDOMAIN records of
    wpad and isatap at every preset, with no successful lookup."""

    for seed in range(1, 21):
        trickle = [e for e in _plan("REP-016", intensity, seed).events if e.control != "positive"]
        assert len(trickle) == 12, (intensity, seed, len(trickle))
        assert {e.extra["rcode"] for e in trickle} == {"NXDOMAIN"}
        assert {e.extra["qname"].split(".")[0] for e in trickle} == {"wpad", "isatap"}


def test_spec_index_matches_the_catalog() -> None:
    index = (SPECS / "README.md").read_text(encoding="utf-8")
    for spec_path in SPEC_FILES:
        technique = CATALOG.by_id(spec_path.stem)
        assert spec_path.name in index, spec_path.name
        assert technique.ndr_rule in index, technique.ndr_rule
        assert technique.ndr_uc in index, technique.ndr_uc


def test_specs_carry_no_typographic_dashes() -> None:
    # ~/.claude and repo CLAUDE.md both forbid em/en dashes in docs.
    for spec_path in [*SPEC_FILES, SPECS / "README.md"]:
        text = spec_path.read_text(encoding="utf-8")
        assert "—" not in text, f"em-dash in {spec_path.name}"
        assert "–" not in text, f"en-dash in {spec_path.name}"
