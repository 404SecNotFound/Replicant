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
"""Per-technique validation-transferability property (roadmap 2026-09 item 5).

Does a green result on a technique exercise the SHIPPED production rule, or only
its parser? REP-011 fires on a synthetic srccountry tag while the production rule
joins real GeoIP/ASN to an identity; REP-016's DGA sits under .invalid; REP-020
cites a domain-age detector under a reserved TLD with no registration date. Those
three are parser-only, and a parser-only claim carries a reason. Everything else
transfers by default, subject to the overall delivery-unverified gate.
"""

from __future__ import annotations

import io

import pytest
from pydantic import ValidationError
from rich.console import Console

from replicant.cli.app import cmd_list
from replicant.core.models import FortigateBinding, Technique, load_catalog
from replicant.resources import TECHNIQUE_CATALOG

CATALOG = load_catalog(TECHNIQUE_CATALOG)
PARSER_ONLY = {"REP-011", "REP-016", "REP-020"}


def _binding() -> FortigateBinding:
    return FortigateBinding(log_type="traffic", subtype="forward", signature_id="00013")


def test_named_parser_only_techniques_are_labelled_with_a_reason() -> None:
    for tid in PARSER_ONLY:
        t = CATALOG.by_id(tid)
        assert t.transferability == "parser-only", tid
        assert t.transferability_note and t.transferability_note.strip(), tid


def test_the_rest_transfer_by_default() -> None:
    transfers = [t for t in CATALOG.techniques if t.transferability == "transfers"]
    assert len(transfers) == len(CATALOG.techniques) - len(PARSER_ONLY)


def test_rep024_transfers_but_discloses_the_eventtime_ceiling() -> None:
    t = CATALOG.by_id("REP-024")
    assert t.transferability == "transfers"
    assert t.transferability_note and "second" in t.transferability_note.lower()


def test_parser_only_without_a_note_is_rejected() -> None:
    """Positive control: revert the _parser_only_needs_a_reason validator on
    Technique and this stops raising."""
    with pytest.raises(ValidationError):
        Technique(
            id="REP-999",
            name="x",
            ndr_rule="r",
            ndr_uc="uc",
            fortigate=_binding(),
            transferability="parser-only",
        )


def test_transfers_technique_may_omit_the_note() -> None:
    t = Technique(id="REP-998", name="x", ndr_rule="r", ndr_uc="uc", fortigate=_binding())
    assert t.transferability == "transfers"
    assert t.transferability_note is None


def test_cli_list_shows_the_transfers_column_and_the_parser_only_notes() -> None:
    console = Console(file=io.StringIO(), width=240)
    cmd_list(CATALOG, console)
    out = console.file.getvalue()  # type: ignore[attr-defined]
    assert "Transfers" in out
    assert "Parser-only techniques" in out
    for tid in PARSER_ONLY:
        assert tid in out


def test_web_catalog_exposes_transferability() -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from replicant.config.settings import Settings
    from replicant.web.server import create_app

    app = create_app(CATALOG, Settings(), token="t")
    client = TestClient(app, base_url="http://localhost")
    data = client.get("/api/catalog", headers={"x-replicant-token": "t"}).json()
    by_id = {t["id"]: t for t in data["techniques"]}
    assert by_id["REP-011"]["transferability"] == "parser-only"
    assert by_id["REP-011"]["transferability_note"]
    assert by_id["REP-001"]["transferability"] == "transfers"
