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
"""A single-technique run writes an analyst validation card (roadmap item 7).

After an ad-hoc run the analyst should not have to reverse-engineer the pivot,
window and expected rule from raw JSON. Positive control: drop the
write_validation_card call in Orchestrator.run and every assertion here goes red
(no card_path, no card file).
"""

from __future__ import annotations

from pathlib import Path

from replicant.audit import validation_card
from replicant.config.settings import Settings
from replicant.core.models import CollectorProfile, RunRequest, load_catalog
from replicant.core.orchestrator import (
    SYNTHETIC_MARKER_KEY,
    SYNTHETIC_MARKER_LABEL,
    SYNTHETIC_MARKER_LABEL_KEY,
    Orchestrator,
)
from replicant.resources import TECHNIQUE_CATALOG

CATALOG = load_catalog(TECHNIQUE_CATALOG)


def test_the_card_module_marker_constants_match_the_orchestrator() -> None:
    # The card duplicates the marker keys to avoid an import cycle; pin them equal.
    assert validation_card._MARKER_LABEL_KEY == SYNTHETIC_MARKER_LABEL_KEY
    assert validation_card._MARKER_KEY == SYNTHETIC_MARKER_KEY
    assert validation_card._MARKER_LABEL == SYNTHETIC_MARKER_LABEL


def test_a_single_technique_run_writes_a_card_next_to_the_manifest(tmp_path: Path) -> None:
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
    result = orch.run(
        RunRequest(
            technique_id="REP-001",
            intensity="low",
            to_file=str(tmp_path / "o.log"),
            no_send=True,
        )
    )
    assert result.card_path is not None
    assert result.card_path.exists()
    assert result.card_path.name.endswith(".card.md")
    assert str(result.card_path) in result.summary()
    text = result.card_path.read_text(encoding="utf-8")
    # The card names what a raw manifest makes the analyst reconstruct.
    assert "REP-001" in text
    assert "NDR-C2-001" in text  # ndr_rule
    assert "Emitted window" in text
    assert "does and does not prove" in text


def test_an_unmarked_run_pivots_on_entities_not_the_run_id(tmp_path: Path) -> None:
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
    result = orch.run(
        RunRequest(
            technique_id="REP-001",
            intensity="low",
            to_file=str(tmp_path / "o.log"),
            no_send=True,
        )
    )
    text = result.card_path.read_text(encoding="utf-8")  # type: ignore[union-attr]
    assert "was not marked" in text
    # No run-id search line, because an unmarked line carries no run id.
    assert f"{SYNTHETIC_MARKER_KEY}={result.run_id}" not in text


def test_a_marked_run_keys_the_search_on_the_run_id(tmp_path: Path, monkeypatch) -> None:
    captured: list[str] = []

    class _FakeEmitter:
        def __init__(self, collector: object, hostname: str = "") -> None: ...
        def connect(self) -> None: ...
        def send(self, line: str, level: str = "info") -> int:
            captured.append(line)
            return len(line)

        def close(self) -> None: ...

    monkeypatch.setattr("replicant.core.orchestrator.SyslogEmitter", _FakeEmitter)
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
    result = orch.run(
        RunRequest(
            technique_id="REP-001",
            intensity="low",
            pace="burst",
            collector=CollectorProfile(host="203.0.113.9", port=514, transport="udp"),
        )
    )
    text = result.card_path.read_text(encoding="utf-8")  # type: ignore[union-attr]
    assert captured, "run sent nothing"
    # The marked line and the card agree on the run-id search.
    assert f"{SYNTHETIC_MARKER_KEY}={result.run_id}" in text
    assert f"{SYNTHETIC_MARKER_KEY}={result.run_id}" in captured[0]


def test_the_card_carries_a_parser_only_transferability_note(tmp_path: Path) -> None:
    """REP-011 is parser-only; the card states what a green result does not prove."""
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
    result = orch.run(
        RunRequest(
            technique_id="REP-011",
            intensity="low",
            to_file=str(tmp_path / "o.log"),
            no_send=True,
        )
    )
    text = result.card_path.read_text(encoding="utf-8")  # type: ignore[union-attr]
    assert "parser-only" in text
    assert "GeoIP" in text  # from REP-011's transferability_note
