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
"""Operator-facing validation and replay commands."""

from __future__ import annotations

from pathlib import Path

from replicant.cli.app import main
from replicant.config.settings import Settings


def test_validate_show_prints_the_resolved_contract(capsys) -> None:
    assert main(["validate", "show", "REP-001"]) == 0
    output = capsys.readouterr().out
    normalized = " ".join(output.split())
    assert "technique_id: REP-001" in output
    assert "expected_event_families" in output
    assert "does not prove collector receipt" in normalized


def test_validate_plan_prints_not_run_and_evidence(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "replicant.cli.app.load_settings",
        lambda: Settings(manifest_dir=str(tmp_path / "manifests")),
    )
    rc = main(
        [
            "validate",
            "REP-011",
            "--tier",
            "plan",
            "--intensity",
            "low",
            "--evidence-dir",
            str(tmp_path / "evidence"),
        ]
    )
    output = capsys.readouterr().out
    assert rc == 0
    assert "PASS" in output
    assert "delivery" in output and "NOT_RUN" in output
    assert "does not prove" in output
    assert (tmp_path / "evidence").is_dir()


def test_validation_usage_and_configuration_errors_exit_three(capsys) -> None:
    assert main(["validate"]) == 3
    assert main(["validate", "REP-999"]) == 3
    assert main(["validate", "REP-001", "--tier", "unknown"]) == 3
    assert "validation" in capsys.readouterr().err.lower()
