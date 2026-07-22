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
"""Manifest filenames must be collision-resistant.

A manifest is written for every run (safety rule 5). The name embedded the id,
seed, and a timestamp with only second precision, so two same-id, same-seed runs
in one wall-clock second resolved to one path and the second overwrote the first,
silently destroying the earlier run's audit record. Concurrent web runs made this
reachable in normal use. These tests pin distinct paths even when the timestamp
component is identical.
"""

from __future__ import annotations

from pathlib import Path

from replicant.audit import manifest as manifest_mod
from replicant.audit.manifest import write_manifest, write_scenario_manifest
from replicant.core.models import RunManifest, ScenarioManifest


def _run_manifest() -> RunManifest:
    return RunManifest(
        replicant_version="0.1.0",
        technique_id="REP-001",
        technique_name="Periodic C2 callback",
        ndr_uc="UC-001",
        intensity="low",
        seed=1337,
        params={},
        entities={},
        target="dry-run",
        transport="none",
        event_count=1,
        started_at="2026-07-22T12:00:00+04:00",
        ended_at="2026-07-22T12:00:00+04:00",
        anchor_epoch=0,
    )


def _scenario_manifest() -> ScenarioManifest:
    return ScenarioManifest(
        replicant_version="0.1.0",
        scenario_id="SCEN-001",
        scenario_name="Perimeter intrusion",
        seed=1337,
        entities={},
        target="dry-run",
        transport="none",
        vendor="fortigate",
        total_event_count=1,
        stages=[],
        started_at="2026-07-22T12:00:00+04:00",
        ended_at="2026-07-22T12:00:00+04:00",
        anchor_epoch=0,
    )


def test_two_run_manifests_same_second_do_not_collide(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(manifest_mod, "_stamp_for_filename", lambda: "20260722T120000")
    p1 = write_manifest(_run_manifest(), tmp_path)
    p2 = write_manifest(_run_manifest(), tmp_path)
    assert p1 != p2
    assert p1.exists() and p2.exists()
    assert len(list(tmp_path.glob("*.json"))) == 2
    # Prefix stays stable so existing name-prefix expectations still hold.
    assert p1.name.startswith("REP-001-seed1337-")
    assert p2.name.startswith("REP-001-seed1337-")


def test_two_scenario_manifests_same_second_do_not_collide(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(manifest_mod, "_stamp_for_filename", lambda: "20260722T120000")
    p1 = write_scenario_manifest(_scenario_manifest(), tmp_path)
    p2 = write_scenario_manifest(_scenario_manifest(), tmp_path)
    assert p1 != p2
    assert p1.exists() and p2.exists()
    assert len(list(tmp_path.glob("*.json"))) == 2
    assert p1.name.startswith("SCEN-001-seed1337-")
