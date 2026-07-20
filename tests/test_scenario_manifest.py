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
from __future__ import annotations

import json
from pathlib import Path

from replicant.audit.manifest import write_advisory, write_scenario_manifest
from replicant.core.models import ScenarioManifest, ScenarioStageRecord


def _manifest() -> ScenarioManifest:
    return ScenarioManifest(
        replicant_version="test",
        scenario_id="SCEN-001",
        scenario_name="x",
        seed=1337,
        entities={"internal_hosts": 1},
        target="dry-run",
        transport="none",
        vendor="fortigate",
        total_event_count=3,
        stages=[
            ScenarioStageRecord(
                index=0,
                technique_id="REP-003",
                label="recon",
                ndr_uc="UC-002b",
                intensity="medium",
                start_offset="0s",
                event_count=3,
                tactics=["TA0007 Discovery"],
                techniques=["T1046"],
            )
        ],
        started_at="2026-07-19T14:00:00+04:00",
        ended_at="2026-07-19T14:00:01+04:00",
        anchor_epoch=1_752_586_800,
        coverage={"covered_tactics": ["TA0007 Discovery"]},
    )


def test_write_scenario_manifest_and_advisory(tmp_path: Path) -> None:
    manifest = _manifest()
    manifest_path = write_scenario_manifest(manifest, tmp_path)
    assert manifest_path.exists()
    assert manifest_path.name.startswith("SCEN-001-seed1337-")
    data = json.loads(manifest_path.read_text())
    assert data["total_event_count"] == 3 and data["stages"][0]["technique_id"] == "REP-003"

    advisory_path = write_advisory("# advisory\n", manifest_path)
    assert advisory_path.exists()
    assert advisory_path.name == manifest_path.stem + ".advisory.md"
    assert advisory_path.read_text().endswith("\n")
