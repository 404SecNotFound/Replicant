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
"""Manifest and syslog identity must follow the active vendor.

``accepted_as`` (the log-source type the manifest tells an operator to parse the
run as) and the syslog frame hostname were sourced from FortiGate-flavoured
defaults on ``Settings`` regardless of vendor. A Palo Alto or Check Point run
therefore wrote an audit record claiming a Fortinet FortiGate parser identity and
framed its syslog with ``FGT-LAB-01``. These tests pin identity to the profile,
while still letting an operator override it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from replicant.config.settings import Settings
from replicant.core.models import CollectorProfile, RunRequest, load_catalog
from replicant.core.orchestrator import Orchestrator
from replicant.profiles.checkpoint import CheckPointProfile
from replicant.profiles.fortigate import FortiGateProfile
from replicant.profiles.paloalto import PaloAltoProfile

CATALOG = load_catalog(
    Path(__file__).resolve().parents[1] / "replicant" / "data" / "technique-catalog.yaml"
)
FORTI_ACCEPTED = "Syslog - Fortinet FortiGate v5.6 CEF"


# --- profile-level identity --------------------------------------------------


def test_fortigate_profile_identity() -> None:
    p = FortiGateProfile()
    assert p.hostname == "FGT-LAB-01"
    assert p.accepted_as == FORTI_ACCEPTED


def test_paloalto_profile_identity_is_not_fortigate() -> None:
    p = PaloAltoProfile()
    assert p.hostname == "PA-LAB-01"
    assert p.accepted_as != FORTI_ACCEPTED
    assert "PAN-OS" in p.accepted_as or "Palo Alto" in p.accepted_as


def test_checkpoint_profile_identity_is_not_fortigate() -> None:
    p = CheckPointProfile()
    assert p.hostname == "CP-LAB-GW-01"
    assert p.accepted_as != FORTI_ACCEPTED
    assert "Check Point" in p.accepted_as


# --- manifest reflects the vendor, not FortiGate -----------------------------


@pytest.mark.parametrize("vendor", ["paloalto", "checkpoint"])
def test_alternate_vendor_manifest_does_not_claim_fortigate(vendor: str, tmp_path: Path) -> None:
    settings = Settings(vendor=vendor, manifest_dir=str(tmp_path))
    orch = Orchestrator(CATALOG, settings)
    req = RunRequest(
        technique_id="REP-001",
        intensity="low",
        no_send=True,
        to_file=str(tmp_path / "out.log"),
    )
    result = orch.run(req)
    assert result.manifest.accepted_as != FORTI_ACCEPTED
    assert result.manifest.accepted_as == orch.profile.accepted_as


def test_fortigate_manifest_keeps_its_identity(tmp_path: Path) -> None:
    settings = Settings(vendor="fortigate", manifest_dir=str(tmp_path))
    orch = Orchestrator(CATALOG, settings)
    req = RunRequest(
        technique_id="REP-001", intensity="low", no_send=True, to_file=str(tmp_path / "o.log")
    )
    result = orch.run(req)
    assert result.manifest.accepted_as == FORTI_ACCEPTED


def test_operator_accepted_as_override_wins(tmp_path: Path) -> None:
    settings = Settings(
        vendor="paloalto", accepted_as="Custom LR Log Source", manifest_dir=str(tmp_path)
    )
    orch = Orchestrator(CATALOG, settings)
    req = RunRequest(
        technique_id="REP-001", intensity="low", no_send=True, to_file=str(tmp_path / "o.log")
    )
    result = orch.run(req)
    assert result.manifest.accepted_as == "Custom LR Log Source"


# --- syslog frame hostname follows the vendor --------------------------------


def test_orchestrator_frames_syslog_with_vendor_hostname(monkeypatch, tmp_path: Path) -> None:
    captured: dict[str, str] = {}

    class FakeEmitter:
        def __init__(self, collector: CollectorProfile, hostname: str) -> None:
            captured["hostname"] = hostname

        def connect(self) -> None:  # pragma: no cover - trivial
            pass

        def send(self, line: str, level: str) -> None:  # pragma: no cover - trivial
            pass

        def close(self) -> None:  # pragma: no cover - trivial
            pass

    monkeypatch.setattr("replicant.core.orchestrator.SyslogEmitter", FakeEmitter)
    settings = Settings(vendor="checkpoint", manifest_dir=str(tmp_path))
    orch = Orchestrator(CATALOG, settings)
    collector = CollectorProfile(host="127.0.0.1", port=9999, transport="udp")
    req = RunRequest(technique_id="REP-001", intensity="low", collector=collector)
    orch.run(req)
    assert captured["hostname"] == "CP-LAB-GW-01"
