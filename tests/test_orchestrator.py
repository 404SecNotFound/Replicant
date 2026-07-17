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
"""End-to-end orchestrator tests: fail-closed, determinism, manifest, test log."""

from __future__ import annotations

from pathlib import Path

import pytest

from replicant.config.settings import Settings
from replicant.core.models import RunRequest, load_catalog
from replicant.core.orchestrator import Orchestrator

CATALOG = load_catalog(Path(__file__).resolve().parents[1] / "data" / "technique-catalog.yaml")


def _orchestrator(tmp_path: Path) -> Orchestrator:
    settings = Settings(manifest_dir=str(tmp_path / "manifests"))
    return Orchestrator(CATALOG, settings)


def test_fail_closed_when_no_collector_and_no_file(tmp_path: Path) -> None:
    orchestrator = _orchestrator(tmp_path)
    request = RunRequest(technique_id="REP-001", intensity="medium", seed=1337, duration="2m")
    with pytest.raises(RuntimeError, match="fail-closed"):
        orchestrator.run(request)


def test_run_to_file_is_deterministic(tmp_path: Path) -> None:
    orchestrator = _orchestrator(tmp_path)
    out_a = tmp_path / "a.log"
    out_b = tmp_path / "b.log"
    for target in (out_a, out_b):
        orchestrator.run(
            RunRequest(
                technique_id="REP-001",
                intensity="medium",
                seed=1337,
                duration="2m",
                to_file=str(target),
                no_send=True,
            )
        )
    assert out_a.read_text() == out_b.read_text()
    assert out_a.read_text().startswith("CEF:0|Fortinet|Fortigate|")


def test_rep001_to_file_periodic_shape(tmp_path: Path) -> None:
    orchestrator = _orchestrator(tmp_path)
    out = tmp_path / "rep001.log"
    result = orchestrator.run(
        RunRequest(
            technique_id="REP-001",
            intensity="medium",
            seed=1337,
            duration="2m",
            to_file=str(out),
            no_send=True,
        )
    )
    lines = out.read_text().splitlines()
    assert lines, "no events emitted"
    assert result.event_count == len(lines)
    # Constant src, dst, dpt across the callback stream.
    srcs = {line.split(" src=")[1].split(" ")[0] for line in lines}
    dpts = {line.split(" dpt=")[1].split(" ")[0] for line in lines}
    assert len(srcs) == 1 and len(dpts) == 1


def test_rep002_mostly_deny_many_ports(tmp_path: Path) -> None:
    orchestrator = _orchestrator(tmp_path)
    out = tmp_path / "rep002.log"
    orchestrator.run(
        RunRequest(
            technique_id="REP-002",
            intensity="low",
            seed=1337,
            to_file=str(out),
            no_send=True,
        )
    )
    lines = out.read_text().splitlines()
    dpts = {line.split(" dpt=")[1].split(" ")[0] for line in lines}
    deny = sum(1 for line in lines if "act=deny" in line)
    assert len(dpts) == len(lines)  # unique destination ports
    assert deny / len(lines) > 0.9


def test_rep004_dns_query_qnames(tmp_path: Path) -> None:
    orchestrator = _orchestrator(tmp_path)
    out = tmp_path / "rep004.log"
    orchestrator.run(
        RunRequest(
            technique_id="REP-004",
            intensity="medium",
            seed=1337,
            duration="10s",
            to_file=str(out),
            no_send=True,
        )
    )
    lines = out.read_text().splitlines()
    assert lines
    assert all("dns:dns-query pass" in line for line in lines)
    assert all("FTNTFGTqname=" in line for line in lines)


def test_manifest_written_with_utc4_times(tmp_path: Path) -> None:
    orchestrator = _orchestrator(tmp_path)
    result = orchestrator.run(
        RunRequest(
            technique_id="REP-001",
            intensity="low",
            seed=99,
            duration="2m",
            to_file=str(tmp_path / "x.log"),
            no_send=True,
        )
    )
    assert result.manifest_path.exists()
    assert result.manifest.seed == 99
    assert result.manifest.event_count > 0
    # UTC+04:00 offset in the ISO timestamps.
    assert result.manifest.started_at.endswith("+04:00")
    assert result.manifest.ended_at.endswith("+04:00")


def test_unimplemented_technique_raises(tmp_path: Path) -> None:
    orchestrator = _orchestrator(tmp_path)
    with pytest.raises(NotImplementedError):
        orchestrator.run(
            RunRequest(
                technique_id="REP-003",
                intensity="low",
                seed=1,
                to_file=str(tmp_path / "y.log"),
                no_send=True,
            )
        )


def test_build_test_line_is_benign_accept(tmp_path: Path) -> None:
    orchestrator = _orchestrator(tmp_path)
    line = orchestrator.build_test_line()
    assert line.startswith("CEF:0|Fortinet|Fortigate|")
    assert "traffic:forward accept" in line
    # benign external destination (documentation range), not the adversary pool
    assert " dst=198.51.100." in line
