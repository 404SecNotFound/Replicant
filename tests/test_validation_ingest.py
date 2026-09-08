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
"""Real loopback ingestion and deliberate failure-path coverage."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from replicant.config.settings import Settings
from replicant.core.models import RunRequest, load_catalog
from replicant.core.orchestrator import Orchestrator
from replicant.evidence.replay import replay_evidence
from replicant.resources import TECHNIQUE_CATALOG
from replicant.validation.sources.file import FileLogSource, FixtureSource, parse_cef_line
from replicant.validation.verdict import Verdict

CATALOG = load_catalog(TECHNIQUE_CATALOG)


def _request() -> RunRequest:
    return RunRequest(
        technique_id="REP-011",
        intensity="low",
        seed=7,
        no_send=True,
        pace="burst",
    )


@pytest.mark.parametrize("transport", ("udp", "tcp"))
def test_real_transport_is_observed_and_packaged(tmp_path: Path, transport: str) -> None:
    settings = Settings(manifest_dir=str(tmp_path / "manifests"))
    result = Orchestrator(CATALOG, settings).validate(
        _request(),
        tier="ingest",
        ingest_transport=transport,
        evidence_root=tmp_path / "evidence",
    )
    assert result.verdict == Verdict.PASS
    assert result.observed_events == result.expected_events == 2
    assert result.dimensions["delivery"] == "pass"
    assert result.dimensions["detection"] == "not_run"
    assert result.evidence_path is not None
    evidence = Path(result.evidence_path)
    assert {path.name for path in evidence.iterdir()} == {
        "REPORT.md",
        "contract.yaml",
        "manifest.json",
        "mapping.md",
        "replay.json",
        "result.json",
        "telemetry.cef",
        "telemetry.json",
    }
    assert "does not prove that any SIEM rule fired" in (evidence / "REPORT.md").read_text()
    replay = replay_evidence(evidence, CATALOG, settings)
    assert replay.matches
    assert replay.parameters_match
    recipe = json.loads((evidence / "replay.json").read_text(encoding="utf-8"))
    manifest = json.loads((evidence / "manifest.json").read_text(encoding="utf-8"))
    assert recipe["effective_params"] == manifest["params"]


def test_dropped_receiver_record_is_fail_no_events_not_a_crash(tmp_path: Path) -> None:
    settings = Settings(manifest_dir=str(tmp_path / "manifests"))
    result = Orchestrator(CATALOG, settings).validate(
        _request(),
        tier="ingest",
        evidence_root=tmp_path / "evidence",
        _drop_last_observed=True,
    )
    assert result.verdict == Verdict.FAIL_NO_EVENTS
    assert result.observed_events == result.expected_events - 1
    assert any(check.id == "ingest-count" and check.status == "fail" for check in result.checks)


def test_ingest_forces_its_local_correlation_marker(tmp_path: Path) -> None:
    settings = Settings(manifest_dir=str(tmp_path / "manifests"), no_marker=True)
    result = Orchestrator(CATALOG, settings).validate(
        _request(), tier="ingest", evidence_root=tmp_path / "evidence"
    )
    assert result.verdict == Verdict.PASS
    assert result.observed_events == result.expected_events


def test_plan_pack_opening_states_that_no_collector_was_configured(tmp_path: Path) -> None:
    settings = Settings(manifest_dir=str(tmp_path / "manifests"))
    result = Orchestrator(CATALOG, settings).validate(
        _request(), tier="plan", evidence_root=tmp_path / "evidence"
    )
    report = (Path(result.evidence_path or "") / "REPORT.md").read_text(encoding="utf-8")
    assert report.splitlines()[2].startswith("No collector was configured")


def test_fixture_and_file_sources_filter_by_run_and_window(tmp_path: Path) -> None:
    fixture = FixtureSource(
        [
            {"run_id": "RUN-A", "eventtime": 10, "src": "10.0.0.1"},
            {"run_id": "RUN-B", "eventtime": 10, "src": "10.0.0.2"},
        ]
    )
    assert len(fixture.fetch("RUN-A", (0, 20)).records) == 1

    line = (
        "<189>Sep  8 12:00:00 FGT CEF:0|Fortinet|Fortigate|v7|00013|name|3|"
        "FTNTFGTeventtime=10 flexString1Label=ReplicantSynthetic flexString1=RUN-A "
        "msg=a value\\=with equals"
    )
    parsed = parse_cef_line(line)
    assert parsed["msg"] == "a value=with equals"
    path = tmp_path / "capture.log"
    path.write_text(line + "\n", encoding="utf-8")
    observed = FileLogSource(path).fetch("RUN-A", (0, 20))
    assert len(observed.records) == 1
    assert observed.records[0]["flexString1"] == "RUN-A"


def test_result_json_matches_returned_result(tmp_path: Path) -> None:
    settings = Settings(manifest_dir=str(tmp_path / "manifests"))
    result = Orchestrator(CATALOG, settings).validate(
        _request(), tier="plan", evidence_root=tmp_path / "evidence"
    )
    stored = json.loads((Path(result.evidence_path or "") / "result.json").read_text())
    assert stored == result.model_dump(mode="json")


def test_replay_rejects_effective_parameter_mismatch(tmp_path: Path) -> None:
    settings = Settings(manifest_dir=str(tmp_path / "manifests"))
    result = Orchestrator(CATALOG, settings).validate(
        _request(), tier="plan", evidence_root=tmp_path / "evidence"
    )
    evidence = Path(result.evidence_path or "")
    replay_path = evidence / "replay.json"
    recipe = json.loads(replay_path.read_text(encoding="utf-8"))
    recipe["effective_params"]["countries"] += 1
    replay_path.write_text(json.dumps(recipe), encoding="utf-8")

    replay = replay_evidence(evidence, CATALOG, settings)
    assert replay.matches is False
    assert replay.parameters_match is False


def test_large_evidence_pack_uses_explicit_bounded_sample(tmp_path: Path) -> None:
    settings = Settings(manifest_dir=str(tmp_path / "manifests"))
    request = RunRequest(
        technique_id="REP-004",
        intensity="low",
        seed=7,
        no_send=True,
        pace="burst",
    )
    result = Orchestrator(CATALOG, settings).validate(
        request, tier="plan", evidence_root=tmp_path / "evidence"
    )
    evidence = Path(result.evidence_path or "")
    telemetry = json.loads((evidence / "telemetry.json").read_text(encoding="utf-8"))
    assert telemetry["original_count"] == result.observed_events
    assert telemetry["sample_count"] == 10_000
    assert telemetry["truncated"] is True
    assert telemetry["sample_strategy"] == "first-middle-last"
    assert len((evidence / "telemetry.cef").read_text(encoding="utf-8").splitlines()) == 10_000
    report = (evidence / "REPORT.md").read_text(encoding="utf-8")
    assert "bounded first/middle/last sample" in report
