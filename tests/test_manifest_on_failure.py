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
"""Safety rule 5 says every run writes a manifest. It did not.

Found by an external review on 2026-08-02 and reproduced before fixing: a run
against a closed TCP port raised ``ConnectionRefusedError`` and left the manifest
directory empty. ``run()`` called ``_emit`` first and built the manifest
afterwards, so any transport error exited the function before the audit record
existed.

The failure path is the one that most needs a record. A run can reach a collector
part-way and then fail, and without a manifest there is nothing durable saying
what was attempted, how far it got, or against which target -- only transient
error text in a terminal or a browser tab.

A manifest for a failed run has to be distinguishable from one for a clean run,
so it carries an explicit status and a bounded error rather than looking like a
short but successful run.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from replicant.config.settings import Settings
from replicant.core.models import (
    CollectorProfile,
    RunRequest,
    ScenarioRunRequest,
    load_catalog,
    load_scenario_catalog,
)
from replicant.core.orchestrator import Orchestrator
from replicant.resources import SCENARIO_CATALOG, TECHNIQUE_CATALOG

CATALOG = load_catalog(TECHNIQUE_CATALOG)
SCENARIOS = load_scenario_catalog(SCENARIO_CATALOG, CATALOG)


def _closed_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    sock.close()
    return port


def _manifests(directory: Path) -> list[dict]:
    return [
        json.loads(path.read_text(encoding="utf-8")) for path in sorted(directory.glob("*.json"))
    ]


def test_a_refused_connection_still_writes_a_manifest(tmp_path: Path) -> None:
    """The exact reproduction from the review."""

    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
    request = RunRequest(
        technique_id="REP-002",
        intensity="low",
        pace="burst",
        collector=CollectorProfile(host="127.0.0.1", port=_closed_port(), transport="tcp"),
    )

    with pytest.raises(OSError):
        orch.run(request)

    written = _manifests(tmp_path)
    assert len(written) == 1, "a failed run left no durable record"


def test_the_failed_manifest_says_it_failed(tmp_path: Path) -> None:
    """A short manifest and a failed manifest must not look alike. Without a
    status, a run that died after two events is indistinguishable from a run that
    was only ever meant to emit two."""

    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
    with pytest.raises(OSError):
        orch.run(
            RunRequest(
                technique_id="REP-002",
                intensity="low",
                pace="burst",
                collector=CollectorProfile(host="127.0.0.1", port=_closed_port(), transport="tcp"),
            )
        )

    manifest = _manifests(tmp_path)[0]
    assert manifest["status"] == "error"
    assert manifest["error"]
    assert "ConnectionRefused" in manifest["error"] or "refused" in manifest["error"].lower()


def test_the_failed_manifest_still_carries_the_audit_fields(tmp_path: Path) -> None:
    """Target, technique, seed and anchor are the fields that make the record
    worth having. A failure manifest missing them would satisfy the letter of
    safety rule 5 and none of its purpose."""

    port = _closed_port()
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
    with pytest.raises(OSError):
        orch.run(
            RunRequest(
                technique_id="REP-002",
                intensity="low",
                seed=4242,
                pace="burst",
                collector=CollectorProfile(host="127.0.0.1", port=port, transport="tcp"),
            )
        )

    manifest = _manifests(tmp_path)[0]
    assert manifest["technique_id"] == "REP-002"
    assert manifest["seed"] == 4242
    assert str(port) in manifest["target"]
    assert manifest["transport"] == "tcp"
    assert manifest["anchor_epoch"]


def test_a_clean_run_is_still_marked_done(tmp_path: Path) -> None:
    """The status has to discriminate, or it is decoration."""

    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
    result = orch.run(
        RunRequest(
            technique_id="REP-002",
            intensity="low",
            no_send=True,
            to_file=str(tmp_path / "out.log"),
        )
    )

    assert result.manifest.status == "done"
    assert result.manifest.error is None


def test_a_failed_scenario_run_also_writes_a_manifest(tmp_path: Path) -> None:
    """Scenarios go through a separate method, so they need their own guard."""

    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
    with pytest.raises(OSError):
        orch.run_scenario(
            ScenarioRunRequest(
                scenario_id="SCEN-003",
                duration="10m",
                pace="burst",
                collector=CollectorProfile(host="127.0.0.1", port=_closed_port(), transport="tcp"),
            ),
            SCENARIOS,
        )

    written = _manifests(tmp_path)
    assert len(written) == 1
    assert written[0]["status"] == "error"
