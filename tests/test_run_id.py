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
"""Every run carries a stable identifier that ties its manifest, its telemetry,
and (with --mark-run) its emitted lines together.

Before this, nothing in an emitted CEF line or in the manifest said which run
produced it: a uuid existed only inside the web run handle, which the CLI never
made and the manifest never recorded. An operator holding 500 lines in a SIEM
had no id to search for, and the web 409 named a bare hex handle that resolved to
nothing on disk.

The positive control for this guard is the failure path. The id is generated
before anything can raise, so a run that dies on connect must still write a
manifest carrying the id it was known by. Reverting that (generating the id after
the emit) leaves the clean-run tests green and only this one red, which is the
whole point of writing it.
"""

from __future__ import annotations

import json
import re
import socket
from datetime import UTC, datetime
from pathlib import Path

import pytest

from replicant.audit.manifest import new_run_id
from replicant.config.settings import Settings
from replicant.core.models import CollectorProfile, RunRequest, load_catalog
from replicant.core.orchestrator import Orchestrator
from replicant.resources import TECHNIQUE_CATALOG

CATALOG = load_catalog(TECHNIQUE_CATALOG)

# RUN-<14-char UTC stamp>Z-<6 hex>, e.g. RUN-20260831T142212Z-a3f9c1.
_RUN_ID = re.compile(r"^RUN-\d{8}T\d{6}Z-[0-9a-f]{6}$")


def _closed_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    sock.close()
    return port


def _dry_request(**kw) -> RunRequest:
    base = dict(technique_id="REP-001", intensity="low", no_send=True, pace="burst")
    base.update(kw)
    return RunRequest(**base)


def test_new_run_id_matches_the_documented_shape() -> None:
    assert _RUN_ID.match(new_run_id())


def test_new_run_id_is_utc_not_the_catalog_timezone() -> None:
    fixed = datetime(2026, 8, 31, 14, 22, 12, tzinfo=UTC)
    assert new_run_id(fixed).startswith("RUN-20260831T142212Z-")


def test_two_ids_in_the_same_second_differ() -> None:
    fixed = datetime(2026, 8, 31, 14, 22, 12, tzinfo=UTC)
    assert new_run_id(fixed) != new_run_id(fixed)


def test_a_clean_run_records_a_well_formed_id(tmp_path: Path) -> None:
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
    result = orch.run(_dry_request())
    assert _RUN_ID.match(result.run_id)
    assert result.manifest.run_id == result.run_id


def test_the_id_reaches_the_manifest_on_disk(tmp_path: Path) -> None:
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
    result = orch.run(_dry_request())
    written = json.loads(result.manifest_path.read_text(encoding="utf-8"))
    assert written["run_id"] == result.run_id


def test_the_manifest_filename_carries_the_id(tmp_path: Path) -> None:
    """The id is how an operator finds the file from the id in their hand."""

    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
    result = orch.run(_dry_request())
    assert result.run_id in result.manifest_path.name


def test_an_explicit_id_is_honoured(tmp_path: Path) -> None:
    """The web runner passes its handle id in so the two cannot diverge."""

    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
    given = new_run_id()
    result = orch.run(_dry_request(), run_id=given)
    assert result.run_id == given
    assert given in result.manifest_path.name


def test_the_summary_prints_the_id(tmp_path: Path) -> None:
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
    result = orch.run(_dry_request())
    assert result.run_id in result.summary()


def test_a_failed_run_still_records_its_id(tmp_path: Path) -> None:
    """The positive control. The id is assigned before the emit, so a run that
    raises on connect writes a manifest carrying it. This is the assertion that
    goes red if the id is moved after the point that can raise."""

    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
    request = RunRequest(
        technique_id="REP-002",
        intensity="low",
        pace="burst",
        collector=CollectorProfile(host="127.0.0.1", port=_closed_port(), transport="tcp"),
    )
    with pytest.raises(OSError):
        orch.run(request)

    written = sorted(tmp_path.glob("*.json"))
    assert len(written) == 1
    manifest = json.loads(written[0].read_text(encoding="utf-8"))
    assert manifest["status"] == "error"
    assert _RUN_ID.match(manifest["run_id"]), "a failed run left no resolvable id"
    assert manifest["run_id"] in written[0].name
