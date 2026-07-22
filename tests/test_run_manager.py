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
"""Web run manager: concurrency and retention.

Each web run gets its own Orchestrator and its own rate limiter, and completed
handles were never evicted. Unbounded concurrent runs to one collector multiply
the configured eps cap (safety rule 4), and the handle map grows without bound on
a long-lived server. These tests pin a single active run and a bounded number of
retained terminal handles, without evicting a live one.
"""

from __future__ import annotations

import queue
import time
from pathlib import Path
from typing import Any, cast

import pytest

from replicant.config.settings import Settings
from replicant.core.models import RunRequest, load_catalog
from replicant.web.runner import (
    MAX_TERMINAL_RETAINED,
    RunHandle,
    RunInProgressError,
    RunManager,
)

CATALOG = load_catalog(Path(__file__).resolve().parents[1] / "data" / "technique-catalog.yaml")


def _manager(tmp_path: Path) -> RunManager:
    return RunManager(CATALOG, Settings(manifest_dir=str(tmp_path)))


def _running_handle(run_id: str) -> RunHandle:
    return RunHandle(
        run_id=run_id,
        orchestrator=cast(Any, None),
        queue=queue.Queue(),
        total=0,
        status="running",
    )


def _terminal_handle(run_id: str) -> RunHandle:
    return RunHandle(
        run_id=run_id,
        orchestrator=cast(Any, None),
        queue=queue.Queue(),
        total=0,
        status="done",
    )


def _drain(manager: RunManager, run_id: str, timeout: float = 5.0) -> None:
    """Wait for a real run to reach a terminal status."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        handle = manager.get(run_id)
        if handle is not None and handle.status in {"done", "stopped", "error"}:
            return
        time.sleep(0.02)
    raise AssertionError(f"run {run_id} did not finish within {timeout}s")


def test_start_rejects_a_second_run_while_one_is_active(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    manager._runs["already"] = _running_handle("already")
    req = RunRequest(
        technique_id="REP-001", intensity="low", no_send=True, to_file=str(tmp_path / "o.log")
    )
    with pytest.raises(RunInProgressError):
        manager.start(req)


def test_start_succeeds_once_the_active_run_is_terminal(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    req = RunRequest(
        technique_id="REP-001", intensity="low", no_send=True, to_file=str(tmp_path / "o.log")
    )
    handle = manager.start(req)
    _drain(manager, handle.run_id)
    # A second run is now allowed.
    handle2 = manager.start(req)
    _drain(manager, handle2.run_id)
    assert handle2.run_id != handle.run_id


def test_terminal_handles_are_evicted_beyond_the_retention_bound(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    for i in range(MAX_TERMINAL_RETAINED + 5):
        manager._runs[f"old-{i}"] = _terminal_handle(f"old-{i}")
    req = RunRequest(
        technique_id="REP-001", intensity="low", no_send=True, to_file=str(tmp_path / "o.log")
    )
    handle = manager.start(req)
    _drain(manager, handle.run_id)
    # Eviction runs at start (pruning the injected terminal handles to the bound),
    # then the new run finishes, so the map holds at most the bound plus that one.
    assert len(manager._runs) <= MAX_TERMINAL_RETAINED + 1


def test_eviction_never_removes_a_live_run(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    live = _running_handle("live")
    manager._runs["live"] = live
    for i in range(MAX_TERMINAL_RETAINED + 5):
        manager._runs[f"old-{i}"] = _terminal_handle(f"old-{i}")
    manager._evict_terminal()
    assert "live" in manager._runs


def test_stop_works_on_a_running_handle(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    req = RunRequest(
        technique_id="REP-001", intensity="low", no_send=True, to_file=str(tmp_path / "o.log")
    )
    handle = manager.start(req)
    assert manager.stop(handle.run_id) is True
    assert manager.stop("no-such-run") is False
