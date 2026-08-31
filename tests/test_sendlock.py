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
"""F-08: one sending run per host, enforced rather than stated.

The cap is applied by one process's emit loop, so two sending processes deliver
twice the cap to the operator's collector. These hold the lock the way a second
process would and assert the second attempt is refused.

The lock is taken by a real second OS process, not by calling the context
manager twice in this one: ``flock`` is per open file description, and a test
that re-entered it in-process could pass against code that never locked
anything. That is the failure this file has to avoid, because the finding it
closes is precisely "the guard is scoped to one process".
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from replicant.core.sendlock import SendInProgressError, lock_path, sending_lock

HOLDER = textwrap.dedent("""
    import os, sys, time
    from replicant.core.sendlock import sending_lock
    with sending_lock():
        sys.stdout.write("held\\n")
        sys.stdout.flush()
        time.sleep(float(sys.argv[1]))
    """)


@pytest.fixture()
def config_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("REPLICANT_CONFIG_DIR", str(tmp_path))
    return tmp_path


def _spawn_holder(config_home: Path, seconds: float) -> subprocess.Popen[str]:
    env = dict(os.environ, REPLICANT_CONFIG_DIR=str(config_home))
    proc = subprocess.Popen(
        [sys.executable, "-c", HOLDER, str(seconds)],
        env=env,
        stdout=subprocess.PIPE,
        text=True,
        cwd=str(Path(__file__).resolve().parents[1]),
    )
    assert proc.stdout is not None
    assert proc.stdout.readline().strip() == "held", "holder never acquired the lock"
    return proc


def test_a_second_sender_is_refused_while_the_first_holds_it(config_home: Path) -> None:
    proc = _spawn_holder(config_home, 30)
    try:
        with pytest.raises(SendInProgressError) as caught:
            with sending_lock():
                pass
        message = str(caught.value)
        assert (
            str(proc.pid) in message
        ), "the refusal must name the holder, not just 'another process'"
        assert "twice the cap" in message
    finally:
        proc.kill()
        proc.wait(timeout=10)


def test_the_slot_is_free_again_once_the_holder_exits(config_home: Path) -> None:
    """The whole guard is worthless if it leaks: the next run must be able to send."""

    proc = _spawn_holder(config_home, 30)
    proc.kill()  # SIGKILL, the case a lease-based design has to clean up after
    proc.wait(timeout=10)
    with sending_lock():
        pass  # acquired, so the kernel released it on exit and nothing is stale


def test_the_lock_records_the_holding_pid(config_home: Path) -> None:
    with sending_lock():
        assert lock_path().read_text().strip() == str(os.getpid())


def test_nothing_is_locked_when_no_one_is_sending(config_home: Path) -> None:
    """A positive control on the fixture: without a holder this must succeed,
    or the two tests above would pass against a lock that always refuses."""

    with sending_lock():
        pass
    with sending_lock():
        pass


def test_a_scenario_send_is_refused_while_a_holder_holds_the_lock(config_home: Path) -> None:
    """F-08 covers scenarios too, and run_scenario has its own emit path.

    run() and run_scenario() are separate methods, and only run() took the lock
    when the guard first shipped, so a `scenario run` sent unlocked and a
    concurrent `replicant run` doubled the cap. This asserts the scenario path is
    now under the same lock, through the real Orchestrator rather than the bare
    context manager. The collector is a documentation-range address that is never
    contacted: the lock is acquired before any socket work, so the refusal fires
    first.
    """

    from replicant.config.settings import Settings
    from replicant.core.models import (
        CollectorProfile,
        ScenarioRunRequest,
        load_catalog,
        load_scenario_catalog,
    )
    from replicant.core.orchestrator import Orchestrator
    from replicant.resources import SCENARIO_CATALOG, TECHNIQUE_CATALOG

    catalog = load_catalog(TECHNIQUE_CATALOG)
    scenarios = load_scenario_catalog(SCENARIO_CATALOG, catalog)
    orch = Orchestrator(catalog, Settings(manifest_dir=str(config_home / "manifests")))

    proc = _spawn_holder(config_home, 30)
    try:
        with pytest.raises(SendInProgressError):
            orch.run_scenario(
                ScenarioRunRequest(
                    scenario_id="SCEN-001",
                    duration="10m",
                    pace="burst",
                    collector=CollectorProfile(host="192.0.2.10", port=514, transport="udp"),
                ),
                scenarios,
            )
    finally:
        proc.kill()
        proc.wait(timeout=10)


def test_a_scenario_dry_run_does_not_take_the_lock(config_home: Path) -> None:
    """The control on the test above: --no-send/--to-file must not be blocked,
    because they cannot reach a collector and so cannot exceed the cap."""

    from replicant.config.settings import Settings
    from replicant.core.models import ScenarioRunRequest, load_catalog, load_scenario_catalog
    from replicant.core.orchestrator import Orchestrator
    from replicant.resources import SCENARIO_CATALOG, TECHNIQUE_CATALOG

    catalog = load_catalog(TECHNIQUE_CATALOG)
    scenarios = load_scenario_catalog(SCENARIO_CATALOG, catalog)
    orch = Orchestrator(catalog, Settings(manifest_dir=str(config_home / "manifests")))

    proc = _spawn_holder(config_home, 30)
    try:
        # A holder is sending, but a file-only scenario run is not, so it must
        # proceed rather than be refused.
        result = orch.run_scenario(
            ScenarioRunRequest(
                scenario_id="SCEN-001",
                duration="10m",
                pace="burst",
                no_send=True,
                to_file=str(config_home / "scenario.log"),
            ),
            scenarios,
        )
        assert result.event_count > 0
    finally:
        proc.kill()
        proc.wait(timeout=10)
