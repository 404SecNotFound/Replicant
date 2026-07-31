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
"""A run with no destination has to say so.

The defect this guards: a run with neither a collector nor a file renders every
event and delivers none, while the event stream, the progress and the
events-per-second readout stay identical to a working run, because all three
measure rendering rather than delivery.

It cost a live LogRhythm session. The run reported 921 events per second, tcpdump
saw no packets, and nothing anywhere connected the two. The destination switch in
the web form defaults to off and carried the whole meaning silently.

Warning rather than refusing, deliberately: a dry render with no output is a
legitimate thing to ask for, and it still produces a plan, a count and a manifest.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from replicant.config.settings import Settings
from replicant.core.models import RunRequest, load_catalog
from replicant.core.orchestrator import Orchestrator
from replicant.obs import log as obs_log
from replicant.resources import TECHNIQUE_CATALOG

CATALOG = load_catalog(TECHNIQUE_CATALOG)


@pytest.fixture(autouse=True)
def fresh_buffer() -> Iterator[None]:
    obs_log.reset_for_tests()
    obs_log.install(capacity=500, level="debug")
    yield
    obs_log.reset_for_tests()


def _messages() -> list[str]:
    return [entry.message for entry in obs_log.snapshot()]


def _warnings() -> list[str]:
    return [entry.message for entry in obs_log.snapshot() if entry.level == "warning"]


def _run(tmp_path: Path, **kwargs: object) -> None:
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
    orch.run(RunRequest(technique_id="REP-001", intensity="low", **kwargs))  # type: ignore[arg-type]


def test_a_run_with_no_destination_warns(tmp_path: Path) -> None:
    _run(tmp_path, no_send=True)

    warnings = [m for m in _warnings() if "no destination" in m]
    assert len(warnings) == 1
    assert "sending none" in warnings[0]


def test_the_warning_says_the_rate_measures_rendering_not_delivery(tmp_path: Path) -> None:
    """The eps figure is what made the silent run look like a working one."""

    _run(tmp_path, no_send=True)

    warning = next(m for m in _warnings() if "no destination" in m)
    assert "rendering, not delivery" in warning


def test_the_warning_survives_the_warning_only_mode(tmp_path: Path) -> None:
    """An operator narrowing the Logs tab to warnings must still see this."""

    obs_log.set_level("warning")
    _run(tmp_path, no_send=True)

    assert any("no destination" in m for m in _messages())


def test_a_file_run_states_where_it_writes_and_does_not_warn(tmp_path: Path) -> None:
    target = tmp_path / "out.log"
    _run(tmp_path, no_send=True, to_file=str(target))

    assert [m for m in _warnings() if "no destination" in m] == []
    assert any("writing" in m and str(target) in m for m in _messages())
    assert target.is_file()


def test_a_sending_run_does_not_warn_about_the_destination(tmp_path: Path) -> None:
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    try:
        from replicant.core.models import CollectorProfile

        collector = CollectorProfile(host="127.0.0.1", port=sock.getsockname()[1], transport="udp")
        _run(tmp_path, collector=collector)
    finally:
        sock.close()

    assert [m for m in _warnings() if "no destination" in m] == []
    assert any("connecting to collector" in m for m in _messages())
