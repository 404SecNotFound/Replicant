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
"""Events go out as a stream, not as a burst.

The defect this guards, measured in a live LogRhythm lab: 1000 events left the
host in about 0.4 seconds, 670 KB of UDP with no gap between datagrams, zero send
errors, and nothing arriving at the SIEM. Two causes, both in the old
fixed-window limiter:

1. It only throttled on REACHING the cap, so a run shorter than the cap was never
   paced at all. 1000 events against a cap of 2000 was a free-for-all.
2. When it did engage it delivered the second's budget as a spike then slept,
   which is not what a firewall does and not what a receive buffer expects.

These assert on observed send times rather than on the shape of the code, because
the claim is about what a collector sees.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from replicant.config.settings import Settings
from replicant.core.models import CollectorProfile, RunRequest, load_catalog
from replicant.core.orchestrator import Orchestrator
from replicant.resources import TECHNIQUE_CATALOG

CATALOG = load_catalog(TECHNIQUE_CATALOG)


class RecordingEmitter:
    """Captures the monotonic time of every send. No socket involved.

    A real socket would add its own jitter and make the timing assertions flaky
    on a loaded CI runner. What is under test is the scheduler, not the network.
    """

    sends: list[float] = []

    def __init__(self, collector: CollectorProfile, hostname: str) -> None:
        RecordingEmitter.sends = []

    def connect(self) -> None:
        pass

    def send(self, line: str, level: str) -> int:
        RecordingEmitter.sends.append(time.monotonic())
        return len(line)

    def close(self) -> None:
        pass


@pytest.fixture()
def recording(monkeypatch: pytest.MonkeyPatch) -> type[RecordingEmitter]:
    monkeypatch.setattr("replicant.core.orchestrator.SyslogEmitter", RecordingEmitter)
    return RecordingEmitter


def _run(tmp_path: Path, rate: int | None) -> None:
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
    orch.run(
        RunRequest(
            technique_id="REP-001",
            intensity="low",
            collector=CollectorProfile(host="127.0.0.1", port=5514, transport="udp"),
            rate_override=rate,
            # Named, not inherited. Sending to a collector now defaults to plan
            # pacing, and REP-001 low is a 238 minute plan. What these tests are
            # about is the rate cap, which is the whole of burst pacing and the
            # floor under plan pacing, so burst is the pace that isolates it.
            pace="burst",
        )
    )


def _gaps(sends: list[float]) -> list[float]:
    # Not strict: the offset slice is one shorter by construction.
    return [later - earlier for earlier, later in zip(sends, sends[1:], strict=False)]


def test_a_run_shorter_than_the_cap_is_still_paced(
    tmp_path: Path, recording: type[RecordingEmitter]
) -> None:
    """The exact case that broke the lab test.

    REP-001 low is well under any sane cap. The old limiter never throttled it, so
    the whole run left as one burst.
    """

    _run(tmp_path, rate=200)

    sends = recording.sends
    assert len(sends) > 10
    span = sends[-1] - sends[0]
    # 200/s means each event is 5ms apart. Anything close to zero is a burst.
    assert span > (len(sends) - 1) * 0.005 * 0.7, f"{len(sends)} events in {span:.3f}s is a burst"


def test_events_are_evenly_spaced_rather_than_clustered(
    tmp_path: Path, recording: type[RecordingEmitter]
) -> None:
    _run(tmp_path, rate=200)

    gaps = _gaps(recording.sends)
    assert len(gaps) > 10
    # Every gap should be near the 5ms interval. The old shape produced a run of
    # near-zero gaps followed by one long sleep, so the max/min ratio exploded.
    biggest = max(gaps)
    assert biggest < 0.05, f"largest gap {biggest * 1000:.1f}ms suggests a sleep after a burst"
    clustered = [gap for gap in gaps if gap < 0.001]
    assert not clustered, f"{len(clustered)} sends were less than 1ms apart"


def test_the_delivered_rate_matches_the_requested_one(
    tmp_path: Path, recording: type[RecordingEmitter]
) -> None:
    _run(tmp_path, rate=100)

    sends = recording.sends
    span = sends[-1] - sends[0]
    observed = (len(sends) - 1) / span
    # Generous bounds: this runs on shared CI hardware, and the claim is "about
    # the requested rate", not a real-time guarantee.
    assert 50 < observed < 160, f"asked for 100/s, observed {observed:.0f}/s"


def test_a_faster_rate_finishes_sooner(tmp_path: Path, recording: type[RecordingEmitter]) -> None:
    """The control has to actually control something."""

    _run(tmp_path, rate=100)
    slow = recording.sends[-1] - recording.sends[0]

    _run(tmp_path, rate=400)
    fast = recording.sends[-1] - recording.sends[0]

    assert fast < slow
