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
"""Events go out when the plan says they happen, not all at once.

The defect this guards, measured against a live LogRhythm collector: REP-001 at
low intensity delivered 49 events in about 3 seconds carrying event times spread
over 238 minutes. The plan has always held a per-event ``eventtime``; the emit
loop ignored it and fired as fast as the rate cap allowed.

What a collector received was therefore a snapshot claiming to be four hours of
history. An interval-keyed detection cannot work on that: a beacon rule asking
for N callbacks at a regular interval over M minutes sees every callback at once,
so it either never fires or fires on the wrong shape.

The scheduling maths is asserted purely, with no clock and no sleeping. The
delivered shape is then asserted on observed send times, because the claim is
about what a collector sees rather than about the shape of the code.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from replicant.config.settings import Settings
from replicant.core.models import CollectorProfile, EventRecord, RunRequest, load_catalog
from replicant.core.orchestrator import Orchestrator
from replicant.core.pacing import compress_timeline, projected_seconds, send_offsets
from replicant.resources import TECHNIQUE_CATALOG

CATALOG = load_catalog(TECHNIQUE_CATALOG)


def _events(*eventtimes: int) -> list[EventRecord]:
    """Bare events carrying only the field the scheduler reads."""

    return [
        EventRecord(
            log_type="traffic",
            subtype="forward",
            action="accept",
            level="notice",
            eventtime=when,
        )
        for when in eventtimes
    ]


# -- the schedule ------------------------------------------------------------


def test_burst_offsets_are_one_rate_interval_apart() -> None:
    """Burst ignores the plan's own times: it is the pre-existing behaviour."""

    offsets = send_offsets(_events(100, 400, 700), pace="burst", interval=0.005)

    assert offsets == pytest.approx([0.0, 0.005, 0.010])


def test_plan_offsets_reproduce_the_gaps_between_event_times() -> None:
    """The whole point: a 30 second gap in the plan is a 30 second gap on the wire."""

    offsets = send_offsets(_events(100, 130, 131, 400), pace="plan", interval=0.001)

    assert offsets == pytest.approx([0.0, 30.0, 31.0, 300.0])


def test_the_rate_cap_still_separates_simultaneous_events() -> None:
    """--rate stays the flood guard. A plan may put events at the same second;
    delivering them together is the burst this change exists to prevent."""

    offsets = send_offsets(_events(100, 100, 100, 100), pace="plan", interval=0.01)

    assert offsets == pytest.approx([0.0, 0.01, 0.02, 0.03])


def test_the_schedule_never_runs_backwards() -> None:
    """Builders sort their events, but a schedule that can go negative would sleep
    for a negative time and silently burst. Monotonic by construction instead."""

    offsets = send_offsets(_events(100, 400, 130), pace="plan", interval=0.0)

    assert offsets == pytest.approx([0.0, 300.0, 300.0])
    assert offsets == sorted(offsets)


def test_a_zero_interval_leaves_the_plan_gaps_exact() -> None:
    """eps_cap of 0 disables the limiter, so nothing floors the plan's own spacing."""

    offsets = send_offsets(_events(0, 7, 9), pace="plan", interval=0.0)

    assert offsets == pytest.approx([0.0, 7.0, 9.0])


def test_an_empty_plan_schedules_nothing() -> None:
    assert send_offsets([], pace="plan", interval=0.005) == []
    assert projected_seconds([]) == 0.0


def test_the_projection_is_how_long_the_run_will_take() -> None:
    """What the CLI prints and the web form shows before the operator commits."""

    offsets = send_offsets(_events(0, 60, 3600), pace="plan", interval=0.001)

    assert projected_seconds(offsets) == pytest.approx(3600.0)


# -- compressing the timeline ------------------------------------------------


def test_speed_one_leaves_every_event_time_alone() -> None:
    """The default path has to stay byte-identical, or every golden test is a lie."""

    events = _events(1_752_537_600, 1_752_537_900, 1_752_541_200)

    compressed = compress_timeline(events, 1.0)

    assert [e.eventtime for e in compressed] == [
        1_752_537_600,
        1_752_537_900,
        1_752_541_200,
    ]


def test_speed_divides_the_gaps_and_holds_the_anchor() -> None:
    """A run compressed 3x still starts where the anchor put it. Only the spread
    changes, so 'now' still means now."""

    compressed = compress_timeline(_events(100, 400, 700), 3.0)

    assert [e.eventtime for e in compressed] == [100, 200, 300]


def test_compression_rewrites_times_rather_than_only_the_schedule() -> None:
    """Compressing the schedule alone would re-create the original defect at 1/60
    scale: events stamped 238 minutes ahead, delivered in four minutes. Event time
    has to move with the send time or the payload is dishonest."""

    compressed = compress_timeline(_events(0, 14_280), 60.0)

    assert [e.eventtime for e in compressed] == [0, 238]


def test_compression_refuses_a_non_positive_speed() -> None:
    with pytest.raises(ValueError):
        compress_timeline(_events(0, 10), 0.0)


# -- what a collector actually sees ------------------------------------------


class RecordingEmitter:
    """Captures the monotonic time of every send. No socket involved.

    Mirrors ``tests/test_pacing.py``: a real socket adds its own jitter and makes
    the timing assertions flaky on a loaded runner. The scheduler is under test,
    not the network.
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


# REP-002 low, not the REP-001 beacon from the lab, and the reason is a real
# constraint rather than test convenience: ``eventtime`` is integer epoch seconds,
# so one second is the finest gap a plan can express and therefore the floor on
# how short an honest plan-paced run can be. REP-001 low spans 238 minutes, and
# reproducing it faithfully takes 238 minutes; compressing it far enough to fit a
# test collapses every gap to the same second and measures nothing.
#
# REP-002 low is the shape that fits: 200 events across 5 seconds, most of them
# inside the same second and a handful a full second apart. That mixture exercises
# both halves at once, the plan's own gaps and the rate cap holding the dense
# stretches apart, in about five seconds of wall clock.
DENSE = "REP-002"
RATE = 200
FLOOR_S = 1.0 / RATE


def _run(tmp_path: Path, technique: str = DENSE, **kwargs: object) -> None:
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
    orch.run(
        RunRequest(
            technique_id=technique,
            intensity="low",
            collector=CollectorProfile(host="127.0.0.1", port=5514, transport="udp"),
            rate_override=RATE,
            **kwargs,  # type: ignore[arg-type]
        )
    )


def _gaps(values: list[float]) -> list[float]:
    return [later - earlier for earlier, later in zip(values, values[1:], strict=False)]


def _planned_gaps(tmp_path: Path, technique: str = DENSE) -> list[float]:
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
    plan = orch.build_plan(RunRequest(technique_id=technique, intensity="low"))
    return _gaps([float(event.eventtime) for event in plan.events])


@pytest.fixture(scope="module")
def default_sends(tmp_path_factory: pytest.TempPathFactory) -> list[float]:
    """One live-send run with no pace named at all, shared by the tests below.

    Naming no pace is the point. Sending to a collector defaults to plan pacing,
    so this proves the default and the mode together: an operator who has never
    heard of the option still gets a stream rather than a snapshot. Module scoped
    because the run takes the plan's own five seconds and three tests ask
    different questions of the same delivery.
    """

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("replicant.core.orchestrator.SyslogEmitter", RecordingEmitter)
        _run(tmp_path_factory.mktemp("plan"))
    return list(RecordingEmitter.sends)


def test_a_collector_gets_the_plan_s_gaps_without_anyone_asking(
    default_sends: list[float], tmp_path: Path
) -> None:
    """The gaps the plan holds are the gaps that reach the wire.

    Under burst pacing every gap is the 5ms rate interval, so a second-long gap
    cannot occur at all and this count would be zero.
    """

    delivered = [gap for gap in _gaps(default_sends) if gap > 0.5]
    planned = [gap for gap in _planned_gaps(tmp_path) if gap >= 1.0]

    assert len(delivered) == len(planned) > 0


def test_the_rate_cap_still_holds_the_dense_stretches_apart(
    default_sends: list[float],
) -> None:
    """Plan pacing does not repeal safety rule 4. Most of REP-002 lands inside a
    single second, and delivering a second's worth together is the burst this
    change exists to prevent."""

    dense = [gap for gap in _gaps(default_sends) if gap <= 0.5]

    assert len(dense) > 50, "expected most of a port scan to fall inside one second"
    assert min(dense) >= FLOOR_S * 0.7, (
        f"closest two sends were {min(dense) * 1000:.1f}ms apart, "
        f"under the {FLOOR_S * 1000:.0f}ms rate floor"
    )


def test_the_run_takes_as_long_as_the_plan_says(default_sends: list[float], tmp_path: Path) -> None:
    planned_span = sum(_planned_gaps(tmp_path))
    span = default_sends[-1] - default_sends[0]

    assert span == pytest.approx(
        planned_span, rel=0.25
    ), f"plan spans {planned_span:.0f}s, run took {span:.2f}s"


def test_burst_pacing_ignores_the_plan_and_finishes_sooner(
    tmp_path: Path, recording: type[RecordingEmitter], default_sends: list[float]
) -> None:
    """Burst is still available and still does exactly what it did before."""

    _run(tmp_path, pace="burst")
    burst = _gaps(recording.sends)
    plan_span = default_sends[-1] - default_sends[0]

    assert recording.sends[-1] - recording.sends[0] < plan_span
    # Burst is the rate cap and nothing else, so the plan's second-long gaps are
    # simply absent from what the collector sees.
    assert max(burst) < 0.5


def test_speed_compresses_the_event_times_that_get_rendered(tmp_path: Path) -> None:
    """Compression end to end, without waiting for it.

    ``on_event`` receives the record as rendered, after compression, so the claim
    can be checked exactly. No collector means no emitter and therefore no
    sleeping, which is the only way to assert a 60x compression of a 238 minute
    beacon inside a test.
    """

    seen: list[int] = []
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
    orch.run(
        RunRequest(
            technique_id="REP-001",
            intensity="low",
            to_file=str(tmp_path / "out.log"),
            no_send=True,
            pace="plan",
            speed=60.0,
        ),
        on_event=lambda _line, event: seen.append(event.eventtime),
    )

    planned_span = 14_280  # REP-001 low: 49 events across 238 minutes
    assert seen[-1] - seen[0] == pytest.approx(planned_span / 60, abs=1)


def test_speed_is_refused_when_the_pace_cannot_use_it(tmp_path: Path) -> None:
    """A control whose output cannot change is decoration. Burst has no timeline
    to compress, so asking for both is a mistake worth naming."""

    with pytest.raises(ValueError):
        RunRequest(technique_id="REP-001", pace="burst", speed=60.0)
