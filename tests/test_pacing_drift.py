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
"""Ordinary per-event cost must not push a plan-paced run permanently late.

The defect this guards, measured against a loopback listener: the emit loop
resynchronised its schedule whenever it fell more than ONE rate interval
(0.5ms at the default cap) behind the plan. Rendering plus sending one record
costs about 0.7ms, so every dense stretch tripped the resync, and each resync
moved the whole remaining schedule later. REP-004 medium at ``--speed 10`` was
1.24s late after 15s and never recovered, which breaks the plan-pacing invariant:
an event must leave inside the second its own timestamp names.

Driven by a fake clock so the assertion is exact and immune to runner load:
``time.monotonic`` advances only when the loop waits or an emitter "sends".
The cost model matches the review's measurement (146 datagrams per 100ms, so
about 0.7ms per iteration including the 0.5ms rate floor) plus the occasional
slow send every real host has. Under the old one-interval bound each of those
slow sends moved the rest of the run later and the lateness only accumulated.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from replicant.config.settings import Settings
from replicant.core import orchestrator as orchestrator_mod
from replicant.core.models import CollectorProfile, RunRequest, load_catalog
from replicant.core.orchestrator import Orchestrator
from replicant.resources import TECHNIQUE_CATALOG

CATALOG = load_catalog(TECHNIQUE_CATALOG)
SEND_COST_S = 0.0002  # render + send, on top of the 0.5ms floor: ~0.7ms per iteration
JITTER_EVERY = 200
JITTER_S = 0.002  # an ordinary scheduling hiccup, far below the 1s resync bound


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now


class CostlyEmitter:
    """Every send costs SEND_COST_S of fake time; the send moment is recorded."""

    clock: FakeClock
    sends: list[float]

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        pass

    def connect(self) -> None:
        pass

    def send(self, line: str, level: str = "notice") -> int:
        slow = len(CostlyEmitter.sends) % JITTER_EVERY == JITTER_EVERY - 1
        CostlyEmitter.clock.now += JITTER_S if slow else SEND_COST_S
        CostlyEmitter.sends.append(CostlyEmitter.clock.now)
        return len(line)

    def close(self) -> None:
        pass


class FakeStop:
    """Stands in for the kill-switch Event: waiting advances the fake clock."""

    def __init__(self, clock: FakeClock) -> None:
        self.clock = clock

    def is_set(self) -> bool:
        return False

    def wait(self, timeout: float) -> bool:
        self.clock.now += max(0.0, timeout)
        return False

    def set(self) -> None:  # pragma: no cover - not used here
        pass

    def clear(self) -> None:
        pass


def test_render_and_send_cost_does_not_drift_the_schedule(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = FakeClock()
    CostlyEmitter.clock = clock
    CostlyEmitter.sends = []
    monkeypatch.setattr(orchestrator_mod.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(orchestrator_mod, "SyslogEmitter", CostlyEmitter)
    monkeypatch.setattr(orchestrator_mod, "sending_lock", _null_lock)

    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
    orch._stop = FakeStop(clock)  # type: ignore[assignment]
    events: list[int] = []
    request = RunRequest(
        technique_id="REP-004",
        intensity="medium",
        collector=CollectorProfile(host="127.0.0.1", port=5514, transport="udp"),
        pace="plan",
        speed=10.0,
    )
    plan = orch.build_plan(request)
    # 15 plan seconds after compression is plenty to show the drift.
    first = plan.events[0].eventtime
    cutoff = next(i for i, e in enumerate(plan.events) if e.eventtime - first >= 150)
    monkeypatch.setattr(orch, "build_plan", lambda _r: _truncated(plan, cutoff))

    orch.run(request, on_event=lambda _line, event: events.append(event.eventtime))

    sends = CostlyEmitter.sends
    assert len(sends) == len(events) > 5000
    start = sends[0] - SEND_COST_S
    lateness = [
        (sent - start) - (eventtime - events[0] + 1)
        for sent, eventtime in zip(sends, events, strict=True)
    ]
    worst = max(lateness)
    # Every event must leave before its own second ends. Before the fix every
    # hiccup tripped the resync and pushed the rest of the run later, so the
    # lateness grew by the jitter each time and never came back.
    # 10ms of slack: a second can hold 1320 events here, so its last event is
    # planned 0.8ms before the boundary and one send's own cost can cross it.
    assert worst <= 0.010, f"an event left {worst:.3f}s after its own second ended"


def _truncated(plan: object, cutoff: int) -> object:
    plan.events = plan.events[:cutoff]  # type: ignore[attr-defined]
    return plan


class _null_lock:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *_exc: object) -> None:
        return None
