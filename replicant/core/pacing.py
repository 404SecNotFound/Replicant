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
"""When each event is allowed to leave the host.

A plan has always carried a per-event ``eventtime``. The emit loop ignored it and
sent as fast as the rate cap allowed, so a four hour beacon arrived as a three
second burst carrying four hours of timestamps. A collector cannot tell that from
a broken clock, and no interval-keyed detection can work on it.

Two modes:

``burst``
    One event every rate interval, plan times ignored. What Replicant did before
    this module existed, and still the right thing for ``--to-file``, where the
    wall clock means nothing.

``plan``
    The plan's own gaps, reproduced on the wire. A four hour beacon takes four
    hours; ``speed`` trades that duration away for a proportional loss of
    interval fidelity.

Everything here is pure: no clock, no sockets, no sleeping. The emit loop owns
the waiting, this module owns the arithmetic, and the arithmetic can therefore be
asserted exactly rather than measured. See ``replicant/core/orchestrator.py``.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:  # models imports this module for Pace/MAX_SPEED, so keep it type-only
    from replicant.core.models import EventRecord

Pace = Literal["burst", "plan"]

#: Beyond this, compression stops being a timeline and starts being a burst with
#: extra steps. Bounded so a typo cannot silently turn plan pacing back into the
#: defect it exists to fix.
MAX_SPEED = 10_000.0


#: Raised, printed and returned as an API error whenever a speed is asked for that
#: cannot do anything. Named once so the CLI, the model validator and the web layer
#: cannot drift into three different explanations of the same mistake.
SPEED_WITHOUT_PLAN = (
    "speed applies to plan pacing only: burst ignores the plan's timeline, so there is "
    "nothing to compress. Use pace 'plan', or drop the speed."
)


def resolve_pace(pace: Pace | None, *, sending: bool) -> Pace:
    """The pace to run at when the operator did not name one.

    Plan whenever events go to a collector, because a collector is the only place
    the shape matters and getting it wrong there is what cost a lab session.
    Burst otherwise: a file has no wall clock, and sleeping four hours to write
    one would be absurd. An explicit choice always wins.
    """

    if pace is not None:
        return pace
    return "plan" if sending else "burst"


def compress_timeline(events: Sequence[EventRecord], speed: float) -> list[EventRecord]:
    """Squeeze the plan's timeline by ``speed``, holding the first event in place.

    The event times move, not only the send schedule. Compressing the schedule
    alone would re-create the original defect at 1/60 scale: events stamped 238
    minutes ahead, delivered inside four minutes. Moving both keeps one invariant
    that an operator can rely on at any speed:

        with ``pace='plan'`` and ``--anchor now``, an event is sent at the moment
        its own timestamp says it happened.

    The cost is stated rather than hidden: compression preserves *relative*
    timing and changes *absolute* intervals, so a rule keyed on five minutes
    between beacons will not match a run compressed 60x. Real time to validate a
    rule, compressed for a smoke test.

    ``speed == 1.0`` returns the events untouched, so the default path renders
    byte-identical output and the golden tests keep their meaning.
    """

    if speed <= 0.0:
        raise ValueError(f"speed must be positive, got {speed}")
    if speed > MAX_SPEED:
        raise ValueError(f"speed must be at most {MAX_SPEED:.0f}, got {speed}")
    if speed == 1.0 or not events:
        return list(events)

    anchor = events[0].eventtime
    return [
        event.model_copy(update={"eventtime": anchor + round((event.eventtime - anchor) / speed)})
        for event in events
    ]


def send_offsets(events: Sequence[EventRecord], *, pace: Pace, interval: float) -> list[float]:
    """Seconds after the first send at which each event may go out.

    ``interval`` is ``1 / eps_cap``, the rate limiter expressed as the closest two
    sends may ever be. It enters both modes as a floor on spacing rather than as a
    competing schedule, which is what lets ``--rate`` and ``--pace`` compose: rate
    stays the flood guard, pace sets the shape. Without it a plan holding several
    events in the same second would deliver them together, which is the burst this
    module exists to prevent.

    The result is non-decreasing by construction. Builders sort their events, but
    a schedule that could run backwards would ask for a negative sleep and burst
    silently, so the invariant is enforced here rather than assumed upstream.
    """

    offsets: list[float] = []
    previous = 0.0
    first = events[0].eventtime if events else 0
    for index, event in enumerate(events):
        floor = 0.0 if index == 0 else previous + interval
        planned = float(event.eventtime - first) if pace == "plan" else floor
        previous = max(planned, floor)
        offsets.append(previous)
    return offsets


def projected_seconds(offsets: Sequence[float]) -> float:
    """How long the run will take on the wall clock.

    Printed by the CLI and shown in the web form before the operator commits,
    because plan pacing turns a three second run into a four hour one and that
    must never be a surprise.
    """

    return offsets[-1] if offsets else 0.0


def format_span(seconds: float) -> str:
    """A duration an operator can read at a glance: ``3h 58m``, ``4m 02s``, ``0.2s``."""

    if seconds < 1.0:
        return f"{seconds:.1f}s"
    total = int(round(seconds))
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes:02d}m"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"
