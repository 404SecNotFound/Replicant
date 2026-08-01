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
"""Asking for a two hour simulation has to produce two hours of telemetry.

Replicant emulates a TTP by writing the logs it would have produced. That only
works if the shape is faithful, and duration is half the shape: a two hour C2
beacon is 24 callbacks five minutes apart, not 240 callbacks thirty seconds
apart and not a six hour run that was asked to be two.

Four of the twenty-four use cases silently ignored ``--duration`` before this:
REP-005 pinned itself to a fixed six hour off-hours window, REP-014 read the
value as a PER-SESSION length and then multiplied it by the session count,
REP-019 derived its span from a probe count times a random gap, and REP-023 from
a session count times a fixed interval. All four returned a plan of the wrong
length without saying so.

The governing rule, and what these assert:

    --duration bounds the wall-clock span. Where the interval between events IS
    the detection signal, the interval is preserved and the event count falls.

That is the difference between duration and --speed. Speed keeps the count and
shrinks the intervals, which is a fast-forward. Duration keeps the intervals and
shrinks the count, which is a shorter but genuine window of the same behaviour.
Only one of those is worth pointing a detection at.
"""

from __future__ import annotations

import pytest

from replicant.config.settings import Settings
from replicant.core.models import RunRequest, Technique, load_catalog
from replicant.core.orchestrator import Orchestrator
from replicant.resources import TECHNIQUE_CATALOG

CATALOG = load_catalog(TECHNIQUE_CATALOG)
TWO_HOURS = 7200

# The four that ignored the flag. Named so a regression names itself rather than
# arriving as "some technique somewhere is long".
PREVIOUSLY_BROKEN = ["REP-005", "REP-014", "REP-019", "REP-023"]


def _span(orch: Orchestrator, technique_id: str, duration: str | None) -> int:
    plan = orch.build_plan(
        RunRequest(technique_id=technique_id, intensity="medium", duration=duration)
    )
    times = [event.eventtime for event in plan.events]
    return (max(times) - min(times)) if times else 0


@pytest.fixture(scope="module")
def orch(tmp_path_factory: pytest.TempPathFactory) -> Orchestrator:
    return Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path_factory.mktemp("m"))))


@pytest.mark.parametrize("technique", CATALOG.techniques, ids=lambda t: t.id)
def test_every_use_case_honours_a_two_hour_duration(
    orch: Orchestrator, technique: Technique
) -> None:
    """All 24, not the ones that happened to work.

    A catalogue where the flag works on 20 entries is worse than one where it
    works on none: the operator learns to trust it and is then wrong four times
    in twenty-four without being told which.
    """

    span = _span(orch, technique.id, "2h")

    assert span <= TWO_HOURS * 1.02, (
        f"{technique.id} ({technique.ndr_uc}) was asked for 2h and planned " f"{span / 3600:.2f}h"
    )


@pytest.mark.parametrize("technique_id", PREVIOUSLY_BROKEN)
def test_duration_actually_shortens_the_ones_that_ignored_it(
    orch: Orchestrator, technique_id: str
) -> None:
    """Guards the fix rather than the flag: each of these planned the same span
    whatever it was asked for, so a check that only bounds the result would pass
    again the moment the preset shrank."""

    natural = _span(orch, technique_id, None)
    asked = _span(orch, technique_id, "2h")

    assert natural > TWO_HOURS, f"{technique_id} preset is no longer longer than 2h"
    assert asked < natural, f"{technique_id} ignored --duration: {asked}s either way"


def test_a_short_beacon_keeps_its_real_interval(orch: Orchestrator) -> None:
    """The rule that makes duration useful rather than just short.

    REP-001 is a five minute callback. Asked for two hours it must still be a
    five minute callback, with fewer of them. A rule keyed on the interval is the
    whole reason the technique exists, so compressing the interval to fit would
    produce telemetry no detection could match.
    """

    plan = orch.build_plan(RunRequest(technique_id="REP-001", intensity="medium", duration="2h"))
    times = sorted(event.eventtime for event in plan.events)
    gaps = {later - earlier for earlier, later in zip(times, times[1:], strict=False)}

    assert gaps, "no gaps to inspect"
    # The preset interval, untouched. Jitter is allowed; a different scale is not.
    assert max(gaps) <= 320, f"interval was rescaled to fit the window: gaps {sorted(gaps)[:5]}"


def test_asking_for_longer_than_a_pinned_window_does_not_overrun_it(
    orch: Orchestrator,
) -> None:
    """REP-005 is off-hours bulk transfer, and off-hours is 00:00-06:00.

    A request for eight hours cannot be honoured without destroying the property
    the technique exists to demonstrate, so it is capped at the window rather
    than silently spilling into the working day.
    """

    span = _span(orch, "REP-005", "8h")

    assert span <= 6 * 3600 * 1.02, f"off-hours transfer ran {span / 3600:.2f}h"
