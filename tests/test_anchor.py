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
"""Event-time anchor resolution and the stale-anchor warning.

Background. The default anchor is fixed so identical seeds produce byte-identical
output. Correct for artifacts and for the golden tests, and a trap for a live
send: the syslog header is stamped now while the CEF eventtime stays at the
anchor. A SIEM that keys on parsed event time then drops the events outside every
recent-window rule and nothing fires, which is indistinguishable from the
detection being broken. Measured at 371 days of skew before this existed.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from replicant.config.settings import (
    STALE_ANCHOR_DAYS,
    parse_anchor,
    stale_anchor_warning,
)


def test_parse_anchor_now_is_close_to_now() -> None:
    assert abs(parse_anchor("now") - int(datetime.now(UTC).timestamp())) < 5


def test_parse_anchor_accepts_a_bare_epoch() -> None:
    assert parse_anchor("1752586800") == 1752586800


def test_parse_anchor_accepts_iso_with_zulu() -> None:
    assert parse_anchor("2025-07-15T13:40:00Z") == 1752586800


def test_parse_anchor_reads_naive_iso_as_utc_not_local() -> None:
    """A naive timestamp must mean the same instant on every machine.

    Falling back to local time would make the same command produce different
    output in different timezones, which breaks the determinism guarantee in a
    way that only shows up when someone else runs it.
    """
    assert parse_anchor("2025-07-15T13:40:00") == 1752586800


def test_parse_anchor_rejects_nonsense_with_a_usable_message() -> None:
    with pytest.raises(ValueError, match="anchor must be"):
        parse_anchor("yesterday-ish")


def test_no_warning_when_not_sending() -> None:
    """Writing to a file with a fixed anchor is the intended, reproducible case."""
    stale = int((datetime.now(UTC) - timedelta(days=400)).timestamp())
    assert stale_anchor_warning(stale, sending=False) is None


def test_no_warning_when_the_anchor_is_current() -> None:
    assert stale_anchor_warning(int(datetime.now(UTC).timestamp()), sending=True) is None


def test_warns_when_sending_with_a_stale_anchor() -> None:
    stale = int((datetime.now(UTC) - timedelta(days=371)).timestamp())
    msg = stale_anchor_warning(stale, sending=True)
    assert msg is not None
    assert "371 days in the past" in msg
    # The warning has to name the remedy, not just the symptom.
    assert "--anchor now" in msg


def test_warns_on_a_future_anchor_too() -> None:
    """A clock-skewed or mistyped future anchor breaks recent-window rules equally."""
    ahead = int((datetime.now(UTC) + timedelta(days=30)).timestamp())
    msg = stale_anchor_warning(ahead, sending=True)
    assert msg is not None
    assert "in the future" in msg


def test_threshold_is_exclusive_at_the_boundary() -> None:
    """Just inside the window is quiet, comfortably outside it warns.

    Pinned because a run started slightly before midnight should not start
    warning purely because the day rolled over.
    """
    now = int(datetime.now(UTC).timestamp())
    just_inside = now - int((STALE_ANCHOR_DAYS - 0.5) * 86400)
    well_outside = now - int((STALE_ANCHOR_DAYS + 1) * 86400)
    assert stale_anchor_warning(just_inside, sending=True, now=now) is None
    assert stale_anchor_warning(well_outside, sending=True, now=now) is not None
