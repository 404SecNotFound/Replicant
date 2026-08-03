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
"""Garbage in must be an error, not a different answer.

``parse_duration`` used ``findall`` on an unanchored token pattern, so it
scavenged digits out of whatever it was given: ``"10x"`` became 10 seconds,
``"abc123"`` became 123 seconds, and ``"-1h"`` became a positive hour because the
minus sign simply was not part of any token. A typo in ``--duration`` therefore
produced a run of a *different length* rather than a complaint, which is the
worst shape a parser can have: the operator gets a plausible result and no signal.

This is F-09 in the 2026-08 security review, deferred there, and re-reported
independently by a later end-to-end review.

One correction to both reports: ``"1h30junk"`` is 3630 seconds, not 90 minutes.
The trailing text leaves the second token's unit empty, and the empty unit maps
to 1 second, so it parses as 1h + 30s. Measured, not assumed.

The vertical-scan case is the same principle in the port space: a count above
65535 cannot be satisfied from 65535 distinct ports, and ``unique_ints`` raises
rather than the caller explaining itself.
"""

from __future__ import annotations

import pytest

from replicant.config.settings import parse_duration


class TestParseDuration:
    @pytest.mark.parametrize(
        ("text", "seconds"),
        [
            ("30", 30),  # a bare integer is seconds
            ("30s", 30),
            ("5m", 300),
            ("2h", 7200),
            ("2d", 172800),
            ("1h30m", 5400),
            ("1h 30m", 5400),
            ("  45s  ", 45),
            ("1H30M", 5400),  # case-insensitive
        ],
    )
    def test_well_formed_durations_still_parse(self, text: str, seconds: int) -> None:
        """The fix must not narrow what already worked."""
        assert parse_duration(text) == seconds

    @pytest.mark.parametrize(
        "text",
        [
            "10x",  # was 10
            "abc123",  # was 123
            "1h30junk",  # was 3630, reported as 90 minutes
            "-1h",  # was 3600: a negative duration read as positive
            "1h garbage",  # was 3600
            "1h,30m",
            "h",
            "",
            "   ",
            "1.5h",  # no fractional support; silently became 1s + 5h before
        ],
    )
    def test_malformed_durations_raise(self, text: str) -> None:
        with pytest.raises(ValueError):
            parse_duration(text)

    def test_the_error_names_the_input(self) -> None:
        """An operator who mistyped needs to see what was read."""
        with pytest.raises(ValueError, match="10x"):
            parse_duration("10x")


class TestVerticalScanPortSpan:
    def test_a_port_count_above_the_port_space_is_clamped_not_raised(self) -> None:
        """65535 distinct ports is the ceiling. Asking for more is a clamp.

        Reachable only from the Python API or a hand-edited scenario stage, not
        from the CLI or the web form, so this is robustness rather than a live
        operator path. It still must not surface as a bare ValueError out of a
        distribution helper: the engine clamps `max_events` two lines above and
        records it, and the port span deserves the same treatment.
        """
        from replicant.config.settings import Settings
        from replicant.core.models import RunRequest, load_catalog
        from replicant.core.orchestrator import Orchestrator
        from replicant.resources import TECHNIQUE_CATALOG

        catalog = load_catalog(TECHNIQUE_CATALOG)
        orch = Orchestrator(catalog, Settings())

        # REP-002 is the vertical port scan (engine._BUILDERS).
        plan = orch.build_plan(
            RunRequest(
                technique_id="REP-002",
                intensity="low",
                param_overrides={"unique_ports": 70000},
            )
        )

        assert plan.events
