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
"""Terminal frame validation (F-05 from the 2026-08 review).

The bridge assumed decoded JSON was an object, so a valid JSON scalar or array
raised at ``control.get()``. That ended the input task while the parent waited
only on ``closing``, so the PTY and its child process stayed alive with nobody
reading them: one malformed frame stranded a session.

These cover the pure validation helpers. The lifecycle change (waiting on the
first of input failure, output failure or disconnect) is exercised by the
terminal websocket tests in ``test_web_origin.py``.
"""

from __future__ import annotations

import pytest

from replicant.web.pty_bridge import MAX_DIMENSION, MIN_DIMENSION, _bounded


# 1 was in this list. It is now refused: see MIN_DIMENSION, and the
# one-character-per-line terminal that accepting it produced.
@pytest.mark.parametrize("value", [MIN_DIMENSION, 30, 200, MAX_DIMENSION])
def test_a_usable_dimension_is_accepted(value: int) -> None:
    assert _bounded(value, 30) == value


def test_a_missing_dimension_falls_back(value: int = 0) -> None:
    assert _bounded(None, 30) == 30


@pytest.mark.parametrize("value", [0, -1, MAX_DIMENSION + 1, 10**9])
def test_an_out_of_range_dimension_is_refused(value: int) -> None:
    """struct.pack raises on a huge int, and a browser never reports one. The
    frame is dropped rather than allowed to kill the input task."""

    assert _bounded(value, 30) is None


@pytest.mark.parametrize("value", ["30", 30.5, [30], {"rows": 30}, True])
def test_a_non_integer_dimension_is_refused(value: object) -> None:
    """``True`` is an int in Python and would pack as 1, silently resizing the
    terminal to a single row."""

    assert _bounded(value, 30) is None


# A terminal one column wide is not a terminal.
#
# Found while verifying F-04 in a real browser: the xterm fit addon runs against
# a container that is briefly zero-width (a tab that has not been laid out yet, a
# hidden pane), computes cols=1, and sends it. `_bounded` accepted anything from
# 1 to MAX_DIMENSION, so the PTY was duly resized to one column and every
# subsequent prompt wrapped one character per line. The banner printed before the
# resize stayed readable, which is what makes it look like a rendering fault
# rather than a resize the server agreed to.
#
# Floored server-side rather than client-side. The client is the thing that was
# wrong, and a bound that only holds when the client is correct is not a bound.
def test_a_degenerate_width_is_refused() -> None:
    from replicant.web.pty_bridge import MIN_DIMENSION, _bounded

    assert _bounded(1, 100) is None
    assert _bounded(MIN_DIMENSION - 1, 100) is None


def test_a_usable_width_is_still_accepted() -> None:
    from replicant.web.pty_bridge import MIN_DIMENSION, _bounded

    assert _bounded(MIN_DIMENSION, 100) == MIN_DIMENSION
    assert _bounded(100, 100) == 100
    assert _bounded(200, 100) == 200


def test_the_floor_leaves_room_for_the_menu() -> None:
    """The Rich menu draws an 80-column table; a floor below that would ship a
    terminal that connects and is still unusable."""
    from replicant.web.pty_bridge import MIN_DIMENSION

    assert MIN_DIMENSION >= 20
