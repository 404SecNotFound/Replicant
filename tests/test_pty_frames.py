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

from replicant.web.pty_bridge import MAX_DIMENSION, _bounded


@pytest.mark.parametrize("value", [1, 30, 200, MAX_DIMENSION])
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
