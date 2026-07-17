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
"""Rich menu helpers: saved-collector selection logic."""

from __future__ import annotations

from unittest.mock import patch

from rich.console import Console

from replicant.cli.menu import _pick_saved_profile
from replicant.core.models import CollectorProfile


def _profiles() -> dict[str, CollectorProfile]:
    return {
        "prod": CollectorProfile(name="prod", host="10.0.0.5", port=514, transport="udp"),
        "lab": CollectorProfile(name="lab", host="10.0.0.6", port=6514, transport="tls"),
    }


def test_pick_saved_profile_returns_selection_by_sorted_index() -> None:
    console = Console(quiet=True)
    # Profiles are listed sorted by name -> ["lab", "prod"]; choice "1" is lab.
    with patch("replicant.cli.menu.Prompt.ask", return_value="1"):
        chosen = _pick_saved_profile(console, _profiles())
    assert chosen is not None
    assert chosen.name == "lab"
    assert chosen.transport == "tls"


def test_pick_saved_profile_new_returns_none() -> None:
    console = Console(quiet=True)
    with patch("replicant.cli.menu.Prompt.ask", return_value="n"):
        assert _pick_saved_profile(console, _profiles()) is None
