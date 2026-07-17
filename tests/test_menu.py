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
"""Rich menu helpers: saved-collector selection and vendor selection logic."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from rich.console import Console

from replicant.cli.menu import _pick_saved_profile, _pick_vendor, _vendor_label
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


@pytest.mark.parametrize(
    ("choice", "expected"),
    [("1", "fortigate"), ("2", "paloalto"), ("3", "checkpoint")],
)
def test_pick_vendor_maps_index_to_vendor(choice: str, expected: str) -> None:
    console = Console(quiet=True)
    with patch("replicant.cli.menu.Prompt.ask", return_value=choice):
        assert _pick_vendor(console, "fortigate") == expected


def test_pick_vendor_default_index_tracks_current() -> None:
    console = Console(quiet=True)
    # When the user accepts the default, Prompt.ask returns the computed default,
    # which is the current vendor's 1-based index. checkpoint is option 3.
    captured: dict[str, str] = {}

    def _fake_ask(*_args: object, **kwargs: object) -> str:
        captured["default"] = str(kwargs["default"])
        return str(kwargs["default"])

    with patch("replicant.cli.menu.Prompt.ask", side_effect=_fake_ask):
        assert _pick_vendor(console, "checkpoint") == "checkpoint"
    assert captured["default"] == "3"


def test_vendor_label_falls_back_to_id() -> None:
    assert _vendor_label("checkpoint") == "Check Point"
    assert _vendor_label("mystery") == "mystery"
