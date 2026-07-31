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
"""Pacing in the Rich menu.

The menu is an interactive interface, so a run that quietly becomes four hours
long is worse here than anywhere else: the operator is sitting in front of it
waiting for a prompt to come back. "Start run?" has to be an informed question.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from rich.console import Console

from replicant.cli.menu import _params_flow, _run_technique
from replicant.config.settings import Settings
from replicant.core.models import CollectorProfile, RunRequest, load_catalog
from replicant.core.orchestrator import Orchestrator
from replicant.resources import TECHNIQUE_CATALOG

CATALOG = load_catalog(TECHNIQUE_CATALOG)
COLLECTOR = CollectorProfile(name="lab", host="127.0.0.1", port=5514, transport="udp")


def _answers(monkeypatch: pytest.MonkeyPatch, prompts: list[str], confirms: list[bool]) -> None:
    """Feed the flow a fixed script of answers, in order."""

    remaining_prompts = list(prompts)
    remaining_confirms = list(confirms)
    monkeypatch.setattr(
        "replicant.cli.menu.Prompt.ask",
        staticmethod(lambda *a, **k: remaining_prompts.pop(0)),
    )
    monkeypatch.setattr(
        "replicant.cli.menu.Confirm.ask",
        staticmethod(lambda *a, **k: remaining_confirms.pop(0)),
    )


def test_a_live_run_offers_the_pace_and_defaults_to_the_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Accepting every default while sending to a collector gives plan pacing,
    the same answer the CLI and the web form reach."""

    # intensity, duration, pace, speed
    _answers(monkeypatch, ["low", "", "plan", "1"], [False])

    request = _params_flow(Console(), "REP-001", 1337, COLLECTOR)

    assert request.pace == "plan"
    assert request.speed == 1.0


def test_a_dry_run_to_file_is_never_asked_about_pacing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A file has no wall clock to reproduce, so the question has no answer worth
    having. Asking it would be a control whose output cannot change."""

    # intensity, duration, output file, and nothing else. The script has no
    # fourth answer, so asking a fourth question fails this test.
    _answers(monkeypatch, ["low", "", "./out/x.log"], [True])

    request = _params_flow(Console(), "REP-001", 1337, COLLECTOR)

    # Left unset rather than defaulted here: the destination decides, in one
    # place, the same way the CLI leaves it to resolve_pace.
    assert request.pace is None


def test_the_speed_is_only_asked_for_when_the_plan_is_being_followed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _answers(monkeypatch, ["low", "", "burst"], [False])

    request = _params_flow(Console(), "REP-001", 1337, COLLECTOR)

    assert request.pace == "burst"
    assert request.speed == 1.0


def test_the_confirmation_says_how_long_the_run_will_take(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The defect this guards: the prompt showed an event count and nothing else,
    so "Start run?" on a 238 minute plan looked identical to one on a 3 second
    plan. An operator cannot consent to a cost they are not shown."""

    console = Console(record=True, width=100)
    monkeypatch.setattr("replicant.cli.menu.Confirm.ask", staticmethod(lambda *a, **k: False))

    orchestrator = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
    _run_technique(
        orchestrator,
        RunRequest(technique_id="REP-001", intensity="low", collector=COLLECTOR, pace="plan"),
        console,
    )

    output = console.export_text()
    assert "3h 58m" in output, output
