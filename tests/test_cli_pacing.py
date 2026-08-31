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
"""The pacing controls, as the command line exposes them.

Plan pacing turns a three second run into a four hour one. That is the point, and
it must never be a surprise, so the run says how long it will take before it emits
anything rather than after.
"""

from __future__ import annotations

import socket
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from replicant.cli.app import main
from replicant.config.settings import Settings
from replicant.core.models import RunRequest, load_catalog
from replicant.core.orchestrator import Orchestrator, PacingPreview
from replicant.resources import TECHNIQUE_CATALOG

CATALOG = load_catalog(TECHNIQUE_CATALOG)


class _Recorder:
    """Stands in for the Orchestrator so the flags can be read off the request."""

    seen: list[Any] = []

    def __init__(self, catalog: Any, settings: Any) -> None:
        _Recorder.seen = []

    def preview_pacing(self, request: Any, *, sending: bool) -> PacingPreview:
        return PacingPreview(
            event_count=0,
            plan_span_s=0,
            compressed_span_s=0,
            projected_s=0.0,
            projected_by_pace={"plan": 0.0, "burst": 0.0},
            pace=request.pace or ("plan" if sending else "burst"),
            speed=request.speed,
        )

    def preview_scenario_pacing(
        self, request: Any, scenarios: Any, *, sending: bool
    ) -> PacingPreview:
        return self.preview_pacing(request, sending=sending)

    def run(self, request: RunRequest) -> Any:
        _Recorder.seen.append(request)
        return SimpleNamespace(summary=lambda: "recorded", stopped=False)


# -- the projection ----------------------------------------------------------


def test_the_projection_is_the_plan_s_own_span(tmp_path: Path) -> None:
    """REP-001 low is 49 events across 238 minutes. Plan paced, it takes 238
    minutes, and an operator is entitled to know that before committing."""

    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))

    preview = orch.preview_pacing(
        RunRequest(technique_id="REP-001", intensity="low", pace="plan"), sending=True
    )

    assert preview.event_count == 49
    assert preview.plan_span_s == 14_280
    assert preview.projected_s == pytest.approx(14_280, abs=1)


def test_speed_shortens_the_projection_proportionally(tmp_path: Path) -> None:
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))

    preview = orch.preview_pacing(
        RunRequest(technique_id="REP-001", intensity="low", pace="plan", speed=60.0),
        sending=True,
    )

    assert preview.projected_s == pytest.approx(238, abs=2)


def test_burst_is_projected_at_the_rate_cap_not_the_plan(tmp_path: Path) -> None:
    """The same 238 minute plan, sent as a burst, is over in a fraction of a
    second. The contrast is the whole reason the control exists."""

    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))

    preview = orch.preview_pacing(
        RunRequest(technique_id="REP-001", intensity="low", pace="burst", rate_override=200),
        sending=True,
    )

    assert preview.plan_span_s == 14_280
    assert preview.projected_s == pytest.approx(48 * 0.005, abs=0.01)


# -- the flags ---------------------------------------------------------------


def test_pace_and_speed_reach_the_request(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("replicant.cli.app.Orchestrator", _Recorder)

    rc = main(
        [
            "run",
            "REP-001",
            "--to-file",
            str(tmp_path / "o.log"),
            "--no-send",
            "--pace",
            "plan",
            "--speed",
            "60",
        ]
    )

    assert rc == 0
    request = _Recorder.seen[-1]
    assert request.pace == "plan"
    assert request.speed == 60.0


def test_the_pace_is_left_unset_when_not_asked_for(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Unset, not defaulted at the CLI. The destination decides, in one place."""

    monkeypatch.setattr("replicant.cli.app.Orchestrator", _Recorder)

    main(["run", "REP-001", "--to-file", str(tmp_path / "o.log"), "--no-send"])

    assert _Recorder.seen[-1].pace is None


def test_malformed_duration_is_refused_cleanly_not_with_a_traceback(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """`--duration 30min` used to raise a raw ValueError traceback out of the
    orchestrator, and in the Rich menu it tore down the whole session. Validating
    on the request model turns it into the same clean refusal every other bad
    flag gets. Nothing is written to stdout, so a redirected run does not swallow
    the reason."""

    rc = main(
        ["run", "REP-001", "--no-send", "--to-file", str(tmp_path / "o.log"), "--duration", "30min"]
    )

    captured = capsys.readouterr()
    assert rc == 1
    assert "cannot parse duration" in captured.err.lower()
    assert "traceback" not in captured.err.lower()
    assert captured.out.strip() == ""
    assert not (tmp_path / "o.log").exists()


def test_speed_beside_burst_is_refused_rather_than_ignored(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A control whose output cannot change is decoration. Burst has no timeline
    to compress, so asking for both is a mistake worth naming."""

    rc = main(["run", "REP-001", "--no-send", "--pace", "burst", "--speed", "60"])

    captured = capsys.readouterr()
    assert rc == 1
    assert "speed applies to plan pacing only" in captured.err.lower()
    # The diagnostic belongs on stderr: `replicant run ... > events.log` must not
    # swallow the reason it refused.
    assert "speed applies" not in captured.out.lower()


def test_speed_on_a_file_run_is_refused_because_a_file_bursts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """No pace named and no collector resolves to burst, which would discard the
    speed silently. The resolved pace is what has to be checked, not the flag."""

    rc = main(
        ["run", "REP-001", "--to-file", str(tmp_path / "o.log"), "--no-send", "--speed", "60"]
    )

    assert rc == 1
    assert "speed applies to plan pacing only" in capsys.readouterr().err.lower()


def test_a_live_run_says_how_long_it_will_take_before_emitting(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    try:
        rc = main(
            [
                "run",
                "REP-002",
                "--intensity",
                "low",
                "--host",
                "127.0.0.1",
                "--port",
                str(sock.getsockname()[1]),
                "--pace",
                "burst",
                "--anchor",
                "now",
            ]
        )
    finally:
        sock.close()

    out = capsys.readouterr().out
    assert rc == 0
    assert "burst" in out.lower()
    assert "will take" in out.lower()


def test_the_scenario_runner_takes_the_same_flags(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A scenario is a longer timeline, so pacing matters there more, not less."""

    seen: list[Any] = []

    class _ScenarioRecorder(_Recorder):
        def run_scenario(self, request: Any, scenarios: Any) -> Any:
            seen.append(request)
            return SimpleNamespace(
                manifest=SimpleNamespace(scenario_id="SCEN-001", stages=[]),
                event_count=0,
                manifest_path=tmp_path / "m.json",
                advisory_path=tmp_path / "a.md",
                stopped=False,
            )

    monkeypatch.setattr("replicant.cli.app.Orchestrator", _ScenarioRecorder)

    main(
        [
            "scenario",
            "run",
            "SCEN-001",
            "--to-file",
            str(tmp_path / "s.log"),
            "--no-send",
            "--pace",
            "plan",
            "--speed",
            "120",
        ]
    )

    assert seen[-1].pace == "plan"
    assert seen[-1].speed == 120.0
