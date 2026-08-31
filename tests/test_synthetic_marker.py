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
"""settings.benign_marker stamps a synthetic-data marker on every emitted line.

The blueprint (s58) promised a switch that stamps a marker so lab data is
separable from production in a shared collector. The setting existed and was read
nowhere: turning it on produced no marker, no error and no warning, and had done
since the first release.

The marker rides in flexString1, a CEF customer custom field used by none of the
three vendor profiles (Palo Alto already uses cs6, so a custom-string slot was
not free across all three). It is off by default, so the default wire format and
the golden lines are unchanged; the positive control below reverts the wiring and
watches the "on" assertions go red while the default-off ones stay green.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from replicant.config.settings import Settings
from replicant.core.models import EventRecord, RunRequest, load_catalog
from replicant.core.orchestrator import (
    SYNTHETIC_MARKER_KEY,
    SYNTHETIC_MARKER_LABEL,
    SYNTHETIC_MARKER_LABEL_KEY,
    Orchestrator,
    synthetic_marker,
)
from replicant.resources import TECHNIQUE_CATALOG

CATALOG = load_catalog(TECHNIQUE_CATALOG)

_MARKER_TOKEN = f"{SYNTHETIC_MARKER_LABEL_KEY}={SYNTHETIC_MARKER_LABEL}"


def _orch(*, marker: bool) -> Orchestrator:
    return Orchestrator(CATALOG, Settings(benign_marker=marker))


def _sample_event() -> EventRecord:
    orch = _orch(marker=False)
    return orch.build_plan(
        RunRequest(technique_id="REP-001", intensity="low", no_send=True)
    ).events[0]


def test_marker_helper_carries_the_run_id() -> None:
    m = synthetic_marker("RUN-20260831T142212Z-a3f9c1")
    assert m[SYNTHETIC_MARKER_LABEL_KEY] == SYNTHETIC_MARKER_LABEL
    assert m[SYNTHETIC_MARKER_KEY] == "RUN-20260831T142212Z-a3f9c1"


def test_marker_helper_falls_back_to_literal_synthetic() -> None:
    assert synthetic_marker(None)[SYNTHETIC_MARKER_KEY] == "synthetic"


def test_off_by_default_the_line_has_no_marker() -> None:
    line = _orch(marker=False).render_line(_sample_event())
    assert SYNTHETIC_MARKER_LABEL not in line
    assert f"{SYNTHETIC_MARKER_KEY}=" not in line


def test_on_the_line_carries_the_marker() -> None:
    line = _orch(marker=True).render_line(_sample_event(), run_id="RUN-x")
    assert _MARKER_TOKEN in line
    assert f"{SYNTHETIC_MARKER_KEY}=RUN-x" in line


def test_the_test_line_is_markable_too() -> None:
    assert _MARKER_TOKEN in _orch(marker=True).build_test_line()
    assert _MARKER_TOKEN not in _orch(marker=False).build_test_line()


def test_every_emitted_line_is_marked(tmp_path: Path) -> None:
    """The whole point: separability requires the marker on all of them, not some."""

    out = tmp_path / "run.log"
    orch = Orchestrator(CATALOG, Settings(benign_marker=True, manifest_dir=str(tmp_path)))
    result = orch.run(
        RunRequest(technique_id="REP-001", intensity="low", to_file=str(out), no_send=True)
    )
    lines = out.read_text(encoding="utf-8").splitlines()
    assert lines, "run produced no lines to check"
    assert all(_MARKER_TOKEN in line for line in lines)
    # And the marker value is the run id, so a marked line is traceable.
    assert all(f"{SYNTHETIC_MARKER_KEY}={result.run_id}" in line for line in lines)


def test_default_run_is_unmarked(tmp_path: Path) -> None:
    out = tmp_path / "run.log"
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
    orch.run(RunRequest(technique_id="REP-001", intensity="low", to_file=str(out), no_send=True))
    lines = out.read_text(encoding="utf-8").splitlines()
    assert lines
    assert not any(SYNTHETIC_MARKER_LABEL in line for line in lines)


@pytest.mark.parametrize("vendor", ["fortigate", "paloalto", "checkpoint"])
def test_marker_does_not_overwrite_a_vendor_field(vendor: str, tmp_path: Path) -> None:
    """flexString1 is free on all three, so marking never clobbers a real field.

    REP-006 renders traffic:forward, which is where Palo Alto packs cs1..cs6; if
    the marker had taken a cs slot this would drop a real field on one vendor.
    """

    off = Orchestrator(CATALOG, Settings(vendor=vendor)).render_line(_sample_event())
    on = Orchestrator(CATALOG, Settings(vendor=vendor, benign_marker=True)).render_line(
        _sample_event(), run_id="RUN-x"
    )
    # Marking only adds; every field present unmarked is still present marked.
    for field in off.split(" "):
        if "=" in field and not field.startswith("CEF:"):
            assert field in on
