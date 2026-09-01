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
not free across all three). The default is destination-conditional (roadmap
2026-09 item 3, see the section at the end of this file): off for --to-file and
loopback so the golden lines are unchanged, on for a non-loopback send.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from replicant.config.settings import Settings
from replicant.core.models import CollectorProfile, EventRecord, RunRequest, load_catalog
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


# --- roadmap 2026-09 item 3: destination-conditional default -----------------
#
# The default flips from "off unless asked" to "off for --to-file and loopback,
# ON for a non-loopback send". flexString1 is an unused flex slot no detection
# reads (see above), so marking a live send corrupts nothing a rule keys on,
# while separability on a shared collector is exactly what an analyst needs at
# 3am. --to-file and loopback stay off so the golden line remains the oracle.
#
# Positive control: revert the `non_loopback_send` branch of
# Orchestrator._resolve_marker (make it always fall through to "off") and the
# non-loopback assertions here go red while the loopback/file ones stay green.


def _decision(*, send: bool, host: str | None = None, **flags: bool) -> tuple[bool, str]:
    orch = Orchestrator(CATALOG, Settings(**flags))
    collector = CollectorProfile(host=host) if host else None
    return orch._resolve_marker(send=send, collector=collector)


def test_default_on_for_a_non_loopback_send() -> None:
    on, note = _decision(send=True, host="10.0.20.125")
    assert on is True
    assert "10.0.20.125" in note


def test_default_off_for_a_loopback_send() -> None:
    assert _decision(send=True, host="127.0.0.1")[0] is False
    assert _decision(send=True, host="localhost")[0] is False
    assert _decision(send=True, host="::1")[0] is False


def test_default_off_for_file_or_no_send() -> None:
    assert _decision(send=False)[0] is False


def test_mark_synthetic_forces_on_even_off_wire() -> None:
    assert _decision(send=False, benign_marker=True)[0] is True


def test_no_marker_forces_off_and_warns_on_a_non_loopback_send(
    caplog: pytest.LogCaptureFixture,
) -> None:
    import logging

    with caplog.at_level(logging.WARNING):
        on, note = _decision(send=True, host="10.0.20.125", no_marker=True)
    assert on is False
    assert "no-marker" in note.lower()
    assert any("no-marker" in r.message.lower() for r in caplog.records)


def test_a_non_loopback_send_is_marked_by_default_end_to_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No marker flag set: a send to a non-loopback collector is marked anyway."""

    captured: list[str] = []

    class _FakeEmitter:
        def __init__(self, collector: object, hostname: str = "") -> None: ...
        def connect(self) -> None: ...
        def send(self, line: str, level: str = "info") -> int:
            captured.append(line)
            return len(line)

        def close(self) -> None: ...

    monkeypatch.setattr("replicant.core.orchestrator.SyslogEmitter", _FakeEmitter)
    orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
    result = orch.run(
        RunRequest(
            technique_id="REP-001",
            intensity="low",
            pace="burst",
            collector=CollectorProfile(host="203.0.113.9", port=514, transport="udp"),
        )
    )
    assert captured, "fake emitter captured nothing"
    assert all(_MARKER_TOKEN in line for line in captured)
    assert "applied" in result.manifest.marker_attestation
