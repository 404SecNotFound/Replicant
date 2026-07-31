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
from __future__ import annotations

import socket
import threading
from pathlib import Path

import pytest

from replicant.core.models import (
    CollectorProfile,
    ScenarioRunRequest,
    load_catalog,
    load_scenario_catalog,
)
from replicant.core.orchestrator import Orchestrator

ROOT = Path(__file__).resolve().parents[1]
TECH = load_catalog(ROOT / "replicant" / "data" / "technique-catalog.yaml")
SCEN = load_scenario_catalog(ROOT / "replicant" / "data" / "scenario-catalog.yaml", TECH)


def _orch(tmp_path: Path, vendor: str = "fortigate") -> Orchestrator:
    from replicant.config.settings import Settings

    return Orchestrator(TECH, Settings(manifest_dir=str(tmp_path / "m"), vendor=vendor))


def test_scenario_manifest_records_stage_truncation(tmp_path: Path) -> None:
    """A stage cut short by the engine cap must say so in the manifest, exactly as run()
    does for a single technique (safety rule 5: the audit trail records what was emitted)."""

    from replicant.config.settings import Settings
    from replicant.scenario.engine import ScenarioEngine

    orch = Orchestrator(
        TECH,
        Settings(manifest_dir=str(tmp_path / "m")),
        engine=ScenarioEngine(max_events=25),
    )
    result = orch.run_scenario(
        ScenarioRunRequest(
            scenario_id="SCEN-001",
            seed=1337,
            to_file=str(tmp_path / "t.log"),
            no_send=True,
        ),
        SCEN,
    )
    truncated = [s for s in result.manifest.stages if s.truncated]
    assert truncated, "expected at least one stage to hit the 25-event cap"
    assert "truncated" in (result.manifest.warmup_note or "")
    assert f"stage {truncated[0].index}" in (result.manifest.warmup_note or "")


def test_scenario_to_file_is_byte_identical(tmp_path: Path) -> None:
    orch = _orch(tmp_path)
    a = tmp_path / "a.log"
    b = tmp_path / "b.log"
    orch.run_scenario(
        ScenarioRunRequest(scenario_id="SCEN-001", seed=1337, to_file=str(a), no_send=True), SCEN
    )
    orch.run_scenario(
        ScenarioRunRequest(scenario_id="SCEN-001", seed=1337, to_file=str(b), no_send=True), SCEN
    )
    assert a.read_bytes() == b.read_bytes() and a.stat().st_size > 0


def test_scenario_fails_closed(tmp_path: Path) -> None:
    orch = _orch(tmp_path)
    with pytest.raises(RuntimeError, match="fail-closed"):
        orch.run_scenario(ScenarioRunRequest(scenario_id="SCEN-001", no_send=False), SCEN)


def test_scenario_writes_manifest_and_advisory(tmp_path: Path) -> None:
    orch = _orch(tmp_path)
    result = orch.run_scenario(
        ScenarioRunRequest(
            scenario_id="SCEN-001", seed=1337, to_file=str(tmp_path / "s.log"), no_send=True
        ),
        SCEN,
    )
    assert result.manifest_path.exists() and result.advisory_path.exists()
    assert result.manifest.total_event_count == result.event_count > 0
    assert len(result.manifest.stages) == 3
    assert result.manifest.coverage["covered_tactics"]


def test_scenario_vendor_renders_panos(tmp_path: Path) -> None:
    orch = _orch(tmp_path, vendor="paloalto")
    out = tmp_path / "pan.log"
    orch.run_scenario(
        ScenarioRunRequest(scenario_id="SCEN-001", seed=1337, to_file=str(out), no_send=True), SCEN
    )
    first = out.read_text().splitlines()[0]
    assert first.startswith("CEF:0|Palo Alto Networks|PAN-OS")


def test_scenario_loopback_udp_delivers(tmp_path: Path) -> None:
    """UDP delivery is best-effort, so this asserts what UDP actually promises.

    This test previously asserted ``len(received) == result.event_count``. That
    is not a guarantee UDP makes. SCEN-001 emits 1133 datagrams as fast as the
    socket accepts them, and if the kernel receive buffer fills before the
    reader thread drains it, the surplus is dropped by design. It passed on an
    idle developer machine and failed on a contended CI runner at 890/1133.

    Asserting exactness here encoded a false contract and produced a test that
    reported a transport regression when the real cause was scheduling. The
    exact-delivery claim now lives in the TCP test below, where the transport
    genuinely provides it.

    What remains worth asserting: something arrived, nothing extra arrived
    (which would mean duplicate sends), and the bulk got through, so a genuine
    regression that delivers only a trickle still fails.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Ask for a large receive buffer before binding. The kernel may clamp this,
    # which is fine: it reduces loss without the test depending on the increase.
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(2.0)
    port = sock.getsockname()[1]
    received: list[bytes] = []

    def rx() -> None:
        try:
            while True:
                received.append(sock.recvfrom(65535)[0])
        except OSError:
            pass

    thread = threading.Thread(target=rx, daemon=True)
    thread.start()
    orch = _orch(tmp_path)
    collector = CollectorProfile(name="t", host="127.0.0.1", port=port, transport="udp")
    result = orch.run_scenario(
        # Burst: what is under test is loopback delivery, not the schedule. A live
        # send now defaults to plan pacing, and SCEN-001 is a multi-hour timeline.
        ScenarioRunRequest(
            scenario_id="SCEN-001",
            seed=1337,
            collector=collector,
            no_send=False,
            pace="burst",
        ),
        SCEN,
    )
    # Join before close: let the receiver's own 2s recv timeout drain whatever is
    # already queued in the kernel UDP buffer. Closing first would cut it off mid-drain.
    thread.join(timeout=3)
    sock.close()

    assert result.event_count > 0
    assert len(received) > 0, "no datagrams arrived; the UDP path is broken"
    assert len(received) <= result.event_count, "more datagrams arrived than events were emitted"
    assert len(received) >= result.event_count // 2, (
        f"only {len(received)} of {result.event_count} datagrams arrived. "
        "Some UDP loss under load is expected; losing half is a regression."
    )


def test_scenario_loopback_tcp_delivers_every_event(tmp_path: Path) -> None:
    """TCP does guarantee delivery, so the exact-count assertion belongs here.

    Counts lines rather than reads, because TCP is a byte stream: a single recv
    can return several syslog frames or a partial one, so counting recv calls
    would measure segmentation instead of delivery.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    server.settimeout(10.0)
    port = server.getsockname()[1]
    chunks: list[bytes] = []

    def rx() -> None:
        try:
            conn, _ = server.accept()
            conn.settimeout(5.0)
            with conn:
                while True:
                    data = conn.recv(65535)
                    if not data:
                        return
                    chunks.append(data)
        except OSError:
            pass

    thread = threading.Thread(target=rx, daemon=True)
    thread.start()
    orch = _orch(tmp_path)
    collector = CollectorProfile(name="t", host="127.0.0.1", port=port, transport="tcp")
    result = orch.run_scenario(
        # Burst: what is under test is loopback delivery, not the schedule. A live
        # send now defaults to plan pacing, and SCEN-001 is a multi-hour timeline.
        ScenarioRunRequest(
            scenario_id="SCEN-001",
            seed=1337,
            collector=collector,
            no_send=False,
            pace="burst",
        ),
        SCEN,
    )
    thread.join(timeout=10)
    server.close()

    payload = b"".join(chunks)
    delivered = payload.count(b"CEF:0|")
    assert result.event_count > 0
    assert delivered == result.event_count, (
        f"TCP delivered {delivered} of {result.event_count} events. "
        "Unlike UDP, this transport guarantees delivery, so any shortfall is a real defect."
    )
