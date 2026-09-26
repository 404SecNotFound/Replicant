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
"""Receiver robustness and verdict labelling from the 2026-09-26 review.

All sockets are 127.0.0.1 and owned by the test, per safety rule 1.
"""

from __future__ import annotations

import socket
import threading
from pathlib import Path

import pytest

from replicant.config.settings import Settings
from replicant.core.models import RunRequest, load_catalog
from replicant.core.orchestrator import Orchestrator
from replicant.resources import TECHNIQUE_CATALOG
from replicant.validation.contract import load_contracts
from replicant.validation.evaluator import evaluate_ingest, evaluate_plan
from replicant.validation.receiver import LocalSyslogReceiver
from replicant.validation.sources.base import Observation
from replicant.validation.verdict import Verdict, exit_code

CATALOG = load_catalog(TECHNIQUE_CATALOG)
CONTRACTS = load_contracts(CATALOG)
ORCHESTRATOR = Orchestrator(CATALOG, Settings())

# -- 10. receiver -------------------------------------------------------------


def _udp(port: int, payload: bytes) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        sender.sendto(payload, ("127.0.0.1", port))


def test_udp_receiver_survives_a_non_utf8_datagram(tmp_path: Path) -> None:
    """One bad datagram raised UnicodeDecodeError and killed the thread silently.

    Every later record was then lost and the verdict read fail_no_events for a
    run that had delivered everything. The bad record is kept (replacement
    characters) and reception continues.
    """

    with LocalSyslogReceiver(tmp_path / "rx.log", transport="udp") as receiver:
        _udp(receiver.port, b"first")
        assert receiver.wait_for_count(1, timeout=5.0)
        _udp(receiver.port, b"bad \xff\xfe bytes")
        _udp(receiver.port, b"third")
        assert receiver.wait_for_count(3, timeout=5.0), receiver.records
    assert receiver.records[0] == "first"
    assert receiver.records[2] == "third"
    assert "�" in receiver.records[1]


def test_tcp_receiver_survives_a_non_utf8_line(tmp_path: Path) -> None:
    with LocalSyslogReceiver(tmp_path / "rx.log", transport="tcp") as receiver:
        with socket.create_connection(("127.0.0.1", receiver.port)) as client:
            client.sendall(b"one\nbad \xff line\nthree\n")
        assert receiver.wait_for_count(3, timeout=5.0), receiver.records
    assert receiver.records[0] == "one" and receiver.records[2] == "three"


def test_tcp_receiver_accepts_more_than_one_connection(tmp_path: Path) -> None:
    """TCP mode accepted exactly one connection; a reconnecting sender lost the rest."""

    with LocalSyslogReceiver(tmp_path / "rx.log", transport="tcp") as receiver:
        for index in range(3):
            with socket.create_connection(("127.0.0.1", receiver.port)) as client:
                client.sendall(f"conn-{index}\n".encode())
        assert receiver.wait_for_count(3, timeout=5.0), receiver.records
    assert sorted(receiver.records) == ["conn-0", "conn-1", "conn-2"]


def test_receiver_thread_failure_surfaces_through_wait(tmp_path: Path) -> None:
    """Any exception in the receive path, not only OSError, must reach the caller.

    A failure that only ends the thread reports as missing telemetry, which is
    the wrong failure. The decode path is forced to raise something that is not
    an OSError.
    """

    receiver = LocalSyslogReceiver(tmp_path / "rx.log", transport="udp")

    def explode(raw: bytes) -> None:
        raise RuntimeError("synthetic receive failure")

    receiver._append = explode  # type: ignore[method-assign]
    with receiver:
        _udp(receiver.port, b"anything")
        with pytest.raises(OSError, match="synthetic receive failure"):
            receiver.wait_for_count(1, timeout=5.0)


def test_receiver_close_stops_open_tcp_readers(tmp_path: Path) -> None:
    """Shutdown is bounded: an idle client connection must not hold close() open."""

    receiver = LocalSyslogReceiver(tmp_path / "rx.log", transport="tcp")
    with receiver:
        client = socket.create_connection(("127.0.0.1", receiver.port))
        client.sendall(b"held\n")
        assert receiver.wait_for_count(1, timeout=5.0)
    try:
        assert all(
            not thread.is_alive()
            for thread in threading.enumerate()
            if thread.name == "replicant-ingest-conn"
        )
    finally:
        client.close()
    assert (tmp_path / "rx.log").read_text(encoding="utf-8") == "held\n"


# -- 11. a failed property is not "no events" ---------------------------------


def test_a_failed_axis_is_fail_contract_not_fail_no_events() -> None:
    """Every failed check used to map to fail_no_events, even with events present.

    REP-001's cadence axis is a property of events that exist. Scrambling their
    times keeps every event and breaks only the property.
    """

    plan = ORCHESTRATOR.build_plan(
        RunRequest(technique_id="REP-001", intensity="low", seed=7, no_send=True)
    )
    positive = [event for event in plan.events if event.control == "positive"]
    for index, event in enumerate(positive):
        event.eventtime = plan.anchor_epoch + (index * index * 37) % 7919
    plan.events.sort(key=lambda event: event.eventtime)
    result = evaluate_plan(CONTRACTS.by_id("REP-001"), plan, seed=7)

    failed = {check.id for check in result.checks if check.status == "fail"}
    assert failed == {"axis:cadence"}
    assert result.verdict == Verdict.FAIL_CONTRACT
    assert result.dimensions["plan"] == "fail_contract"
    assert exit_code(result) == 1


def test_missing_events_are_still_fail_no_events() -> None:
    plan = ORCHESTRATOR.build_plan(
        RunRequest(technique_id="REP-001", intensity="low", seed=7, no_send=True)
    )
    plan.events = [event for event in plan.events if event.control == "negative"]
    result = evaluate_plan(CONTRACTS.by_id("REP-001"), plan, seed=7)
    assert result.verdict == Verdict.FAIL_NO_EVENTS


def test_an_out_of_order_plan_fails_the_contract() -> None:
    """The REP-006/REP-007 defect as a contract: a plan emitted in list order must be sorted."""

    plan = ORCHESTRATOR.build_plan(
        RunRequest(technique_id="REP-006", intensity="low", seed=1337, no_send=True)
    )
    plan.events.reverse()
    result = evaluate_plan(CONTRACTS.by_id("REP-006"), plan, seed=1337)
    assert {check.id for check in result.checks if check.status == "fail"} == {"event-order"}
    assert result.verdict == Verdict.FAIL_CONTRACT


def test_ingest_keeps_the_plan_verdict_and_names_delivery_loss_separately() -> None:
    plan = ORCHESTRATOR.build_plan(
        RunRequest(technique_id="REP-006", intensity="low", seed=1337, no_send=True)
    )
    plan.events.reverse()
    plan_result = evaluate_plan(CONTRACTS.by_id("REP-006"), plan, seed=1337)
    empty = Observation(source="fixture", run_id="RUN-X", window=(0, 0))
    ingest = evaluate_ingest(plan_result, empty, [])
    assert ingest.verdict == Verdict.FAIL_CONTRACT
    assert ingest.dimensions["delivery"] == "fail_no_events"
