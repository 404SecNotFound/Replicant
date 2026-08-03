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
"""Three defects that all made a run report less than it knew.

**F-12, the run stream was destructive.** Every consumer read the same
``queue.Queue``, and ``get()`` removes the item, so two browser tabs watching one
run each received a random subset of the lines and neither saw the whole stream.

**A failed run reported nothing.** The orchestrator writes a manifest on every
exit path (F-02) and then re-raises the original exception unchanged, which is
right. But the web runner had no way to reach that manifest, so it published
``manifest: None, count: 0`` while a complete partial record sat on disk. Half of
what F-02 guaranteed was invisible from the one surface most likely to need it.

**Progress never reported its last word.** The callback fired on multiples of
100, so a 250-event run reported 200 and stopped, and every consumer sat at 80%
on a finished run.
"""

from __future__ import annotations

import queue
from pathlib import Path

import pytest

from replicant.config.settings import Settings
from replicant.core.models import CollectorProfile, RunRequest, load_catalog
from replicant.core.orchestrator import Orchestrator, attach_run_record, run_record_of
from replicant.resources import TECHNIQUE_CATALOG
from replicant.web.runner import RunHandle

CATALOG = load_catalog(TECHNIQUE_CATALOG)


def _handle() -> RunHandle:
    return RunHandle(
        run_id="r1",
        orchestrator=Orchestrator(CATALOG, Settings()),
        queue=queue.Queue(maxsize=100),
        total=3,
    )


class TestFanOut:
    def test_two_consumers_both_see_every_item(self) -> None:
        """The defect, stated directly: they used to split the stream."""
        handle = _handle()
        a, b = handle.subscribe(), handle.subscribe()

        for i in range(5):
            handle.publish({"type": "line", "data": f"line-{i}"})

        assert [a.get_nowait()["data"] for _ in range(5)] == [f"line-{i}" for i in range(5)]
        assert [b.get_nowait()["data"] for _ in range(5)] == [f"line-{i}" for i in range(5)]

    def test_the_handles_own_queue_still_receives(self) -> None:
        """Callers that predate fan-out read handle.queue directly."""
        handle = _handle()
        handle.publish({"type": "line", "data": "x"})

        assert handle.queue.get_nowait()["data"] == "x"

    def test_unsubscribing_stops_delivery(self) -> None:
        handle = _handle()
        gone = handle.subscribe()
        handle.unsubscribe(gone)

        handle.publish({"type": "line", "data": "after"})

        assert gone.empty()

    def test_the_handles_own_queue_cannot_be_unsubscribed(self) -> None:
        """The worker would otherwise be publishing into nothing."""
        handle = _handle()
        handle.unsubscribe(handle.queue)

        handle.publish({"type": "line", "data": "x"})

        assert handle.queue.get_nowait()["data"] == "x"

    def test_one_stalled_reader_does_not_starve_the_others(self) -> None:
        """Isolation is the second reason for fan-out, after correctness."""
        handle = _handle()
        slow = handle.subscribe()
        fast = handle.subscribe()
        while True:  # fill the slow reader's queue
            try:
                slow.put_nowait({"type": "filler"})
            except queue.Full:
                break

        handle.publish({"type": "line", "data": "important"})

        # Drain the fast one; the item must be in there despite the stall.
        seen = []
        while not fast.empty():
            seen.append(fast.get_nowait())
        assert any(i.get("data") == "important" for i in seen)


class TestFailedRunRecord:
    def test_a_record_survives_on_the_exception(self) -> None:
        exc = RuntimeError("boom")
        attach_run_record(exc, {"technique_id": "REP-001"}, "/tmp/m.json", 42)

        record = run_record_of(exc)
        assert record is not None
        assert record["manifest_path"] == "/tmp/m.json"
        assert record["event_count"] == 42

    def test_an_exception_with_no_record_reads_as_none(self) -> None:
        assert run_record_of(RuntimeError("boom")) is None

    def test_a_failed_run_attaches_its_partial_manifest(self, tmp_path: Path) -> None:
        """End to end: a refused collector must still leave an auditable record."""
        probe = __import__("socket").socket()
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
        probe.close()

        orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
        with pytest.raises(OSError) as caught:
            orch.run(
                RunRequest(
                    technique_id="REP-001",
                    intensity="low",
                    duration="20s",
                    no_send=False,
                    collector=CollectorProfile(
                        name="t", host="127.0.0.1", port=closed_port, transport="tcp"
                    ),
                )
            )

        record = run_record_of(caught.value)
        assert record is not None, "a failed run left no reachable record"
        assert Path(record["manifest_path"]).is_file()
        assert record["manifest"]["status"] == "error"


class TestFinalProgress:
    def test_the_last_callback_reports_the_true_count(self, tmp_path: Path) -> None:
        """250 events used to report 200 as the last word."""
        seen: list[int] = []
        orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
        result = orch.run(
            RunRequest(technique_id="REP-002", intensity="low", seed=1337, no_send=True),
            on_progress=lambda count, _total: seen.append(count),
        )

        assert seen, "no progress was reported at all"
        assert seen[-1] == result.event_count

    def test_a_consumer_that_arrives_late_still_gets_the_run(self) -> None:
        """The replay, and the regression that proved it was load-bearing.

        The client starts a run and only then opens the stream, so a short run
        routinely finishes before any subscriber exists. The old shared queue
        covered that by accident: nothing had drained it, so a late consumer
        found the whole run waiting. Fan-out removed the accident, and
        `test_run_stream_reports_lines_and_done` immediately began receiving an
        empty body. Without this guard the next refactor reintroduces it.
        """
        handle = _handle()
        for i in range(3):
            handle.publish({"type": "line", "data": f"line-{i}"})
        handle.publish({"type": "done", "count": 3})

        late = handle.subscribe()

        seen = []
        while not late.empty():
            seen.append(late.get_nowait())
        assert [i.get("data") for i in seen if i["type"] == "line"] == [
            "line-0",
            "line-1",
            "line-2",
        ]
        assert seen[-1]["type"] == "done"

    def test_the_replay_is_bounded(self) -> None:
        from replicant.web.runner import MAX_HISTORY_ITEMS

        handle = _handle()
        for i in range(MAX_HISTORY_ITEMS + 500):
            handle.publish({"type": "line", "data": str(i)})

        assert len(handle.history) == MAX_HISTORY_ITEMS


class TestManifestCompleteness:
    """The manifest should answer questions about its own run without help.

    Review finding #1: ScenarioManifest recorded vendor and duration, RunManifest
    did not, and neither recorded the rate in force or what the socket actually
    did. A manifest that cannot say which profile rendered it, or how many
    datagrams left, is a weaker audit record than safety rule 5 implies.
    """

    def test_a_run_records_its_vendor_duration_and_rate(self, tmp_path: Path) -> None:
        orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
        result = orch.run(
            RunRequest(
                technique_id="REP-001",
                intensity="low",
                duration="90s",
                seed=1337,
                no_send=True,
            )
        )

        assert result.manifest.vendor == "fortigate"
        assert result.manifest.duration == "90s"
        assert result.manifest.rate is not None and result.manifest.rate > 0

    def test_a_sending_run_records_what_the_socket_did(self, tmp_path: Path) -> None:
        import socket as _socket

        listener = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        listener.bind(("127.0.0.1", 0))
        port = int(listener.getsockname()[1])
        try:
            orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
            result = orch.run(
                RunRequest(
                    technique_id="REP-001",
                    intensity="low",
                    duration="60s",
                    no_send=False,
                    pace="burst",
                    collector=CollectorProfile(
                        name="t", host="127.0.0.1", port=port, transport="udp"
                    ),
                )
            )
        finally:
            listener.close()

        stats = result.manifest.send_stats
        assert stats is not None
        assert stats["sends"] == result.event_count
        assert stats["errors"] == 0

    def test_a_run_with_no_collector_records_no_send_stats(self, tmp_path: Path) -> None:
        """None is the honest answer, not a row of zeroes that reads like a send."""
        orch = Orchestrator(CATALOG, Settings(manifest_dir=str(tmp_path)))
        result = orch.run(RunRequest(technique_id="REP-001", intensity="low", no_send=True))

        assert result.manifest.send_stats is None

    def test_an_older_manifest_without_the_new_fields_still_loads(self) -> None:
        """Every new field is defaulted, as pace and speed were before them."""
        from replicant.core.models import RunManifest

        manifest = RunManifest(
            replicant_version="0.1.0",
            technique_id="REP-001",
            technique_name="x",
            ndr_uc="UC-001",
            intensity="low",
            seed=1,
            params={},
            entities={},
            target="none",
            transport="none",
            event_count=1,
            started_at="t",
            ended_at="t",
            anchor_epoch=0,
        )

        assert manifest.vendor == ""
        assert manifest.send_stats is None
