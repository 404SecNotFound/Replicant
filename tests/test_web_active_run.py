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
"""The active run is server state, so the client has to be able to ask for it.

The defect this guards: only one run may be active at a time, which is correct
because each run carries its own rate limiter and concurrent runs to one
collector would multiply the eps cap (safety rule 4). But the only way a client
could learn a run was active was to try to start one and read a 409 carrying a
bare run id.

That became acute when sending to a collector started defaulting to plan pace: a
REP-001 run is then just under four hours, and the form's ``running`` flag is
per-panel state. Selecting a different technique remounted the panel, the flag
reset, the button re-enabled, and pressing it produced a 409 whose text named a
run the operator could not see, stop, or identify. The reported symptom was "I
press the button and nothing starts".
"""

from __future__ import annotations

import threading
import time
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from replicant.config.settings import Settings  # noqa: E402
from replicant.core.models import load_catalog  # noqa: E402
from replicant.resources import TECHNIQUE_CATALOG  # noqa: E402
from replicant.web.server import create_app  # noqa: E402

TOKEN = "test-token"
HEADERS = {"x-replicant-token": TOKEN}
CATALOG = load_catalog(TECHNIQUE_CATALOG)
# Discard: port 9 is the standard sink. Nothing listens, and UDP never says so,
# which is exactly the deployment this endpoint has to describe honestly.
COLLECTOR = {"host": "127.0.0.1", "port": 9, "transport": "udp"}


@pytest.fixture()
def client(tmp_path: Path) -> TestClient:
    settings = Settings(manifest_dir=str(tmp_path / "manifests"))
    app = create_app(CATALOG, settings, token=TOKEN)
    return TestClient(app, base_url="http://localhost")


def _start(client: TestClient, **over: object) -> dict:
    body = {
        "technique_id": "REP-001",
        "intensity": "medium",
        "seed": 1337,
        "collector": COLLECTOR,
        "no_send": False,
        **over,
    }
    resp = client.post("/api/runs", headers=HEADERS, json=body)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _reserve(client: TestClient, **over: object) -> dict:
    body = {
        "admission_id": str(uuid.uuid4()),
        "technique_id": "REP-001",
        "vendor": "fortigate",
        **over,
    }
    resp = client.post("/api/run-admissions", headers=HEADERS, json=body)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _wait_for_status(client: TestClient, run_id: str, expected: str) -> dict[str, Any]:
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        snapshot = client.get(f"/api/runs/{run_id}", headers=HEADERS).json()
        if snapshot["status"] == expected:
            return snapshot
        time.sleep(0.01)
    pytest.fail(f"run {run_id} did not reach {expected}")


def test_no_active_run_is_reported_as_none(client: TestClient) -> None:
    resp = client.get("/api/runs/active", headers=HEADERS)

    assert resp.status_code == 200
    assert resp.json()["run_id"] is None
    assert resp.json()["admission_id"] is None
    assert resp.json()["vendor"] is None


def test_acknowledged_reservation_is_authoritative_and_queryable(client: TestClient) -> None:
    reserved = _reserve(client, vendor="paloalto")

    try:
        active = client.get("/api/runs/active", headers=HEADERS).json()
        admission = client.get(
            f"/api/run-admissions/{reserved['admission_id']}", headers=HEADERS
        ).json()
        status = client.get(f"/api/runs/{reserved['run_id']}", headers=HEADERS).json()

        assert active["run_id"] == admission["run_id"] == status["run_id"]
        assert active["admission_id"] == admission["admission_id"] == reserved["admission_id"]
        assert active["status"] == admission["status"] == status["status"] == "reserved"
        assert active["vendor"] == admission["vendor"] == status["vendor"] == "paloalto"
    finally:
        client.post(f"/api/runs/{reserved['run_id']}/stop", headers=HEADERS)


def test_lost_reservation_response_can_retry_the_same_client_id(client: TestClient) -> None:
    admission_id = str(uuid.uuid4())
    body = {
        "admission_id": admission_id,
        "technique_id": "REP-001",
        "vendor": "fortigate",
    }

    first = client.post("/api/run-admissions", headers=HEADERS, json=body)
    retried = client.post("/api/run-admissions", headers=HEADERS, json=body)

    try:
        assert first.status_code == retried.status_code == 200
        assert first.json() == retried.json()
        assert retried.json()["admission_id"] == admission_id
    finally:
        client.post(f"/api/runs/{first.json()['run_id']}/stop", headers=HEADERS)


def test_a_second_reservation_conflicts_with_the_authoritative_owner(
    client: TestClient,
) -> None:
    reserved = _reserve(client, vendor="checkpoint")

    try:
        response = client.post(
            "/api/run-admissions",
            headers=HEADERS,
            json={
                "admission_id": str(uuid.uuid4()),
                "technique_id": "REP-002",
                "vendor": "fortigate",
            },
        )

        assert response.status_code == 409
        detail = response.json()["detail"]
        assert detail["authoritative"] is True
        assert detail["code"] == "run_in_progress"
        assert detail["admission_id"] == reserved["admission_id"]
        assert detail["run_id"] == reserved["run_id"]
        assert detail["vendor"] == "checkpoint"
        assert detail["status"] == "reserved"
    finally:
        client.post(f"/api/runs/{reserved['run_id']}/stop", headers=HEADERS)


def test_claim_remains_visible_during_slow_preview_and_promotes_without_a_gap(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from replicant.core.orchestrator import Orchestrator

    reserved = _reserve(client)
    entered_preview = threading.Event()
    release_preview = threading.Event()
    original_preview = Orchestrator.preview_pacing
    result: dict[str, Any] = {}

    def slow_preview(self: Orchestrator, *args: Any, **kwargs: Any) -> Any:
        entered_preview.set()
        assert release_preview.wait(timeout=5.0), "test did not release preview"
        return original_preview(self, *args, **kwargs)

    monkeypatch.setattr(Orchestrator, "preview_pacing", slow_preview)

    def start_reserved() -> None:
        result["response"] = client.post(
            "/api/runs",
            headers=HEADERS,
            json={
                "admission_id": reserved["admission_id"],
                "technique_id": "REP-001",
                "intensity": "low",
                "no_send": True,
            },
        )

    thread = threading.Thread(target=start_reserved)
    thread.start()
    try:
        assert entered_preview.wait(timeout=5.0), "start never entered preview"
        active = client.get("/api/runs/active", headers=HEADERS).json()
        status = client.get(f"/api/runs/{reserved['run_id']}", headers=HEADERS).json()
        conflict = client.post(
            "/api/run-admissions",
            headers=HEADERS,
            json={
                "admission_id": str(uuid.uuid4()),
                "technique_id": "REP-002",
                "vendor": "paloalto",
            },
        )

        assert active["run_id"] == status["run_id"] == reserved["run_id"]
        assert active["status"] == status["status"] == "admitting"
        assert conflict.status_code == 409
        assert conflict.json()["detail"]["run_id"] == reserved["run_id"]
    finally:
        release_preview.set()
        thread.join(timeout=10.0)

    assert not thread.is_alive()
    response = result["response"]
    assert response.status_code == 200, response.text
    assert response.json()["run_id"] == reserved["run_id"]
    assert response.json()["admission_id"] == reserved["admission_id"]


def test_preview_failure_releases_the_admission_and_remains_queryable(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    reserved = _reserve(client)

    def fail_preview(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("preview failed")

    monkeypatch.setattr("replicant.web.server.Orchestrator.preview_pacing", fail_preview)
    response = client.post(
        "/api/runs",
        headers=HEADERS,
        json={
            "admission_id": reserved["admission_id"],
            "technique_id": "REP-001",
            "intensity": "low",
            "no_send": True,
        },
    )

    assert response.status_code == 400
    assert client.get("/api/runs/active", headers=HEADERS).json()["run_id"] is None
    admission = client.get(
        f"/api/run-admissions/{reserved['admission_id']}", headers=HEADERS
    ).json()
    assert admission["run_id"] == reserved["run_id"]
    assert admission["status"] == "error"


def test_stop_cancels_an_unclaimed_reservation_without_late_promotion(
    client: TestClient,
) -> None:
    reserved = _reserve(client)

    stopped = client.post(f"/api/runs/{reserved['run_id']}/stop", headers=HEADERS)
    response = client.post(
        "/api/runs",
        headers=HEADERS,
        json={
            "admission_id": reserved["admission_id"],
            "technique_id": "REP-001",
            "intensity": "low",
            "no_send": True,
        },
    )

    assert stopped.json() == {"ok": True}
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "admission_not_claimable"
    assert response.json()["detail"]["authoritative"] is True
    assert client.get("/api/runs/active", headers=HEADERS).json()["run_id"] is None
    assert (
        client.get(f"/api/runs/{reserved['run_id']}", headers=HEADERS).json()["status"] == "stopped"
    )


def test_stop_after_running_publication_is_not_lost_before_worker_entry(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A worker scheduled after Stop must inherit it, not clear and continue."""
    from replicant.web.runner import RunManager

    worker_entered = threading.Event()
    release_worker = threading.Event()
    original_worker = RunManager._worker

    def blocked_worker(self: RunManager, *args: Any, **kwargs: Any) -> None:
        worker_entered.set()
        assert release_worker.wait(timeout=5.0), "test did not release worker entry"
        original_worker(self, *args, **kwargs)

    monkeypatch.setattr(RunManager, "_worker", blocked_worker)
    started = _start(client, intensity="low", no_send=True)

    try:
        assert worker_entered.wait(timeout=5.0), "worker thread did not start"
        stopped = client.post(f"/api/runs/{started['run_id']}/stop", headers=HEADERS)
        assert stopped.json() == {"ok": True}
    finally:
        release_worker.set()

    terminal = _wait_for_status(client, started["run_id"], "stopped")
    assert terminal["event_count"] == 0


def test_an_active_run_is_reported_with_enough_to_identify_it(client: TestClient) -> None:
    started = _start(client)

    body = client.get("/api/runs/active", headers=HEADERS).json()

    assert body["run_id"] == started["run_id"]
    # The id alone is what the 409 already carried and it was not enough to act
    # on. Naming the technique is what lets the form say which run is holding the
    # lock rather than quoting a hex string at the operator.
    assert body["technique_id"] == "REP-001"
    assert body["status"] == "running"


def test_paloalto_run_identity_survives_start_and_restoration(client: TestClient) -> None:
    started = _start(client, vendor="paloalto")

    try:
        active = client.get("/api/runs/active", headers=HEADERS).json()
        status = client.get(f"/api/runs/{started['run_id']}", headers=HEADERS).json()

        assert active["run_id"] == status["run_id"] == started["run_id"]
        assert started["vendor"] == "paloalto"
        assert active["vendor"] == "paloalto"
        assert status["vendor"] == "paloalto"
    finally:
        client.post(f"/api/runs/{started['run_id']}/stop", headers=HEADERS)


def test_conflict_reports_the_paloalto_holder_not_the_attempted_vendor(
    client: TestClient,
) -> None:
    started = _start(client, vendor="paloalto")

    try:
        resp = client.post(
            "/api/runs",
            headers=HEADERS,
            json={
                "technique_id": "REP-002",
                "intensity": "low",
                "vendor": "checkpoint",
                "no_send": True,
            },
        )

        assert resp.status_code == 409
        detail = resp.json()["detail"]
        assert detail["run_id"] == started["run_id"]
        assert detail["vendor"] == "paloalto"
    finally:
        client.post(f"/api/runs/{started['run_id']}/stop", headers=HEADERS)


def test_restored_run_endpoints_track_each_render_before_progress_callback(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A sub-100 plan run must not read zero until its final callback."""
    from replicant.web.runner import RunHandle

    class FakeEmitter:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def connect(self) -> None:
            pass

        def send(self, line: str, level: str) -> int:
            return len(line) + len(level)

        def close(self) -> None:
            pass

    monkeypatch.setattr("replicant.core.orchestrator.SyslogEmitter", FakeEmitter)
    line_published = threading.Event()
    progress_published = threading.Event()
    release_worker = threading.Event()
    terminal_published = threading.Event()
    original_publish = RunHandle.publish

    def publish_then_pause(self: RunHandle, item: dict[str, object]) -> None:
        original_publish(self, item)
        if item.get("type") == "line" and not line_published.is_set():
            line_published.set()
            release_worker.wait(timeout=5.0)
        elif item.get("type") == "progress":
            progress_published.set()
        if item.get("type") in {"done", "error"}:
            terminal_published.set()

    monkeypatch.setattr(RunHandle, "publish", publish_then_pause)
    started = _start(client, intensity="low", duration="20m")

    try:
        assert line_published.wait(timeout=5.0), "worker published no rendered line"
        assert started["pace"] == "plan"
        assert 0 < started["total"] < 100
        assert started["projected_s"] > 60
        assert not progress_published.is_set(), "the coalesced progress callback fired early"
        active = client.get("/api/runs/active", headers=HEADERS).json()
        status = client.get(f"/api/runs/{started['run_id']}", headers=HEADERS).json()

        assert active["status"] == status["status"] == "running"
        assert active["event_count"] == status["event_count"] == 1
    finally:
        client.post(f"/api/runs/{started['run_id']}/stop", headers=HEADERS)
        release_worker.set()
        assert terminal_published.wait(timeout=5.0), "worker did not stop"


@pytest.mark.parametrize(("stopped", "terminal_status"), [(False, "done"), (True, "stopped")])
def test_done_or_stopped_status_never_precedes_its_final_snapshot(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    stopped: bool,
    terminal_status: str,
) -> None:
    """Pause at manifest transfer, where status used to become terminal first."""
    from replicant.core.orchestrator import Orchestrator

    transfer_entered = threading.Event()
    release_transfer = threading.Event()
    manifest_path = str(tmp_path / f"{terminal_status}.json")
    expected_manifest: dict[str, Any] = {}

    class BlockingManifest:
        def model_dump(self) -> dict[str, Any]:
            transfer_entered.set()
            assert release_transfer.wait(timeout=5.0), "test did not release manifest transfer"
            return expected_manifest

    def finish_run(*_args: object, **kwargs: object) -> SimpleNamespace:
        expected_manifest.update(
            {
                "run_id": kwargs["run_id"],
                "status": terminal_status,
                "event_count": 7,
            }
        )
        return SimpleNamespace(
            stopped=stopped,
            manifest=BlockingManifest(),
            manifest_path=Path(manifest_path),
            event_count=7,
        )

    monkeypatch.setattr(Orchestrator, "run", finish_run)
    started = _start(client, intensity="low", no_send=True)

    try:
        assert transfer_entered.wait(timeout=5.0), "worker did not enter manifest transfer"
        during_transfer = client.get(f"/api/runs/{started['run_id']}", headers=HEADERS).json()

        assert during_transfer["status"] == "running"
        assert during_transfer["manifest"] is None
        assert during_transfer["manifest_path"] is None
        assert during_transfer["event_count"] == 0
    finally:
        release_transfer.set()

    terminal = _wait_for_status(client, started["run_id"], terminal_status)
    assert terminal["manifest"] == expected_manifest
    assert terminal["manifest_path"] == manifest_path
    assert terminal["event_count"] == 7


def test_error_status_never_precedes_its_final_snapshot(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Pause at failed-record transfer, where error used to be visible first."""
    from replicant.core.orchestrator import Orchestrator

    transfer_entered = threading.Event()
    release_transfer = threading.Event()
    manifest_path = str(tmp_path / "error.json")
    expected_manifest = {"status": "error", "event_count": 5}

    def fail_run(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("forced worker failure")

    def read_failed_record(_exc: BaseException) -> dict[str, Any]:
        transfer_entered.set()
        assert release_transfer.wait(timeout=5.0), "test did not release record transfer"
        return {
            "manifest": expected_manifest,
            "manifest_path": manifest_path,
            "event_count": 5,
        }

    monkeypatch.setattr(Orchestrator, "run", fail_run)
    monkeypatch.setattr("replicant.web.runner.run_record_of", read_failed_record)
    started = _start(client, intensity="low", no_send=True)

    try:
        assert transfer_entered.wait(timeout=5.0), "worker did not enter record transfer"
        during_transfer = client.get(f"/api/runs/{started['run_id']}", headers=HEADERS).json()

        assert during_transfer["status"] == "running"
        assert during_transfer["manifest"] is None
        assert during_transfer["manifest_path"] is None
        assert during_transfer["event_count"] == 0
    finally:
        release_transfer.set()

    terminal = _wait_for_status(client, started["run_id"], "error")
    assert terminal["manifest"] == expected_manifest
    assert terminal["manifest_path"] == manifest_path
    assert terminal["event_count"] == 5


def test_a_rejected_second_start_names_the_technique_holding_the_lock(client: TestClient) -> None:
    _start(client)

    resp = client.post(
        "/api/runs",
        headers=HEADERS,
        json={
            "technique_id": "REP-002",
            "intensity": "low",
            "collector": COLLECTOR,
            "no_send": False,
        },
    )

    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["technique_id"] == "REP-001"
    assert detail["run_id"]


def test_the_active_run_clears_once_it_is_stopped(client: TestClient) -> None:
    started = _start(client)

    client.post(f"/api/runs/{started['run_id']}/stop", headers=HEADERS)
    for _ in range(200):
        if client.get("/api/runs/active", headers=HEADERS).json()["run_id"] is None:
            break
        time.sleep(0.05)

    assert client.get("/api/runs/active", headers=HEADERS).json()["run_id"] is None


def test_active_run_needs_a_token(client: TestClient) -> None:
    assert client.get("/api/runs/active").status_code == 401
