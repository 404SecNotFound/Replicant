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

from pathlib import Path

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


def test_no_active_run_is_reported_as_none(client: TestClient) -> None:
    resp = client.get("/api/runs/active", headers=HEADERS)

    assert resp.status_code == 200
    assert resp.json()["run_id"] is None


def test_an_active_run_is_reported_with_enough_to_identify_it(client: TestClient) -> None:
    started = _start(client)

    body = client.get("/api/runs/active", headers=HEADERS).json()

    assert body["run_id"] == started["run_id"]
    # The id alone is what the 409 already carried and it was not enough to act
    # on. Naming the technique is what lets the form say which run is holding the
    # lock rather than quoting a hex string at the operator.
    assert body["technique_id"] == "REP-001"
    assert body["status"] == "running"


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
        import time

        time.sleep(0.05)

    assert client.get("/api/runs/active", headers=HEADERS).json()["run_id"] is None


def test_active_run_needs_a_token(client: TestClient) -> None:
    assert client.get("/api/runs/active").status_code == 401
