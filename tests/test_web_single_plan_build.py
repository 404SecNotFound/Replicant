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
"""A web start builds its plan once.

The defect this guards: ``POST /api/runs`` built the plan to price its pacing,
then the worker's Orchestrator built the same plan again before emitting it.
Building is pure and seeded, so the second build was wasted CPU on the request
path, about 1.6 seconds for REP-004 at high intensity. Counting builds is used
rather than timing, which passes or fails on how busy the machine is.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from replicant.config.settings import Settings  # noqa: E402
from replicant.core.models import load_catalog  # noqa: E402
from replicant.core.orchestrator import Orchestrator  # noqa: E402
from replicant.resources import TECHNIQUE_CATALOG  # noqa: E402
from replicant.web.server import create_app  # noqa: E402

TOKEN = "test-token"
HEADERS = {"x-replicant-token": TOKEN}
CATALOG = load_catalog(TECHNIQUE_CATALOG)


@pytest.fixture()
def client(tmp_path: Path) -> TestClient:
    settings = Settings(manifest_dir=str(tmp_path / "manifests"))
    return TestClient(create_app(CATALOG, settings, token=TOKEN), base_url="http://localhost")


@pytest.fixture()
def builds(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    counter = {"n": 0}
    original = Orchestrator.build_plan

    def counted(self, request):  # type: ignore[no-untyped-def]
        counter["n"] += 1
        return original(self, request)

    monkeypatch.setattr(Orchestrator, "build_plan", counted)
    return counter


def _run_to_done(client: TestClient, **over: object) -> dict[str, Any]:
    body = {"technique_id": "REP-001", "intensity": "medium", "seed": 1337, "no_send": True}
    body.update(over)
    resp = client.post("/api/runs", headers=HEADERS, json=body)
    assert resp.status_code == 200, resp.text
    run_id = resp.json()["run_id"]
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        snapshot = client.get(f"/api/runs/{run_id}", headers=HEADERS).json()
        if snapshot["status"] in {"done", "stopped", "error"}:
            return snapshot
        time.sleep(0.01)
    pytest.fail(f"run {run_id} did not finish")


@pytest.mark.parametrize("vendor", ["fortigate", "paloalto"])
def test_a_web_start_builds_the_plan_once(
    client: TestClient, builds: dict[str, int], vendor: str
) -> None:
    # paloalto is not the configured default, so it takes the per-vendor
    # orchestrator path on both the preview and the worker side.
    snapshot = _run_to_done(client, vendor=vendor)

    assert snapshot["status"] == "done"
    assert builds["n"] == 1, f"the plan was built {builds['n']} times for one start"


def test_the_reused_plan_is_the_plan_the_run_records(client: TestClient) -> None:
    """Reuse must not change what is emitted: the count and the manifest agree."""
    priced = client.post(
        "/api/plan",
        headers=HEADERS,
        json={"technique_id": "REP-004", "intensity": "low", "seed": 7, "no_send": True},
    )
    assert priced.status_code == 200, priced.text

    snapshot = _run_to_done(client, technique_id="REP-004", intensity="low", seed=7)

    planned = priced.json()["event_count"]
    assert snapshot["status"] == "done"
    assert snapshot["event_count"] == planned
    assert snapshot["manifest"]["planned_event_count"] == planned
    assert snapshot["manifest"]["seed"] == 7
